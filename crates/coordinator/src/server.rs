//! The HTTP surface: `/webhook`, `/connect`, `/enroll`, `/healthz`.
//!
//! TLS is terminated by the reverse proxy in front (Caddy, see
//! `deploy/coordinator`), so this listens on plain HTTP.
//!
//! # Logging
//!
//! Identifiers, counts and fixed words only. Never the webhook secret, an
//! invite code, a signature, a nonce, a key, or text that came off the wire
//! (repository names, labels and bodies included): a delivery id is logged
//! only after it was checked to be GUID-shaped.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;
use runner_manager_coordinator_protocol::{
    CLOSE_UNAUTHORIZED, CLOSE_UNSUPPORTED_VERSION, CONNECT_PATH, ENROLL_PATH, EnrollRequest,
    EnrollResponse, HEALTH_PATH, HostMessage, LAUNCH_VERSION, MAX_MESSAGE_BYTES,
    MIN_PROTOCOL_VERSION, NONCE_LEN, PROTOCOL_VERSION, ServerMessage, WEBHOOK_PATH,
    decode_public_key, encode_nonce, supported, verify_challenge,
};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::sync::mpsc;

use crate::placement::{CLAIM_GRACE, JobKey, Placement};
use crate::registry::{OUTBOUND_QUEUE, Outbound, Registry};
use crate::store::{EnrollError, Store};
use crate::webhook::{
    DELIVERY_MEMORY, DeliveryLog, MAX_BODY_BYTES, WorkflowJobEvent, action_name, required_labels,
    signature_valid, valid_delivery_id,
};

/// Largest enrollment request body.
const MAX_ENROLL_BYTES: usize = 16 * 1024;

/// How often a connected host's `last_seen_at` is rewritten.
const TOUCH_EVERY: Duration = Duration::from_secs(60);

/// The server's settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// `https://runners.example.com` — what hosts sign their challenge for.
    pub public_origin: String,
    pub webhook_secret: SecretString,
    /// Take the client address from the right-most `X-Forwarded-For` entry,
    /// which is the one the proxy in front appended. Only behind that proxy.
    pub trust_forwarded_for: bool,
    pub heartbeat_interval: Duration,
    /// How long a new connection has to answer its challenge.
    pub auth_timeout: Duration,
    /// How often the server checks whether the admin CLI wrote to the
    /// database (SQLite's `data_version`, no query), and if so closes the
    /// connections of revoked hosts. Also how often a connection checks that
    /// its host is still heard from.
    pub revocation_check: Duration,
    /// Connection and enrollment attempts allowed per client address per
    /// minute.
    pub attempts_per_minute: u32,
}

impl Config {
    #[must_use]
    pub fn new(public_origin: String, webhook_secret: SecretString) -> Self {
        Self {
            public_origin,
            webhook_secret,
            trust_forwarded_for: false,
            heartbeat_interval: Duration::from_secs(15),
            auth_timeout: Duration::from_secs(10),
            revocation_check: Duration::from_millis(500),
            attempts_per_minute: 20,
        }
    }
}

/// Everything the handlers share.
#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub store: Mutex<Store>,
    pub registry: Arc<Registry>,
    /// Stage 3: which host starts a runner for a queued pool job.
    pub placement: Arc<Placement>,
    deliveries: Mutex<DeliveryLog>,
    limiter: RateLimiter,
}

impl AppState {
    #[must_use]
    pub fn new(config: Config, store: Store) -> Arc<Self> {
        let registry = Arc::new(Registry::default());
        Arc::new(Self {
            limiter: RateLimiter::new(config.attempts_per_minute),
            config,
            store: Mutex::new(store),
            placement: Arc::new(Placement::new(Arc::clone(&registry))),
            registry,
            deliveries: Mutex::new(DeliveryLog::new(DELIVERY_MEMORY)),
        })
    }

    /// Revokes a host and closes its live connection at once: the in-process
    /// path. The admin CLI, another process, is noticed by
    /// `watch_revocations` instead.
    ///
    /// # Errors
    /// The store's: no such active host, an ambiguous name, SQLite.
    pub fn revoke(&self, host: &str) -> Result<crate::store::HostRecord, crate::store::StoreError> {
        let record = self.store().revoke(host, Utc::now())?;
        close_revoked(self);
        Ok(record)
    }

    /// Rebalances `key` after `delay`, off the caller's task.
    fn rebalance_later(&self, key: JobKey, delay: Duration) {
        let placement = Arc::clone(&self.placement);
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            placement.rebalance(&key).await;
        });
    }

    /// Retries every unplaced pool job, off the caller's task: a slot was
    /// freed somewhere.
    fn retry_placement(&self) {
        let placement = Arc::clone(&self.placement);
        tokio::spawn(async move {
            for key in placement.expire(Instant::now()) {
                placement.rebalance(&key).await;
            }
        });
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn client_address(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        if self.config.trust_forwarded_for
            && let Some(forwarded) = headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .filter_map(|entry| entry.trim().parse::<IpAddr>().ok())
                .next_back()
        {
            return forwarded;
        }
        peer.ip()
    }
}

/// The router, for [`serve`] and for tests.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            WEBHOOK_PATH,
            post(webhook).layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
        )
        .route(
            ENROLL_PATH,
            post(enroll).layer(DefaultBodyLimit::max(MAX_ENROLL_BYTES)),
        )
        .route(CONNECT_PATH, get(connect))
        .route(HEALTH_PATH, get(|| async { "ok" }))
        .with_state(state)
}

/// Serves until the listener fails or `shutdown` resolves, with placement's
/// lease clock and the revocation watcher running beside it.
///
/// # Errors
/// The listener's.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let placement = tokio::spawn(Arc::clone(&state.placement).run());
    let revocations = tokio::spawn(watch_revocations(Arc::clone(&state)));
    let served = axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await;
    placement.abort();
    revocations.abort();
    served
}

/// Closes a revoked host's connection as soon as `hosts revoke` commits.
///
/// The admin CLI is another process writing the same SQLite file, so there is
/// nothing to signal across. Every [`Config::revocation_check`] (500 ms) this
/// reads SQLite's `data_version`, which only another connection's commit
/// changes and which costs no query; only when it moved does it look up the
/// connected hosts. Chosen over a loopback admin endpoint, which would be one
/// more door on a server that faces the internet behind a proxy.
async fn watch_revocations(state: Arc<AppState>) {
    let mut ticks = tokio::time::interval(state.config.revocation_check);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut seen = state.store().data_version().ok();
    loop {
        ticks.tick().await;
        let version = state.store().data_version().ok();
        if version == seen {
            continue;
        }
        seen = version;
        close_revoked(&state);
    }
}

/// Closes the connection of every connected host that is no longer active.
pub fn close_revoked(state: &AppState) {
    for host_id in state.registry.host_ids() {
        let active = state
            .store()
            .active_host(&host_id)
            .map(|record| record.is_some());
        if matches!(active, Ok(false))
            && state
                .registry
                .close(&host_id, CLOSE_UNAUTHORIZED, "revoked")
        {
            tracing::info!(%host_id, "a revoked host was disconnected");
        }
    }
}

// ---------------------------------------------------------------------------
// /webhook
// ---------------------------------------------------------------------------

async fn webhook(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    // Before anything else, and with no detail either way.
    if !signature_valid(
        state.config.webhook_secret.expose_secret().as_bytes(),
        &body,
        header("x-hub-signature-256"),
    ) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Some(event), Some(delivery)) = (header("x-github-event"), header("x-github-delivery"))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !valid_delivery_id(delivery) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let first_time = state
        .deliveries
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .first_time(delivery);
    if !first_time {
        tracing::info!(%delivery, "a repeated webhook delivery was acknowledged and ignored");
        return StatusCode::OK.into_response();
    }
    match event {
        "ping" => {
            tracing::info!(%delivery, "GitHub pinged the webhook");
            StatusCode::OK.into_response()
        }
        "workflow_job" => {
            let Ok(job) = serde_json::from_slice::<WorkflowJobEvent>(&body) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let action = action_name(&job.action);
            let required = required_labels(&job.workflow_job.labels);
            let repository = &job.repository.full_name;
            if action == "queued" {
                let woken =
                    state
                        .registry
                        .wake_for_job(repository, &job.workflow_job.labels, delivery);
                let placed = required
                    .and_then(|required| {
                        state
                            .placement
                            .queued(repository, &required, job.workflow_job.id)
                    })
                    .map(|key| state.rebalance_later(key, Duration::ZERO))
                    .is_some();
                tracing::info!(
                    %delivery,
                    job_id = job.workflow_job.id,
                    run_id = job.workflow_job.run_id,
                    woken,
                    placed,
                    "a queued job woke the hosts that serve it"
                );
            } else {
                // A pool job left the queue: its surplus lease, if any, is
                // cancelled once the host whose runner took it had time to
                // say so.
                if matches!(action, "in_progress" | "completed")
                    && let Some(key) = required.and_then(|required| {
                        state
                            .placement
                            .dequeued(repository, &required, job.workflow_job.id)
                    })
                {
                    state.rebalance_later(key, CLAIM_GRACE);
                }
                // Recorded for later stages (statistics, lease confirmation).
                tracing::info!(
                    %delivery,
                    action,
                    job_id = job.workflow_job.id,
                    run_id = job.workflow_job.run_id,
                    "workflow job event"
                );
            }
            StatusCode::OK.into_response()
        }
        _ => StatusCode::ACCEPTED.into_response(),
    }
}

// ---------------------------------------------------------------------------
// /enroll
// ---------------------------------------------------------------------------

async fn enroll(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state
        .limiter
        .allow(state.client_address(peer, &headers), Instant::now())
    {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Ok(request) = serde_json::from_slice::<EnrollRequest>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !supported(request.protocol_version) {
        return StatusCode::UPGRADE_REQUIRED.into_response();
    }
    if decode_public_key(&request.public_key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let result = state.store().enroll(
        &request.code,
        &request.hostname,
        &request.public_key,
        Utc::now(),
    );
    match result {
        Ok(host) => {
            tracing::info!(host_id = %host.id, "a host enrolled");
            axum::Json(EnrollResponse {
                // The host's own version back: enrollment is the same in both.
                protocol_version: request.protocol_version,
                host_id: host.id,
                name: host.name,
            })
            .into_response()
        }
        Err(EnrollError::InvalidCode) => {
            tracing::warn!("an enrollment with an unusable code was refused");
            StatusCode::UNAUTHORIZED.into_response()
        }
        Err(EnrollError::Store(error)) => {
            tracing::error!(%error, "an enrollment could not be stored");
            StatusCode::CONFLICT.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// /connect
// ---------------------------------------------------------------------------

async fn connect(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !state
        .limiter
        .allow(state.client_address(peer, &headers), Instant::now())
    {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    upgrade
        .max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| connection(socket, state))
}

async fn send(socket: &mut WebSocket, message: &ServerMessage) -> bool {
    socket
        .send(Message::Text(message.encode().into()))
        .await
        .is_ok()
}

async fn close(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await;
}

/// The next text frame, skipping control frames; `None` when the socket ended.
async fn next_text(socket: &mut WebSocket) -> Option<String> {
    loop {
        match socket.recv().await? {
            Ok(Message::Text(text)) => return Some(text.to_string()),
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Binary(_)) => {}
            Ok(Message::Close(_)) | Err(_) => return None,
        }
    }
}

/// Challenge, verify, then serve one authenticated host.
async fn connection(mut socket: WebSocket, state: Arc<AppState>) {
    let nonce: [u8; NONCE_LEN] = rand::random();
    // `protocol_version` is the oldest accepted, which is what a version-1
    // host checks; the newest is in the additive field.
    let challenge = ServerMessage::Challenge {
        protocol_version: MIN_PROTOCOL_VERSION,
        nonce: encode_nonce(&nonce),
        max_protocol_version: Some(PROTOCOL_VERSION),
    };
    if !send(&mut socket, &challenge).await {
        return;
    }
    let answer = tokio::time::timeout(state.config.auth_timeout, next_text(&mut socket)).await;
    let Ok(Some(text)) = answer else {
        close(&mut socket, CLOSE_UNAUTHORIZED, "unauthorized").await;
        return;
    };
    let Ok(HostMessage::Auth {
        protocol_version,
        host_id,
        signature,
    }) = HostMessage::decode(&text)
    else {
        close(&mut socket, CLOSE_UNAUTHORIZED, "unauthorized").await;
        return;
    };
    if !supported(protocol_version) {
        close(
            &mut socket,
            CLOSE_UNSUPPORTED_VERSION,
            "unsupported protocol version",
        )
        .await;
        return;
    }
    // Unknown, revoked and wrong-key look the same from outside.
    let record = state.store().active_host(&host_id).ok().flatten();
    let verified = record.as_ref().is_some_and(|record| {
        decode_public_key(&record.public_key).is_ok_and(|key| {
            verify_challenge(&key, &nonce, &state.config.public_origin, &signature)
        })
    });
    let Some(record) = record.filter(|_| verified) else {
        tracing::warn!("a connection failed host authentication");
        close(&mut socket, CLOSE_UNAUTHORIZED, "unauthorized").await;
        return;
    };
    let host_id = record.id;
    let welcome = ServerMessage::Welcome {
        protocol_version,
        heartbeat_interval_secs: u32::try_from(state.config.heartbeat_interval.as_secs())
            .unwrap_or(u32::MAX),
    };
    if !send(&mut socket, &welcome).await {
        return;
    }
    let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE);
    let connection = state.registry.register(&host_id, protocol_version, sender);
    // A revocation committed between the check above and this registration
    // would be missed by the watcher, which looks only at connected hosts.
    if !matches!(state.store().active_host(&host_id), Ok(Some(_))) {
        state.registry.unregister(&host_id, connection);
        close(&mut socket, CLOSE_UNAUTHORIZED, "revoked").await;
        return;
    }
    tracing::info!(%host_id, version = protocol_version, "a host connected");
    let _ = state.store().touch(&host_id, Utc::now());
    serve_host(
        &mut socket,
        &state,
        &host_id,
        (connection, protocol_version),
        receiver,
    )
    .await;
    if state.registry.unregister(&host_id, connection) {
        state.placement.host_gone(&host_id);
    }
    tracing::info!(%host_id, "a host disconnected");
}

async fn serve_host(
    socket: &mut WebSocket,
    state: &AppState,
    host_id: &str,
    (connection, version): (u64, u32),
    mut receiver: mpsc::Receiver<Outbound>,
) {
    let silence_limit = state.config.heartbeat_interval.saturating_mul(3);
    let mut last_heard = Instant::now();
    // `connection` touched the record just before this.
    let mut last_touched = Instant::now();
    let mut checks = tokio::time::interval(state.config.revocation_check);
    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            frame = socket.recv() => {
                let text = match frame {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Binary(_))) => {
                        last_heard = Instant::now();
                        continue;
                    }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                };
                last_heard = Instant::now();
                match HostMessage::decode(&text) {
                    Ok(HostMessage::Hello(hello)) => {
                        if hello.protocol_version != version {
                            close(socket, CLOSE_UNSUPPORTED_VERSION, "unsupported protocol version").await;
                            return;
                        }
                        tracing::info!(
                            %host_id,
                            targets = hello.targets.len(),
                            cores = hello.cores,
                            "a host described itself"
                        );
                        state.registry.set_hello(host_id, connection, hello);
                    }
                    Ok(HostMessage::Heartbeat(heartbeat)) => {
                        state.registry.set_heartbeat(host_id, connection, heartbeat);
                        // `last_seen_at` is for `hosts list`; a write per
                        // heartbeat per host would hold the shared store's
                        // lock on the runtime for nothing.
                        if last_touched.elapsed() >= TOUCH_EVERY {
                            last_touched = Instant::now();
                            let _ = state.store().touch(host_id, Utc::now());
                        }
                    }
                    Ok(HostMessage::LaunchAck(ack)) if version >= LAUNCH_VERSION => {
                        state.placement.acknowledged(host_id, ack);
                    }
                    Ok(HostMessage::AttemptStarted(started)) if version >= LAUNCH_VERSION => {
                        state.placement.attempt_started(host_id, &started);
                    }
                    Ok(HostMessage::AttemptFinished(finished)) if version >= LAUNCH_VERSION => {
                        state.placement.attempt_finished(host_id, &finished);
                        state.retry_placement();
                    }
                    // A second `auth`, a message its version does not have, a
                    // newer message type, or garbage: skipped.
                    Ok(
                        HostMessage::Auth { .. }
                        | HostMessage::Unknown
                        | HostMessage::LaunchAck(_)
                        | HostMessage::AttemptStarted(_)
                        | HostMessage::AttemptFinished(_),
                    )
                    | Err(_) => {}
                }
            }
            outbound = receiver.recv() => match outbound {
                Some(Outbound::Send(message)) => {
                    if !send(socket, &message).await {
                        return;
                    }
                }
                Some(Outbound::Close(code, reason)) => {
                    close(socket, code, reason).await;
                    return;
                }
                None => return,
            },
            // Revocation is the watcher's (`watch_revocations`): it closes
            // this connection through the registry.
            _ = checks.tick() => {
                if last_heard.elapsed() > silence_limit {
                    tracing::info!(%host_id, "a silent host was disconnected");
                    close(socket, 1001, "silent").await;
                    return;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// Attempts per client address per fixed one-minute window.
#[derive(Debug)]
struct RateLimiter {
    per_minute: u32,
    windows: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

/// Addresses remembered before expired windows are swept.
const RATE_LIMIT_SWEEP_AT: usize = 4096;
const WINDOW: Duration = Duration::from_secs(60);

impl RateLimiter {
    fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            windows: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, address: IpAddr, now: Instant) -> bool {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if windows.len() >= RATE_LIMIT_SWEEP_AT {
            windows.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
        }
        let entry = windows.entry(address).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= self.per_minute
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_are_limited_per_address_per_minute() {
        let limiter = RateLimiter::new(2);
        let start = Instant::now();
        let one: IpAddr = "203.0.113.1".parse().expect("ip");
        let two: IpAddr = "203.0.113.2".parse().expect("ip");
        assert!(limiter.allow(one, start));
        assert!(limiter.allow(one, start));
        assert!(!limiter.allow(one, start));
        assert!(
            limiter.allow(two, start),
            "another address has its own budget"
        );
        assert!(limiter.allow(one, start + WINDOW), "a new window resets it");
    }

    #[test]
    fn the_forwarded_address_is_used_only_when_trusted() {
        let mut config = Config::new("https://x.example".into(), SecretString::from("s"));
        let peer: SocketAddr = "10.0.0.2:5000".parse().expect("addr");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "1.1.1.1, 198.51.100.7".parse().expect("header"),
        );
        let untrusted = AppState::new(config.clone(), Store::open_in_memory().expect("store"));
        assert_eq!(untrusted.client_address(peer, &headers), peer.ip());
        config.trust_forwarded_for = true;
        let trusted = AppState::new(config, Store::open_in_memory().expect("store"));
        assert_eq!(
            trusted.client_address(peer, &headers),
            "198.51.100.7".parse::<IpAddr>().expect("ip"),
            "the right-most entry is the one the proxy appended"
        );
    }
}
