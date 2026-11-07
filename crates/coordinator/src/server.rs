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
    EnrollResponse, HEALTH_PATH, HostMessage, MAX_MESSAGE_BYTES, NONCE_LEN, PROTOCOL_VERSION,
    ServerMessage, WEBHOOK_PATH, decode_public_key, encode_nonce, verify_challenge,
};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::sync::mpsc;

use crate::registry::{OUTBOUND_QUEUE, Outbound, Registry};
use crate::store::{EnrollError, Store};
use crate::webhook::{
    DELIVERY_MEMORY, DeliveryLog, MAX_BODY_BYTES, WorkflowJobEvent, action_name, signature_valid,
    valid_delivery_id,
};

/// Largest enrollment request body.
const MAX_ENROLL_BYTES: usize = 16 * 1024;

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
    /// How often a live connection re-checks that its host is not revoked.
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
            revocation_check: Duration::from_secs(10),
            attempts_per_minute: 20,
        }
    }
}

/// Everything the handlers share.
#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub store: Mutex<Store>,
    pub registry: Registry,
    deliveries: Mutex<DeliveryLog>,
    limiter: RateLimiter,
}

impl AppState {
    #[must_use]
    pub fn new(config: Config, store: Store) -> Arc<Self> {
        Arc::new(Self {
            limiter: RateLimiter::new(config.attempts_per_minute),
            config,
            store: Mutex::new(store),
            registry: Registry::default(),
            deliveries: Mutex::new(DeliveryLog::new(DELIVERY_MEMORY)),
        })
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

/// Serves until the listener fails or `shutdown` resolves.
///
/// # Errors
/// The listener's.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
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
            if action == "queued" {
                let woken = state.registry.wake_for_job(
                    &job.repository.full_name,
                    &job.workflow_job.labels,
                    delivery,
                );
                tracing::info!(
                    %delivery,
                    job_id = job.workflow_job.id,
                    run_id = job.workflow_job.run_id,
                    woken,
                    "a queued job woke the hosts that serve it"
                );
            } else {
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
    if request.protocol_version != PROTOCOL_VERSION {
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
                protocol_version: PROTOCOL_VERSION,
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
    let challenge = ServerMessage::Challenge {
        protocol_version: PROTOCOL_VERSION,
        nonce: encode_nonce(&nonce),
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
    if protocol_version != PROTOCOL_VERSION {
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
        protocol_version: PROTOCOL_VERSION,
        heartbeat_interval_secs: u32::try_from(state.config.heartbeat_interval.as_secs())
            .unwrap_or(u32::MAX),
    };
    if !send(&mut socket, &welcome).await {
        return;
    }
    let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE);
    let connection = state.registry.register(&host_id, sender);
    tracing::info!(%host_id, "a host connected");
    let _ = state.store().touch(&host_id, Utc::now());
    serve_host(&mut socket, &state, &host_id, connection, receiver).await;
    state.registry.unregister(&host_id, connection);
    tracing::info!(%host_id, "a host disconnected");
}

async fn serve_host(
    socket: &mut WebSocket,
    state: &AppState,
    host_id: &str,
    connection: u64,
    mut receiver: mpsc::Receiver<Outbound>,
) {
    let silence_limit = state.config.heartbeat_interval.saturating_mul(3);
    let mut last_heard = Instant::now();
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
                        if hello.protocol_version != PROTOCOL_VERSION {
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
                        let _ = state.store().touch(host_id, Utc::now());
                    }
                    // A second `auth`, a newer message type, or garbage: skipped.
                    Ok(HostMessage::Auth { .. } | HostMessage::Unknown) | Err(_) => {}
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
            _ = checks.tick() => {
                let active = state.store().active_host(host_id).map(|record| record.is_some());
                if matches!(active, Ok(false)) {
                    tracing::info!(%host_id, "a revoked host was disconnected");
                    close(socket, CLOSE_UNAUTHORIZED, "revoked").await;
                    return;
                }
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
