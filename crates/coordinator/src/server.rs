//! The HTTP surface: `/webhook`, `/connect`, `/enroll`, `/healthz`, and the
//! web dashboard ([`crate::dashboard`]).
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
use runner_manager_domain::coordinator_protocol::{
    CLOSE_UNAUTHORIZED, CLOSE_UNSUPPORTED_VERSION, CONNECT_PATH, ENROLL_PATH, EnrollRequest,
    EnrollResponse, HEALTH_PATH, HostMessage, LAUNCH_VERSION, MAX_MEMORY_ESTIMATES,
    MAX_MESSAGE_BYTES, MIN_PROTOCOL_VERSION, MemoryEstimates, NONCE_LEN, PROTOCOL_VERSION,
    STATS_VERSION, ServerMessage, SessionPurpose, TargetRef, WEBHOOK_PATH, WakeReason,
    decode_public_key, encode_nonce, supported, verify_challenge,
};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::sync::mpsc;

use crate::placement::{CLAIM_GRACE, Placement};
use crate::registry::is_pool_job;
use crate::registry::{OUTBOUND_QUEUE, Outbound, Registry};
use crate::stats::{JobIdentity, JobTimes, LiveState, Statistics, StatsConfig};
use crate::store::{EnrollError, Store};
use crate::webhook::{
    DELIVERY_MEMORY, DeliveryLog, MAX_BODY_BYTES, WorkflowJobEvent, action_name, required_labels,
    signature_valid, valid_delivery_id,
};
use runner_manager_domain::coordinator_protocol::is_managed_runner_name;

/// Largest enrollment request body.
const MAX_ENROLL_BYTES: usize = 16 * 1024;

/// How often a connected host's `last_seen_at` is rewritten.
const TOUCH_EVERY: Duration = Duration::from_secs(60);

/// How often a host's memory estimates are worked out again, and sent when
/// they changed.
const ESTIMATES_EVERY: Duration = Duration::from_secs(60);

/// The most a `memory_estimates` frame may take, with room to spare under
/// [`MAX_MESSAGE_BYTES`].
const ESTIMATES_BYTES: usize = MAX_MESSAGE_BYTES - 1024;

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
    /// connections of revoked hosts.
    pub revocation_check: Duration,
    /// Connection and enrollment attempts allowed per client address per
    /// minute.
    pub attempts_per_minute: u32,
    /// Stage 4: job weight statistics and the placement weights.
    pub stats: StatsConfig,
    /// How often placement expires leases and retries the queues nothing
    /// took ([`crate::placement::TICK`]); a freed slot retries at once.
    pub placement_tick: Duration,
    /// How long an accepted launch counts without its runner taking a job
    /// (`COORDINATOR_LEASE_TTL`).
    pub lease_ttl: Duration,
    /// The web dashboard's GitHub sign-in; `None`, no dashboard.
    pub dashboard: Option<crate::dashboard::auth::AuthConfig>,
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
            stats: StatsConfig::default(),
            placement_tick: crate::placement::TICK,
            lease_ttl: crate::placement::LEASE_TTL,
            dashboard: None,
        }
    }
}

/// Everything the handlers share.
#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub store: Arc<Mutex<Store>>,
    pub registry: Arc<Registry>,
    /// Stage 3: which host starts a runner for a queued pool job.
    pub placement: Arc<Placement>,
    /// Stage 4: what jobs used, and the counters `stats` shows.
    pub statistics: Arc<Statistics>,
    /// The web dashboard: its sign-in, and its view of the jobs.
    pub dashboard: crate::dashboard::Dashboard,
    deliveries: Mutex<DeliveryLog>,
    limiter: RateLimiter,
}

impl AppState {
    #[must_use]
    pub fn new(config: Config, store: Store) -> Arc<Self> {
        let registry = Arc::new(Registry::default());
        let store = Arc::new(Mutex::new(store));
        let statistics = Arc::new(Statistics::load(Arc::clone(&store), config.stats));
        let lease_ttl = config.lease_ttl;
        let dashboard = crate::dashboard::Dashboard::new(config.dashboard.clone());
        if let Some(auth) = &dashboard.auth {
            // A login taken off the allowlist keeps no session.
            if let Ok(removed) = store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .delete_sessions_except(&auth.allowed_logins)
                && removed > 0
            {
                tracing::info!(
                    removed,
                    "dashboard sessions of logins no longer allowed were ended"
                );
            }
        }
        Arc::new(Self {
            dashboard,
            limiter: RateLimiter::new(config.attempts_per_minute),
            config,
            store,
            placement: Arc::new(
                Placement::with_timings(
                    Arc::clone(&registry),
                    crate::placement::ACK_TIMEOUT,
                    lease_ttl,
                )
                .with_statistics(Arc::clone(&statistics)),
            ),
            statistics,
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
        .merge(crate::dashboard::routes())
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
    let placement = tokio::spawn(Arc::clone(&state.placement).run(state.config.placement_tick));
    let revocations = tokio::spawn(watch_revocations(Arc::clone(&state)));
    let counters = tokio::spawn(flush_counters(Arc::clone(&state)));
    let history = tokio::spawn(crate::dashboard::record_metrics(Arc::clone(&state)));
    let served = axum::serve(
        listener,
        router(Arc::clone(&state)).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await;
    placement.abort();
    revocations.abort();
    counters.abort();
    history.abort();
    collect_wakes(&state);
    state.statistics.flush();
    served
}

/// Hands the wakes the registry sent since last time to the statistics.
fn collect_wakes(state: &AppState) {
    state
        .statistics
        .count_wakes(state.registry.take_wakes_sent());
}

/// Adds the launch and wake counts to the database every minute, and saves
/// placement's live state for the admin CLI.
async fn flush_counters(state: Arc<AppState>) {
    let mut ticks = tokio::time::interval(Duration::from_secs(60));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        collect_wakes(&state);
        state.statistics.flush();
        state.statistics.save_live(&live_state(&state));
    }
}

fn live_state(state: &AppState) -> LiveState {
    let (pending, leases) = state.placement.snapshot();
    LiveState {
        pending,
        leases,
        connected: state.registry.connected_stats(),
    }
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
            // Forgotten by the registry, so its own disconnect will not.
            state.placement.host_gone(&host_id);
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
            state
                .dashboard
                .activity
                .job_event(&job, Utc::now().timestamp());
            let action = action_name(&job.action);
            let required = required_labels(&job.workflow_job.labels);
            let repository = &job.repository.full_name;
            state.registry.repository_seen(repository);
            let workflows = state.statistics.run_workflows();
            let run_id = job.workflow_job.run_id;
            // Worth a request only for a job this coordinator keeps figures on.
            let measured = required.as_deref().is_some_and(is_pool_job)
                || job
                    .workflow_job
                    .runner_name
                    .as_deref()
                    .is_some_and(is_managed_runner_name);
            if measured {
                workflows.want(repository, run_id);
            }
            let identity = JobIdentity::new(repository, job.workflow_job.name.as_deref())
                .map(|identity| identity.in_workflow(workflows.of(run_id).as_deref()));
            if action == "queued" {
                let woken = required.as_ref().map_or(0, |required| {
                    state
                        .registry
                        .wake_for(repository, required, WakeReason::JobQueued, delivery)
                });
                let placed = required
                    .and_then(|required| {
                        state.placement.queued_job(
                            repository,
                            &required,
                            job.workflow_job.id,
                            identity.as_ref().map(JobIdentity::key),
                        )
                    })
                    .map(|key| state.placement.spawn_rebalance(key, Duration::ZERO))
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
                        // The runner that took it, said once: `in_progress`.
                        let runner = job
                            .workflow_job
                            .runner_name
                            .as_deref()
                            .filter(|_| action == "in_progress");
                        state.placement.dequeued_by(
                            repository,
                            &required,
                            job.workflow_job.id,
                            runner,
                        )
                    })
                {
                    state.placement.spawn_rebalance(key, CLAIM_GRACE);
                }
                // Which job a runner took and when it ran, for its attempt's
                // statistics: `in_progress` says when it started,
                // `completed` when it ended.
                if matches!(action, "in_progress" | "completed")
                    && let (Some(runner), Some(identity)) =
                        (job.workflow_job.runner_name.as_deref(), identity)
                {
                    let times = JobTimes {
                        failed: job
                            .workflow_job
                            .conclusion
                            .as_deref()
                            .is_some_and(|conclusion| conclusion != "success"),
                        ..JobTimes::parse(
                            job.workflow_job.created_at.as_deref(),
                            job.workflow_job.started_at.as_deref(),
                            job.workflow_job.completed_at.as_deref(),
                        )
                    };
                    state.statistics.job_identified(runner, identity, times);
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
        purpose,
    }) = HostMessage::decode(&text)
    else {
        close(&mut socket, CLOSE_UNAUTHORIZED, "unauthorized").await;
        return;
    };
    let purpose = purpose.unwrap_or_default();
    // A query session needs version 4; an unknown purpose is not served.
    if !supported(protocol_version)
        || (purpose != SessionPurpose::Link && protocol_version < STATS_VERSION)
        || purpose == SessionPurpose::Other
    {
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
    if purpose == SessionPurpose::Query {
        answer_query(&mut socket, &state, &host_id).await;
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
    // Whatever an earlier (perhaps half-open) connection of this host held,
    // the new link starts with no launch: the host dropped them when it lost
    // the old one.
    state.placement.host_gone(&host_id);
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

/// A query session: never registered as the host's link, so the daemon's
/// connection stays up. One `stats_request` within the auth timeout, one
/// answer, closed.
async fn answer_query(socket: &mut WebSocket, state: &AppState, host_id: &str) {
    let request = tokio::time::timeout(state.config.auth_timeout, next_text(socket)).await;
    let Ok(Some(text)) = request else {
        return;
    };
    if !matches!(HostMessage::decode(&text), Ok(HostMessage::StatsRequest)) {
        close(socket, 1008, "unexpected message").await;
        return;
    }
    collect_wakes(state);
    match state
        .statistics
        .report_with(Utc::now(), Some(live_state(state)))
    {
        Ok(report) => {
            tracing::info!(%host_id, jobs = report.jobs.len(), "a host read the statistics");
            // A reader that stops reading does not hold the task open.
            let answered = tokio::time::timeout(state.config.auth_timeout, async {
                if send(socket, &ServerMessage::Stats(report)).await {
                    close(socket, 1000, "done").await;
                }
            })
            .await;
            if answered.is_err() {
                tracing::info!(%host_id, "a statistics reader did not read in time");
            }
        }
        Err(error) => {
            tracing::error!(%error, "the statistics could not be read");
            close(socket, 1011, "statistics unavailable").await;
        }
    }
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
    let mut checks = tokio::time::interval(state.config.heartbeat_interval);
    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Memory estimates for the host's own admission, from 0.4.53. A host
    // before it skips the message as one it does not know.
    let mut targets: Vec<TargetRef> = Vec::new();
    let mut sent_estimates: Option<MemoryEstimates> = None;
    let mut estimated_at = Instant::now();
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
                        targets = hello.targets.iter().map(|target| target.reference()).collect();
                        state.registry.set_hello(host_id, connection, hello);
                        if version >= STATS_VERSION {
                            // Always after a `hello`: the host may have restarted.
                            sent_estimates = None;
                            estimated_at = Instant::now();
                            if !send_estimates(socket, state, host_id, &targets, &mut sent_estimates).await {
                                return;
                            }
                        }
                    }
                    Ok(HostMessage::Heartbeat(mut heartbeat)) => {
                        // Leases the host no longer holds are closed, and
                        // their jobs placed again. The list is not kept: every
                        // placement copies the heartbeat.
                        let dropped = match (heartbeat.open_leases.take(), version >= LAUNCH_VERSION) {
                            (Some(held), true) => state.placement.reconcile_leases(host_id, &held),
                            _ => 0,
                        };
                        // A slot freed (a host sends a heartbeat right after
                        // an attempt ends): pending pool jobs are placed now,
                        // not at the next tick.
                        if state.registry.set_heartbeat(host_id, connection, heartbeat)
                            || dropped > 0
                        {
                            state.placement.spawn_retry_all();
                        }
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
                        state.dashboard.activity.runner_started(host_id, &started.runner_name);
                    }
                    Ok(HostMessage::AttemptFinished(finished)) if version >= LAUNCH_VERSION => {
                        state.placement.attempt_finished(host_id, &finished);
                        state.statistics.attempt_finished(
                            host_id,
                            &finished,
                            state.registry.ram_bytes(host_id),
                        );
                        state.placement.spawn_retry_all();
                    }
                    // A second `auth`, a message its version does not have, a
                    // newer message type, or garbage: skipped.
                    Ok(
                        HostMessage::Auth { .. }
                        | HostMessage::StatsRequest
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
                if version >= STATS_VERSION
                    && !targets.is_empty()
                    && estimated_at.elapsed() >= ESTIMATES_EVERY
                {
                    estimated_at = Instant::now();
                    if !send_estimates(socket, state, host_id, &targets, &mut sent_estimates).await {
                        return;
                    }
                }
            }
        }
    }
}

/// What each of `targets` is expected to need on `host_id`, from the job
/// statistics. Targets never measured are left out.
#[must_use]
pub fn memory_estimates(state: &AppState, host_id: &str, targets: &[TargetRef]) -> MemoryEstimates {
    let mut unique: Vec<&TargetRef> = Vec::new();
    for target in targets {
        if !unique.iter().any(|seen| seen.same_as(target)) {
            unique.push(target);
        }
    }
    let mut estimates = state
        .statistics
        .with_aggregates(|aggregates| MemoryEstimates {
            estimates: unique
                .into_iter()
                .filter_map(|target| aggregates.target_estimate(host_id, target))
                .take(MAX_MEMORY_ESTIMATES)
                .collect(),
        });
    // Within one frame, or the host's transport refuses it and the link
    // reconnects into the same message. Targets dropped from the end fall
    // back to the host's own measurements.
    while ServerMessage::MemoryEstimates(estimates.clone())
        .encode()
        .len()
        > ESTIMATES_BYTES
    {
        estimates.estimates.pop();
    }
    estimates
}

/// Sends the host its memory estimates unless they are what it was last sent;
/// `false` when the connection is gone.
async fn send_estimates(
    socket: &mut WebSocket,
    state: &AppState,
    host_id: &str,
    targets: &[TargetRef],
    sent: &mut Option<MemoryEstimates>,
) -> bool {
    let estimates = memory_estimates(state, host_id, targets);
    // Nothing known and nothing said yet: nothing to say.
    if sent
        .as_ref()
        .map_or(estimates.estimates.is_empty(), |sent| *sent == estimates)
    {
        return true;
    }
    tracing::debug!(%host_id, targets = estimates.estimates.len(), "memory estimates sent");
    let delivered = send(socket, &ServerMessage::MemoryEstimates(estimates.clone())).await;
    *sent = Some(estimates);
    delivered
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
    fn memory_estimates_fit_one_frame_and_name_each_target_once() {
        use crate::store::JobSample;
        use runner_manager_domain::coordinator_protocol::TargetScope;
        let mut store = Store::open_in_memory().expect("store");
        let name = |index: usize| format!("acme/{}{index}", "r".repeat(130));
        for index in 0..MAX_MEMORY_ESTIMATES {
            store
                .record_sample(
                    &JobSample {
                        job_key: format!("{}/build", name(index)),
                        repository: name(index),
                        host_id: "h".into(),
                        finished_at: Utc::now(),
                        duration_secs: Some(1),
                        queue_wait_secs: None,
                        peak_rss_bytes: Some(1 << 30),
                        cpu_avg_millicores: None,
                        cpu_peak_millicores: None,
                    },
                    30,
                    Utc::now() - chrono::TimeDelta::days(1),
                )
                .expect("sample");
        }
        let state = AppState::new(
            Config::new("http://127.0.0.1".into(), SecretString::from("s")),
            store,
        );
        let mut targets: Vec<TargetRef> = (0..MAX_MEMORY_ESTIMATES)
            .map(|index| TargetRef {
                scope: TargetScope::Repo,
                name: name(index),
            })
            .collect();
        targets.insert(
            1,
            TargetRef {
                scope: TargetScope::Repo,
                name: name(0).to_uppercase(),
            },
        );
        let estimates = memory_estimates(&state, "h", &targets);
        let frame = ServerMessage::MemoryEstimates(estimates.clone()).encode();
        assert!(frame.len() <= ESTIMATES_BYTES, "{}", frame.len());
        assert!(
            estimates.estimates.len() > 100,
            "{}",
            estimates.estimates.len()
        );
        let first = &estimates.estimates[0].target;
        assert_eq!(
            estimates
                .estimates
                .iter()
                .filter(|estimate| estimate.target.same_as(first))
                .count(),
            1,
            "a target named twice is estimated once"
        );
    }

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
