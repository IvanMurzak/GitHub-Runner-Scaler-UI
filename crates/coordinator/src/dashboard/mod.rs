//! The web dashboard: the fleet's machines, queue, running jobs and history,
//! behind a GitHub sign-in for an allowlist of logins.
//!
//! The page and its assets are embedded in the binary and served from this
//! origin with a strict Content-Security-Policy (no inline script or style,
//! nothing from elsewhere but GitHub avatars). Every `/api/*` answer needs a
//! session; without sign-in settings the dashboard does not exist at all and
//! every one of its paths answers 404.

pub mod activity;
pub mod auth;
pub mod metrics;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::server::AppState;
use crate::store::{DashboardSession, MetricSample};
use activity::{ActiveJob, Activity};
use auth::AuthConfig;

const INDEX_HTML: &str = include_str!("../../assets/index.html");
const APP_CSS: &str = include_str!("../../assets/app.css");
const APP_JS: &str = include_str!("../../assets/app.js");
const ICON_SVG: &str = include_str!("../../assets/icon.svg");

const SESSION_COOKIE: &str = "rm_session";
const STATE_COOKIE: &str = "rm_oauth_state";

/// What every dashboard response carries.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' https://avatars.githubusercontent.com data:; connect-src 'self'; \
    font-src 'self'; base-uri 'none'; form-action 'self' https://github.com; \
    frame-ancestors 'none'";

/// Where the updater (`deploy/coordinator/update.sh`) leaves its status.
pub const UPDATE_STATUS: &str = "/run/coordinator-update/status.json";

/// How long queue-wait percentiles, read from every kept sample, are reused.
const PERCENTILES_FOR: Duration = Duration::from_secs(60);

/// Queue-wait p50 and p90, in seconds.
type Percentiles = (Option<u64>, Option<u64>);

/// The dashboard's own state.
#[derive(Debug)]
pub struct Dashboard {
    /// `None`: no sign-in settings, so no dashboard.
    pub auth: Option<AuthConfig>,
    pub activity: Activity,
    http: reqwest::Client,
    started_at: i64,
    update_status: PathBuf,
    percentiles: Mutex<Option<(std::time::Instant, Percentiles)>>,
}

impl Dashboard {
    #[must_use]
    pub fn new(auth: Option<AuthConfig>) -> Self {
        Self {
            auth,
            activity: Activity::default(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            started_at: Utc::now().timestamp(),
            update_status: PathBuf::from(UPDATE_STATUS),
            percentiles: Mutex::new(None),
        }
    }

    /// Reads the updater's status from `path` instead (tests).
    #[must_use]
    pub fn with_update_status(mut self, path: PathBuf) -> Self {
        self.update_status = path;
        self
    }
}

/// The dashboard's routes, merged into the server's router.
pub fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/", get(index))
        .route(
            "/assets/app.css",
            get(|s| asset(s, APP_CSS, "text/css; charset=utf-8")),
        )
        .route(
            "/assets/app.js",
            get(|s| asset(s, APP_JS, "text/javascript; charset=utf-8")),
        )
        .route(
            "/assets/icon.svg",
            get(|s| asset(s, ICON_SVG, "image/svg+xml")),
        )
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/api/session", get(session))
        .route("/api/overview", get(overview))
        .route("/api/metrics", get(metrics_route))
}

fn secure_headers(response: &mut Response) {
    let headers = response.headers_mut();
    for (name, value) in [
        ("content-security-policy", CSP),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-opener-policy", "same-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
}

fn with_headers(mut response: Response) -> Response {
    secure_headers(&mut response);
    response
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

async fn index(State(state): State<Arc<AppState>>) -> Response {
    if state.dashboard.auth.is_none() {
        return not_found();
    }
    let mut response = (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        INDEX_HTML,
    )
        .into_response();
    secure_headers(&mut response);
    response
}

async fn asset(
    State(state): State<Arc<AppState>>,
    body: &'static str,
    kind: &'static str,
) -> Response {
    if state.dashboard.auth.is_none() {
        return not_found();
    }
    with_headers(
        (
            [
                (header::CONTENT_TYPE, kind),
                // Revalidated each load: a new version ships new assets
                // under the same names.
                (header::CACHE_CONTROL, "no-cache"),
            ],
            body,
        )
            .into_response(),
    )
}

fn secure_origin(state: &AppState) -> bool {
    state.config.public_origin.starts_with("https://")
}

fn redirect_uri(state: &AppState) -> String {
    format!(
        "{}/auth/callback",
        state.config.public_origin.trim_end_matches('/')
    )
}

fn redirect_with_cookies(to: &str, cookies: &[String]) -> Response {
    let mut response = Redirect::to(to).into_response();
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    with_headers(response)
}

async fn login(State(state): State<Arc<AppState>>) -> Response {
    let Some(config) = &state.dashboard.auth else {
        return not_found();
    };
    let oauth_state = auth::token();
    let url = auth::authorize_url(config, &redirect_uri(&state), &oauth_state);
    redirect_with_cookies(
        &url,
        &[auth::set_cookie(
            STATE_COOKIE,
            &oauth_state,
            auth::STATE_SECS,
            secure_origin(&state),
        )],
    )
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

async fn callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(config) = &state.dashboard.auth else {
        return not_found();
    };
    let secure = secure_origin(&state);
    let clear_state = auth::set_cookie(STATE_COOKIE, "", 0, secure);
    let expected = auth::cookie(&headers, STATE_COOKIE);
    let (Some(code), Some(returned), Some(expected)) = (&query.code, &query.state, expected) else {
        return redirect_with_cookies("/?error=1", &[clear_state]);
    };
    if code.len() > 256 || !auth::same_token(returned, expected) {
        tracing::warn!("a dashboard sign-in came back with a state it was not given");
        return redirect_with_cookies("/?error=1", &[clear_state]);
    }
    let user = match auth::who_signed_in(&state.dashboard.http, config, code, &redirect_uri(&state))
        .await
    {
        Ok(user) => user,
        Err(error) => {
            tracing::warn!(%error, "a dashboard sign-in failed");
            return redirect_with_cookies("/?error=1", &[clear_state]);
        }
    };
    if !config.allows(&user.login) {
        // The login is not logged: it is text off the wire.
        tracing::warn!("a GitHub account not on the dashboard allowlist was turned away");
        return redirect_with_cookies("/?denied=1", &[clear_state]);
    }
    let token = auth::token();
    let now = Utc::now().timestamp();
    let session = DashboardSession {
        login: user.login,
        avatar_url: user
            .avatar_url
            .filter(|url| url.starts_with("https://avatars.githubusercontent.com/")),
        expires_at: now + auth::SESSION_SECS,
    };
    if state
        .store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .create_session(&auth::token_hash(&token), &session, now)
        .is_err()
    {
        return redirect_with_cookies("/?error=1", &[clear_state]);
    }
    tracing::info!("a dashboard session was opened");
    redirect_with_cookies(
        "/",
        &[
            clear_state,
            auth::set_cookie(SESSION_COOKIE, &token, auth::SESSION_SECS, secure),
        ],
    )
}

/// The signed-in session of a request, if any.
fn signed_in(state: &AppState, headers: &HeaderMap) -> Option<DashboardSession> {
    let config = state.dashboard.auth.as_ref()?;
    let token = auth::cookie(headers, SESSION_COOKIE)?;
    if token.len() != 64 {
        return None;
    }
    let session = state
        .store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .session(&auth::token_hash(token), Utc::now().timestamp())
        .ok()
        .flatten()?;
    // Taken off the allowlist since: out at once, not at the next restart.
    config.allows(&session.login).then_some(session)
}

fn unauthenticated() -> Response {
    with_headers(
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "unauthenticated"})),
        )
            .into_response(),
    )
}

fn json<T: Serialize>(value: &T) -> Response {
    with_headers(([(header::CACHE_CONTROL, "no-store")], axum::Json(value)).into_response())
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if state.dashboard.auth.is_none() {
        return not_found();
    }
    // A cross-site form cannot sign anyone out.
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if origin != Some(state.config.public_origin.trim_end_matches('/')) {
        return with_headers(StatusCode::FORBIDDEN.into_response());
    }
    if let Some(token) = auth::cookie(&headers, SESSION_COOKIE) {
        let _ = state
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .delete_session(&auth::token_hash(token));
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(value) = HeaderValue::from_str(&auth::set_cookie(
        SESSION_COOKIE,
        "",
        0,
        secure_origin(&state),
    )) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    with_headers(response)
}

async fn session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if state.dashboard.auth.is_none() {
        return not_found();
    }
    let Some(session) = signed_in(&state, &headers) else {
        return unauthenticated();
    };
    json(&serde_json::json!({
        "login": session.login,
        "avatar_url": session.avatar_url,
    }))
}

/// The updater's last word, as `deploy/coordinator/update.sh` writes it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub state: String,
    pub current: Option<String>,
    pub previous: Option<String>,
    pub latest: Option<String>,
    pub checked_at: Option<i64>,
    pub changed_at: Option<i64>,
    pub message: Option<String>,
}

fn update_status(dashboard: &Dashboard) -> Option<UpdateStatus> {
    let bytes = std::fs::read(&dashboard.update_status).ok()?;
    if bytes.len() > 16 * 1024 {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

#[derive(Debug, Serialize)]
struct HostView {
    id: String,
    name: String,
    hostname: String,
    online: bool,
    os: Option<String>,
    arch: Option<String>,
    cores: Option<u32>,
    ram_bytes: Option<u64>,
    free_ram_bytes: Option<u64>,
    cpu_load_percent: Option<u32>,
    disk_free_bytes: Option<u64>,
    busy_slots: Option<u32>,
    free_slots: Option<u32>,
    unfit: bool,
    draining: bool,
    last_seen_at: Option<i64>,
    enrolled_at: i64,
    connected_since: Option<i64>,
}

#[derive(Debug, Serialize)]
struct JobView {
    id: u64,
    run_id: u64,
    repository: String,
    name: Option<String>,
    labels: Vec<String>,
    queued_at: i64,
    wait_secs: i64,
    runner_name: Option<String>,
    host_id: Option<String>,
    host_name: Option<String>,
    started_at: Option<i64>,
    queued_secs: Option<i64>,
}

#[derive(Debug, Serialize)]
struct RecentView {
    #[serde(flatten)]
    job: activity::FinishedJob,
    host_id: Option<String>,
    host_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct Summary {
    hosts_online: usize,
    hosts_total: usize,
    slots_busy: u32,
    slots_total: u32,
    jobs_queued: usize,
    jobs_running: usize,
    p50_queue_wait_secs: Option<u64>,
    p90_queue_wait_secs: Option<u64>,
}

fn percentiles(state: &AppState) -> Percentiles {
    let mut cached = state
        .dashboard
        .percentiles
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((at, value)) = *cached
        && at.elapsed() < PERCENTILES_FOR
    {
        return value;
    }
    let value = {
        let store = state
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::stats::report(&store, &state.config.stats, Utc::now())
            .map(|report| (report.p50_queue_wait_secs, report.p90_queue_wait_secs))
            .unwrap_or_default()
    };
    *cached = Some((std::time::Instant::now(), value));
    value
}

fn host_names(state: &AppState) -> BTreeMap<String, String> {
    state
        .store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .hosts()
        .unwrap_or_default()
        .into_iter()
        .map(|host| (host.id, host.name))
        .collect()
}

async fn overview(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if state.dashboard.auth.is_none() {
        return not_found();
    }
    if signed_in(&state, &headers).is_none() {
        return unauthenticated();
    }
    let now = Utc::now().timestamp();
    let records = state
        .store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .hosts()
        .unwrap_or_default();
    let connected: BTreeMap<String, crate::registry::ConnectedHost> = state
        .registry
        .connected()
        .into_iter()
        .map(|host| (host.host_id.clone(), host))
        .collect();
    let stats: BTreeMap<String, runner_manager_domain::coordinator_protocol::ConnectedHostStats> =
        state
            .registry
            .connected_stats()
            .into_iter()
            .map(|host| (host.host_id.clone(), host))
            .collect();
    let names: BTreeMap<String, String> = records
        .iter()
        .map(|record| (record.id.clone(), record.name.clone()))
        .collect();
    let mut hosts: Vec<HostView> = records
        .iter()
        .filter(|record| record.is_active())
        .map(|record| {
            let live = stats.get(&record.id);
            let hello = connected
                .get(&record.id)
                .and_then(|host| host.hello.as_ref());
            HostView {
                id: record.id.clone(),
                name: record.name.clone(),
                hostname: record.hostname.clone(),
                online: live.is_some(),
                os: hello.map(|hello| hello.os.clone()),
                arch: hello.map(|hello| hello.arch.clone()),
                cores: hello.map(|hello| hello.cores),
                ram_bytes: live.and_then(|live| live.ram_bytes),
                free_ram_bytes: live.and_then(|live| live.free_ram_bytes),
                cpu_load_percent: live.and_then(|live| live.cpu_load_percent),
                disk_free_bytes: live.and_then(|live| live.disk_free_bytes),
                busy_slots: live.map(|live| live.busy_slots),
                free_slots: live.map(|live| live.free_slots),
                unfit: live.is_some_and(|live| live.unfit),
                draining: live.is_some_and(|live| live.draining),
                last_seen_at: record.last_seen_at.map(|at| at.timestamp()),
                enrolled_at: record.enrolled_at.timestamp(),
                connected_since: None,
            }
        })
        .collect();
    hosts.sort_by(|a, b| b.online.cmp(&a.online).then_with(|| a.name.cmp(&b.name)));
    let snapshot = state.dashboard.activity.snapshot(now);
    let host_of = |runner: Option<&str>| -> (Option<String>, Option<String>) {
        let id = runner.and_then(|runner| state.dashboard.activity.host_of(runner));
        let name = id.as_ref().and_then(|id| names.get(id).cloned());
        (id, name)
    };
    let view = |job: &ActiveJob| {
        let (host_id, host_name) = host_of(job.runner_name.as_deref());
        JobView {
            id: job.id,
            run_id: job.run_id,
            repository: job.repository.clone(),
            name: job.name.clone(),
            labels: job.labels.clone(),
            queued_at: job.queued_at,
            wait_secs: job.started_at.unwrap_or(now) - job.queued_at,
            runner_name: job.runner_name.clone(),
            host_id,
            host_name,
            started_at: job.started_at,
            queued_secs: job
                .started_at
                .map(|started| (started - job.queued_at).max(0)),
        }
    };
    let queue: Vec<JobView> = snapshot.queued.iter().map(view).collect();
    let running: Vec<JobView> = snapshot.running.iter().map(view).collect();
    let recent: Vec<RecentView> = snapshot
        .recent
        .into_iter()
        .map(|job| {
            let (host_id, host_name) = host_of(job.runner_name.as_deref());
            RecentView {
                job,
                host_id,
                host_name,
            }
        })
        .collect();
    let (pools, leases) = state.placement.snapshot();
    let (p50, p90) = percentiles(&state);
    let summary = Summary {
        hosts_online: hosts.iter().filter(|host| host.online).count(),
        hosts_total: hosts.len(),
        slots_busy: stats.values().map(|host| host.busy_slots).sum(),
        slots_total: stats
            .values()
            .map(|host| host.busy_slots + host.free_slots)
            .sum(),
        jobs_queued: queue.len(),
        jobs_running: running.len(),
        p50_queue_wait_secs: p50,
        p90_queue_wait_secs: p90,
    };
    json(&serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "generated_at": now,
        "started_at": state.dashboard.started_at,
        "update": update_status(&state.dashboard),
        "summary": summary,
        "hosts": hosts,
        "queue": queue,
        "running": running,
        "recent": recent,
        "pools": pools,
        "leases": leases,
    }))
}

#[derive(Debug, Deserialize)]
struct MetricsQuery {
    range: Option<String>,
}

async fn metrics_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<MetricsQuery>,
) -> Response {
    if state.dashboard.auth.is_none() {
        return not_found();
    }
    if signed_in(&state, &headers).is_none() {
        return unauthenticated();
    }
    let Some(range) = Range::parse(query.range.as_deref().unwrap_or("6h")) else {
        return with_headers(StatusCode::BAD_REQUEST.into_response());
    };
    let now = Utc::now().timestamp();
    let (span, _) = range.span_and_step();
    let samples = state
        .store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .metrics(now - span)
        .unwrap_or_default();
    json(&metrics::series(&samples, range, now, &host_names(&state)))
}

use metrics::Range;

/// One minute's samples: each connected host's load, and the fleet's jobs.
#[must_use]
pub fn sample(state: &AppState, now: i64) -> Vec<MetricSample> {
    let snapshot = state.dashboard.activity.snapshot(now);
    let mut samples = vec![MetricSample {
        at: now,
        host_id: String::new(),
        queued: u32::try_from(snapshot.queued.len()).ok(),
        running: u32::try_from(snapshot.running.len()).ok(),
        ..MetricSample::default()
    }];
    samples.extend(state.registry.connected_stats().into_iter().map(|host| {
        MetricSample {
            at: now,
            ram_used: host
                .ram_bytes
                .zip(host.free_ram_bytes)
                .map(|(total, free)| total.saturating_sub(free)),
            ram_total: host.ram_bytes,
            cpu: host.cpu_load_percent,
            busy: Some(host.busy_slots),
            slots: Some(host.busy_slots + host.free_slots),
            disk_free: host.disk_free_bytes,
            host_id: host.host_id,
            ..MetricSample::default()
        }
    }));
    samples
}

/// Takes [`sample`] every minute while the dashboard exists.
pub async fn record_metrics(state: Arc<AppState>) {
    if state.dashboard.auth.is_none() {
        return;
    }
    let mut ticks = tokio::time::interval(Duration::from_secs(metrics::SAMPLE_EVERY_SECS));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let now = Utc::now().timestamp();
        let samples = sample(&state, now);
        if let Err(error) = state
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_metrics(&samples, now - metrics::RETENTION_SECS)
        {
            tracing::warn!(%error, "the dashboard's minute of history was not saved");
        }
    }
}
