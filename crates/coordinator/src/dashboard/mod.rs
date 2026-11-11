//! The web dashboard: the fleet's machines, queue, running jobs and history,
//! behind a GitHub sign-in for an allowlist of logins.
//!
//! The page and its assets are embedded in the binary and served from this
//! origin with a strict Content-Security-Policy (no inline script or style,
//! nothing from elsewhere but GitHub avatars). The routes exist only when the
//! sign-in is configured, every response carries the security headers, and
//! every `/api/*` route answers 401 without a session: all three are layers on
//! the router, so a new route cannot forget them.

pub mod activity;
pub mod auth;
pub mod metrics;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Extension, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::server::AppState;
use crate::store::{DashboardSession, HostRecord, MetricSample};
use activity::Activity;
use auth::AuthConfig;
use metrics::Range;

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

/// Where the updater (`deploy/coordinator/update.sh`) leaves its status, by
/// default (`COORDINATOR_UPDATE_STATUS`).
pub const UPDATE_STATUS: &str = "/run/coordinator-update/status.json";

/// The dashboard's own state; it exists only with sign-in settings.
#[derive(Debug)]
pub struct Dashboard {
    pub auth: AuthConfig,
    pub activity: Activity,
    http: reqwest::Client,
    started_at: i64,
    update_status: PathBuf,
}

impl Dashboard {
    #[must_use]
    pub fn new(auth: AuthConfig, update_status: PathBuf) -> Self {
        Self {
            auth,
            activity: Activity::default(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            started_at: Utc::now().timestamp(),
            update_status,
        }
    }
}

/// The dashboard's routes, merged into the server's router only when the
/// dashboard exists: without it each of these paths is a plain 404.
pub fn routes(state: &Arc<AppState>) -> axum::Router<Arc<AppState>> {
    use axum::middleware::{from_fn_with_state, map_response};
    use axum::routing::{get, post};
    let asset = |body: &'static str, kind: &'static str| {
        get(move || async move {
            // Revalidated each load: a new version ships new assets under the
            // same names.
            (
                [
                    (header::CONTENT_TYPE, kind),
                    (header::CACHE_CONTROL, "no-cache"),
                ],
                body,
            )
        })
    };
    let api = axum::Router::new()
        .route("/api/session", get(session))
        .route("/api/overview", get(overview))
        .route("/api/metrics", get(metrics_route))
        .route_layer(from_fn_with_state(Arc::clone(state), require_session));
    axum::Router::new()
        .route("/", asset(INDEX_HTML, "text/html; charset=utf-8"))
        .route("/assets/app.css", asset(APP_CSS, "text/css; charset=utf-8"))
        .route(
            "/assets/app.js",
            asset(APP_JS, "text/javascript; charset=utf-8"),
        )
        .route("/assets/icon.svg", asset(ICON_SVG, "image/svg+xml"))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .merge(api)
        .layer(map_response(secure_headers))
}

async fn secure_headers(mut response: Response) -> Response {
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
    response
}

/// The dashboard, for a handler only ever routed when it exists.
fn dashboard(state: &AppState) -> &Dashboard {
    state
        .dashboard
        .as_ref()
        .expect("dashboard routes are merged only when the dashboard exists")
}

/// Lets an `/api/*` request through only with a live session of an allowed
/// login, which it hands on as an extension.
async fn require_session(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    match signed_in(&state, request.headers()) {
        Some(session) => {
            request.extensions_mut().insert(session);
            next.run(request).await
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthenticated"})),
        )
            .into_response(),
    }
}

/// The signed-in session of a request, if any.
fn signed_in(state: &AppState, headers: &HeaderMap) -> Option<DashboardSession> {
    let token = auth::cookie(headers, SESSION_COOKIE).filter(|token| token.len() == 64)?;
    let session = state
        .store()
        .session(&auth::token_hash(token), Utc::now().timestamp())
        .ok()
        .flatten()?;
    // Taken off the allowlist since: out at once.
    dashboard(state)
        .auth
        .allows(&session.login)
        .then_some(session)
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

fn with_cookies(mut response: Response, cookies: &[String]) -> Response {
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

fn redirect(to: &str, cookies: &[String]) -> Response {
    with_cookies(Redirect::to(to).into_response(), cookies)
}

async fn login(State(state): State<Arc<AppState>>) -> Response {
    let oauth_state = auth::token();
    let url = auth::authorize_url(&dashboard(&state).auth, &redirect_uri(&state), &oauth_state);
    redirect(
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
    let dashboard = dashboard(&state);
    let secure = secure_origin(&state);
    let clear_state = auth::set_cookie(STATE_COOKIE, "", 0, secure);
    let expected = auth::cookie(&headers, STATE_COOKIE);
    let (Some(code), Some(returned), Some(expected)) = (&query.code, &query.state, expected) else {
        return redirect("/?error=1", &[clear_state]);
    };
    if code.len() > 256 || !auth::same_token(returned, expected) {
        tracing::warn!("a dashboard sign-in came back with a state it was not given");
        return redirect("/?error=1", &[clear_state]);
    }
    let user = match auth::who_signed_in(
        &dashboard.http,
        &dashboard.auth,
        code,
        &redirect_uri(&state),
    )
    .await
    {
        Ok(user) => user,
        Err(error) => {
            tracing::warn!(%error, "a dashboard sign-in failed");
            return redirect("/?error=1", &[clear_state]);
        }
    };
    if !dashboard.auth.allows(&user.login) {
        // The login is not logged: it is text off the wire.
        tracing::warn!("a GitHub account not on the dashboard allowlist was turned away");
        return redirect("/?denied=1", &[clear_state]);
    }
    let token = auth::token();
    let now = Utc::now().timestamp();
    let session = DashboardSession {
        login: user.login,
        avatar_url: user
            .avatar_url
            .filter(|url| url.starts_with("https://avatars.githubusercontent.com/")),
    };
    if state
        .store()
        .create_session(
            &auth::token_hash(&token),
            &session,
            now,
            now + auth::SESSION_SECS,
        )
        .is_err()
    {
        return redirect("/?error=1", &[clear_state]);
    }
    tracing::info!("a dashboard session was opened");
    redirect(
        "/",
        &[
            clear_state,
            auth::set_cookie(SESSION_COOKIE, &token, auth::SESSION_SECS, secure),
        ],
    )
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // A cross-site form cannot sign anyone out.
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if origin != Some(state.config.public_origin.trim_end_matches('/')) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(token) = auth::cookie(&headers, SESSION_COOKIE) {
        let _ = state.store().delete_session(&auth::token_hash(token));
    }
    with_cookies(
        StatusCode::NO_CONTENT.into_response(),
        &[auth::set_cookie(
            SESSION_COOKIE,
            "",
            0,
            secure_origin(&state),
        )],
    )
}

fn json<T: Serialize>(value: &T) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

async fn session(Extension(session): Extension<DashboardSession>) -> Response {
    json(&session)
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

/// A job with the host its runner belongs to, when its host said.
#[derive(Debug, Serialize)]
struct WithHost<T> {
    #[serde(flatten)]
    job: T,
    host_id: Option<String>,
    host_name: Option<String>,
}

fn host_names(records: &[HostRecord]) -> BTreeMap<String, String> {
    records
        .iter()
        .map(|record| (record.id.clone(), record.name.clone()))
        .collect()
}

async fn overview(State(state): State<Arc<AppState>>) -> Response {
    let dashboard = dashboard(&state);
    let now = Utc::now().timestamp();
    let records = state.store().hosts().unwrap_or_default();
    let names = host_names(&records);
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
    let mut hosts: Vec<HostView> = records
        .iter()
        .filter(|record| record.is_active())
        .map(|record| {
            let live = stats.get(&record.id);
            let link = connected.get(&record.id);
            let hello = link.and_then(|host| host.hello.as_ref());
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
                connected_since: link.map(|host| host.since.timestamp()),
            }
        })
        .collect();
    hosts.sort_by(|a, b| b.online.cmp(&a.online).then_with(|| a.name.cmp(&b.name)));
    let snapshot = dashboard.activity.snapshot(now);
    let with_host = |runner: Option<&str>| {
        let host_id = runner.and_then(|runner| dashboard.activity.host_of(runner));
        let host_name = host_id.as_ref().and_then(|id| names.get(id).cloned());
        (host_id, host_name)
    };
    let queue: Vec<_> = snapshot
        .queued
        .into_iter()
        .map(|job| WithHost {
            job,
            host_id: None,
            host_name: None,
        })
        .collect();
    let running: Vec<_> = snapshot
        .running
        .into_iter()
        .map(|job| {
            let (host_id, host_name) = with_host(job.runner_name.as_deref());
            WithHost {
                job,
                host_id,
                host_name,
            }
        })
        .collect();
    let recent: Vec<_> = snapshot
        .recent
        .into_iter()
        .map(|job| {
            let (host_id, host_name) = with_host(job.runner_name.as_deref());
            WithHost {
                job,
                host_id,
                host_name,
            }
        })
        .collect();
    let (pools, leases) = state.placement.snapshot();
    let (p50, p90) = state
        .statistics
        .with_aggregates(crate::stats::Aggregates::queue_wait_percentiles);
    let summary = serde_json::json!({
        "hosts_online": hosts.iter().filter(|host| host.online).count(),
        "hosts_total": hosts.len(),
        "slots_busy": stats.values().map(|host| host.busy_slots).sum::<u32>(),
        "slots_total": stats.values().map(|host| host.busy_slots + host.free_slots).sum::<u32>(),
        "jobs_queued": queue.len(),
        "jobs_running": running.len(),
        "p50_queue_wait_secs": p50,
        "p90_queue_wait_secs": p90,
    });
    json(&serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "generated_at": now,
        "started_at": dashboard.started_at,
        "update": update_status(dashboard),
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
    Query(query): Query<MetricsQuery>,
) -> Response {
    let Some(range) = Range::parse(query.range.as_deref().unwrap_or("6h")) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let now = Utc::now().timestamp();
    let (span, _) = range.span_and_step();
    let (samples, names) = {
        let store = state.store();
        (
            store.metrics(now - span).unwrap_or_default(),
            host_names(&store.hosts().unwrap_or_default()),
        )
    };
    json(&metrics::series(&samples, range, now, &names))
}

/// One minute's samples: each connected host's load, and the fleet's jobs.
#[must_use]
pub fn sample(state: &AppState, dashboard: &Dashboard, now: i64) -> Vec<MetricSample> {
    let (queued, running) = dashboard.activity.counts(now);
    let mut samples = vec![MetricSample {
        at: now,
        host_id: String::new(),
        queued: u32::try_from(queued).ok(),
        running: u32::try_from(running).ok(),
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

/// Saves this minute's [`sample`]; called by the server's minute loop.
pub fn record_minute(state: &AppState) {
    let Some(dashboard) = &state.dashboard else {
        return;
    };
    let now = Utc::now().timestamp();
    let samples = sample(state, dashboard, now);
    if let Err(error) = state
        .store()
        .record_metrics(&samples, now - metrics::RETENTION_SECS)
    {
        tracing::warn!(%error, "the dashboard's minute of history was not saved");
    }
}
