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
pub mod cli;
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
use crate::store::{DashboardSession, HostRecord, MetricSample, SessionKind};
use activity::Activity;
use auth::AuthConfig;
use metrics::Range;

const INDEX_HTML: &str = include_str!("../../assets/index.html");
const APP_CSS: &str = include_str!("../../assets/app.css");
const APP_JS: &str = include_str!("../../assets/app.js");
const ICON_SVG: &str = include_str!("../../assets/icon.svg");

const SESSION_COOKIE: &str = "rm_session";
const STATE_COOKIE: &str = "rm_oauth_state";
/// Where the browser goes after GitHub, when not the dashboard.
const NEXT_COOKIE: &str = "rm_oauth_next";

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
    /// Shared with the sweep, which settles what a restart missed.
    pub activity: Arc<Activity>,
    /// CLI sign-ins waiting for a person to approve them.
    pub cli: cli::CliSignIns,
    http: reqwest::Client,
    started_at: i64,
    update_status: PathBuf,
}

impl Dashboard {
    #[must_use]
    pub fn new(auth: AuthConfig, update_status: PathBuf) -> Self {
        Self {
            auth,
            activity: Arc::new(Activity::default()),
            cli: cli::CliSignIns::default(),
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
        .route("/api/hosts/{id}/config", get(host_config))
        .route("/api/hosts/{id}/command", post(host_command))
        .route("/api/audit", get(audit))
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
        .route("/auth/cli", get(cli::page))
        .route("/auth/cli/start", post(cli::start))
        .route("/auth/cli/approve", post(cli::approve))
        .route("/auth/cli/poll", post(cli::poll))
        .route("/auth/cli/logout", post(cli::logout))
        .route("/assets/cli.css", get(cli::css))
        .merge(api)
        .layer(map_response(secure_headers))
}

async fn secure_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for (name, value) in [
        ("content-security-policy", CSP),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    // `no-referrer` unless a page chose a stricter-than-default one of its
    // own: the CLI sign-in page's form needs its Origin sent.
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("no-referrer"));
    response
}

/// The dashboard, for a handler only ever routed when it exists.
fn dashboard(state: &AppState) -> &Dashboard {
    state
        .dashboard
        .as_ref()
        .expect("dashboard routes are merged only when the dashboard exists")
}

/// How a request proved its session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Credential {
    /// A browser's session cookie: a cross-site page can make the browser
    /// send it, so a change also needs this origin.
    Cookie,
    /// The CLI's `Authorization: Bearer` token: never sent by a browser on
    /// its own, so no origin is asked for.
    Bearer,
}

/// Lets an `/api/*` request through only with a live session of an allowed
/// login, which it hands on as an extension with its [`Credential`]. A
/// request with an `Authorization` header is judged by it alone.
async fn require_session(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let signed_in = if request.headers().contains_key(header::AUTHORIZATION) {
        cli_session(&state, request.headers()).map(|session| (session, Credential::Bearer))
    } else {
        web_session(&state, request.headers()).map(|session| (session, Credential::Cookie))
    };
    match signed_in {
        Some((session, credential)) => {
            request.extensions_mut().insert(session);
            request.extensions_mut().insert(credential);
            next.run(request).await
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthenticated"})),
        )
            .into_response(),
    }
}

/// The bearer token of a request, when it carries one of the right shape.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| token.len() == 64)
}

/// The browser session of a request (its cookie), if any.
fn web_session(state: &AppState, headers: &HeaderMap) -> Option<DashboardSession> {
    let token = auth::cookie(headers, SESSION_COOKIE).filter(|token| token.len() == 64)?;
    live_session(state, token, SessionKind::Web)
}

/// The CLI session of a request (its bearer token), if any.
fn cli_session(state: &AppState, headers: &HeaderMap) -> Option<DashboardSession> {
    live_session(state, bearer_token(headers)?, SessionKind::Cli)
}

fn live_session(state: &AppState, token: &str, kind: SessionKind) -> Option<DashboardSession> {
    let session = state
        .store()
        .session(&auth::token_hash(token), kind, Utc::now().timestamp())
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

#[derive(Debug, Deserialize)]
struct LoginQuery {
    /// Where to come back to after GitHub: `/`, or the CLI sign-in page.
    next: Option<String>,
}

async fn login(State(state): State<Arc<AppState>>, Query(query): Query<LoginQuery>) -> Response {
    let oauth_state = auth::token();
    let url = auth::authorize_url(&dashboard(&state).auth, &redirect_uri(&state), &oauth_state);
    let secure = secure_origin(&state);
    let mut cookies = vec![auth::set_cookie(
        STATE_COOKIE,
        &oauth_state,
        auth::STATE_SECS,
        secure,
    )];
    match query.next.as_deref() {
        // Anything else is ignored: the dashboard, as before.
        Some(next) if cli::valid_next(next) && next != "/" => {
            cookies.push(auth::set_cookie(
                NEXT_COOKIE,
                next,
                auth::STATE_SECS,
                secure,
            ));
        }
        _ => cookies.push(auth::set_cookie(NEXT_COOKIE, "", 0, secure)),
    }
    redirect(&url, &cookies)
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
    // Checked again: a cookie is the browser's to change.
    let next = auth::cookie(&headers, NEXT_COOKIE)
        .filter(|next| cli::valid_next(next))
        .unwrap_or("/")
        .to_owned();
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
            SessionKind::Web,
            now,
            now + auth::SESSION_SECS,
        )
        .is_err()
    {
        return redirect("/?error=1", &[clear_state]);
    }
    tracing::info!("a dashboard session was opened");
    redirect(
        &next,
        &[
            clear_state,
            auth::set_cookie(NEXT_COOKIE, "", 0, secure),
            auth::set_cookie(SESSION_COOKIE, &token, auth::SESSION_SECS, secure),
        ],
    )
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // A cross-site form cannot sign anyone out.
    if !same_origin(&state, &headers) {
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
    /// The volume's size, from its heartbeat (0.4.66).
    disk_total_bytes: Option<u64>,
    busy_slots: Option<u32>,
    free_slots: Option<u32>,
    unfit: bool,
    draining: bool,
    last_seen_at: Option<i64>,
    enrolled_at: i64,
    connected_since: Option<i64>,
    /// Connected and new enough to take commands (protocol version 5).
    manageable: bool,
    /// Its operator allowed changes through the coordinator.
    remote_changes: bool,
    /// Its runner-manager builds, from its last heartbeat (0.4.64).
    versions: Option<runner_manager_domain::coordinator_protocol::HostVersions>,
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
                cpu_load_percent: live
                    .and_then(|live| live.cpu_load_percent)
                    .map(metrics::cpu_share),
                disk_free_bytes: live.and_then(|live| live.disk_free_bytes),
                disk_total_bytes: link
                    .and_then(|host| host.heartbeat.as_ref())
                    .and_then(|heartbeat| heartbeat.disk_total_bytes),
                busy_slots: live.map(|live| live.busy_slots),
                free_slots: live.map(|live| live.free_slots),
                unfit: live.is_some_and(|live| live.unfit),
                draining: live.is_some_and(|live| live.draining),
                last_seen_at: record.last_seen_at.map(|at| at.timestamp()),
                enrolled_at: record.enrolled_at.timestamp(),
                connected_since: link.map(|host| host.since.timestamp()),
                manageable: state.registry.takes_commands(&record.id) == Some(true),
                remote_changes: hello.is_some_and(|hello| hello.remote_changes),
                versions: link
                    .and_then(|host| host.heartbeat.as_ref())
                    .and_then(|heartbeat| heartbeat.versions.clone()),
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
        "github_web": dashboard.auth.web_base,
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
    let (start, step) = range.window(now);
    let (samples, names) = {
        let store = state.store();
        (
            store.metrics(start, step).unwrap_or_default(),
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
            cpu: host.cpu_load_percent.map(metrics::cpu_share),
            busy: Some(host.busy_slots),
            slots: Some(host.busy_slots + host.free_slots),
            disk_free: host.disk_free_bytes,
            host_id: host.host_id,
            ..MetricSample::default()
        }
    }));
    samples
}

/// Takes back the job lists the last run saved, unless they are older than
/// anything they could still show.
pub fn restore_activity(dashboard: &Dashboard, store: &crate::store::Store) {
    let (saved_at, body) = match store.activity() {
        Ok(Some(saved)) => saved,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%error, "the dashboard's saved job lists could not be read");
            return;
        }
    };
    if Utc::now().timestamp() - saved_at > activity::MAX_RESTORED_AGE {
        return;
    }
    match serde_json::from_str::<activity::Saved>(&body) {
        Ok(saved) => {
            tracing::info!(
                jobs = saved.jobs.len(),
                recent = saved.recent.len(),
                "the dashboard's job lists were restored"
            );
            dashboard.activity.restore(saved);
        }
        Err(error) => tracing::warn!(%error, "the dashboard's saved job lists were not readable"),
    }
}

/// Saves the dashboard's job lists: every minute, and at shutdown.
pub fn save_activity(state: &AppState) {
    let Some(dashboard) = &state.dashboard else {
        return;
    };
    let body = match serde_json::to_string(&dashboard.activity.saved()) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "the dashboard's job lists could not be written out");
            return;
        }
    };
    if let Err(error) = state.store().save_activity(&body, Utc::now().timestamp()) {
        tracing::warn!(%error, "the dashboard's job lists were not saved");
    }
}

/// Saves this minute's [`sample`] and the job lists; called by the server's
/// minute loop.
pub fn record_minute(state: &AppState) {
    let Some(dashboard) = &state.dashboard else {
        return;
    };
    save_activity(state);
    let now = Utc::now().timestamp();
    let samples = sample(state, dashboard, now);
    if let Err(error) = state
        .store()
        .record_metrics(&samples, now - metrics::RETENTION_SECS)
    {
        tracing::warn!(%error, "the dashboard's minute of history was not saved");
    }
}

// ---------------------------------------------------------------------------
// Remote commands
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CommandBody {
    argv: Vec<String>,
}

/// Runs a command on a host for the signed-in person, and records it when
/// `recorded`: the dashboard's own read of a machine, on every opening and
/// after every change, is not, or it would push the changes out of the
/// record (the host keeps no reads either).
async fn run_on_host(
    state: &AppState,
    host_id: &str,
    argv: Vec<String>,
    login: &str,
    recorded: bool,
) -> Result<runner_manager_domain::coordinator_protocol::CommandResult, crate::remote::RemoteError>
{
    let outcome = state
        .remote
        .run(
            &state.registry,
            host_id,
            argv.clone(),
            login,
            crate::remote::COMMAND_TIMEOUT,
        )
        .await;
    if !recorded {
        return outcome;
    }
    let record = crate::store::RemoteCommandRecord {
        at: Utc::now().timestamp(),
        login: login.to_owned(),
        host_id: host_id.to_owned(),
        argv,
        outcome: match &outcome {
            Ok(result) => format!("exit {}", result.exit_code),
            Err(error) => error.code().to_owned(),
        },
        access: outcome
            .as_ref()
            .ok()
            .and_then(|result| result.access.clone()),
    };
    if let Err(error) = state.store().record_remote_command(&record) {
        tracing::warn!(%error, "a remote command was not recorded");
    }
    // The host and the outcome only: arguments are text off the wire.
    tracing::info!(host_id, outcome = %record.outcome, "a remote command ran");
    outcome
}

fn remote_failure(error: crate::remote::RemoteError) -> Response {
    error_json(error.status(), &error.to_string())
}

/// A JSON error answer, never cached.
fn error_json(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

/// Whether a state-changing request came from this origin: a cross-site page
/// can send the cookie with a form, never this header.
fn same_origin(state: &AppState, headers: &HeaderMap) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        == Some(state.config.public_origin.trim_end_matches('/'))
}

async fn host_command(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<DashboardSession>,
    Extension(credential): Extension<Credential>,
    axum::extract::Path(host_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(body): Json<CommandBody>,
) -> Response {
    if credential == Credential::Cookie && !same_origin(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match run_on_host(&state, &host_id, body.argv, &session.login, true).await {
        Ok(result) => json(&result),
        Err(error) => remote_failure(error),
    }
}

async fn host_config(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<DashboardSession>,
    axum::extract::Path(host_id): axum::extract::Path<String>,
) -> Response {
    let argv = ["repo", "list", "--json"].map(String::from).to_vec();
    match run_on_host(&state, &host_id, argv, &session.login, false).await {
        Ok(result) if result.exit_code == 0 => {
            let Ok(config) = serde_json::from_str::<serde_json::Value>(&result.stdout) else {
                return error_json(
                    StatusCode::BAD_GATEWAY,
                    "the host's answer was not understood",
                );
            };
            json(&serde_json::json!({
                "remote_changes": state.registry.remote_changes(&host_id),
                "config": config,
            }))
        }
        Ok(result) => error_json(StatusCode::BAD_GATEWAY, result.stderr.trim()),
        Err(error) => remote_failure(error),
    }
}

async fn audit(State(state): State<Arc<AppState>>) -> Response {
    let records = state.store().remote_commands(100).unwrap_or_default();
    let names = host_names(&state.store().hosts().unwrap_or_default());
    let records: Vec<_> = records
        .into_iter()
        .map(|record| {
            let host_name = names.get(&record.host_id).cloned();
            serde_json::json!({
                "at": record.at,
                "login": record.login,
                "host_id": record.host_id,
                "host_name": host_name,
                "argv": record.argv,
                "outcome": record.outcome,
                "access": record.access,
            })
        })
        .collect();
    json(&serde_json::json!({ "commands": records }))
}
