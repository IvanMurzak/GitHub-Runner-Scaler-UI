//! Sign-in of the `runner-manager` CLI, in the style of a device flow, on
//! top of the dashboard's own GitHub sign-in: no other GitHub setting.
//!
//! 1. The CLI starts a sign-in (`POST /auth/cli/start`) and is given a secret
//!    device code, which only it knows, and a short user code it shows.
//! 2. The person opens `/auth/cli?code=USER-CODE` in a browser signed in to
//!    the dashboard (or signs in there first), checks the code is the one
//!    the terminal shows, and approves it (`POST /auth/cli/approve`, a form
//!    from this origin).
//! 3. The CLI, polling with the device code (`POST /auth/cli/poll`), is
//!    handed a session token once: a bearer token for `/api/*`, stored
//!    hashed like a browser's cookie, of its own kind, for 90 days.
//!
//! Pending sign-ins live in memory only (a restart forgets them; the CLI
//! starts again), at most [`MAX_PENDING`] of them, each for
//! [`SIGN_IN_SECS`]. Only the hash of a device code is kept.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::Deserialize;

use super::{auth, dashboard, json, same_origin, web_session};
use crate::server::AppState;
use crate::store::{DashboardSession, SessionKind};

/// How long a started sign-in waits for its approval.
pub const SIGN_IN_SECS: u64 = 10 * 60;
/// How often the CLI is asked to poll.
pub const POLL_INTERVAL_SECS: u64 = 3;
/// How long a CLI session lasts.
pub const CLI_SESSION_SECS: i64 = 90 * 24 * 60 * 60;
/// The most sign-ins waiting at once.
pub const MAX_PENDING: usize = 256;

/// Consonants only: no `0`/`O` or `1`/`I`/`L` to confuse, and no vowels to
/// spell words with.
const ALPHABET: &[u8] = b"BCDFGHJKMNPQRSTVWXZ";

/// The path a signed-out browser comes back to after GitHub, for a code.
pub const PAGE_PREFIX: &str = "/auth/cli?code=";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    Waiting,
    Approved(DashboardSession),
    Denied,
}

#[derive(Debug)]
struct Pending {
    user_code: String,
    started: Instant,
    decision: Decision,
}

/// A sign-in just started: the device code exists only in this value.
#[derive(Debug)]
pub struct Started {
    pub device_code: String,
    pub user_code: String,
}

/// What a poll finds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    Waiting,
    Denied,
    /// Expired, already answered, or never started: the same from outside.
    Expired,
    Approved(DashboardSession),
}

/// The CLI sign-ins waiting for a person, by the hash of their device code.
#[derive(Debug, Default)]
pub struct CliSignIns {
    pending: Mutex<HashMap<String, Pending>>,
}

const LIFETIME: Duration = Duration::from_secs(SIGN_IN_SECS);

impl CliSignIns {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Starts a sign-in, or `None` when [`MAX_PENDING`] are already waiting.
    pub fn start(&self, now: Instant) -> Option<Started> {
        let mut pending = self.lock();
        pending.retain(|_, sign_in| now.duration_since(sign_in.started) < LIFETIME);
        if pending.len() >= MAX_PENDING {
            return None;
        }
        let user_code = loop {
            let code = user_code();
            if !pending.values().any(|sign_in| sign_in.user_code == code) {
                break code;
            }
        };
        let device_code = auth::token();
        pending.insert(
            auth::token_hash(&device_code),
            Pending {
                user_code: user_code.clone(),
                started: now,
                decision: Decision::Waiting,
            },
        );
        Some(Started {
            device_code,
            user_code,
        })
    }

    /// Whether `user_code` names a sign-in still waiting for its answer.
    pub fn is_waiting(&self, user_code: &str, now: Instant) -> bool {
        self.lock().values().any(|sign_in| {
            sign_in.user_code == user_code
                && sign_in.decision == Decision::Waiting
                && now.duration_since(sign_in.started) < LIFETIME
        })
    }

    /// Approves (`Some(session)`) or denies (`None`) the sign-in `user_code`
    /// names; `false` when it is not waiting any more.
    pub fn decide(
        &self,
        user_code: &str,
        approved: Option<DashboardSession>,
        now: Instant,
    ) -> bool {
        let mut pending = self.lock();
        let Some(sign_in) = pending.values_mut().find(|sign_in| {
            sign_in.user_code == user_code
                && sign_in.decision == Decision::Waiting
                && now.duration_since(sign_in.started) < LIFETIME
        }) else {
            return false;
        };
        sign_in.decision = approved.map_or(Decision::Denied, Decision::Approved);
        true
    }

    /// What became of the sign-in `device_code` started. An answer is given
    /// once: the sign-in is forgotten with it.
    pub fn poll(&self, device_code: &str, now: Instant) -> Poll {
        let key = auth::token_hash(device_code);
        let mut pending = self.lock();
        let Some(sign_in) = pending.get(&key) else {
            return Poll::Expired;
        };
        if now.duration_since(sign_in.started) >= LIFETIME {
            pending.remove(&key);
            return Poll::Expired;
        }
        match &sign_in.decision {
            Decision::Waiting => Poll::Waiting,
            Decision::Denied => {
                pending.remove(&key);
                Poll::Denied
            }
            Decision::Approved(session) => {
                let session = session.clone();
                pending.remove(&key);
                Poll::Approved(session)
            }
        }
    }
}

fn user_code() -> String {
    let letters: Vec<char> = rand::random::<[u8; 8]>()
        .iter()
        .map(|byte| char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]))
        .collect();
    let (left, right) = letters.split_at(4);
    format!(
        "{}-{}",
        left.iter().collect::<String>(),
        right.iter().collect::<String>()
    )
}

/// Whether `code` is shaped like a user code: `ABCD-EFGH` from [`ALPHABET`].
#[must_use]
pub fn valid_user_code(code: &str) -> bool {
    code.len() == 9
        && code.bytes().enumerate().all(|(index, byte)| {
            if index == 4 {
                byte == b'-'
            } else {
                ALPHABET.contains(&byte)
            }
        })
}

/// Whether `next` is a place `/auth/login` may send a browser back to: the
/// dashboard, or the CLI sign-in page for a well-formed code. Nothing else.
#[must_use]
pub fn valid_next(next: &str) -> bool {
    next == "/" || next.strip_prefix(PAGE_PREFIX).is_some_and(valid_user_code)
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

fn status_json(status: StatusCode, word: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "status": word })),
    )
        .into_response()
}

/// `POST /auth/cli/start`.
pub(super) async fn start(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !state.allow_cli_sign_in(peer, &headers) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Some(started) = dashboard(&state).cli.start(Instant::now()) else {
        return status_json(StatusCode::SERVICE_UNAVAILABLE, "busy");
    };
    json(&serde_json::json!({
        "device_code": started.device_code,
        "user_code": started.user_code,
        "verification_url": format!(
            "{}{PAGE_PREFIX}{}",
            state.config.public_origin.trim_end_matches('/'),
            started.user_code
        ),
        "interval_secs": POLL_INTERVAL_SECS,
        "expires_in_secs": SIGN_IN_SECS,
    }))
}

#[derive(Debug, Deserialize)]
pub(super) struct PageQuery {
    code: Option<String>,
}

/// `GET /auth/cli?code=...`: the page a person approves a sign-in on.
pub(super) async fn page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    let code = query
        .code
        .map(|code| code.trim().to_ascii_uppercase())
        .filter(|code| valid_user_code(code));
    let Some(code) = code else {
        return html(
            StatusCode::BAD_REQUEST,
            "<h1>No sign-in code</h1><p>Open the link <code>runner-manager coordinator \
             login</code> printed.</p>",
        );
    };
    if !dashboard(&state).cli.is_waiting(&code, Instant::now()) {
        return gone();
    }
    let Some(session) = web_session(&state, &headers) else {
        let next = format!("{PAGE_PREFIX}{code}");
        let login: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("next", &next)
            .finish();
        return html(
            StatusCode::OK,
            &format!(
                "<h1>Sign in the runner-manager CLI</h1>\
                 <p>Code <span class=\"code\">{code}</span></p>\
                 <p>Sign in to this coordinator first; you come back here after.</p>\
                 <p><a class=\"button\" href=\"/auth/login?{login}\">Sign in with GitHub</a></p>"
            ),
        );
    };
    let login = escape(&session.login);
    html(
        StatusCode::OK,
        &format!(
            "<h1>Sign in the runner-manager CLI</h1>\
             <p>Sign in the runner-manager CLI as <strong>{login}</strong>?</p>\
             <p>Code <span class=\"code\">{code}</span></p>\
             <p class=\"note\">Approve only if your terminal shows this code. The CLI can \
             then read and change your hosts through this coordinator, as {login}, for 90 \
             days.</p>\
             <form method=\"post\" action=\"/auth/cli/approve\">\
             <input type=\"hidden\" name=\"code\" value=\"{code}\">\
             <button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button> \
             <button type=\"submit\" name=\"decision\" value=\"deny\" class=\"secondary\">Deny\
             </button></form>"
        ),
    )
}

/// `POST /auth/cli/approve`: a form from this origin, by a signed-in browser.
pub(super) async fn approve(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // A cross-site form can carry the cookie; it cannot carry this origin.
    if !same_origin(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // A browser's session only: a CLI token cannot approve another sign-in.
    let Some(session) = web_session(&state, &headers) else {
        return html(
            StatusCode::UNAUTHORIZED,
            "<h1>Not signed in</h1><p>Open the link the CLI printed again.</p>",
        );
    };
    let mut code = None;
    let mut decision = None;
    for (key, value) in url::form_urlencoded::parse(&body) {
        match key.as_ref() {
            "code" => code = Some(value.trim().to_ascii_uppercase()),
            "decision" => decision = Some(value.into_owned()),
            _ => {}
        }
    }
    let (Some(code), Some(decision)) = (code.filter(|code| valid_user_code(code)), decision) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let approved = match decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    if !dashboard(&state)
        .cli
        .decide(&code, approved.then(|| session.clone()), Instant::now())
    {
        return gone();
    }
    tracing::info!(approved, "a CLI sign-in was answered");
    if approved {
        html(
            StatusCode::OK,
            &format!(
                "<h1>Approved</h1><p>The runner-manager CLI is signed in as \
                 <strong>{}</strong>. You can close this page and go back to the terminal.</p>",
                escape(&session.login)
            ),
        )
    } else {
        html(
            StatusCode::OK,
            "<h1>Denied</h1><p>That terminal was not signed in.</p>",
        )
    }
}

/// `POST /auth/cli/poll` `{"device_code": ...}`.
pub(super) async fn poll(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    #[derive(Deserialize)]
    struct PollBody {
        device_code: String,
    }
    let Ok(request) = serde_json::from_slice::<PollBody>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if request.device_code.len() != 64 {
        return status_json(StatusCode::GONE, "expired");
    }
    let dashboard = dashboard(&state);
    match dashboard.cli.poll(&request.device_code, Instant::now()) {
        Poll::Waiting => status_json(StatusCode::PRECONDITION_REQUIRED, "pending"),
        Poll::Denied => status_json(StatusCode::FORBIDDEN, "denied"),
        Poll::Expired => status_json(StatusCode::GONE, "expired"),
        Poll::Approved(session) => {
            // Taken off the allowlist while the sign-in waited.
            if !dashboard.auth.allows(&session.login) {
                return status_json(StatusCode::FORBIDDEN, "denied");
            }
            let token = auth::token();
            let now = Utc::now().timestamp();
            if state
                .store()
                .create_session(
                    &auth::token_hash(&token),
                    &session,
                    SessionKind::Cli,
                    now,
                    now + CLI_SESSION_SECS,
                )
                .is_err()
            {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            tracing::info!("a CLI session was opened");
            json(&serde_json::json!({ "token": token, "login": session.login }))
        }
    }
}

/// `POST /auth/cli/logout`: ends the CLI session whose bearer token this is.
pub(super) async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = super::bearer_token(&headers) {
        let _ = state.store().delete_session(&auth::token_hash(token));
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /assets/cli.css`.
pub(super) async fn css() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        CSS,
    )
        .into_response()
}

const CSS: &str = "\
body{margin:0;font:16px/1.5 system-ui,sans-serif;background:#f6f7f9;color:#1b1f24}\
main{max-width:30rem;margin:4rem auto;padding:2rem;background:#fff;border-radius:.75rem;\
box-shadow:0 1px 3px rgba(0,0,0,.12)}\
h1{font-size:1.25rem;margin:0 0 1rem}\
.code{font:600 1.5rem ui-monospace,monospace;letter-spacing:.1em}\
.note{color:#57606a;font-size:.875rem}\
button,.button{display:inline-block;font:inherit;padding:.5rem 1.25rem;border-radius:.5rem;\
border:1px solid #1f6feb;background:#1f6feb;color:#fff;text-decoration:none;cursor:pointer}\
button.secondary{background:#fff;color:#1b1f24;border-color:#d0d7de}\
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}\
main{background:#161b22}.note{color:#8d96a0}\
button.secondary{background:#21262d;color:#e6edf3;border-color:#30363d}}";

fn gone() -> Response {
    html(
        StatusCode::GONE,
        "<h1>This sign-in is over</h1><p>The code is unknown, already answered, or expired. \
         Run <code>runner-manager coordinator login</code> again.</p>",
    )
}

/// A small page. No inline script or style: the CSP forbids both. Its
/// referrer policy is `same-origin` rather than the dashboard's
/// `no-referrer`, because under `no-referrer` a browser sends `Origin: null`
/// with the form, and the approval requires this origin.
fn html(status: StatusCode, body: &str) -> Response {
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>runner-manager CLI sign-in</title>\
         <link rel=\"stylesheet\" href=\"/assets/cli.css\"></head>\
         <body><main>{body}</main></body></html>"
    );
    let mut response = (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        page,
    )
        .into_response();
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    response
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> DashboardSession {
        DashboardSession {
            login: "me".into(),
            avatar_url: None,
        }
    }

    #[test]
    fn user_codes_are_unambiguous_and_checked_strictly() {
        for _ in 0..200 {
            let code = user_code();
            assert!(valid_user_code(&code), "{code}");
            assert!(!code.contains(['0', 'O', '1', 'I', 'L']), "{code}");
        }
        for bad in [
            "",
            "BCDF-GHJ",
            "BCDFGHJKM",
            "bcdf-ghjk",
            "BCDF-GHJ0",
            "BCDF_GHJK",
        ] {
            assert!(!valid_user_code(bad), "{bad}");
        }
        assert!(valid_next("/"));
        assert!(valid_next("/auth/cli?code=BCDF-GHJK"));
        for bad in [
            "",
            "//evil.example",
            "https://evil.example/",
            "/auth/cli?code=BCDF-GHJK&x=1",
            "/auth/cli?code=",
            "/api/overview",
        ] {
            assert!(!valid_next(bad), "{bad}");
        }
    }

    #[test]
    fn a_sign_in_is_answered_once_and_expires() {
        let sign_ins = CliSignIns::default();
        let now = Instant::now();
        let started = sign_ins.start(now).expect("room");
        assert_eq!(started.device_code.len(), 64);
        assert_eq!(sign_ins.poll(&started.device_code, now), Poll::Waiting);
        assert!(sign_ins.is_waiting(&started.user_code, now));
        assert!(sign_ins.decide(&started.user_code, Some(me()), now));
        assert!(
            !sign_ins.decide(&started.user_code, None, now),
            "answered already"
        );
        assert_eq!(
            sign_ins.poll(&started.device_code, now),
            Poll::Approved(me())
        );
        assert_eq!(
            sign_ins.poll(&started.device_code, now),
            Poll::Expired,
            "handed out once"
        );

        let denied = sign_ins.start(now).expect("room");
        assert!(sign_ins.decide(&denied.user_code, None, now));
        assert_eq!(sign_ins.poll(&denied.device_code, now), Poll::Denied);

        let late = sign_ins.start(now).expect("room");
        let later = now + LIFETIME;
        assert!(!sign_ins.is_waiting(&late.user_code, later));
        assert!(!sign_ins.decide(&late.user_code, Some(me()), later));
        assert_eq!(sign_ins.poll(&late.device_code, later), Poll::Expired);
        assert_eq!(sign_ins.poll(&auth::token(), now), Poll::Expired);
    }

    #[test]
    fn the_waiting_sign_ins_are_bounded() {
        let sign_ins = CliSignIns::default();
        let now = Instant::now();
        for _ in 0..MAX_PENDING {
            assert!(sign_ins.start(now).is_some());
        }
        assert!(sign_ins.start(now).is_none(), "full");
        assert!(
            sign_ins.start(now + LIFETIME).is_some(),
            "the expired ones make room"
        );
    }
}
