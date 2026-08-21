// owner: c2-device-flow-auth
//
// c2 also owns the shared authenticated HTTP client that lives at this crate
// root; c3 owns `rest`, and c4 owns `demand` and `jit`.

//! The GitHub gateway.
//!
//! This crate holds every line of code in the product that talks to GitHub, and
//! the crate root holds the one client all of it goes through.
//!
//! * [`device_flow`] — the OAuth 2.0 Device Authorization Grant, which is the
//!   *only* way this product ever obtains a credential (D3, D16).
//! * [`AuthenticatedClient`] — the shared `api.github.com` client. Every request
//!   in this crate is built by it, which is what makes "sets
//!   `X-GitHub-Api-Version` and an explicit `Accept`" a property of the design
//!   rather than of each call site, and what lets the authentication-failure
//!   taxonomy be implemented exactly once.
//! * [`rest`], [`demand`], [`jit`] — typed adapters owned by `c3` and `c4`,
//!   built on [`AuthenticatedClient`].
//!
//! # Three properties this crate is required to keep
//!
//! **It holds no client secret and has no token-renewal path.** The published
//! App opts out of user-token expiration, so the user access token does not
//! expire and no renewal token is ever issued. Renewing a user token would
//! require the client secret, and a public client cannot hold one — that is the
//! whole reason this design has no server in it
//! (`01-current-architecture.md`, "User-to-server token expiration";
//! `07-security.md`, "Authentication model"). See
//! [`AuthenticatedClient::revalidate`] for what happens on a `401` instead.
//!
//! **It persists nothing.** [`device_flow::DeviceFlow::complete`] *returns* the
//! token; it never writes it anywhere. The machine-scoped secret store is `d2`
//! and the wiring is `f1`. That boundary is why this crate has no dependency on
//! `runner-manager-platform` and performs no filesystem write outside its own
//! tests — and it is what lets the whole gateway be tested with no platform
//! dependency at all.
//!
//! **It never renders a secret.** The device code, the user access token, and
//! every header carrying either are absent from `Debug`, from `Display`, from
//! errors, and from tracing output. Every type here that holds one wraps it in
//! [`secrecy::SecretString`] *and* implements [`fmt::Debug`] by hand, because a
//! `#[derive(Debug)]` added later to a struct with a plain `String` field is
//! precisely how this control is lost. `tests::no_secret_reaches_the_logs`
//! drives a whole login and an authenticated round trip through a capturing
//! `tracing` subscriber and fails if any of the three appears.

pub mod demand;
pub mod device_flow;
pub mod jit;
pub mod rest;

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use reqwest::{Method, StatusCode, header::HeaderMap};
use runner_manager_domain::model::{Clock, Org, OwnerRepo, Timestamp};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use url::Url;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The REST API version every request pins.
///
/// `04-subsystem-contracts.md`: "All requests set `X-GitHub-Api-Version` and an
/// explicit `Accept` header." Both spikes ran against this version.
pub const GITHUB_API_VERSION: &str = "2022-11-28";

/// The media type every request asks for, stated rather than defaulted.
pub const GITHUB_ACCEPT: &str = "application/vnd.github+json";

/// Production `api.github.com`.
pub const GITHUB_API_BASE: &str = "https://api.github.com/";

/// Production `github.com`, which hosts the device-flow endpoints. They are on
/// the web host, not the API host.
pub const GITHUB_WEB_BASE: &str = "https://github.com/";

/// The canonical page a user types their code into.
///
/// This constant *is* the phishing control (`07-security.md`, threat table): the
/// tool prints this URL and never proxies, embeds, or imitates the approval
/// page. [`Endpoints::verification_url`] derives from the configured web base so
/// a test server can be pointed at, and
/// [`device_flow::DeviceAuthorization::verification_uri`] is checked against it
/// so a response that tries to send the user somewhere else is rejected rather
/// than displayed.
pub const DEVICE_VERIFICATION_PATH: &str = "login/device";

/// What a `401` re-validates the held credential against.
///
/// `GET /user/installations` rather than `GET /user`, because it is the call the
/// D18 spike actually made with a user-to-server token and observed `200` from
/// (`docs/spikes/d18-org-jit-verification.md`, "The permission that authorized
/// it"), and because a successful re-validation then carries the same answer
/// [`AuthenticatedClient::discover_installations`] needs.
pub const REVALIDATION_PATH: &str = "/user/installations";

/// How long a lockout backs off for when GitHub sends no `retry-after`.
///
/// `03-control-flows.md` flow 4.3 requires a back-off but names no duration.
/// Sixty seconds is GitHub's own documented floor for its secondary rate limits.
pub const DEFAULT_LOCKOUT_BACKOFF: Duration = Duration::from_secs(60);

/// Per-request ceiling, so one wedged connection cannot stall the agent's
/// reconciliation loop forever.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The `User-Agent` GitHub requires on every API request.
pub const USER_AGENT: &str = concat!("runner-manager/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------
// The published App
// ---------------------------------------------------------------------------

/// The published GitHub App this product authenticates as (D3, D16).
///
/// Both fields are **public by design**. `07-security.md`'s credential inventory
/// lists the `client_id` as "Not secret … may appear in logs and documentation",
/// which is exactly what makes the device flow serverless: a public client
/// cannot secure a client secret, and this design never tries to.
///
/// The concrete values are *not* compiled in here. Registering and publishing
/// the App is Phase 0 of `06-migration-rollout.md` and has not happened, so
/// there is no honest value to write; `f1` supplies both when it wires the CLI.
/// Committing a placeholder that looked real would be worse than requiring the
/// caller to pass one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRegistration {
    client_id: String,
    slug: String,
}

impl AppRegistration {
    /// # Errors
    /// An empty `client_id` or an empty `slug`.
    pub fn new(client_id: impl Into<String>, slug: impl Into<String>) -> Result<Self, ConfigError> {
        let client_id = client_id.into();
        let slug = slug.into();
        if client_id.trim().is_empty() {
            return Err(ConfigError::Empty { what: "client_id" });
        }
        if slug.trim().is_empty() {
            return Err(ConfigError::Empty { what: "app slug" });
        }
        Ok(Self { client_id, slug })
    }

    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    #[must_use]
    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// The canonical URL a user with no installation must visit.
    ///
    /// `03-control-flows.md` flow 1.1: "If the published App is not yet installed
    /// on any repository, it prints the installation URL."
    ///
    /// # Panics
    /// Never, for a registration built through [`AppRegistration::new`]: the slug
    /// is non-empty and is percent-encoded into the path.
    #[must_use]
    pub fn install_url(&self, endpoints: &Endpoints) -> Url {
        endpoints
            .web_base
            .join("apps/")
            .and_then(|u| u.join(&format!("{}/", encode_path_segment(&self.slug))))
            .and_then(|u| u.join("installations/new"))
            .expect("a non-empty encoded slug always joins onto the web base")
    }
}

fn encode_path_segment(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                c.to_string()
            } else {
                let mut buf = [0_u8; 4];
                c.encode_utf8(&mut buf)
                    .as_bytes()
                    .iter()
                    .map(|b| format!("%{b:02X}"))
                    .collect()
            }
        })
        .collect()
}

/// Where GitHub is.
///
/// Two bases rather than one, because the device grant lives on `github.com`
/// while every API call lives on `api.github.com`. Tests point both at one
/// `wiremock` server; the paths do not collide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    api_base: Url,
    web_base: Url,
}

impl Endpoints {
    /// Production GitHub.
    ///
    /// # Panics
    /// Never: both constants are parsed at every call and are valid URLs.
    #[must_use]
    pub fn production() -> Self {
        Self {
            api_base: Url::parse(GITHUB_API_BASE).expect("GITHUB_API_BASE is a valid URL"),
            web_base: Url::parse(GITHUB_WEB_BASE).expect("GITHUB_WEB_BASE is a valid URL"),
        }
    }

    /// Both bases are normalised to end in `/` so that relative joins keep the
    /// whole base path instead of replacing its last segment.
    #[must_use]
    pub fn new(api_base: Url, web_base: Url) -> Self {
        Self {
            api_base: with_trailing_slash(api_base),
            web_base: with_trailing_slash(web_base),
        }
    }

    /// Point every endpoint at one test server.
    ///
    /// # Errors
    /// `root` not being a parseable absolute URL.
    pub fn for_test_server(root: &str) -> Result<Self, ConfigError> {
        let root = Url::parse(root).map_err(|_| ConfigError::Empty {
            what: "test server URL",
        })?;
        Ok(Self::new(root.clone(), root))
    }

    #[must_use]
    pub fn api_base(&self) -> &Url {
        &self.api_base
    }

    #[must_use]
    pub fn web_base(&self) -> &Url {
        &self.web_base
    }

    /// # Panics
    /// Never: the path is a constant and the base ends in `/`.
    #[must_use]
    pub fn device_code_url(&self) -> Url {
        self.web_base
            .join("login/device/code")
            .expect("a constant path joins onto a normalised base")
    }

    /// # Panics
    /// Never: the path is a constant and the base ends in `/`.
    #[must_use]
    pub fn access_token_url(&self) -> Url {
        self.web_base
            .join("login/oauth/access_token")
            .expect("a constant path joins onto a normalised base")
    }

    /// The canonical page the user code is typed into, and the only device-flow
    /// URL this product ever prints.
    ///
    /// # Panics
    /// Never: the path is a constant and the base ends in `/`.
    #[must_use]
    pub fn verification_url(&self) -> Url {
        self.web_base
            .join(DEVICE_VERIFICATION_PATH)
            .expect("a constant path joins onto a normalised base")
    }
}

impl Default for Endpoints {
    fn default() -> Self {
        Self::production()
    }
}

fn with_trailing_slash(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url
}

/// A configuration value this crate refuses to start with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{what} must not be empty")]
    Empty { what: &'static str },
}

// ---------------------------------------------------------------------------
// The credential
// ---------------------------------------------------------------------------

/// A user access token obtained from the device flow.
///
/// **Non-expiring, and non-renewable.** The published App opts out of
/// user-token expiration, so GitHub issues no renewal token alongside this one
/// and there is nothing to renew — see the crate documentation. The token is
/// invalidated only by the user uninstalling the App or revoking the
/// authorization at GitHub.
///
/// `Debug` is written by hand. Deriving it here would put the token into every
/// `tracing` field, every `unwrap()` panic message, and every `anyhow` chain
/// that ever carries one, which is the exact leak `07-security.md` gates on.
#[derive(Clone)]
pub struct UserAccessToken {
    token: SecretString,
    token_type: String,
    scope: Option<String>,
}

impl UserAccessToken {
    #[must_use]
    pub fn new(token: SecretString) -> Self {
        Self {
            token,
            token_type: "bearer".to_string(),
            scope: None,
        }
    }

    /// The whole credential as the token endpoint returned it. `pub(crate)`
    /// because [`device_flow`] is the only thing in the product entitled to mint
    /// one — every other path receives a token rather than constructing it.
    pub(crate) fn from_parts(
        token: SecretString,
        token_type: String,
        scope: Option<String>,
    ) -> Self {
        Self {
            token,
            token_type,
            scope,
        }
    }

    /// Rebuild the credential `d2` handed back, for `f1`.
    #[must_use]
    pub fn from_stored(token: SecretString) -> Self {
        Self::new(token)
    }

    /// The token itself. Every call site of this is a place a secret can escape,
    /// so there are deliberately few: the `Authorization` header, and `d2`'s
    /// store call.
    #[must_use]
    pub fn secret(&self) -> &SecretString {
        &self.token
    }

    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// The token's four-character family prefix — `ghu_` for an App
    /// user-to-server token — and nothing else.
    ///
    /// This exists so diagnostics can answer "did the device flow return the
    /// kind of token we expected?" without exposing the token. The D17 spike
    /// asserted exactly this and no more.
    #[must_use]
    pub fn family(&self) -> &str {
        let raw = self.token.expose_secret();
        match raw.find('_') {
            Some(idx) if idx < 8 => &raw[..=idx],
            _ => "",
        }
    }

    /// `true` for the `ghu_` family the published App issues.
    #[must_use]
    pub fn is_user_to_server(&self) -> bool {
        self.family() == "ghu_"
    }
}

impl fmt::Debug for UserAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserAccessToken")
            .field("token", &"[REDACTED]")
            .field("family", &self.family())
            .finish_non_exhaustive()
    }
}

impl PartialEq for UserAccessToken {
    /// Equality exists so [`device_flow::PollOutcome`] can carry a token and
    /// still be compared in a test. Production code never compares two
    /// credentials, and this is not a constant-time comparison.
    fn eq(&self, other: &Self) -> bool {
        self.token.expose_secret() == other.token.expose_secret()
            && self.token_type == other.token_type
            && self.scope == other.scope
    }
}

impl Eq for UserAccessToken {}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything [`AuthenticatedClient`] can fail with.
///
/// The first three variants are the taxonomy `03-control-flows.md` flow 4.3
/// requires, and they are separate variants because `c3` and `f1` both act on
/// the distinction: [`GithubError::AuthenticationFailed`] moves a policy to
/// `authentication_failed` and tells the operator to run `auth login`,
/// [`GithubError::AuthenticationLockout`] must *wait* and tell the operator
/// nothing is wrong with their credential, and [`GithubError::Forbidden`] is a
/// permissions answer that re-authenticating will not change.
#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    /// GitHub rejected the credential and a single re-validation confirmed it.
    /// Terminal: only an interactive `auth login` clears this.
    #[error(
        "GitHub rejected the stored credential; run `runner-manager auth login` to sign in again"
    )]
    AuthenticationFailed,

    /// GitHub answered `403` after `401`s — its temporary authentication
    /// lockout, not a permissions change. Back off; do not re-authenticate and
    /// do not retry.
    #[error(
        "GitHub has temporarily locked out authentication for this credential; \
         back off for {}s and do not retry — the credential itself is not the problem",
        retry_after.as_secs()
    )]
    AuthenticationLockout { retry_after: Duration },

    /// A permissions answer, with no `401` before it.
    #[error(
        "GitHub denied {method} {path}: the App installation does not grant it{}",
        message.as_deref().map(|m| format!(" ({m})")).unwrap_or_default()
    )]
    Forbidden {
        method: String,
        path: String,
        message: Option<String>,
    },

    #[error(
        "GitHub returned {status} for {method} {path}{}",
        message.as_deref().map(|m| format!(": {m}")).unwrap_or_default()
    )]
    Status {
        status: u16,
        method: String,
        path: String,
        message: Option<String>,
    },

    /// The request never got an answer. The URL is stripped from the source
    /// error before it is stored: a device-flow URL never carries a secret, but
    /// stripping it costs nothing and removes a whole class of future leak.
    #[error("GitHub was unreachable")]
    Transport(#[source] reqwest::Error),

    #[error("a {what} response from GitHub could not be decoded as {expected}")]
    Decode {
        what: &'static str,
        expected: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("GitHub returned {value:?} for {what}, which this client cannot use")]
    Malformed { what: &'static str, value: String },

    #[error(transparent)]
    Config(#[from] ConfigError),
}

impl GithubError {
    /// `true` for the two authentication outcomes, which callers handle
    /// differently from every other failure.
    #[must_use]
    pub fn is_authentication(&self) -> bool {
        matches!(
            self,
            Self::AuthenticationFailed | Self::AuthenticationLockout { .. }
        )
    }

    /// `true` only for the lockout, which is the one authentication outcome that
    /// resolves by waiting rather than by signing in again.
    #[must_use]
    pub fn is_lockout(&self) -> bool {
        matches!(self, Self::AuthenticationLockout { .. })
    }
}

fn transport(err: reqwest::Error) -> GithubError {
    GithubError::Transport(err.without_url())
}

// ---------------------------------------------------------------------------
// Requests and responses
// ---------------------------------------------------------------------------

/// One `api.github.com` request, before authentication headers are applied.
///
/// `Debug` is written by hand and never renders the body: `c4` posts
/// `generate-jitconfig` requests through this type, and a JIT configuration is
/// a sensitive short-lived value (`07-security.md`, credential inventory).
#[derive(Clone)]
pub struct ApiRequest {
    method: Method,
    /// Either a path relative to the API base, or an absolute URL — which is
    /// what a `Link: rel="next"` page is.
    path: String,
    query: Vec<(String, String)>,
    body: Option<serde_json::Value>,
}

impl ApiRequest {
    #[must_use]
    pub fn get(path: impl Into<String>) -> Self {
        Self::new(Method::GET, path)
    }

    #[must_use]
    pub fn delete(path: impl Into<String>) -> Self {
        Self::new(Method::DELETE, path)
    }

    #[must_use]
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            query: Vec::new(),
            body: None,
        }
    }

    /// # Errors
    /// `body` failing to serialize.
    pub fn post_json<T: Serialize>(path: impl Into<String>, body: &T) -> Result<Self, GithubError> {
        let value = serde_json::to_value(body).map_err(|source| GithubError::Decode {
            what: "request",
            expected: "JSON",
            source,
        })?;
        Ok(Self {
            method: Method::POST,
            path: path.into(),
            query: Vec::new(),
            body: Some(value),
        })
    }

    #[must_use]
    pub fn query(mut self, key: impl Into<String>, value: impl fmt::Display) -> Self {
        self.query.push((key.into(), value.to_string()));
        self
    }

    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Debug for ApiRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiRequest")
            .field("method", &self.method.as_str())
            .field("path", &self.path)
            .field(
                "query_keys",
                &self.query.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .field(
                "body",
                &self.body.as_ref().map_or("none", |_| "[REDACTED JSON]"),
            )
            .finish()
    }
}

/// One buffered `api.github.com` response.
///
/// Buffered rather than streamed because every API response this crate reads is
/// small JSON. The one large download in the product — the runner package — is
/// `e2`'s and uses its own streaming client.
///
/// `Debug` renders the status and the body's *length*, never the body: a
/// `generate-jitconfig` response body is an encoded JIT configuration.
#[derive(Clone)]
pub struct ApiResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl ApiResponse {
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// # Errors
    /// A body that is not the expected JSON shape.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, GithubError> {
        serde_json::from_slice(&self.body).map_err(|source| GithubError::Decode {
            what: "response",
            expected: std::any::type_name::<T>(),
            source,
        })
    }

    /// The next page of a paginated collection, from the `Link` header.
    ///
    /// `04-subsystem-contracts.md`: "Pagination is mandatory; the dashboard must
    /// not treat a first page as a complete inventory." It lives on the shared
    /// response type so that `c3`'s inventory and this module's installation
    /// discovery cannot disagree about how a `Link` header is read.
    #[must_use]
    pub fn next_page(&self) -> Option<Url> {
        self.header("link").and_then(parse_link_next)
    }
}

impl fmt::Debug for ApiResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiResponse")
            .field("status", &self.status.as_u16())
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

fn parse_link_next(link: &str) -> Option<Url> {
    for part in link.split(',') {
        let mut segments = part.split(';');
        let Some(target) = segments.next() else {
            continue;
        };
        let target = target.trim();
        let Some(raw) = target
            .strip_prefix('<')
            .and_then(|rest| rest.strip_suffix('>'))
        else {
            continue;
        };
        let is_next = segments.any(|param| {
            let param = param.trim().replace(['"', '\''], "");
            param.eq_ignore_ascii_case("rel=next")
        });
        if is_next {
            return Url::parse(raw).ok();
        }
    }
    None
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    message: Option<String>,
}

/// GitHub's own message for a failure, and never the raw body.
fn error_message(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<ErrorEnvelope>(body)
        .ok()
        .and_then(|e| e.message)
        .filter(|m| !m.is_empty())
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

// ---------------------------------------------------------------------------
// Sleeping
// ---------------------------------------------------------------------------

/// The one way anything in this crate waits.
///
/// A port rather than a direct `tokio::time::sleep`, for the same reason the
/// domain has a `Clock`: the device flow's `slow_down` handling is a *timing*
/// behaviour, and a timing behaviour tested by actually waiting is either
/// untested or slow. A test substitutes a sleeper that records the requested
/// durations and returns immediately, which turns "`slow_down` increases the
/// poll interval" into an equality assertion on a `Vec<Duration>` rather than a
/// stopwatch reading.
#[async_trait::async_trait]
pub trait Sleeper: Send + Sync + fmt::Debug {
    async fn sleep(&self, duration: Duration);
}

/// The production adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioSleeper;

#[async_trait::async_trait]
impl Sleeper for TokioSleeper {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

// ---------------------------------------------------------------------------
// The shared authenticated client
// ---------------------------------------------------------------------------

/// What a single re-validation of the held credential concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revalidation {
    /// GitHub still accepts the credential, so the `401` was about the request
    /// rather than about the token. One retry is warranted.
    Valid,
    /// GitHub rejects the credential. Terminal; only `auth login` clears it.
    Rejected,
    /// The probe itself could not be completed — GitHub was unreachable, or
    /// answered something neither `2xx` nor `401`. Nothing was learned, so the
    /// caller still gets its one retry.
    Unavailable,
}

#[derive(Debug)]
struct LockoutState {
    until: Option<Timestamp>,
    backoff: Duration,
}

/// The one client every `api.github.com` request in this crate goes through.
///
/// It exists to make four things structural rather than remembered:
///
/// 1. `X-GitHub-Api-Version`, `Accept`, `User-Agent`, and `Authorization` are
///    set on every request because they are set *here*.
/// 2. The `401` / `403` taxonomy of `03-control-flows.md` flow 4.3 is
///    implemented once. `c3` and `f1` both branch on the distinction, and two
///    implementations of it would eventually disagree.
/// 3. A `401` storm produces **one** credential re-validation, not one per
///    caller — see [`AuthenticatedClient::revalidate`].
/// 4. A lockout stops traffic. Once GitHub answers `403` after `401`s, this
///    client issues no further HTTP at all until the back-off elapses.
pub struct AuthenticatedClient {
    http: reqwest::Client,
    endpoints: Endpoints,
    credential: UserAccessToken,
    clock: Arc<dyn Clock>,

    /// Bumped once per completed re-validation. A caller that took a `401`
    /// samples this *before* queuing on the gate; if it changed while the caller
    /// waited, some other caller already did the work and this one must not
    /// repeat it. This is the whole single-flight mechanism.
    revalidation_generation: AtomicU64,
    revalidation_gate: tokio::sync::Mutex<()>,
    last_revalidation: std::sync::Mutex<Revalidation>,
    revalidations_performed: AtomicU64,

    /// `401`s seen since the last success. A `403` while this is non-zero is a
    /// lockout; a `403` while it is zero is a permissions answer.
    consecutive_unauthorized: AtomicU64,
    lockout: std::sync::Mutex<LockoutState>,
}

impl fmt::Debug for AuthenticatedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedClient")
            .field("api_base", &self.endpoints.api_base.as_str())
            .field("credential", &self.credential)
            .field(
                "revalidations_performed",
                &self.revalidations_performed.load(Ordering::Relaxed),
            )
            .field("locked_out", &self.is_locked_out())
            .finish_non_exhaustive()
    }
}

impl AuthenticatedClient {
    /// # Errors
    /// The HTTP client failing to build — a TLS backend that will not
    /// initialise, in practice.
    pub fn new(
        endpoints: Endpoints,
        credential: UserAccessToken,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, GithubError> {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .map_err(transport)?;
        Ok(Self::with_http_client(http, endpoints, credential, clock))
    }

    #[must_use]
    pub fn with_http_client(
        http: reqwest::Client,
        endpoints: Endpoints,
        credential: UserAccessToken,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            http,
            endpoints,
            credential,
            clock,
            revalidation_generation: AtomicU64::new(0),
            revalidation_gate: tokio::sync::Mutex::new(()),
            last_revalidation: std::sync::Mutex::new(Revalidation::Valid),
            revalidations_performed: AtomicU64::new(0),
            consecutive_unauthorized: AtomicU64::new(0),
            lockout: std::sync::Mutex::new(LockoutState {
                until: None,
                backoff: DEFAULT_LOCKOUT_BACKOFF,
            }),
        }
    }

    #[must_use]
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// How many credential re-validations this client has performed.
    ///
    /// Public because it is the observable the single-flight requirement is
    /// stated in terms of: "concurrent callers hitting `401` together produce
    /// **one** attempt, not N".
    #[must_use]
    pub fn revalidations_performed(&self) -> u64 {
        self.revalidations_performed.load(Ordering::SeqCst)
    }

    /// `true` while a lockout back-off is still running, during which this
    /// client issues no HTTP at all.
    ///
    /// # Panics
    /// If a previous holder panicked while the lockout lock was held.
    #[must_use]
    pub fn is_locked_out(&self) -> bool {
        self.lockout_remaining().is_some()
    }

    /// How much of the lockout back-off is left, or `None` when not locked out.
    ///
    /// # Panics
    /// If a previous holder panicked while the lockout lock was held.
    #[must_use]
    pub fn lockout_remaining(&self) -> Option<Duration> {
        let state = self.lockout.lock().expect("lockout lock poisoned");
        let until = state.until?;
        let now = self.clock.now();
        if now >= until {
            return None;
        }
        (until - now).to_std().ok()
    }

    /// Clear a lockout early. `f1` does not need this — the back-off expires on
    /// its own against the clock — but a successful interactive `auth login`
    /// legitimately invalidates the whole lockout premise.
    ///
    /// # Panics
    /// If a previous holder panicked while the lockout lock was held.
    pub fn clear_lockout(&self) {
        self.lockout.lock().expect("lockout lock poisoned").until = None;
        self.consecutive_unauthorized.store(0, Ordering::SeqCst);
    }

    /// Send one request, applying the authentication taxonomy.
    ///
    /// On `401` this performs a single-flight credential re-validation and then
    /// **one** retry — never more, and never a token renewal, because there is
    /// nothing to renew (see [`AuthenticatedClient::revalidate`]).
    ///
    /// # Errors
    /// Every variant of [`GithubError`].
    pub async fn send(&self, request: &ApiRequest) -> Result<ApiResponse, GithubError> {
        if let Some(remaining) = self.lockout_remaining() {
            // "backs off without further attempts": no socket is opened at all.
            tracing::debug!(
                method = request.method.as_str(),
                path = %request.path,
                remaining_secs = remaining.as_secs(),
                "suppressed a request: GitHub authentication lockout is still backing off"
            );
            return Err(GithubError::AuthenticationLockout {
                retry_after: remaining,
            });
        }

        let first = self.send_raw(request).await?;
        match self.classify(request, &first) {
            Classified::Ok => Ok(first),
            Classified::Unauthorized => self.revalidate_and_retry_once(request).await,
            Classified::Error(err) => Err(err),
        }
    }

    /// Deserialize a `GET` in one step.
    ///
    /// # Errors
    /// Every variant of [`GithubError`].
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, GithubError> {
        self.send(&ApiRequest::get(path)).await?.json()
    }

    /// Serialize, `POST`, and deserialize in one step.
    ///
    /// # Errors
    /// Every variant of [`GithubError`].
    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, GithubError> {
        self.send(&ApiRequest::post_json(path, body)?).await?.json()
    }

    /// Re-validate the credential once, no matter how many callers ask at once.
    ///
    /// # This is not a token renewal, and it cannot be
    ///
    /// `03-control-flows.md` flow 4.3 and this task's specification both say a
    /// `401` "triggers one refresh under a single-flight mutex, then one retry".
    /// The *structure* of that sentence is right and is implemented here
    /// literally: one attempt shared by every concurrent caller, then one retry
    /// each. The word is not, and cannot be — the same documents remove the
    /// means. Renewing a user access token requires the client secret
    /// (`01-current-architecture.md`: "The client secret is required when
    /// refreshing user access tokens"), the published App opts out of user-token
    /// expiration so GitHub issues no renewal token at all, and holding a client
    /// secret would put a server back into a design whose entire point is not
    /// having one (D3).
    ///
    /// So the single thing that happens under the mutex is a re-validation of
    /// the credential already held: one `GET /user/installations` with the same
    /// token, asking GitHub whether it still accepts it. A
    /// [`Revalidation::Rejected`] answer is terminal
    /// [`GithubError::AuthenticationFailed`] requiring an interactive
    /// `auth login`; [`Revalidation::Valid`] and [`Revalidation::Unavailable`]
    /// both spend the one retry.
    ///
    /// # Errors
    /// [`GithubError::AuthenticationLockout`] if the probe itself is locked out.
    ///
    /// # Panics
    /// If a previous holder panicked while the re-validation result lock was
    /// held.
    pub async fn revalidate(&self) -> Result<Revalidation, GithubError> {
        // Sample before queuing. If this changes while we wait for the gate,
        // someone else's re-validation covers us and we must not repeat it.
        let sampled = self.revalidation_generation.load(Ordering::SeqCst);
        let _guard = self.revalidation_gate.lock().await;
        if self.revalidation_generation.load(Ordering::SeqCst) != sampled {
            let shared = *self
                .last_revalidation
                .lock()
                .expect("re-validation lock poisoned");
            tracing::debug!(
                outcome = ?shared,
                "reused an in-flight credential re-validation instead of starting another"
            );
            return Ok(shared);
        }

        self.revalidations_performed.fetch_add(1, Ordering::SeqCst);
        let outcome = self.probe_credential().await;
        *self
            .last_revalidation
            .lock()
            .expect("re-validation lock poisoned") = outcome;
        self.revalidation_generation.fetch_add(1, Ordering::SeqCst);
        tracing::info!(
            outcome = ?outcome,
            "re-validated the stored credential (no token renewal exists in this design)"
        );
        Ok(outcome)
    }

    async fn probe_credential(&self) -> Revalidation {
        let probe = ApiRequest::get(REVALIDATION_PATH).query("per_page", 1);
        match self.send_raw(&probe).await {
            // Deliberately does **not** reset `consecutive_unauthorized`. The
            // probe is this client's own diagnostic, not the caller's traffic,
            // and a successful probe is exactly the state a lockout arrives in:
            // GitHub still accepts the credential, and answers the *next* real
            // request with `403`. Resetting here would erase the evidence the
            // `403` is classified against and report a lockout as a permissions
            // failure. Only a successful caller request clears the count, in
            // `classify`.
            Ok(response) if response.status.is_success() => Revalidation::Valid,
            Ok(response) if response.status == StatusCode::UNAUTHORIZED => {
                self.consecutive_unauthorized.fetch_add(1, Ordering::SeqCst);
                Revalidation::Rejected
            }
            Ok(response) if response.status == StatusCode::FORBIDDEN => {
                // A `403` on the probe, with `401`s already counted, is the
                // lockout. Latch it; the caller's own classification will report
                // it.
                if self.consecutive_unauthorized.load(Ordering::SeqCst) > 0 {
                    self.latch_lockout(&response.headers);
                }
                Revalidation::Unavailable
            }
            Ok(_) | Err(_) => Revalidation::Unavailable,
        }
    }

    async fn revalidate_and_retry_once(
        &self,
        request: &ApiRequest,
    ) -> Result<ApiResponse, GithubError> {
        match self.revalidate().await? {
            Revalidation::Rejected => {
                tracing::warn!(
                    method = request.method.as_str(),
                    path = %request.path,
                    "GitHub rejected the stored credential; re-authentication is required"
                );
                Err(GithubError::AuthenticationFailed)
            }
            Revalidation::Valid | Revalidation::Unavailable => {
                if let Some(remaining) = self.lockout_remaining() {
                    return Err(GithubError::AuthenticationLockout {
                        retry_after: remaining,
                    });
                }
                let second = self.send_raw(request).await?;
                match self.classify(request, &second) {
                    Classified::Ok => Ok(second),
                    // The one retry is spent. A second `401` is terminal.
                    Classified::Unauthorized => Err(GithubError::AuthenticationFailed),
                    Classified::Error(err) => Err(err),
                }
            }
        }
    }

    fn classify(&self, request: &ApiRequest, response: &ApiResponse) -> Classified {
        let status = response.status;
        if status.is_success() {
            self.consecutive_unauthorized.store(0, Ordering::SeqCst);
            return Classified::Ok;
        }
        if status == StatusCode::UNAUTHORIZED {
            self.consecutive_unauthorized.fetch_add(1, Ordering::SeqCst);
            return Classified::Unauthorized;
        }
        if status == StatusCode::FORBIDDEN {
            if self.consecutive_unauthorized.load(Ordering::SeqCst) > 0 {
                let backoff = self.latch_lockout(&response.headers);
                tracing::warn!(
                    method = request.method.as_str(),
                    path = %request.path,
                    backoff_secs = backoff.as_secs(),
                    "GitHub answered 403 after 401s: temporary authentication lockout, backing off"
                );
                return Classified::Error(GithubError::AuthenticationLockout {
                    retry_after: backoff,
                });
            }
            return Classified::Error(GithubError::Forbidden {
                method: request.method.as_str().to_string(),
                path: request.path.clone(),
                message: error_message(&response.body),
            });
        }
        Classified::Error(GithubError::Status {
            status: status.as_u16(),
            method: request.method.as_str().to_string(),
            path: request.path.clone(),
            message: error_message(&response.body),
        })
    }

    fn latch_lockout(&self, headers: &HeaderMap) -> Duration {
        let backoff = retry_after(headers).unwrap_or(DEFAULT_LOCKOUT_BACKOFF);
        let mut state = self.lockout.lock().expect("lockout lock poisoned");
        state.backoff = backoff;
        state.until = chrono::TimeDelta::from_std(backoff)
            .ok()
            .map(|delta| self.clock.now() + delta);
        backoff
    }

    /// One HTTP round trip with the standard headers applied and no
    /// interpretation of the result.
    async fn send_raw(&self, request: &ApiRequest) -> Result<ApiResponse, GithubError> {
        let url = self.resolve(&request.path)?;
        let mut builder = self
            .http
            .request(request.method.clone(), url)
            .header(reqwest::header::ACCEPT, GITHUB_ACCEPT)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            // The only place the token is ever written onto the wire. It is
            // never logged, and `reqwest` does not render headers in its errors.
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.credential.secret().expose_secret()),
            );
        if !request.query.is_empty() {
            builder = builder.query(&request.query);
        }
        if let Some(body) = &request.body {
            builder = builder.json(body);
        }

        let response = builder.send().await.map_err(transport)?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await.map_err(transport)?.to_vec();

        tracing::debug!(
            method = request.method.as_str(),
            path = %request.path,
            status = status.as_u16(),
            body_bytes = body.len(),
            "github api request"
        );

        Ok(ApiResponse {
            status,
            headers,
            body,
        })
    }

    fn resolve(&self, path: &str) -> Result<Url, GithubError> {
        if path.starts_with("http://") || path.starts_with("https://") {
            return Url::parse(path).map_err(|_| GithubError::Malformed {
                what: "an absolute request URL",
                value: path.to_string(),
            });
        }
        self.endpoints
            .api_base
            .join(path.trim_start_matches('/'))
            .map_err(|_| GithubError::Malformed {
                what: "a request path",
                value: path.to_string(),
            })
    }
}

enum Classified {
    Ok,
    Unauthorized,
    Error(GithubError),
}

// ---------------------------------------------------------------------------
// Installation discovery
// ---------------------------------------------------------------------------

/// Whether an installation can reach every repository on its account, or only
/// the ones the user picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositorySelection {
    /// Every repository on the account, including ones created later.
    All,
    /// Only the repositories the user chose at install time.
    Selected,
}

impl RepositorySelection {
    /// `07-security.md`: "`auth status` shows which repositories the token can
    /// reach, so an over-broad installation is visible rather than assumed."
    /// This is the flag that makes it visible.
    #[must_use]
    pub fn is_over_broad(self) -> bool {
        matches!(self, Self::All)
    }
}

/// Whose account an installation sits on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationAccount {
    User(String),
    Organization(Org),
}

impl InstallationAccount {
    #[must_use]
    pub fn login(&self) -> &str {
        match self {
            Self::User(login) => login,
            Self::Organization(org) => org.as_str(),
        }
    }

    /// The organization, when the account is one. An organization account is a
    /// reachable *target* in its own right (D18): a policy may scale for the
    /// whole organization.
    #[must_use]
    pub fn organization(&self) -> Option<&Org> {
        match self {
            Self::Organization(org) => Some(org),
            Self::User(_) => None,
        }
    }
}

impl fmt::Display for InstallationAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.login())
    }
}

/// One installation of the published App, and what it can actually reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation {
    pub id: u64,
    pub account: InstallationAccount,
    pub repository_selection: RepositorySelection,
    pub repositories: Vec<OwnerRepo>,
    /// The permissions GitHub reports for this installation, as
    /// `name -> level`. Surfaced verbatim so `auth status` can show a grant the
    /// user did not expect rather than assert the published set was applied.
    pub permissions: Vec<(String, String)>,
}

impl Installation {
    #[must_use]
    pub fn is_over_broad(&self) -> bool {
        self.repository_selection.is_over_broad()
    }
}

/// Everything the stored credential can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachableTargets {
    installations: Vec<Installation>,
}

impl ReachableTargets {
    #[must_use]
    pub fn installations(&self) -> &[Installation] {
        &self.installations
    }

    /// Every repository the credential can reach, sorted and de-duplicated.
    #[must_use]
    pub fn repositories(&self) -> Vec<OwnerRepo> {
        let mut all: Vec<OwnerRepo> = self
            .installations
            .iter()
            .flat_map(|i| i.repositories.iter().cloned())
            .collect();
        all.sort();
        all.dedup();
        all
    }

    /// Every organization the App is installed on, sorted and de-duplicated.
    #[must_use]
    pub fn organizations(&self) -> Vec<Org> {
        let mut all: Vec<Org> = self
            .installations
            .iter()
            .filter_map(|i| i.account.organization().cloned())
            .collect();
        all.sort();
        all.dedup();
        all
    }

    /// The installations that hold `repository_selection: all`.
    #[must_use]
    pub fn over_broad(&self) -> Vec<&Installation> {
        self.installations
            .iter()
            .filter(|i| i.is_over_broad())
            .collect()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.repositories().is_empty() && self.organizations().is_empty()
    }
}

/// What `auth status` and `auth login` show after a successful sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationDiscovery {
    /// The credential is valid but reaches nothing: the App is installed
    /// nowhere, or on nothing. `03-control-flows.md` flow 1.1 requires the
    /// installation URL here, and the URL is the remediation.
    NotInstalled { install_url: Url },
    /// The credential reaches at least one repository or organization.
    Installed(ReachableTargets),
}

impl InstallationDiscovery {
    #[must_use]
    pub fn targets(&self) -> Option<&ReachableTargets> {
        match self {
            Self::Installed(t) => Some(t),
            Self::NotInstalled { .. } => None,
        }
    }

    #[must_use]
    pub fn install_url(&self) -> Option<&Url> {
        match self {
            Self::NotInstalled { install_url } => Some(install_url),
            Self::Installed(_) => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct InstallationsPage {
    #[serde(default)]
    installations: Vec<RawInstallation>,
}

#[derive(Debug, Deserialize)]
struct RawInstallation {
    id: u64,
    account: RawAccount,
    #[serde(default)]
    repository_selection: Option<String>,
    #[serde(default)]
    permissions: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct RawAccount {
    login: String,
    #[serde(rename = "type", default)]
    account_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RepositoriesPage {
    #[serde(default)]
    repositories: Vec<RawRepository>,
}

#[derive(Debug, Deserialize)]
struct RawRepository {
    full_name: String,
}

impl AuthenticatedClient {
    /// Which repositories and organizations the stored credential can actually
    /// reach.
    ///
    /// Two calls, both paginated: `GET /user/installations`, then
    /// `GET /user/installations/{id}/repositories` per installation. The shapes
    /// are the ones the D18 spike observed live
    /// (`docs/spikes/d18-org-jit-verification.md`, "The permission that
    /// authorized it").
    ///
    /// An installation is reported even when it is broader than the user
    /// expected — [`Installation::is_over_broad`] — because `07-security.md`
    /// requires that an over-broad installation be *visible* rather than
    /// assumed. Nothing here narrows or hides one.
    ///
    /// # Errors
    /// Every variant of [`GithubError`]. A `401` here goes through the same
    /// single-flight re-validation as any other request.
    pub async fn discover_installations(
        &self,
        app: &AppRegistration,
    ) -> Result<InstallationDiscovery, GithubError> {
        let mut installations = Vec::new();
        for raw in self.all_installations().await? {
            let account = match raw.account.account_type.as_deref() {
                Some("Organization") => InstallationAccount::Organization(
                    Org::new(&raw.account.login).map_err(|_| GithubError::Malformed {
                        what: "an installation account login",
                        value: raw.account.login.clone(),
                    })?,
                ),
                _ => InstallationAccount::User(raw.account.login.clone()),
            };
            let repository_selection = match raw.repository_selection.as_deref() {
                Some("all") => RepositorySelection::All,
                _ => RepositorySelection::Selected,
            };
            installations.push(Installation {
                id: raw.id,
                account,
                repository_selection,
                repositories: self.installation_repositories(raw.id).await?,
                permissions: raw.permissions.into_iter().collect(),
            });
        }

        let targets = ReachableTargets { installations };
        if targets.is_empty() {
            let install_url = app.install_url(&self.endpoints);
            tracing::info!(
                install_url = %install_url,
                "the published App is not installed on anything this credential can reach"
            );
            return Ok(InstallationDiscovery::NotInstalled { install_url });
        }
        tracing::info!(
            repositories = targets.repositories().len(),
            organizations = targets.organizations().len(),
            over_broad = targets.over_broad().len(),
            "discovered the targets this credential can reach"
        );
        Ok(InstallationDiscovery::Installed(targets))
    }

    async fn all_installations(&self) -> Result<Vec<RawInstallation>, GithubError> {
        let mut out = Vec::new();
        let mut next = Some(ApiRequest::get("/user/installations").query("per_page", 100));
        while let Some(request) = next.take() {
            let response = self.send(&request).await?;
            let page: InstallationsPage = response.json()?;
            out.extend(page.installations);
            next = response
                .next_page()
                .map(|url| ApiRequest::get(url.as_str()));
        }
        Ok(out)
    }

    async fn installation_repositories(&self, id: u64) -> Result<Vec<OwnerRepo>, GithubError> {
        let mut out = Vec::new();
        let mut next = Some(
            ApiRequest::get(format!("/user/installations/{id}/repositories"))
                .query("per_page", 100),
        );
        while let Some(request) = next.take() {
            let response = self.send(&request).await?;
            let page: RepositoriesPage = response.json()?;
            for repo in page.repositories {
                out.push(OwnerRepo::parse(&repo.full_name).map_err(|_| {
                    GithubError::Malformed {
                        what: "a repository full_name",
                        value: repo.full_name.clone(),
                    }
                })?);
            }
            next = response
                .next_page()
                .map(|url| ApiRequest::get(url.as_str()));
        }
        Ok(out)
    }
}

/// Test support shared by this file and [`device_flow`].
///
/// It lives inline rather than in `src/testing.rs` on purpose. `a1` laid out
/// this crate's four source files and owns every manifest; `c3` and `c4` are
/// working in the same directory in parallel, and a new file there is a merge
/// conflict waiting to happen for no benefit. An inline `#[cfg(test)]` module is
/// reachable as `crate::testing` from every module in the crate and adds nothing
/// to a release build.
///
/// It does not live in `runner-manager-testkit` either, and that one is
/// mechanical: `testkit` depends on `runner-manager-github`, so a unit test
/// inside this crate that used a `testkit` helper would link a *second* instance
/// of this library and the two instances' types would not unify — the same
/// hazard `testkit`'s own crate documentation records for `domain`.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use serde_json::{Value, json};
    use std::sync::{Mutex, atomic::AtomicUsize};
    use wiremock::{Request, Respond, ResponseTemplate};

    /// Shaped like a real `ghu_` token, and unmistakably not one.
    pub const FIXTURE_TOKEN: &str = "ghu_fixtureTOKENnotARealCredential00";
    /// Shaped like a real device code, and unmistakably not one.
    pub const FIXTURE_DEVICE_CODE: &str = "fixture-device-code-0e37a9c1b4d84f2a";
    /// The example user code from RFC 8628.
    pub const FIXTURE_USER_CODE: &str = "WDJB-MJHT";

    /// A clock the test moves.
    ///
    /// Deliberately not `runner_manager_testkit::clock::FakeClock`; see this
    /// module's documentation for why a `testkit` import is not available here.
    #[derive(Debug)]
    pub struct TestClock {
        now: Mutex<Timestamp>,
    }

    impl TestClock {
        /// # Panics
        /// If a previous holder panicked while the lock was held.
        pub fn advance_secs(&self, secs: i64) {
            let mut now = self.now.lock().expect("TestClock lock poisoned");
            *now += chrono::TimeDelta::seconds(secs);
        }
    }

    impl Default for TestClock {
        fn default() -> Self {
            // 2026-08-21T00:00:00Z, the date this taskflow's decisions were
            // locked — the same epoch `testkit`'s clock starts at.
            Self {
                now: Mutex::new(
                    chrono::DateTime::from_timestamp(1_787_270_400, 0).expect("a valid instant"),
                ),
            }
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Timestamp {
            *self.now.lock().expect("TestClock lock poisoned")
        }
    }

    /// A sleeper that records what it was asked to wait and returns at once.
    ///
    /// This is what turns "`slow_down` demonstrably increases the poll interval"
    /// into an equality assertion on a `Vec<Duration>`.
    #[derive(Debug, Default)]
    pub struct RecordingSleeper {
        recorded: Mutex<Vec<Duration>>,
    }

    impl RecordingSleeper {
        /// # Panics
        /// If a previous holder panicked while the lock was held.
        pub fn recorded(&self) -> Vec<Duration> {
            self.recorded.lock().expect("sleeper lock poisoned").clone()
        }
    }

    #[async_trait::async_trait]
    impl Sleeper for RecordingSleeper {
        async fn sleep(&self, duration: Duration) {
            self.recorded
                .lock()
                .expect("sleeper lock poisoned")
                .push(duration);
        }
    }

    /// Answers from a fixed script, one entry per call, repeating the last.
    pub struct Script {
        responses: Vec<ResponseTemplate>,
        calls: AtomicUsize,
    }

    impl Script {
        #[must_use]
        pub fn new(responses: Vec<ResponseTemplate>) -> Self {
            assert!(
                !responses.is_empty(),
                "a script needs at least one response"
            );
            Self {
                responses,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Respond for Script {
        fn respond(&self, _: &Request) -> ResponseTemplate {
            let i = self.calls.fetch_add(1, Ordering::SeqCst);
            self.responses[i.min(self.responses.len() - 1)].clone()
        }
    }

    /// `POST https://github.com/login/device/code` → `200`, in the shape both
    /// spikes observed (`docs/spikes/d17-spike.ps1`).
    #[must_use]
    pub fn device_code_body(server_uri: &str, interval: u64, expires_in: u64) -> Value {
        json!({
            "device_code": FIXTURE_DEVICE_CODE,
            "user_code": FIXTURE_USER_CODE,
            "verification_uri": format!("{server_uri}/login/device"),
            "expires_in": expires_in,
            "interval": interval
        })
    }

    /// `POST .../login/oauth/access_token` → `200` with an `error` field, which
    /// is how GitHub answers every state in the matrix.
    #[must_use]
    pub fn error_body(code: &str, interval: Option<u64>) -> Value {
        let mut body = json!({
            "error": code,
            "error_description": "see the OAuth 2.0 Device Authorization Grant",
            "error_uri": "https://docs.github.com/developers/apps/authorizing-oauth-apps"
        });
        if let Some(interval) = interval {
            body["interval"] = json!(interval);
        }
        body
    }

    /// `POST .../login/oauth/access_token` → `200` with an approved token.
    #[must_use]
    pub fn token_body() -> Value {
        json!({ "access_token": FIXTURE_TOKEN, "token_type": "bearer", "scope": "" })
    }

    /// `GET /user/installations` → `200`. The permission set is the one D18 read
    /// back from the live installation.
    #[must_use]
    pub fn installations_body(entries: &[(u64, &str, &str, &str)]) -> Value {
        let installations: Vec<Value> = entries
            .iter()
            .map(|(id, login, account_type, selection)| {
                json!({
                    "id": id,
                    "account": { "login": login, "type": account_type },
                    "repository_selection": selection,
                    "permissions": {
                        "actions": "read",
                        "administration": "write",
                        "metadata": "read",
                        "organization_self_hosted_runners": "write"
                    }
                })
            })
            .collect();
        json!({ "total_count": installations.len(), "installations": installations })
    }

    /// `GET /user/installations/{id}/repositories` → `200`.
    #[must_use]
    pub fn repositories_body(full_names: &[&str]) -> Value {
        let repositories: Vec<Value> = full_names
            .iter()
            .map(|full_name| json!({ "full_name": full_name }))
            .collect();
        json!({ "total_count": repositories.len(), "repositories": repositories })
    }

    // -- log capture --------------------------------------------------------

    /// Everything a `tracing` subscriber saw, as one flat string to scan.
    ///
    /// Hand-written because `tracing-subscriber` is not a dependency of this
    /// crate and `a1` owns every manifest — needing one would have been a reason
    /// to stop and report, not to edit a `Cargo.toml`. It records every event's
    /// target, message and fields, and every span's name and fields, which is
    /// the whole surface a secret could reach a log through.
    #[derive(Clone, Default)]
    pub struct CaptureLog(Arc<Mutex<String>>);

    impl CaptureLog {
        /// # Panics
        /// If a previous holder panicked while the lock was held.
        pub fn contents(&self) -> String {
            self.0.lock().expect("log lock poisoned").clone()
        }

        #[must_use]
        pub fn subscriber(&self) -> CaptureSubscriber {
            CaptureSubscriber {
                sink: self.clone(),
                next_span: AtomicU64::new(1),
            }
        }
    }

    pub struct CaptureSubscriber {
        sink: CaptureLog,
        next_span: AtomicU64,
    }

    impl CaptureSubscriber {
        fn write(
            &self,
            prefix: &str,
            metadata: &tracing::Metadata<'_>,
            record: impl Fn(&mut Sink),
        ) {
            let mut buffer = self.sink.0.lock().expect("log lock poisoned");
            buffer.push_str(prefix);
            buffer.push(' ');
            buffer.push_str(metadata.target());
            buffer.push(' ');
            buffer.push_str(metadata.name());
            let mut sink = Sink(&mut buffer);
            record(&mut sink);
            buffer.push('\n');
        }
    }

    impl tracing::Subscriber for CaptureSubscriber {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            self.write("SPAN", span.metadata(), |sink| span.record(sink));
            tracing::span::Id::from_u64(self.next_span.fetch_add(1, Ordering::SeqCst))
        }

        fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
            let mut buffer = self.sink.0.lock().expect("log lock poisoned");
            buffer.push_str("RECORD");
            let mut sink = Sink(&mut buffer);
            values.record(&mut sink);
            buffer.push('\n');
        }

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            self.write("EVENT", event.metadata(), |sink| event.record(sink));
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    struct Sink<'a>(&'a mut String);

    impl tracing::field::Visit for Sink<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
            use fmt::Write;
            let _ = write!(self.0, " {}={value:?}", field.name());
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            use fmt::Write;
            let _ = write!(self.0, " {}={value}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        CaptureLog, FIXTURE_DEVICE_CODE, FIXTURE_TOKEN, FIXTURE_USER_CODE, Script, TestClock,
        installations_body, repositories_body, token_body,
    };
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    fn client(server: &MockServer, clock: Arc<TestClock>) -> AuthenticatedClient {
        AuthenticatedClient::new(
            Endpoints::for_test_server(&server.uri()).unwrap(),
            UserAccessToken::new(SecretString::from(FIXTURE_TOKEN)),
            clock,
        )
        .unwrap()
    }

    fn app() -> AppRegistration {
        AppRegistration::new("Iv23liTESTCLIENTID", "runner-manager").unwrap()
    }

    // -- headers ------------------------------------------------------------

    #[tokio::test]
    async fn every_request_states_its_api_version_and_accept_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .and(header("x-github-api-version", GITHUB_API_VERSION))
            .and(header("accept", GITHUB_ACCEPT))
            .and(header("authorization", format!("Bearer {FIXTURE_TOKEN}")))
            .and(header("user-agent", USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
            .expect(1)
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        client
            .send(&ApiRequest::get("/user/installations"))
            .await
            .expect("the mock only matches when all four headers are present");
    }

    // -- the 401 path -------------------------------------------------------

    #[tokio::test]
    async fn a_401_revalidates_once_and_retries_once_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(401).set_body_json(json!({"message": "Bad credentials"})),
                ResponseTemplate::new(200).set_body_json(json!({"total_count": 0})),
            ]))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
            .expect(1)
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let response = client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect("the retry succeeds");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            client.revalidations_performed(),
            1,
            "one 401 must produce exactly one re-validation"
        );
    }

    #[tokio::test]
    async fn a_second_401_after_the_retry_is_terminal_authentication_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(ResponseTemplate::new(401))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let err = client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect_err("two 401s is terminal");

        assert!(matches!(err, GithubError::AuthenticationFailed), "{err:?}");
        assert!(err.is_authentication());
        assert!(!err.is_lockout());
    }

    #[tokio::test]
    async fn a_rejected_revalidation_fails_without_spending_the_retry() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(ResponseTemplate::new(401))
            // Exactly one: a credential GitHub has confirmed dead must not be
            // used for a retry.
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let err = client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect_err("the credential is dead");
        assert!(matches!(err, GithubError::AuthenticationFailed), "{err:?}");
    }

    /// The Definition of Done's concurrency claim, tested with real concurrent
    /// callers on a multi-threaded runtime rather than by reasoning about the
    /// mutex.
    ///
    /// Two things make the assertion deterministic rather than lucky. A barrier
    /// releases all eight callers into `send` together, so all eight take their
    /// `401` before any of them reaches the gate; and the re-validation endpoint
    /// is delayed, so the first caller still holds the gate while the other
    /// seven sample the generation counter. Without the delay a caller could
    /// legitimately arrive after the first re-validation completed, which is a
    /// *new* `401` storm and correctly earns its own attempt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn eight_concurrent_401s_produce_one_revalidation_not_eight() {
        const CALLERS: usize = 8;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(installations_body(&[]))
                    .set_delay(Duration::from_millis(250)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = Arc::new(client(&server, Arc::new(TestClock::default())));
        let barrier = Arc::new(tokio::sync::Barrier::new(CALLERS));
        let mut tasks = Vec::new();
        for _ in 0..CALLERS {
            let client = Arc::clone(&client);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                client
                    .send(&ApiRequest::get("/orgs/acme/actions/runners"))
                    .await
                    .expect_err("every caller sees a dead endpoint")
            }));
        }

        let mut outcomes = Vec::new();
        for task in tasks {
            outcomes.push(task.await.expect("no caller panicked"));
        }

        assert_eq!(outcomes.len(), CALLERS);
        for err in &outcomes {
            assert!(matches!(err, GithubError::AuthenticationFailed), "{err:?}");
        }
        assert_eq!(
            client.revalidations_performed(),
            1,
            "{CALLERS} concurrent 401s must produce ONE attempt, not {CALLERS}"
        );

        // The same claim, measured from the server rather than from our own
        // counter: the mock's `.expect(1)` is verified when the server drops.
        let seen = server.received_requests().await.expect("recording is on");
        let probes = seen
            .iter()
            .filter(|r| r.url.path() == "/user/installations")
            .count();
        assert_eq!(probes, 1, "GitHub itself saw exactly one re-validation");
        let attempts = seen
            .iter()
            .filter(|r| r.url.path() == "/orgs/acme/actions/runners")
            .count();
        assert_eq!(
            attempts,
            CALLERS * 2,
            "each caller still gets its own single retry"
        );
    }

    // -- the 403 path -------------------------------------------------------

    #[tokio::test]
    async fn a_403_after_401s_is_a_lockout_and_not_an_authentication_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(401),
                ResponseTemplate::new(403).insert_header("retry-after", "42"),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let err = client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect_err("403 after a 401");

        match err {
            GithubError::AuthenticationLockout { retry_after } => {
                assert_eq!(retry_after, Duration::from_secs(42), "honours retry-after");
            }
            other => panic!("expected a lockout, got {other:?}"),
        }
        assert!(client.is_locked_out());
    }

    #[tokio::test]
    async fn a_403_with_no_preceding_401_is_a_permissions_answer_not_a_lockout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({"message": "Resource not accessible by integration"})),
            )
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let err = client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect_err("403");

        assert!(matches!(err, GithubError::Forbidden { .. }), "{err:?}");
        assert!(!err.is_lockout());
        assert!(!err.is_authentication());
        assert!(!client.is_locked_out(), "a permissions 403 must not latch");
    }

    #[tokio::test]
    async fn a_locked_out_client_issues_no_further_http_until_the_backoff_elapses() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(401),
                ResponseTemplate::new(403).insert_header("retry-after", "60"),
                ResponseTemplate::new(200).set_body_json(json!({"total_count": 0})),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
            .mount(&server)
            .await;

        let clock = Arc::new(TestClock::default());
        let client = client(&server, Arc::clone(&clock));
        let request = ApiRequest::get("/orgs/acme/actions/runners");

        let err = client.send(&request).await.expect_err("locks out");
        assert!(err.is_lockout(), "{err:?}");

        let after_lockout = server.received_requests().await.unwrap().len();

        for _ in 0..3 {
            let err = client.send(&request).await.expect_err("still locked out");
            assert!(err.is_lockout(), "{err:?}");
        }
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            after_lockout,
            "a backed-off client must open no sockets at all"
        );

        clock.advance_secs(61);
        assert!(!client.is_locked_out(), "the back-off expires on the clock");
        let response = client.send(&request).await.expect("traffic resumes");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            after_lockout + 1
        );
    }

    // -- installation discovery ---------------------------------------------

    #[tokio::test]
    async fn discovery_returns_the_reachable_repository_and_organization_set() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(installations_body(&[
                    (11, "IvanMurzak", "User", "selected"),
                    (22, "Tap-Top-Fun", "Organization", "all"),
                ])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations/11/repositories"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(repositories_body(&["IvanMurzak/GitHub-Runner-Scaler-UI"])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations/22/repositories"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(repositories_body(&["Tap-Top-Fun/game", "Tap-Top-Fun/site"])),
            )
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let discovery = client.discover_installations(&app()).await.unwrap();

        let targets = discovery.targets().expect("installed");
        assert_eq!(
            targets
                .repositories()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "IvanMurzak/GitHub-Runner-Scaler-UI",
                "Tap-Top-Fun/game",
                "Tap-Top-Fun/site"
            ]
        );
        assert_eq!(
            targets
                .organizations()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["Tap-Top-Fun"],
            "a User account is not an organization target"
        );
        assert!(discovery.install_url().is_none());
    }

    #[tokio::test]
    async fn an_over_broad_installation_is_visible_rather_than_assumed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(installations_body(&[
                    (11, "IvanMurzak", "User", "selected"),
                    (22, "Tap-Top-Fun", "Organization", "all"),
                ])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations/11/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repositories_body(&["a/b"])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations/22/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repositories_body(&["c/d"])))
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let targets = client
            .discover_installations(&app())
            .await
            .unwrap()
            .targets()
            .cloned()
            .expect("installed");

        let over_broad = targets.over_broad();
        assert_eq!(over_broad.len(), 1);
        assert_eq!(over_broad[0].account.login(), "Tap-Top-Fun");
        assert!(over_broad[0].is_over_broad());
        assert_eq!(
            over_broad[0].repository_selection,
            RepositorySelection::All,
            "`repository_selection: all` reaches repositories created later too"
        );
        assert!(
            targets.installations().iter().any(|i| i
                .permissions
                .iter()
                .any(|(k, v)| k == "administration" && v == "write")),
            "the grant GitHub reports is surfaced verbatim, not assumed from the design"
        );
    }

    #[tokio::test]
    async fn discovery_returns_the_installation_url_when_the_set_is_empty() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let discovery = client.discover_installations(&app()).await.unwrap();

        let url = discovery
            .install_url()
            .expect("an empty set must yield the installation URL");
        assert_eq!(url.path(), "/apps/runner-manager/installations/new");
        assert!(discovery.targets().is_none());
    }

    #[tokio::test]
    async fn an_installation_that_reaches_no_repository_is_still_not_installed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(installations_body(&[(
                    11,
                    "IvanMurzak",
                    "User",
                    "selected",
                )])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations/11/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repositories_body(&[])))
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let discovery = client.discover_installations(&app()).await.unwrap();
        assert!(
            discovery.install_url().is_some(),
            "a user installation that selected no repository reaches nothing"
        );
    }

    #[tokio::test]
    async fn discovery_follows_every_page_rather_than_trusting_the_first() {
        let server = MockServer::start().await;
        let next = format!("<{}/user/installations?page=2>; rel=\"next\"", server.uri());
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(200)
                    .set_body_json(installations_body(&[(
                        11,
                        "one",
                        "Organization",
                        "selected",
                    )]))
                    .insert_header("link", next.as_str()),
                ResponseTemplate::new(200).set_body_json(installations_body(&[(
                    22,
                    "two",
                    "Organization",
                    "selected",
                )])),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations/11/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repositories_body(&["one/a"])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations/22/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repositories_body(&["two/b"])))
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let targets = client
            .discover_installations(&app())
            .await
            .unwrap()
            .targets()
            .cloned()
            .expect("installed");
        assert_eq!(
            targets
                .organizations()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["one", "two"],
            "the second page must not be dropped"
        );
    }

    #[test]
    fn a_link_header_yields_only_the_next_relation() {
        let header = "<https://api.github.com/user/installations?page=3>; rel=\"next\", \
                      <https://api.github.com/user/installations?page=9>; rel=\"last\"";
        assert_eq!(
            parse_link_next(header).map(|u| u.to_string()),
            Some("https://api.github.com/user/installations?page=3".to_string())
        );
        assert!(parse_link_next("<https://x/>; rel=\"last\"").is_none());
        assert!(parse_link_next("nonsense").is_none());
    }

    // -- redaction ----------------------------------------------------------

    #[test]
    fn no_type_in_this_crate_renders_a_secret_through_debug() {
        let token = UserAccessToken::new(SecretString::from(FIXTURE_TOKEN));
        let rendered = format!("{token:?}");
        assert!(!rendered.contains(FIXTURE_TOKEN), "{rendered}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(
            rendered.contains("ghu_"),
            "the family prefix is diagnostic and is not the secret"
        );

        let request = ApiRequest::post_json("/x", &json!({"encoded_jit_config": "SECRETBLOB"}))
            .expect("serializes");
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("SECRETBLOB"), "{rendered}");

        let response = ApiResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: b"{\"encoded_jit_config\":\"SECRETBLOB\"}".to_vec(),
        };
        let rendered = format!("{response:?}");
        assert!(!rendered.contains("SECRETBLOB"), "{rendered}");
    }

    /// The Definition of Done's log scan, over a whole login and an
    /// authenticated round trip that takes a `401`, re-validates, and retries.
    ///
    /// A hand-written `tracing` subscriber rather than `tracing-subscriber`,
    /// which is not a dependency of this crate — and `a1` owns every manifest,
    /// so needing one would have been a reason to stop rather than to edit.
    ///
    /// The flow deliberately logs `?auth`, `?token` and `?client` before
    /// scanning. That is what makes this test bite: it forces every `Debug` impl
    /// that holds a secret through the subscriber, so a `#[derive(Debug)]` added
    /// to any of them later fails here rather than in production.
    #[test]
    fn no_secret_reaches_the_logs() {
        use crate::device_flow::DeviceFlow;

        let sink = CaptureLog::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime, so the thread-local subscriber applies throughout");

        tracing::subscriber::with_default(sink.subscriber(), || {
            runtime.block_on(async {
                let server = MockServer::start().await;
                Mock::given(method("POST"))
                    .and(path("/login/device/code"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "device_code": FIXTURE_DEVICE_CODE,
                        "user_code": FIXTURE_USER_CODE,
                        "verification_uri": format!("{}/login/device", server.uri()),
                        "expires_in": 900,
                        "interval": 5
                    })))
                    .mount(&server)
                    .await;
                Mock::given(method("POST"))
                    .and(path("/login/oauth/access_token"))
                    .respond_with(Script::new(vec![
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"error": "authorization_pending"})),
                        ResponseTemplate::new(200).set_body_json(token_body()),
                    ]))
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path("/orgs/acme/actions/runners"))
                    .respond_with(Script::new(vec![
                        ResponseTemplate::new(401)
                            .set_body_json(json!({"message": "Bad credentials"})),
                        ResponseTemplate::new(200).set_body_json(json!({"total_count": 0})),
                    ]))
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path("/user/installations"))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(installations_body(&[(
                            11,
                            "IvanMurzak",
                            "User",
                            "selected",
                        )])),
                    )
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path("/user/installations/11/repositories"))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(repositories_body(&["a/b"])),
                    )
                    .mount(&server)
                    .await;

                let endpoints = Endpoints::for_test_server(&server.uri()).unwrap();
                let flow = DeviceFlow::new(app(), endpoints.clone()).unwrap();
                let auth = flow.start().await.expect("device authorization");
                tracing::info!(?auth, "device authorization, rendered through Debug");

                let sleeper = crate::testing::RecordingSleeper::default();
                let token = flow.complete(&auth, &sleeper).await.expect("approved");
                tracing::info!(?token, "user access token, rendered through Debug");

                let client = AuthenticatedClient::new(
                    endpoints,
                    token.clone(),
                    Arc::new(TestClock::default()),
                )
                .unwrap();
                tracing::info!(?client, "authenticated client, rendered through Debug");

                client
                    .send(&ApiRequest::get("/orgs/acme/actions/runners"))
                    .await
                    .expect("401 then retry");
                client
                    .discover_installations(&app())
                    .await
                    .expect("discovery");
            });
        });

        let logs = sink.contents();
        assert!(!logs.is_empty(), "the subscriber captured nothing to scan");
        assert!(
            !logs.contains(FIXTURE_TOKEN),
            "the user access token reached the logs:\n{logs}"
        );
        assert!(
            !logs.contains(FIXTURE_DEVICE_CODE),
            "the device code reached the logs:\n{logs}"
        );
        assert!(
            !logs.to_ascii_lowercase().contains("bearer "),
            "an Authorization header value reached the logs:\n{logs}"
        );
        assert!(
            logs.contains(FIXTURE_USER_CODE),
            "the user code is displayed by design and only during login, so the flow \
             must still surface it: {logs}"
        );
    }

    /// The Definition of Done's second item, made checkable rather than
    /// reviewed: "no refresh-token code path exists, and no client secret
    /// appears anywhere in the crate **or its configuration**".
    ///
    /// The two files `c2` owns are scanned, and so is the crate's manifest —
    /// that is what "or its configuration" means for a crate with no config file
    /// of its own. `rest.rs`, `demand.rs` and `jit.rs` are deliberately **not**
    /// scanned: they belong to `c3` and `c4`, and a test here that failed on
    /// their work would be this task reaching across an ownership boundary.
    ///
    /// Prose in this crate deliberately writes "renewal token" and "client
    /// secret" with a space so that this scan stays meaningful.
    #[test]
    fn no_renewal_path_and_no_confidential_credential_in_this_crate() {
        for (name, source) in [
            ("lib.rs", include_str!("lib.rs")),
            ("device_flow.rs", include_str!("device_flow.rs")),
            ("Cargo.toml", include_str!("../Cargo.toml")),
        ] {
            // Spelled in halves so that this test's own source does not trip it.
            for forbidden in [
                concat!("refresh", "_token"),
                concat!("client", "_secret"),
                concat!("REFRESH", "_TOKEN"),
                concat!("CLIENT", "_SECRET"),
                concat!("grant_type=refresh", "_token"),
            ] {
                assert!(
                    !source.contains(forbidden),
                    "{name} contains {forbidden:?}: a public client cannot hold a client \
                     secret, and the published App issues nothing to renew (D3)"
                );
            }
        }
    }

    /// The storage boundary, made checkable the same way. `c2` returns the token
    /// and never persists it; the machine-scoped store is `d2` and the wiring is
    /// `f1`. A dependency on `runner-manager-platform`, or a filesystem write,
    /// would silently move that boundary.
    #[test]
    fn this_crate_persists_nothing_and_does_not_depend_on_the_platform_crate() {
        let manifest = include_str!("../Cargo.toml");
        assert!(
            !manifest.contains("runner-manager-platform"),
            "the gateway must be testable with no platform dependency at all"
        );

        for (name, source) in [
            ("lib.rs", include_str!("lib.rs")),
            ("device_flow.rs", include_str!("device_flow.rs")),
        ] {
            // Everything below `#[cfg(test)]` is test code; the boundary is about
            // non-test code, and the tests above legitimately read this file.
            let non_test = source
                .split("#[cfg(test)]")
                .next()
                .expect("split always yields a first element");
            for forbidden in ["std::fs", "fs::write", "File::create", "tokio::fs"] {
                assert!(
                    !non_test.contains(forbidden),
                    "{name} performs a filesystem operation ({forbidden:?}) outside its tests"
                );
            }
        }
    }
}
