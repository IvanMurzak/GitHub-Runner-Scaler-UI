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
//! precisely how this control is lost. `tests/no_secret_reaches_the_logs.rs`
//! drives a whole login and an authenticated round trip through a capturing
//! `tracing` subscriber and fails if any of the three appears.
//!
//! That scan is a **separate test binary**, and deliberately so. As a unit test
//! it silently stopped working: `tracing` caches each callsite's `Interest`
//! once per *process*, while `with_default` installs a subscriber on one
//! *thread*, so the other unit tests running concurrently registered the
//! library's callsites as disabled before the scan ever installed its
//! subscriber. It captured only its own three events, and passed with a real
//! device-code leak on the live path. A binary holding one test cannot be
//! poisoned that way; the file's own documentation records the measurement.

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

use reqwest::{Method, StatusCode};
use runner_manager_domain::model::{Clock, Org, OwnerRepo, Timestamp};

/// Re-exported because [`GithubError::headers`] and [`ApiResponse::headers`]
/// return one, and a consumer cannot *name* a type it has no path to.
///
/// `a1` owns every manifest in this workspace, so a crate outside this one that
/// wanted to hold a `HeaderMap` from this seam would otherwise need `reqwest`
/// added to its own dependencies — turning a `c2` seam into an `a1` change, and
/// putting `reqwest`'s version in two places at once. [`GithubError::retry_after`]
/// and [`GithubError::rate_limit`] exist precisely so that the common cases need
/// no path at all; this is for the ones that do.
///
/// It is re-exported under its own name rather than an alias so that the type a
/// consumer imports is the type the signatures already show.
pub use reqwest::header::HeaderMap;
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

/// The longest a lockout may silence this client, whatever `Retry-After` said.
///
/// A back-off is a *safety* mechanism, and an unclamped one is a denial of
/// service with extra steps: `Retry-After: 86400` would latch a silent
/// twenty-four-hour outage of the agent's reconciliation loop, clearable only by
/// [`AuthenticatedClient::clear_lockout`]. Fifteen minutes is far longer than any
/// back-off GitHub documents for the authentication lockout this latches on, and
/// short enough that a hostile or simply wrong header cannot take the product
/// down for a shift. Honouring a header without a ceiling is trusting a remote
/// party with the product's availability.
pub const MAX_LOCKOUT_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// The most pages either pagination loop follows before giving up.
///
/// A `Link: rel="next"` that points back at the page it arrived on — a proxy
/// rewriting the header, or a bug at the other end — is an infinite loop inside
/// the agent's reconciliation loop, which is the one place in this product that
/// must not be able to wedge. At `per_page=100` this ceiling is ten thousand
/// installations or repositories, past any real account by orders of magnitude,
/// so it bounds the pathological case without truncating a legitimate one.
pub const MAX_PAGES: usize = 100;

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
///
/// # Why the failing variants carry response headers
///
/// Rate-limit *policy* is `c3`'s and is deliberately not implemented here. But a
/// policy needs evidence, and the evidence — `retry-after`,
/// `x-ratelimit-remaining`, `x-ratelimit-reset` — only exists on the response
/// that failed. An error taxonomy that dropped those headers would leave `c3`
/// with no way to honour a `429` except by editing this file, which is exactly
/// the conflict the `c2`/`c3` ownership split exists to prevent. So
/// [`GithubError::Status`] and [`GithubError::Forbidden`] carry the headers
/// verbatim and interpret none of them; see [`GithubError::headers`].
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

    /// A `403` that is not the lockout: a permissions answer, or GitHub's own
    /// rate limit. `c3` tells the two apart from `headers`; this crate does not,
    /// because which of them is worth retrying is rate-limit policy.
    #[error(
        "GitHub denied {method} {path}: the App installation does not grant it{}",
        message.as_deref().map(|m| format!(" ({m})")).unwrap_or_default()
    )]
    Forbidden {
        method: String,
        path: String,
        message: Option<String>,
        /// The response headers, verbatim and uninterpreted.
        headers: Box<HeaderMap>,
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
        /// The response headers, verbatim and uninterpreted. A `429` reaches
        /// `c3` through this variant, and its `retry-after` survives with it.
        headers: Box<HeaderMap>,
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

    /// The failing response's headers, for the variants that have them.
    ///
    /// This is the whole of `c2`'s contribution to rate limiting: it hands `c3`
    /// the evidence and stops there. Nothing in this crate reads
    /// `x-ratelimit-remaining` to decide anything.
    #[must_use]
    pub fn headers(&self) -> Option<&HeaderMap> {
        match self {
            Self::Status { headers, .. } | Self::Forbidden { headers, .. } => Some(headers),
            _ => None,
        }
    }

    /// The failing response's `retry-after`, in seconds, if it sent one.
    ///
    /// Reading a documented header is evidence, not policy: what to *do* with a
    /// `retry-after` — wait, shed load, surface it to an operator — is `c3`'s.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.headers().and_then(retry_after)
    }

    /// The `x-ratelimit-remaining` / `x-ratelimit-reset` pair, when present.
    ///
    /// Returned as the raw numbers GitHub sent. `reset` is a Unix timestamp in
    /// seconds, which is what the header carries; it is deliberately not turned
    /// into a [`Timestamp`] here, because comparing it against a clock is the
    /// first step of a policy decision and that decision is `c3`'s.
    #[must_use]
    pub fn rate_limit(&self) -> Option<RateLimitEvidence> {
        let headers = self.headers()?;
        let read = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        let remaining = read("x-ratelimit-remaining");
        let reset = read("x-ratelimit-reset");
        if remaining.is_none() && reset.is_none() {
            return None;
        }
        Some(RateLimitEvidence {
            remaining,
            reset_unix_secs: reset,
            retry_after: self.retry_after(),
        })
    }
}

/// What GitHub said about its own rate limit on a response that failed.
///
/// Evidence, carried across the `c2`/`c3` seam. Every field is what the wire
/// said, and none of them has been interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitEvidence {
    /// `x-ratelimit-remaining`. Zero is GitHub's primary rate limit.
    pub remaining: Option<u64>,
    /// `x-ratelimit-reset`, a Unix timestamp in seconds.
    pub reset_unix_secs: Option<u64>,
    /// `retry-after`, which secondary rate limits send instead.
    pub retry_after: Option<Duration>,
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

/// The `rel="next"` target of an RFC 8288 `Link` header, or `None`.
///
/// # Why this scans rather than splits
///
/// A comma separates one link-value from the next, but a comma is also a legal
/// character *inside* a URL, and GitHub sends such URLs routinely — a runner
/// query carries `labels=self-hosted,windows`. Splitting the whole header on `,`
/// first tears that URL in half, neither half parses as `<...>`, and the
/// relation is silently lost. The caller then treats page 1 as the whole
/// inventory, which is the specific outcome `04-subsystem-contracts.md` forbids:
/// "the dashboard must not treat a first page as a complete inventory".
///
/// So the target is located by its `<`…`>` delimiters, and only a comma that
/// actually begins the next link-value — one followed by optional whitespace and
/// `<` — ends the parameter section.
fn parse_link_next(link: &str) -> Option<Url> {
    let mut rest = link;
    while let Some(open) = rest.find('<') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('>') else {
            // An unterminated `<` cannot be a link-value; nothing after it is
            // interpretable either.
            return None;
        };
        let target = after_open[..close].trim();
        let tail = &after_open[close + 1..];

        // The parameters run to the start of the next link-value.
        let cut = tail
            .match_indices(',')
            .find(|(i, _)| tail[i + 1..].trim_start().starts_with('<'))
            .map_or(tail.len(), |(i, _)| i);
        let (params, next) = tail.split_at(cut);

        let is_next = params.split(';').any(|param| {
            let param = param.trim().replace(['"', '\''], "");
            param.eq_ignore_ascii_case("rel=next")
        });
        if is_next {
            return Url::parse(target).ok();
        }
        rest = next.strip_prefix(',').unwrap_or(next);
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
        // `try_lock`, not `is_locked_out()`. `std::sync::Mutex` is not
        // reentrant, and `latch_lockout` holds this one; the moment anybody adds
        // a `tracing` call inside that function — which is a natural thing to
        // want there — rendering the client would deadlock the whole agent. A
        // `Debug` impl must never be able to block, so it reports what it can
        // see and says so when it cannot.
        let locked_out = match self.lockout.try_lock() {
            Ok(state) => {
                if state.until.is_some_and(|until| self.clock.now() < until) {
                    "yes"
                } else {
                    "no"
                }
            }
            Err(_) => "unknown (the lockout state is being updated)",
        };
        f.debug_struct("AuthenticatedClient")
            .field("api_base", &self.endpoints.api_base.as_str())
            .field("credential", &self.credential)
            .field(
                "revalidations_performed",
                &self.revalidations_performed.load(Ordering::Relaxed),
            )
            .field("locked_out", &locked_out)
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
        match self.classify(request, &first, Attempt::First) {
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
    /// # Position, and why this entry point may not latch a lockout
    ///
    /// A `403` is the authentication lockout only when it lands on the *retry*
    /// this client itself issued after a request's own `401`
    /// ([`AuthenticatedClient::is_lockout_403`]). This method is the caller's
    /// own probe: it is a **first** attempt by construction, whatever happened
    /// on some other request minutes ago. So it passes [`Attempt::First`] down,
    /// and the probe it drives cannot latch.
    ///
    /// `revalidate_and_retry_once` uses the private
    /// [`AuthenticatedClient::revalidate_after_unauthorized`] instead, which is
    /// in the retry position and may.
    ///
    /// # Errors
    /// [`GithubError::AuthenticationLockout`] if the probe itself is locked out.
    ///
    /// # Panics
    /// If a previous holder panicked while the re-validation result lock was
    /// held.
    pub async fn revalidate(&self) -> Result<Revalidation, GithubError> {
        self.revalidate_from(Attempt::First).await
    }

    /// The re-validation that `send` runs between a `401` and its one retry.
    ///
    /// Identical to [`AuthenticatedClient::revalidate`] except for position:
    /// this one *is* the retry path, so a `403` on its probe is the lockout and
    /// is latched.
    async fn revalidate_after_unauthorized(&self) -> Result<Revalidation, GithubError> {
        self.revalidate_from(Attempt::Retry).await
    }

    async fn revalidate_from(&self, attempt: Attempt) -> Result<Revalidation, GithubError> {
        // "A lockout stops traffic. This client issues no further HTTP at all
        // until the back-off elapses" is a property of the client, not of
        // `send`, and the probe is HTTP like any other. `send` has already
        // returned by the time it calls in here, so this guard only bites a
        // caller that probes on its own — and one that did would otherwise be
        // the single exception to the rule, which is how a rule stops holding.
        if let Some(retry_after) = self.lockout_remaining() {
            return Err(GithubError::AuthenticationLockout { retry_after });
        }

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
        let outcome = self.probe_credential(attempt).await;
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

    /// One `GET /user/installations` with the credential already held, asking
    /// GitHub whether it still accepts it.
    ///
    /// `attempt` is the *caller's* position, not the probe's own. A probe driven
    /// by `send`'s `401` handling is part of that request's retry; a probe a
    /// caller asked for through [`AuthenticatedClient::revalidate`] is a first
    /// attempt. Only the former may latch a lockout — see
    /// [`AuthenticatedClient::is_lockout_403`], which both this and `classify`
    /// now go through, so the rule is stated once instead of twice.
    async fn probe_credential(&self, attempt: Attempt) -> Revalidation {
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
                // A `403` on a probe that *is* this request's retry is the
                // lockout. Latch it; the caller's own classification will report
                // it. A `403` on a probe a caller asked for directly is not —
                // the comment that used to sit here claimed "the probe only ever
                // runs after a `401`, so it is always in the retry position",
                // and publishing `revalidate` is what made that untrue. The
                // position now arrives as an argument instead of being asserted.
                if self.is_lockout_403(&response, attempt) {
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
        match self.revalidate_after_unauthorized().await? {
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
                match self.classify(request, &second, Attempt::Retry) {
                    Classified::Ok => Ok(second),
                    // The one retry is spent. A second `401` is terminal.
                    Classified::Unauthorized => Err(GithubError::AuthenticationFailed),
                    Classified::Error(err) => Err(err),
                }
            }
        }
    }

    fn classify(
        &self,
        request: &ApiRequest,
        response: &ApiResponse,
        attempt: Attempt,
    ) -> Classified {
        let status = response.status;
        if status.is_success() {
            self.consecutive_unauthorized.store(0, Ordering::SeqCst);
            return Classified::Ok;
        }
        if status == StatusCode::UNAUTHORIZED {
            self.consecutive_unauthorized.fetch_add(1, Ordering::SeqCst);
            return Classified::Unauthorized;
        }
        if status == StatusCode::FORBIDDEN && self.is_lockout_403(response, attempt) {
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
        let headers = Box::new(response.headers.clone());
        let message = error_message(&response.body);
        if status == StatusCode::FORBIDDEN {
            return Classified::Error(GithubError::Forbidden {
                method: request.method.as_str().to_string(),
                path: request.path.clone(),
                message,
                headers,
            });
        }
        Classified::Error(GithubError::Status {
            status: status.as_u16(),
            method: request.method.as_str().to_string(),
            path: request.path.clone(),
            message,
            headers,
        })
    }

    /// Whether a `403` is GitHub's temporary *authentication* lockout, as
    /// opposed to a permissions answer or a rate limit.
    ///
    /// # It must not be a rate limit
    ///
    /// `classify` used to reach the `403` branch before anything looked at the
    /// rate-limit headers, so a primary rate limit arriving during a `401` storm
    /// was reported as `AuthenticationLockout` — telling the operator "the
    /// credential itself is not the problem" about a response that never
    /// mentioned the credential. Recognising GitHub's own rate-limit evidence is
    /// not rate-limit *policy*; it is declining to make an assertion the
    /// evidence contradicts. What to do about the rate limit stays `c3`'s, which
    /// is why this only changes which variant carries the headers onward.
    ///
    /// # Then one of two positions, and the second one is a fix for the first
    ///
    /// **The retry.** `consecutive_unauthorized` counts `401`s since the last
    /// successful caller response and — correctly — does not decay: a request
    /// that ends in `404`, `422` or `500` leaves it set. In the agent's
    /// long-lived reconciliation loop that meant a single `401` from minutes ago
    /// converted the *next* genuine permissions `403` into a fake lockout: sixty
    /// seconds of silence plus an operator message insisting the credential is
    /// fine, when in truth `generate-jitconfig` was missing
    /// `Administration: write`. The lockout's signature is narrower than "a
    /// `403` while the count is set" — it is a `403` on the one retry this
    /// client itself issued after this request's own `401`.
    ///
    /// The count is deliberately *not* consulted. [`Attempt::Retry`] already
    /// means this request's own `401` incremented it moments ago, so reading it
    /// adds no signal — and does add a race that fails open: any concurrent
    /// request succeeding between the `401` and the retry `store(0)`s the
    /// counter, and a real lockout is then reported as a plain permissions
    /// refusal. A conjunct that can only ever weaken a safety check is worse
    /// than no conjunct.
    ///
    /// **The continuation.** Narrowing to the retry position opened a hole at
    /// the far end of the same back-off. When the back-off elapses and GitHub is
    /// still locking the credential out, the next request is a *first* attempt
    /// by construction — this client's retry never happened, because the request
    /// never reached the wire. The position rule then declined to call it a
    /// lockout, `classify` fell through to [`GithubError::Forbidden`] — whose
    /// documented reading is "the App installation does not grant it" — and the
    /// client **stopped backing off entirely**, hammering a credential GitHub
    /// had asked it to leave alone. That is the exact inverse of the
    /// Definition of Done's "backs off without retrying", and it failed for
    /// every lockout outliving one back-off.
    ///
    /// No counter is needed for that case either, because the response says so
    /// itself. GitHub's lockout carries `retry-after` and an empty body; a
    /// permissions refusal carries a message naming what is not accessible and
    /// no `retry-after`. Requiring **both** halves of that signature is what
    /// keeps this from degenerating into "every `403` is a lockout": a
    /// permissions answer has a message, so it never matches, and a secondary
    /// rate limit has both a message and `retry-after`, so `is_rate_limited`
    /// takes it first.
    ///
    /// This also settles a standing worry about [`MAX_LOCKOUT_BACKOFF`]. With
    /// the continuation recognised, the ceiling no longer decides whether the
    /// product ever gives up — it only decides how often it re-asks. A lockout
    /// longer than the ceiling now re-latches instead of being reported as a
    /// permissions failure, so the value is a polling interval rather than a
    /// deadline.
    fn is_lockout_403(&self, response: &ApiResponse, attempt: Attempt) -> bool {
        if is_rate_limited(response) {
            return false;
        }
        match attempt {
            Attempt::Retry => true,
            Attempt::First => is_lockout_continuation(response),
        }
    }

    fn latch_lockout(&self, headers: &HeaderMap) -> Duration {
        // Clamp before latching. An unclamped `Retry-After` is a remote party
        // deciding how long this product stays down.
        let requested = retry_after(headers).unwrap_or(DEFAULT_LOCKOUT_BACKOFF);
        let clamped = requested.min(MAX_LOCKOUT_BACKOFF);

        // A span too large for `chrono` must fall back to the default, never to
        // `None`: the old code's `.ok()` turned an absurd `Retry-After` into "no
        // lockout at all", which fails *open* — the exact inverse of what a
        // back-off is for, and reachable by a header alone. The clamp above
        // already makes this branch unreachable; it stays because the invariant
        // it protects ("latching always latches") is worth more than the line.
        let delta = chrono::TimeDelta::from_std(clamped).unwrap_or_else(|_| {
            chrono::TimeDelta::from_std(DEFAULT_LOCKOUT_BACKOFF)
                .expect("sixty seconds is a representable span")
        });
        // No third clamp. `clamped` is already `<= MAX_LOCKOUT_BACKOFF`, and
        // `TimeDelta` round-trips it exactly, so re-clamping here was dead twice
        // over — it could only ever re-apply a bound already applied, and the
        // fallback it guarded is `DEFAULT_LOCKOUT_BACKOFF`, which is smaller
        // than the ceiling by construction.
        let backoff = delta.to_std().unwrap_or(DEFAULT_LOCKOUT_BACKOFF);

        let mut state = self.lockout.lock().expect("lockout lock poisoned");
        state.backoff = backoff;
        state.until = Some(self.clock.now() + delta);
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

/// Which of a request's at-most-two attempts produced a response.
///
/// The authentication lockout is defined by *position*, not just by status: it
/// is what GitHub answers the retry that follows a `401`. Passing this in makes
/// that explicit at both call sites instead of inferring it from a counter that
/// outlives the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempt {
    First,
    Retry,
}

/// Whether GitHub attributed a failing response to its own rate limit.
///
/// Reading the evidence, and nothing else — see [`GithubError`]'s note on why
/// the headers travel with the error. `c3` decides what to do about it.
fn is_rate_limited(response: &ApiResponse) -> bool {
    if response.status == StatusCode::TOO_MANY_REQUESTS {
        return true;
    }
    // The primary rate limit's documented signature.
    if response
        .header("x-ratelimit-remaining")
        .is_some_and(|v| v.trim() == "0")
    {
        return true;
    }
    // A secondary rate limit sends `retry-after` — but so does the
    // authentication lockout, so that header alone cannot tell them apart.
    // GitHub's own message ("You have exceeded a secondary rate limit") can.
    error_message(&response.body).is_some_and(|m| m.to_ascii_lowercase().contains("rate limit"))
}

/// Whether a `403` on a *first* attempt is GitHub continuing an authentication
/// lockout that outlived this client's back-off.
///
/// The two halves are both required, and both are GitHub's own evidence rather
/// than this client's memory:
///
/// * **`retry-after` is present.** GitHub sends it when it wants to be left
///   alone. A permissions refusal never does — there is nothing to wait for.
/// * **The body carries no message.** A permissions refusal always names what
///   is not accessible ("Resource not accessible by integration"); the lockout's
///   body is empty. This is the half that stops the rule from swallowing
///   [`GithubError::Forbidden`] entirely.
///
/// Callers reach this through [`AuthenticatedClient::is_lockout_403`], which
/// rules out a rate limit first — a secondary rate limit carries `retry-after`
/// *and* a message, so it fails this test on the second half anyway, but the
/// ordering makes the precedence explicit rather than incidental.
fn is_lockout_continuation(response: &ApiResponse) -> bool {
    retry_after(&response.headers).is_some() && error_message(&response.body).is_none()
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
    /// An enterprise account.
    ///
    /// It is its own variant rather than a [`InstallationAccount::User`]
    /// because it is not one, and `auth status` says out loud whose account
    /// each installation sits on. Everything GitHub reports without
    /// `type: "Organization"` used to fall into `User`, so an enterprise was
    /// labelled a user — a wrong statement about the operator's own account, on
    /// the one screen that exists to tell them what their credential reaches.
    ///
    /// It contributes nothing to [`ReachableTargets::organizations`], and that
    /// is correct rather than a second bug: an enterprise is not an
    /// organization, and `GET /orgs/{org}/actions/runners` does not accept one.
    /// The distinction is only visible now because the label is.
    Enterprise(String),
}

impl InstallationAccount {
    #[must_use]
    pub fn login(&self) -> &str {
        match self {
            Self::User(login) | Self::Enterprise(login) => login,
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
            Self::User(_) | Self::Enterprise(_) => None,
        }
    }

    /// What to call this account in `auth status`. `f1` renders it; nothing in
    /// this crate branches on it.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Organization(_) => "organization",
            Self::Enterprise(_) => "enterprise",
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
    skipped: usize,
}

impl ReachableTargets {
    #[must_use]
    pub fn installations(&self) -> &[Installation] {
        &self.installations
    }

    /// How many installations GitHub reported that this client could not
    /// describe, and therefore left out of everything above.
    ///
    /// Non-zero means this report is **incomplete**, not merely small: whatever
    /// those installations reach is absent from
    /// [`ReachableTargets::repositories`] and
    /// [`ReachableTargets::organizations`]. `auth status` should say so, because
    /// the alternative is an operator reading a short list as a complete one.
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.skipped
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
    /// The credential is valid, GitHub reported nothing this client could not
    /// describe, and still nothing is reachable: the App is installed nowhere,
    /// or on nothing. `03-control-flows.md` flow 1.1 requires the installation
    /// URL here, and the URL is the remediation.
    NotInstalled { install_url: Url },
    /// Nothing is reachable, but at least one installation was **skipped**, so
    /// this client cannot tell "not installed" from "installed on something it
    /// could not describe".
    ///
    /// # Why this variant exists at all
    ///
    /// Skipping an unnameable installation is the right trade — one odd
    /// installation must not take down `auth status` for every other one — but
    /// it was made silently, and the silence flipped a verdict. An account this
    /// client cannot name, on the *only* installation the credential has, used
    /// to collapse to [`InstallationDiscovery::NotInstalled`], and `auth status`
    /// then handed an already-installed operator the "install the App" URL. That
    /// is a wrong remediation on the only authentication path there is,
    /// contradicted by nothing louder than a `warn!` in a log the operator is
    /// not reading.
    ///
    /// So the skip stays and the verdict does not flip. There is deliberately no
    /// `install_url` here: the whole point is that this client does not know
    /// whether installing is the remedy, and offering the URL anyway would put
    /// the wrong answer back one field over. `f1` says "1 installation could not
    /// be described" and stops there, which is true.
    Indeterminate { skipped: usize },
    /// The credential reaches at least one repository or organization. It may
    /// still be an incomplete picture — see [`ReachableTargets::skipped`].
    Installed(ReachableTargets),
}

impl InstallationDiscovery {
    #[must_use]
    pub fn targets(&self) -> Option<&ReachableTargets> {
        match self {
            Self::Installed(t) => Some(t),
            Self::NotInstalled { .. } | Self::Indeterminate { .. } => None,
        }
    }

    /// The installation URL, and *only* when installing is actually the
    /// remediation. See [`InstallationDiscovery::Indeterminate`].
    #[must_use]
    pub fn install_url(&self) -> Option<&Url> {
        match self {
            Self::NotInstalled { install_url } => Some(install_url),
            Self::Installed(_) | Self::Indeterminate { .. } => None,
        }
    }

    /// How many installations GitHub reported that this client could not
    /// describe, whichever verdict was reached. One call for `f1`, so that
    /// "this report is incomplete" does not depend on which variant it landed
    /// in.
    #[must_use]
    pub fn skipped(&self) -> usize {
        match self {
            Self::NotInstalled { .. } => 0,
            Self::Indeterminate { skipped } => *skipped,
            Self::Installed(targets) => targets.skipped(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct InstallationsPage {
    /// GitHub reports the size of the whole collection on every page. Decoding
    /// it costs nothing and turns silent under-collection into a visible
    /// warning — see [`under_collected`].
    #[serde(default)]
    total_count: Option<u64>,
    #[serde(default)]
    installations: Vec<RawInstallation>,
}

#[derive(Debug, Deserialize)]
struct RawInstallation {
    id: u64,
    /// **Nullable.** GitHub's published `installation` schema types `account` as
    /// nullable, so a required field here would fail the *whole* decode — and
    /// with it all of `discover_installations`, which is all of `auth status` —
    /// over one installation whose account this client did not need to name.
    #[serde(default)]
    account: Option<RawAccount>,
    #[serde(default)]
    repository_selection: Option<String>,
    #[serde(default)]
    permissions: std::collections::BTreeMap<String, String>,
}

/// An installation's account, which is *not* always a simple user.
///
/// GitHub's schema makes `account` either a simple-user or an enterprise, and an
/// enterprise carries `slug` and `name` where a user carries `login`. Requiring
/// `login` therefore made an enterprise installation a hard decode failure of
/// the entire response. All three are optional here and
/// [`RawAccount::display_login`] takes the first usable one.
#[derive(Debug, Deserialize)]
struct RawAccount {
    #[serde(default)]
    login: Option<String>,
    /// An enterprise account's stable identifier.
    #[serde(default)]
    slug: Option<String>,
    /// An enterprise account's display name, the last resort.
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type", default)]
    account_type: Option<String>,
}

impl RawAccount {
    fn display_login(&self) -> Option<&str> {
        [
            self.login.as_deref(),
            self.slug.as_deref(),
            self.name.as_deref(),
        ]
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
    }

    /// An account with no `login` that still names itself is an enterprise:
    /// `slug`/`name` is the enterprise shape, and every simple-user and
    /// organization account carries `login`.
    fn is_enterprise_shaped(&self) -> bool {
        self.login.as_deref().is_none_or(str::is_empty)
            && (self.slug.as_deref().is_some_and(|s| !s.is_empty())
                || self.name.as_deref().is_some_and(|s| !s.is_empty()))
    }
}

#[derive(Debug, Deserialize)]
struct RepositoriesPage {
    #[serde(default)]
    total_count: Option<u64>,
    #[serde(default)]
    repositories: Vec<RawRepository>,
}

#[derive(Debug, Deserialize)]
struct RawRepository {
    full_name: String,
}

/// How many items a paginated collection said it had, when that is more than
/// arrived.
///
/// This is the cheapest possible check and it is worth more than it looks. The
/// `Link`-header parser used to lose the relation whenever a page URL contained
/// a comma, which stopped pagination at page 1 — and *nothing* noticed, because
/// a short answer and a complete answer are the same shape. Cross-checking the
/// count GitHub itself reported turns that class of bug from a wrong answer into
/// a logged warning. A collection larger than `total_count` is not reported:
/// GitHub can legitimately grow a collection between pages.
fn under_collected(collected: usize, total_count: Option<u64>) -> Option<u64> {
    let total = total_count?;
    (total > collected as u64).then_some(total)
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
        let mut skipped = 0_usize;
        for raw in self.all_installations().await? {
            // A null or nameless account is skipped rather than fatal. GitHub
            // types this field as nullable, and one unnameable installation must
            // not take down `auth status` for every other one — but it is also
            // not something to swallow quietly, because the repositories behind
            // it are then absent from the reported reach. The count is what
            // carries that out of here; a `warn!` alone let the skip change the
            // verdict with nothing to say so.
            let Some(login) = raw.account.as_ref().and_then(RawAccount::display_login) else {
                skipped += 1;
                tracing::warn!(
                    installation_id = raw.id,
                    "skipping an installation GitHub reported with no nameable account; \
                     anything it reaches is missing from this report"
                );
                continue;
            };
            let account_type = raw.account.as_ref().and_then(|a| a.account_type.as_deref());
            let account = match account_type {
                Some("Organization") => {
                    InstallationAccount::Organization(Org::new(login).map_err(|_| {
                        GithubError::Malformed {
                            what: "an installation account login",
                            value: login.to_string(),
                        }
                    })?)
                }
                Some("Enterprise") => InstallationAccount::Enterprise(login.to_string()),
                // An enterprise is also reported with no `type` at all, carrying
                // `slug`/`name` where a user carries `login` — which is the
                // shape D18 observed and the shape `display_login` exists for.
                // Recognising it by that shape is what stops it being labelled a
                // user by default.
                _ if raw
                    .account
                    .as_ref()
                    .is_some_and(RawAccount::is_enterprise_shaped) =>
                {
                    InstallationAccount::Enterprise(login.to_string())
                }
                _ => InstallationAccount::User(login.to_string()),
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

        let targets = ReachableTargets {
            installations,
            skipped,
        };
        if targets.is_empty() {
            // "Nothing reachable" and "nothing this client could describe" are
            // different answers, and only the first one is fixed by installing
            // the App. Reporting them as the same answer is how an
            // already-installed operator was handed an install URL.
            if skipped > 0 {
                tracing::warn!(
                    skipped,
                    "every installation GitHub reported was skipped; whether the App is \
                     installed cannot be determined from this credential"
                );
                return Ok(InstallationDiscovery::Indeterminate { skipped });
            }
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
            skipped,
            "discovered the targets this credential can reach"
        );
        Ok(InstallationDiscovery::Installed(targets))
    }

    async fn all_installations(&self) -> Result<Vec<RawInstallation>, GithubError> {
        let mut out = Vec::new();
        let mut total_count = None;
        let mut next = Some(ApiRequest::get("/user/installations").query("per_page", 100));
        let mut pages = 0_usize;
        while let Some(request) = next.take() {
            let response = self.send(&request).await?;
            let page: InstallationsPage = response.json()?;
            total_count = page.total_count.or(total_count);
            out.extend(page.installations);

            pages += 1;
            if pages >= MAX_PAGES {
                tracing::warn!(
                    pages,
                    collected = out.len(),
                    "stopped following installation pages at the ceiling; a `Link: rel=next` \
                     that never ends would otherwise loop forever"
                );
                break;
            }
            next = response
                .next_page()
                .map(|url| ApiRequest::get(url.as_str()));
        }
        if let Some(expected) = under_collected(out.len(), total_count) {
            tracing::warn!(
                expected,
                collected = out.len(),
                "GitHub reported more installations than pagination collected; the reported \
                 reach is incomplete"
            );
        }
        Ok(out)
    }

    async fn installation_repositories(&self, id: u64) -> Result<Vec<OwnerRepo>, GithubError> {
        let mut out = Vec::new();
        let mut total_count = None;
        let mut next = Some(
            ApiRequest::get(format!("/user/installations/{id}/repositories"))
                .query("per_page", 100),
        );
        let mut pages = 0_usize;
        while let Some(request) = next.take() {
            let response = self.send(&request).await?;
            let page: RepositoriesPage = response.json()?;
            total_count = page.total_count.or(total_count);
            for repo in page.repositories {
                out.push(OwnerRepo::parse(&repo.full_name).map_err(|_| {
                    GithubError::Malformed {
                        what: "a repository full_name",
                        value: repo.full_name.clone(),
                    }
                })?);
            }

            pages += 1;
            if pages >= MAX_PAGES {
                tracing::warn!(
                    installation_id = id,
                    pages,
                    collected = out.len(),
                    "stopped following repository pages at the ceiling; a `Link: rel=next` \
                     that never ends would otherwise loop forever"
                );
                break;
            }
            next = response
                .next_page()
                .map(|url| ApiRequest::get(url.as_str()));
        }
        if let Some(expected) = under_collected(out.len(), total_count) {
            tracing::warn!(
                installation_id = id,
                expected,
                collected = out.len(),
                "GitHub reported more repositories than pagination collected; this \
                 installation's reach is under-reported"
            );
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

    // The `tracing` capture subscriber that used to live here now lives in
    // `tests/no_secret_reaches_the_logs.rs`, and the move is the point rather
    // than tidying. `tracing` caches a callsite's `Interest` once, process-wide,
    // while `with_default` installs a subscriber only on the calling *thread* —
    // so a scan run alongside 34 other unit tests saw its library callsites
    // already registered `Interest::never()` by threads that had no subscriber,
    // and captured nothing but its own three events. It passed with a real
    // device-code leak in the flow. A scan that is the only test in its process
    // cannot be poisoned that way, and no `#[cfg(test)]` module here can offer
    // that guarantee.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FIXTURE_TOKEN, Script, TestClock, installations_body, repositories_body};
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

    /// `consecutive_unauthorized` is reset only by a successful *caller*
    /// response, so a request ending in `404`, `422` or `5xx` leaves it set —
    /// and in the agent's long-lived reconciliation loop it stays set for as
    /// long as nothing succeeds. Before the fix, the next genuine permissions
    /// `403` was therefore reported as `AuthenticationLockout`: sixty seconds of
    /// client silence, plus an operator message asserting "the credential itself
    /// is not the problem" about a credential that was missing
    /// `Administration: write` — the failure `04-subsystem-contracts.md` names
    /// as the *expected* one for `generate-jitconfig`.
    ///
    /// The lockout's real signature is narrower: a `403` on the one retry this
    /// client issues after this request's own `401`. A fresh first attempt
    /// answering `403` is a permissions answer, whatever happened minutes ago.
    #[tokio::test]
    async fn a_stale_401_does_not_turn_a_later_permissions_403_into_a_lockout() {
        let server = MockServer::start().await;
        // The first request ends in a 404, which leaves the 401 count set
        // because only a 2xx clears it.
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(401),
                ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
            .mount(&server)
            .await;
        // Minutes later, a different call is denied for a missing permission.
        Mock::given(method("POST"))
            .and(path("/orgs/acme/actions/runners/generate-jitconfig"))
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
            .expect_err("404");
        assert!(
            matches!(err, GithubError::Status { status: 404, .. }),
            "{err:?}"
        );

        let err = client
            .send(&ApiRequest::new(
                Method::POST,
                "/orgs/acme/actions/runners/generate-jitconfig",
            ))
            .await
            .expect_err("403");

        assert!(
            matches!(err, GithubError::Forbidden { .. }),
            "a fresh first-attempt 403 is a permissions answer, not a lockout: {err:?}"
        );
        assert!(!err.is_lockout());
        assert!(
            !client.is_locked_out(),
            "a stale 401 must not be able to silence the client for a minute"
        );
    }

    /// GitHub's own rate limit is not an answer about the credential, and must
    /// not be reported as one. `classify` reached the `403` branch before
    /// anything looked at the rate-limit headers, so a primary rate limit
    /// arriving during a `401` storm was announced as an authentication lockout
    /// with the message "the credential itself is not the problem" — about a
    /// response that never mentioned the credential.
    #[tokio::test]
    async fn a_rate_limited_403_is_not_reported_as_an_authentication_lockout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(401),
                ResponseTemplate::new(403)
                    .insert_header("x-ratelimit-remaining", "0")
                    .insert_header("x-ratelimit-reset", "1787270460")
                    .insert_header("retry-after", "30")
                    .set_body_json(json!({"message": "API rate limit exceeded"})),
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
            .expect_err("rate limited");

        assert!(
            matches!(err, GithubError::Forbidden { .. }),
            "a rate limit is not an authentication outcome: {err:?}"
        );
        assert!(!err.is_lockout());
        assert!(!err.is_authentication());
        assert!(
            !client.is_locked_out(),
            "a rate limit must not latch this crate's authentication back-off"
        );

        // And `c3` gets the evidence it needs to apply the policy that is its
        // own, without editing this file.
        let evidence = err
            .rate_limit()
            .expect("the headers survived classification");
        assert_eq!(evidence.remaining, Some(0));
        assert_eq!(evidence.reset_unix_secs, Some(1_787_270_460));
        assert_eq!(evidence.retry_after, Some(Duration::from_secs(30)));
    }

    /// The same claim for the variant `429` lands in.
    #[tokio::test]
    async fn a_429_carries_its_retry_after_across_the_c2_c3_seam() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "17")
                    .insert_header("x-ratelimit-remaining", "0")
                    .set_body_json(json!({"message": "You have exceeded a secondary rate limit"})),
            )
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let err = client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect_err("429");

        assert!(
            matches!(err, GithubError::Status { status: 429, .. }),
            "{err:?}"
        );
        assert_eq!(
            err.retry_after(),
            Some(Duration::from_secs(17)),
            "destroying this header is what made `c3`'s Definition of Done unmeetable"
        );
        assert_eq!(
            err.headers().and_then(|h| h.get("x-ratelimit-remaining")),
            Some(&reqwest::header::HeaderValue::from_static("0"))
        );
    }

    /// A back-off is a safety mechanism, and this one had both failure modes at
    /// once: no ceiling, so `Retry-After: 86400` latched a silent twenty-four
    /// hour outage; and `TimeDelta::from_std(...).ok()` on a value too large to
    /// convert, which yielded `until = None` — *not locked out at all*, the
    /// exact inverse of the requirement, reachable by a header alone.
    #[tokio::test]
    async fn an_extreme_retry_after_is_clamped_and_never_fails_open() {
        async fn lockout_for(header: &str) -> (GithubError, bool, Option<Duration>) {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/orgs/acme/actions/runners"))
                .respond_with(Script::new(vec![
                    ResponseTemplate::new(401),
                    ResponseTemplate::new(403).insert_header("retry-after", header),
                ]))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/user/installations"))
                .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
                .mount(&server)
                .await;

            let client = AuthenticatedClient::new(
                Endpoints::for_test_server(&server.uri()).unwrap(),
                UserAccessToken::new(SecretString::from(FIXTURE_TOKEN)),
                Arc::new(TestClock::default()),
            )
            .unwrap();
            let err = client
                .send(&ApiRequest::get("/orgs/acme/actions/runners"))
                .await
                .expect_err("403 after a 401");
            let locked = client.is_locked_out();
            let remaining = client.lockout_remaining();
            (err, locked, remaining)
        }

        // A day-long back-off is clamped to the ceiling.
        let (err, locked, remaining) = lockout_for("86400").await;
        let GithubError::AuthenticationLockout { retry_after } = &err else {
            panic!("expected a lockout, got {err:?}");
        };
        assert_eq!(
            *retry_after, MAX_LOCKOUT_BACKOFF,
            "an unclamped Retry-After lets a remote party decide how long this product \
             stays down"
        );
        assert!(locked);
        assert!(remaining.is_some_and(|r| r <= MAX_LOCKOUT_BACKOFF));

        // A value too large for `chrono` must still lock out. Before the fix
        // this produced `until = None`: the more extreme the header, the less
        // protection it bought.
        let (err, locked, remaining) = lockout_for(&u64::MAX.to_string()).await;
        assert!(err.is_lockout(), "{err:?}");
        assert!(
            locked,
            "an absurd Retry-After must not mean `not locked out at all` — that fails open"
        );
        assert!(remaining.is_some_and(|r| r <= MAX_LOCKOUT_BACKOFF));
    }

    /// The lockout's own contract is "this client issues no HTTP at all", and
    /// `revalidate` is HTTP. It documented an `AuthenticationLockout` it could
    /// never return, which made the one direct entry point into the probe the
    /// single exception to the rule.
    #[tokio::test]
    async fn a_direct_revalidation_is_refused_while_the_lockout_is_backing_off() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(401),
                ResponseTemplate::new(403).insert_header("retry-after", "60"),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect_err("locks out");
        assert!(client.is_locked_out());

        let before = server.received_requests().await.unwrap().len();
        let err = client
            .revalidate()
            .await
            .expect_err("the documented lockout error is now reachable");
        assert!(err.is_lockout(), "{err:?}");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            before,
            "a locked-out client opens no socket, and the probe is not an exception"
        );
    }

    /// The position rule fixed `classify` and left the same defect one function
    /// over, behind a comment asserting it could not happen: "the probe only
    /// ever runs after a `401`, so it is always in the retry position". Making
    /// [`AuthenticatedClient::revalidate`] public — the previous round's own
    /// change — is exactly what made that untrue.
    ///
    /// The sequence is the agent's, not a contrivance. A request 401s, the probe
    /// says the credential is fine, the retry answers `404` — which does *not*
    /// reset the counter, by design. Minutes later `f1` renders `auth status`,
    /// which probes directly, and the probe meets an ordinary permissions `403`.
    /// A stale `401` then latched a sixty-second client-wide lockout and told
    /// the operator to wait, when the real answer was a missing grant.
    #[tokio::test]
    async fn a_directly_requested_probe_does_not_latch_a_lockout_from_a_stale_401() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(401),
                // The retry misses. A `404` leaves `consecutive_unauthorized`
                // set, which is the whole premise of the position rule.
                ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(Script::new(vec![
                // The probe that accompanies the 401 above.
                ResponseTemplate::new(200).set_body_json(installations_body(&[])),
                // The direct probe, minutes later: a plain permissions answer,
                // with no `retry-after` and a message that names a grant.
                ResponseTemplate::new(403)
                    .set_body_json(json!({"message": "Resource not accessible by integration"})),
            ]))
            .mount(&server)
            .await;

        let clock = Arc::new(TestClock::default());
        let client = client(&server, clock.clone());
        client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect_err("the retry 404s");
        assert!(
            !client.is_locked_out(),
            "a 404 on the retry is not a lockout"
        );

        clock.advance_secs(300);
        let outcome = client
            .revalidate()
            .await
            .expect("a direct probe is not a lockout error");

        assert_eq!(
            outcome,
            Revalidation::Unavailable,
            "a 403 on the probe teaches this client nothing about the credential"
        );
        assert!(
            !client.is_locked_out(),
            "a caller-initiated probe is a *first* attempt, not the retry that follows a 401: \
             latching here converts a stale 401 into a 60-second client-wide outage and \
             reports a missing permission as `the credential is fine, please wait`"
        );
        assert_eq!(client.lockout_remaining(), None);
    }

    /// The narrowing that fixed the stale-`401` lockout opened a hole at the
    /// other end of the same back-off.
    ///
    /// While GitHub is still locking the credential out after the back-off
    /// elapses, the next request is a *first* attempt by construction — this
    /// client's own retry never happened, because the request never reached the
    /// wire. So the position rule declined to call it a lockout and `classify`
    /// fell through to [`GithubError::Forbidden`], whose documented reading is
    /// "the App installation does not grant it". The client then stopped backing
    /// off entirely and hammered a credential GitHub had asked it to leave
    /// alone, which is the exact inverse of "backs off without retrying".
    ///
    /// A continuation is distinguishable from a permissions answer without any
    /// counter: GitHub sends `retry-after` and no message body for the lockout,
    /// and a message and no `retry-after` for a permissions refusal.
    #[tokio::test]
    async fn a_lockout_outliving_its_backoff_re_latches_instead_of_reporting_a_permissions_answer()
    {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/actions/runners"))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(401),
                // The retry: the lockout latches here, in the retry position.
                ResponseTemplate::new(403).insert_header("retry-after", "60"),
                // The continuation, once the back-off has elapsed. Same shape,
                // first position.
                ResponseTemplate::new(403).insert_header("retry-after", "60"),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
            .mount(&server)
            .await;

        let clock = Arc::new(TestClock::default());
        let client = client(&server, clock.clone());
        let err = client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect_err("403 on the retry");
        assert!(err.is_lockout(), "{err:?}");
        assert!(client.is_locked_out());

        // The back-off elapses with GitHub unchanged.
        clock.advance_secs(61);
        assert!(!client.is_locked_out(), "the back-off has run out");

        let err = client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect_err("GitHub is still locking the credential out");

        assert!(
            err.is_lockout(),
            "a 403 carrying `retry-after` with no message is GitHub continuing the lockout, \
             not the App installation refusing a permission; reporting `Forbidden` here \
             tells the operator to fix a grant that is not missing: {err:?}"
        );
        assert!(
            client.is_locked_out(),
            "`backs off without retrying` fails for any lockout that outlives one back-off \
             if the continuation does not re-latch"
        );
        let GithubError::AuthenticationLockout { retry_after } = err else {
            unreachable!("asserted above")
        };
        assert_eq!(
            retry_after,
            Duration::from_secs(60),
            "the continuation's own `retry-after` sets the new back-off"
        );

        // And the next request is suppressed before a socket is opened, which is
        // the property the whole back-off exists for.
        let before = server.received_requests().await.unwrap().len();
        let err = client
            .send(&ApiRequest::get("/orgs/acme/actions/runners"))
            .await
            .expect_err("still locked out");
        assert!(err.is_lockout(), "{err:?}");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            before,
            "re-latching must actually stop traffic, not merely rename the error"
        );
    }

    /// A permissions `403` on a first attempt is still a permissions answer, and
    /// the continuation rule above must not swallow it. This is the test that
    /// keeps that rule from becoming "every 403 is a lockout".
    #[tokio::test]
    async fn a_first_attempt_permissions_403_is_still_reported_as_forbidden() {
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

        assert!(
            matches!(err, GithubError::Forbidden { .. }),
            "a message and no `retry-after` is GitHub naming a missing grant: {err:?}"
        );
        assert!(!client.is_locked_out());
    }

    /// The `consecutive_unauthorized > 0` conjunct that used to sit alongside
    /// the position rule added no signal — `Attempt::Retry` already implies this
    /// request's own `401` incremented the counter — and added a fail-open race:
    /// any concurrent success `store(0)`s the counter between the `401` and the
    /// retry, and a real lockout is then reported as a permissions answer.
    ///
    /// The race is driven directly rather than by scheduling two requests and
    /// hoping: `store(0)` is the *only* thing the concurrent success contributes,
    /// so performing it between the `401` and the classification reproduces the
    /// race deterministically and on every run.
    #[tokio::test]
    async fn a_concurrent_success_cannot_downgrade_a_lockout_to_a_permissions_answer() {
        let server = MockServer::start().await;
        let client = client(&server, Arc::new(TestClock::default()));

        // This request's own 401 has landed: the retry position is established.
        client
            .consecutive_unauthorized
            .fetch_add(1, Ordering::SeqCst);
        // ... and a request on another task succeeds in the same instant.
        client.consecutive_unauthorized.store(0, Ordering::SeqCst);

        let mut headers = HeaderMap::new();
        headers.insert("retry-after", "60".parse().unwrap());
        let lockout = ApiResponse {
            status: StatusCode::FORBIDDEN,
            headers,
            body: Vec::new(),
        };

        assert!(
            client.is_lockout_403(&lockout, Attempt::Retry),
            "`Attempt::Retry` already means this request's own 401 incremented the counter, so \
             reading the counter again adds no signal and only lets an unrelated success \
             downgrade a real lockout to `Forbidden`"
        );

        // The counter must stay irrelevant in the other direction too: a
        // permissions `403` on a first attempt is not a lockout however many
        // `401`s are on the count.
        client.consecutive_unauthorized.store(7, Ordering::SeqCst);
        let permissions = ApiResponse {
            status: StatusCode::FORBIDDEN,
            headers: HeaderMap::new(),
            body: br#"{"message":"Resource not accessible by integration"}"#.to_vec(),
        };
        assert!(!client.is_lockout_403(&permissions, Attempt::First));
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

    /// GitHub's published `installation` schema types `account` as **nullable**,
    /// and as either a simple-user *or* an enterprise — which carries
    /// `slug`/`name` where a user carries `login`. A required `RawAccount` with
    /// a required `login` made either shape a hard `response.json()` failure,
    /// which takes down all of `discover_installations`, which is all of
    /// `auth status`. One unusual installation must not blind the command that
    /// exists to show the user what their credential can reach.
    #[tokio::test]
    async fn an_installation_with_a_null_or_enterprise_account_does_not_fail_the_whole_decode() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total_count": 3,
                "installations": [
                    // Nullable, per the published schema.
                    { "id": 10, "account": null, "repository_selection": "selected" },
                    // An enterprise: no `login` at all.
                    {
                        "id": 20,
                        "account": { "slug": "acme-enterprise", "name": "Acme Inc" },
                        "repository_selection": "selected"
                    },
                    // And an ordinary user alongside them.
                    {
                        "id": 30,
                        "account": { "login": "IvanMurzak", "type": "User" },
                        "repository_selection": "selected"
                    }
                ]
            })))
            .mount(&server)
            .await;
        for (id, repo) in [(20_u64, "acme-enterprise/tools"), (30, "IvanMurzak/app")] {
            Mock::given(method("GET"))
                .and(path(format!("/user/installations/{id}/repositories")))
                .respond_with(ResponseTemplate::new(200).set_body_json(repositories_body(&[repo])))
                .mount(&server)
                .await;
        }

        let client = client(&server, Arc::new(TestClock::default()));
        let targets = client
            .discover_installations(&app())
            .await
            .expect("one odd account must not fail the whole discovery")
            .targets()
            .cloned()
            .expect("installed");

        // Membership rather than order: what matters here is that neither
        // installation was lost, not how `OwnerRepo` collates.
        let reached = targets
            .repositories()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert!(
            reached.contains(&"acme-enterprise/tools".to_string()),
            "the enterprise installation is named from `slug` rather than dropped: {reached:?}"
        );
        assert!(
            reached.contains(&"IvanMurzak/app".to_string()),
            "the ordinary installation alongside it survives too: {reached:?}"
        );
        assert_eq!(reached.len(), 2);
        assert_eq!(
            targets.installations().len(),
            2,
            "the null account is skipped, and only it"
        );
        assert_eq!(
            targets.skipped(),
            1,
            "the skip is the right trade, but it must travel with the answer: everything the \
             skipped installation reaches is missing from the lists above, and a short list \
             reads exactly like a complete one"
        );

        // The enterprise is labelled an enterprise. It used to fall through to
        // `User`, so `auth status` told the operator their enterprise was a
        // personal account.
        let enterprise = targets
            .installations()
            .iter()
            .find(|i| i.id == 20)
            .expect("the enterprise installation survived");
        assert_eq!(
            enterprise.account,
            InstallationAccount::Enterprise("acme-enterprise".to_string()),
            "an account with no `login` that names itself through `slug` is an enterprise, \
             and calling it a user is a wrong statement about the operator's own account"
        );
        assert_eq!(enterprise.account.kind(), "enterprise");
        assert!(
            enterprise.account.organization().is_none(),
            "an enterprise is not an organization target: `GET /orgs/{{org}}/actions/runners` \
             does not accept one, so contributing nothing to `organizations()` is correct"
        );
        assert!(
            !targets
                .organizations()
                .iter()
                .any(|o| o.as_str() == "acme-enterprise"),
            "and it must not be smuggled in as one either"
        );
    }

    /// The skip is right; the verdict flip was not.
    ///
    /// A null-account installation that is the *only* installation used to
    /// collapse to `NotInstalled`, so `auth status` handed an operator who **is**
    /// installed the "install the App" URL — a wrong remediation on the only
    /// authentication path there is, contradicted by nothing but a `warn!`.
    #[tokio::test]
    async fn a_credential_whose_only_installation_was_skipped_is_not_reported_as_not_installed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total_count": 1,
                "installations": [
                    { "id": 10, "account": null, "repository_selection": "selected" }
                ]
            })))
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let discovery = client.discover_installations(&app()).await.unwrap();

        assert_eq!(
            discovery,
            InstallationDiscovery::Indeterminate { skipped: 1 },
            "GitHub reported an installation; this client could not describe it. That is not \
             the same answer as `not installed`, and only one of the two is fixed by \
             installing the App"
        );
        assert_eq!(
            discovery.install_url(),
            None,
            "offering the install URL here is the wrong remediation, and putting it one field \
             over from the right verdict would just relocate the defect"
        );
        assert_eq!(discovery.skipped(), 1);
        assert!(discovery.targets().is_none());
    }

    /// The other side of the same rule: with nothing skipped, an empty reach is
    /// still an empty reach, and the install URL is still the remediation.
    #[tokio::test]
    async fn an_empty_reach_with_nothing_skipped_is_still_not_installed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installations_body(&[])))
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let discovery = client.discover_installations(&app()).await.unwrap();

        assert!(discovery.install_url().is_some(), "{discovery:?}");
        assert_eq!(discovery.skipped(), 0);
    }

    /// A `Link: rel="next"` that points back at the page it arrived on is an
    /// infinite loop inside the agent's reconciliation loop — the one place in
    /// this product that must not be able to wedge. The ceiling is what makes
    /// this test terminate at all.
    #[tokio::test]
    async fn a_self_referential_link_header_stops_at_the_page_ceiling() {
        let server = MockServer::start().await;
        let self_link = format!("<{}/user/installations?page=2>; rel=\"next\"", server.uri());
        Mock::given(method("GET"))
            .and(path("/user/installations"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(installations_body(&[]))
                    .insert_header("link", self_link.as_str()),
            )
            .mount(&server)
            .await;

        let client = client(&server, Arc::new(TestClock::default()));
        let discovery = client
            .discover_installations(&app())
            .await
            .expect("the ceiling is what makes this return at all");

        assert!(
            discovery.install_url().is_some(),
            "no installation was found"
        );
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            MAX_PAGES,
            "pagination must stop at the ceiling rather than follow the loop forever"
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

    /// A comma is legal inside a URL and GitHub sends such URLs routinely — a
    /// runner query carries `labels=self-hosted,windows`. Splitting the header
    /// on `,` before recognising `<...>` tore that URL in half, found no
    /// relation, and stopped paginating at page 1 while reporting success. That
    /// is precisely what `04-subsystem-contracts.md` forbids ("the dashboard
    /// must not treat a first page as a complete inventory"), in the one shared
    /// reader `c3`'s inventory also goes through.
    #[test]
    fn a_next_url_containing_a_comma_still_paginates() {
        let header = "<https://api.github.com/repos/o/r/actions/runners\
                      ?labels=self-hosted,windows&page=2>; rel=\"next\"";
        assert_eq!(
            parse_link_next(header).map(|u| u.to_string()),
            Some(
                "https://api.github.com/repos/o/r/actions/runners\
                 ?labels=self-hosted,windows&page=2"
                    .to_string()
            ),
            "a comma inside the URL must not end the link-value"
        );

        // The same URL as the second link-value, so the scan has to walk past a
        // comma-bearing target to reach the relation it wants.
        let header = "<https://api.github.com/x?a=1,2&page=1>; rel=\"prev\", \
                      <https://api.github.com/x?a=1,2&page=3>; rel=\"next\"";
        assert_eq!(
            parse_link_next(header).map(|u| u.to_string()),
            Some("https://api.github.com/x?a=1,2&page=3".to_string())
        );
    }

    /// `rel="next"` is not always the first link-value, and both quoted and
    /// unquoted forms are legal.
    #[test]
    fn the_next_relation_is_found_wherever_it_sits_in_the_header() {
        let not_first = "<https://api.github.com/u?page=1>; rel=\"first\", \
                         <https://api.github.com/u?page=9>; rel=\"last\", \
                         <https://api.github.com/u?page=4>; rel=\"next\"";
        assert_eq!(
            parse_link_next(not_first).map(|u| u.to_string()),
            Some("https://api.github.com/u?page=4".to_string())
        );

        let unquoted = "<https://api.github.com/u?page=1>; rel=prev, \
                        <https://api.github.com/u?page=3>; rel=next";
        assert_eq!(
            parse_link_next(unquoted).map(|u| u.to_string()),
            Some("https://api.github.com/u?page=3".to_string())
        );

        assert!(
            parse_link_next("<https://api.github.com/u?page=2; rel=\"next\"").is_none(),
            "an unterminated target is not a link-value"
        );
    }

    /// The free cross-check that would have caught the comma bug on its own.
    #[test]
    fn a_short_collection_is_measured_against_the_count_github_reported() {
        assert_eq!(under_collected(1, Some(2)), Some(2), "page 2 was dropped");
        assert_eq!(under_collected(2, Some(2)), None, "complete");
        assert_eq!(
            under_collected(3, Some(2)),
            None,
            "a collection that grew between pages is not an under-collection"
        );
        assert_eq!(under_collected(0, None), None, "no count, no claim");
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

    // The Definition of Done's log scan is `tests/no_secret_reaches_the_logs.rs`
    // and not a unit test here. See the note at the end of `mod testing` for the
    // `tracing` callsite-cache reason it cannot be one.

    // -- the crate-shape scans ----------------------------------------------
    //
    // The three gates below share these helpers on purpose. The previous round
    // defined `normalise` twice — once in the scan and once in the meta-test
    // that checks it — which left the meta-test structurally unable to notice a
    // change to the real one. One definition, used by both, is the only shape
    // in which a meta-test proves anything.

    /// Spelled in halves so that this file's own source does not trip the scan
    /// it runs: normalising `concat!("refresh", "token")` leaves the
    /// quote-comma-quote between the halves, so no needle ever appears whole.
    const RENEWAL: &[&str] = &[concat!("refresh", "token")];
    const CONFIDENTIAL: &[&str] = &[concat!("client", "secret"), concat!("app", "secret")];

    const MANIFEST: (&str, &str) = ("Cargo.toml", include_str!("../Cargo.toml"));

    /// Every `.rs` file in `src/`.
    ///
    /// This list used to *be* the claim "every source file in the crate", and a
    /// hard-coded list is not that claim — it is a snapshot of it. `c3` and `c4`
    /// are the tasks that will add files to this directory, so the list was
    /// guaranteed to go stale on exactly the work that most needed scanning: a
    /// new `pagination.rs` holding a confidential credential passed silently.
    /// [`the_confidential_credential_scan_covers_every_source_file`] pins this
    /// against `read_dir`, so adding a file and not adding it here fails.
    const CRATE_SOURCES: &[(&str, &str)] = &[
        ("demand.rs", include_str!("demand.rs")),
        ("device_flow.rs", include_str!("device_flow.rs")),
        ("jit.rs", include_str!("jit.rs")),
        ("lib.rs", include_str!("lib.rs")),
        ("rest.rs", include_str!("rest.rs")),
    ];

    /// The two source files `c2` owns, plus the manifest. The renewal half of
    /// the scan stays inside this boundary; see the scan's own documentation.
    const SOURCES_OWNED_BY_C2: &[(&str, &str)] = &[
        ("device_flow.rs", include_str!("device_flow.rs")),
        ("lib.rs", include_str!("lib.rs")),
        MANIFEST,
    ];

    /// Lower-cased with `_` removed, so that one needle catches the snake,
    /// camel, Pascal and screaming-snake spellings of an identifier at once.
    /// (Those four spellings cannot be written out here: they are exactly what
    /// the gate forbids, which is the constraint on documentation this scan
    /// imposes and defends below.)
    ///
    /// # Why `-` is *not* stripped from Rust source
    ///
    /// It used to be, and that rejected ordinary English. `c3`'s own file opens
    /// with a line stating that the gateway holds no such credential, written
    /// with the compound adjective English requires — and stripping `-` turned
    /// that sentence into the needle, so the gate accused `c3` of naming a
    /// confidential credential in the very line that says it holds none. A
    /// compound adjective is not an evasion; it is how the language works, and
    /// this brief, this crate's documentation and that line all use one.
    ///
    /// Nothing is lost, because **a Rust identifier cannot contain `-`**.
    /// Stripping it never bought identifier coverage: every casing an identifier
    /// can actually take is `_`-separated or unseparated, and all of those still
    /// collapse onto the needle. What it bought was coverage of a *kebab-case
    /// string literal*, and the residual gap is stated plainly rather than
    /// papered over: a `.rs` file that wrote this credential's name as a
    /// hyphenated string would not be caught here. That gap is narrow on
    /// purpose — OAuth 2.0 and GitHub both spell the field `_`-separated, which
    /// this catches — and it is the price of a gate that ordinary prose can
    /// coexist with. A gate that fires on correct English is not a stricter
    /// gate; it is a gate that gets deleted.
    ///
    /// The alternatives were weighed. Requiring identifier context needs a Rust
    /// lexer to tell `a client-secret-free design` from a TOML key, and gets the
    /// wrong answer for both string literals and comments. Excluding comment
    /// text needs the same lexer to avoid mangling `//` inside a string, and
    /// would stop the gate catching a `TODO` comment proposing to read the
    /// credential from the environment — which is precisely the drift worth
    /// catching early, while it is still a comment. Stripping one character
    /// fewer needs neither, which is why it wins.
    ///
    /// A space is not stripped either, and for the same reason: it is what lets
    /// this crate's prose discuss a "client secret" as two words.
    fn normalise_source(source: &str) -> String {
        source.to_ascii_lowercase().replace('_', "")
    }

    /// The manifest keeps `-` stripped: TOML keys and crate names are kebab-case
    /// by convention, so `-` there is a word separator rather than a hyphen, and
    /// a manifest carries no hyphenated English for it to break.
    fn normalise_manifest(manifest: &str) -> String {
        manifest.to_ascii_lowercase().replace(['_', '-'], "")
    }

    /// Which normaliser a scanned file gets. The manifest is the only file whose
    /// `-` is a separator rather than punctuation.
    fn normalise(name: &str, contents: &str) -> String {
        if name == MANIFEST.0 {
            normalise_manifest(contents)
        } else {
            normalise_source(contents)
        }
    }

    /// The part of a source file that is not test code.
    ///
    /// The boundary is the first line that is **exactly** `#[cfg(test)]`, and
    /// the word "exactly" is the fix. Splitting on that literal wherever it
    /// appeared also split on it in *prose*, and `lib.rs` has carried such a
    /// mention since the `testing` module was documented — so the scan below
    /// already stopped nine lines early, today, with nothing to say so. A file
    /// whose module documentation happened to mention an inline test module
    /// would have had its scanned region truncated to a few dozen lines, after
    /// which a real `std::fs::write` in non-test code passed silently. That is
    /// the same class of defect as the log scan that captured only its own
    /// events and the credential scan that claimed a scope it did not have: a
    /// gate whose description outran what it did.
    fn non_test_prefix(source: &str) -> &str {
        let mut offset = 0;
        for line in source.split_inclusive('\n') {
            if line.trim() == "#[cfg(test)]" {
                return &source[..offset];
            }
            offset += line.len();
        }
        source
    }

    /// The Definition of Done's second item, made checkable rather than
    /// reviewed: "no renewal token code path exists, and no client secret
    /// appears anywhere in the crate **or its configuration**".
    ///
    /// # Normalised, because a literal scan is evaded by naming
    ///
    /// This used to be a case-sensitive `contains` over two snake-case
    /// spellings, which is a gate that any ordinary Rust or JSON identifier
    /// walks straight through: the camel-cased, Pascal-cased and
    /// screaming-snake spellings of the very same two identifiers were all
    /// invisible to it. None of those is exotic — several are what the
    /// surrounding ecosystem actually calls these fields — so evading this gate
    /// never had to be deliberate. See [`normalise_source`] for what is
    /// collapsed, what is deliberately not, and why.
    ///
    /// The consequence is that this crate's *prose* may not write those
    /// identifiers either, in any casing: it says "renewal token" and "client
    /// secret" as separate words, which normalisation preserves and the scan
    /// therefore ignores. That is a real constraint on the documentation, and it
    /// is the right way round — a gate loosened until the comments compile is
    /// not a gate. It is a constraint on *identifier spellings*, though, and
    /// never on English: hyphenating a compound adjective is not writing an
    /// identifier, and a gate that could not tell those apart is what this round
    /// fixed.
    ///
    /// # Two different scopes, for two different reasons
    ///
    /// The **renewal** half stays scoped to the two files `c2` owns plus the
    /// manifest. A renewal path in `c3`'s or `c4`'s file would be their finding;
    /// failing here on their work would be this task reaching across an
    /// ownership boundary.
    ///
    /// The **client secret** half covers every source file in the crate. That is
    /// not a boundary crossing but the opposite: a public client cannot hold a
    /// client secret at all (D3, `07-security.md`), so one appearing *anywhere*
    /// in this crate is a product defect rather than a matter of whose file it
    /// is, and `c2` is the designated owner of that clause. "Every source file"
    /// is a claim about the directory, so it is checked against the directory —
    /// see [`the_confidential_credential_scan_covers_every_source_file`].
    #[test]
    fn no_renewal_path_and_no_confidential_credential_in_this_crate() {
        for &(name, source) in SOURCES_OWNED_BY_C2 {
            let haystack = normalise(name, source);
            for forbidden in RENEWAL {
                assert!(
                    !haystack.contains(forbidden),
                    "{name} names {forbidden:?} in some spelling: the published App opts out \
                     of user-token expiration, so GitHub issues nothing to renew (D3)"
                );
            }
        }

        for &(name, source) in CRATE_SOURCES.iter().chain(std::iter::once(&MANIFEST)) {
            let haystack = normalise(name, source);
            for forbidden in CONFIDENTIAL {
                assert!(
                    !haystack.contains(forbidden),
                    "{name} names {forbidden:?} in some spelling: a public client cannot \
                     secure a confidential credential, and this design never tries to (D3)"
                );
            }
        }
    }

    /// "Every source file in the crate" is a claim about a directory, and the
    /// scan above states it as a hard-coded list. A list is a snapshot: the
    /// moment `c3` or `c4` adds a file to `src/`, the claim is false and nothing
    /// says so. A `src/pagination.rs` holding a confidential credential passed
    /// the gate that exists to catch exactly that.
    ///
    /// Reading the directory here is what turns the claim back into a claim. It
    /// cannot be done in the scan itself — `include_str!` needs a literal path
    /// at compile time — so the list stays, and this pins it.
    #[test]
    fn the_confidential_credential_scan_covers_every_source_file() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut on_disk: Vec<String> = std::fs::read_dir(dir)
            .expect("the crate's own source directory is readable")
            .map(|entry| entry.expect("a readable directory entry").file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".rs"))
            .collect();
        on_disk.sort();

        let scanned: Vec<String> = CRATE_SOURCES
            .iter()
            .map(|(name, _)| (*name).to_string())
            .collect();

        assert_eq!(
            scanned, on_disk,
            "`src/` and the scanned list have diverged. Add the new file to `CRATE_SOURCES` \
             with an `include_str!`; leaving it out means the confidential-credential scan \
             silently stops covering `every source file in the crate`, which is the claim it \
             makes."
        );
    }

    /// The scan above, shown to actually catch the spellings it claims to — and
    /// to leave alone the ones it claims to leave alone.
    ///
    /// Without this, "the gate is case-insensitive now" is a comment rather than
    /// a fact, and the finding that produced it was precisely a gate whose
    /// description outran what it did. It calls [`normalise`], the same function
    /// the scan calls, because a meta-test with its own private copy of the
    /// thing under test cannot detect a change to it.
    #[test]
    fn the_confidential_credential_scan_is_not_evaded_by_naming() {
        // Assembled at run time rather than written out, for the same reason the
        // needles are spelled in halves: a test that contained these spellings
        // literally would fail the scan it is checking.
        let source_evasions = [
            format!("let {}Token = fetch()", "refresh"),
            format!("struct {}Token;", "Refresh"),
            format!("{}_TOKEN", "REFRESH"),
            format!("{}Secret", "client"),
            format!("{}_SECRET", "CLIENT"),
            format!("{}_secret", "app"),
        ];
        for evasion in &source_evasions {
            let normalised = normalise("lib.rs", evasion);
            assert!(
                normalised.contains(concat!("refresh", "token"))
                    || normalised.contains(concat!("client", "secret"))
                    || normalised.contains(concat!("app", "secret")),
                "{evasion:?} would walk straight through the scan"
            );
        }

        // The manifest is where kebab-case is a word separator rather than a
        // hyphen, so that is where it is still collapsed.
        let manifest_evasion = format!("{}-secret = \"...\"", "client");
        assert!(
            normalise(MANIFEST.0, &manifest_evasion).contains(concat!("client", "secret")),
            "a kebab-case TOML key is an identifier, and the manifest normaliser must \
             still collapse it"
        );

        // And the prose the crate legitimately writes must still pass, or the
        // gate would be unusable and would be weakened again to make it usable.
        for allowed in [
            "a public client cannot hold a client secret",
            "the published App issues no renewal token",
            // The line that fails the old normalisation, quoted from `c3`'s own
            // file. It says the *opposite* of what the gate accused it of.
            "//! This gateway is deliberately client-secret-free, as D3 requires.",
            // The same shape, for the renewal half.
            "a refresh-free credential model",
        ] {
            let normalised = normalise("lib.rs", allowed);
            assert!(
                !normalised.contains(concat!("client", "secret"))
                    && !normalised.contains(concat!("refresh", "token")),
                "{allowed:?} is English, not an identifier, and must not trip the scan"
            );
        }
    }

    /// The storage boundary, made checkable the same way. `c2` returns the token
    /// and never persists it; the machine-scoped store is `d2` and the wiring is
    /// `f1`. A dependency on `runner-manager-platform`, or a filesystem write,
    /// would silently move that boundary.
    #[test]
    fn this_crate_persists_nothing_and_does_not_depend_on_the_platform_crate() {
        assert!(
            !MANIFEST.1.contains("runner-manager-platform"),
            "the gateway must be testable with no platform dependency at all"
        );

        for &(name, source) in SOURCES_OWNED_BY_C2 {
            if name == MANIFEST.0 {
                continue;
            }
            // Everything below `#[cfg(test)]` is test code; the boundary is about
            // non-test code, and the tests above legitimately read this file.
            let non_test = non_test_prefix(source);
            // `OpenOptions`, `File::options` and `std::io::Write` are on this
            // list because the original four named only the *obvious* ways to
            // write a file. A store built with `OpenOptions::new().create(true)`
            // would have moved the persistence boundary silently, which is the
            // one thing this scan exists to prevent.
            for forbidden in [
                "std::fs",
                "fs::write",
                "File::create",
                "File::options",
                "OpenOptions",
                "std::io::Write",
                "tokio::fs",
            ] {
                assert!(
                    !non_test.contains(forbidden),
                    "{name} performs a filesystem operation ({forbidden:?}) outside its tests"
                );
            }
        }
    }

    /// The scan above, shown to be looking at what it says it is looking at.
    ///
    /// `split("#[cfg(test)]")` matched that literal **anywhere**, prose
    /// included. One ordinary sentence in a module's documentation truncated the
    /// scanned region to whatever preceded it, and every filesystem call after
    /// that point became invisible — with the scan still reporting `ok`. This is
    /// the third gate in this crate found describing more than it did, so it
    /// gets the same treatment as the other two: a synthetic file where the
    /// difference is decisive, and an assertion about the real ones.
    #[test]
    fn the_non_test_boundary_is_a_line_and_not_a_mention() {
        // A file shaped like this crate's own: prose that names the attribute,
        // then real non-test code, then the actual module.
        let file = "//! Test helpers live in an inline #[cfg(test)] module near the bottom.\n\
                    \n\
                    fn persist() { std::fs::write(\"x\", b\"y\").unwrap(); }\n\
                    \n\
                    #[cfg(test)]\n\
                    mod tests {\n\
                        fn helper() { std::fs::write(\"ok-in-tests\", b\"\").unwrap(); }\n\
                    }\n";

        let non_test = non_test_prefix(file);
        assert!(
            non_test.contains("fn persist"),
            "a prose mention of the attribute truncated the scanned region, and every \
             filesystem call below it stopped being scanned — silently:\n{non_test}"
        );
        assert!(
            !non_test.contains("ok-in-tests"),
            "the boundary must still exclude the real test module:\n{non_test}"
        );

        // And on the real files, whose module documentation contains such a
        // mention today. `lib.rs` has carried one since `mod testing` was
        // written, so this crate was shipping the truncated scan.
        for &(name, source) in SOURCES_OWNED_BY_C2 {
            if name == MANIFEST.0 {
                continue;
            }
            let expected = source
                .lines()
                .position(|line| line.trim() == "#[cfg(test)]")
                .expect("each source file has an inline test module");
            let scanned = non_test_prefix(source).lines().count();
            assert_eq!(
                scanned, expected,
                "{name}: the scanned region ends at line {scanned} but the test module starts \
                 at line {expected}. The gap is code that claims to be scanned and is not."
            );
        }
    }
}
