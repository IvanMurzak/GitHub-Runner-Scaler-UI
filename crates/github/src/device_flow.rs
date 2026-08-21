// owner: c2-device-flow-auth

//! The OAuth 2.0 Device Authorization Grant against the published GitHub App.
//!
//! This is the **only** authentication path the product has (D3, D16). It needs
//! a public `client_id` and nothing else: no client secret, no redirect
//! listener, no loopback port, and no server anywhere in the design. GitHub
//! documents that a public client cannot secure a client secret, and this design
//! never tries to (`07-security.md`, "Authentication model").
//!
//! # The shape of a login
//!
//! 1. [`DeviceFlow::start`] posts the `client_id` and gets back a user code, a
//!    device code, an expiry, and a polling interval.
//! 2. The caller displays the user code and the canonical
//!    [`crate::DEVICE_VERIFICATION_PATH`] URL. It displays **nothing else** —
//!    see "Phishing" below.
//! 3. [`DeviceFlow::complete`] polls until the user approves, honouring the
//!    interval and every documented error in the matrix.
//! 4. The token is **returned**. Nothing here writes it anywhere; `d2` owns the
//!    machine-scoped store and `f1` owns the wiring.
//!
//! # The error matrix is four outcomes, not one failure
//!
//! `authorization_pending`, `slow_down`, `expired_token` and `access_denied` are
//! four different things that each need a different response, and collapsing
//! them into one generic error is how a CLI ends up telling a user who *declined*
//! the authorization to try again:
//!
//! | GitHub `error` | Here | Caller does |
//! |---|---|---|
//! | `authorization_pending` | [`PollOutcome::Pending`] | keep polling, same interval |
//! | `slow_down` | [`PollOutcome::SlowDown`] | keep polling, **longer** interval |
//! | `expired_token` | [`DeviceFlowError::Expired`] | start a whole new login |
//! | `access_denied` | [`DeviceFlowError::AccessDenied`] | stop; the user said no |
//!
//! Only the first two are recoverable, and [`DeviceFlowError::is_retryable`]
//! says so for the rest.
//!
//! # Phishing
//!
//! `07-security.md`'s threat table names "a phishing page imitates the
//! device-flow prompt to harvest a code", with the control "the tool prints the
//! canonical `github.com/login/device` URL and never proxies or embeds the
//! approval page". Two things implement it. The tool prints
//! [`crate::Endpoints::verification_url`], a compiled-in constant, rather than
//! whatever a response contained; and [`DeviceFlow::start`] *rejects* a
//! `verification_uri` whose origin is not the configured GitHub web host, so a
//! response that tries to redirect a user elsewhere is an error rather than
//! something the CLI renders.
//!
//! # Renewal
//!
//! There is none, and none may be added. The published App opts out of
//! user-token expiration, so GitHub issues no renewal token with the access
//! token; renewing a user token requires the client secret, which a public
//! client cannot hold. `lib.rs`'s
//! `tests::no_renewal_path_and_no_confidential_credential_in_this_crate` scans both
//! files for the identifiers such a path would need.

use std::{fmt, time::Duration};

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

use crate::{
    AppRegistration, ConfigError, DEFAULT_REQUEST_TIMEOUT, Endpoints, Sleeper, USER_AGENT,
    UserAccessToken,
};

/// The grant type the device flow's token request carries, verbatim from
/// RFC 8628.
pub const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The minimum a `slow_down` lengthens the poll interval by.
///
/// RFC 8628 §3.5: on `slow_down` "the interval MUST be increased by 5 seconds
/// for this and all subsequent requests". GitHub also returns the new interval
/// in the response body; [`DeviceFlow::poll_once`] takes whichever is larger, so
/// the RFC's floor holds even against a response that omits or under-states it.
pub const SLOW_DOWN_INCREMENT: Duration = Duration::from_secs(5);

/// The interval used when a response omits one. RFC 8628's default.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way a login can fail.
///
/// GitHub's `error_description` is deliberately **not** carried into any of
/// these. It is free text from a remote party, and this crate's redaction gate
/// is far easier to keep true by construction than by auditing what a remote
/// string happened to contain. The machine-readable `error` code is documented
/// and exhaustive, and it is what a caller branches on anyway.
#[derive(Debug, thiserror::Error)]
pub enum DeviceFlowError {
    /// The user declined. Terminal, and **not** a failure to retry: retrying
    /// re-prompts someone who already said no.
    #[error("the login was declined on GitHub")]
    AccessDenied,

    /// The device code timed out before approval. A whole new login is needed —
    /// the same code cannot be re-presented.
    #[error("the device code expired before the login was approved; start `auth login` again")]
    Expired,

    /// GitHub does not recognise the device code. A new login is needed.
    #[error("GitHub did not recognise the device code; start `auth login` again")]
    IncorrectDeviceCode,

    /// The App registration itself is wrong — device flow not enabled, or a bad
    /// `client_id`. No amount of retrying helps; a maintainer must fix the
    /// published App (`06-migration-rollout.md`, Phase 0).
    #[error("the published GitHub App is misconfigured for the device flow: GitHub said {code:?}")]
    AppMisconfigured { code: String },

    #[error("GitHub returned an unrecognised device-flow error: {code:?}")]
    Unexpected { code: String },

    /// A `verification_uri` that is not on the configured GitHub web host.
    /// The user's code must only ever be typed on GitHub's own domain.
    #[error(
        "GitHub returned a verification URL on {origin:?}, which is not the canonical device \
         page; refusing to display it"
    )]
    UntrustedVerificationUri { origin: String },

    #[error("GitHub was unreachable")]
    Transport(#[source] reqwest::Error),

    #[error("GitHub returned {status} for the device-flow {stage}")]
    Status { status: u16, stage: &'static str },

    #[error("a device-flow {stage} response could not be decoded")]
    Decode {
        stage: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("GitHub returned {value:?} for {what}, which this client cannot use")]
    Malformed { what: &'static str, value: String },

    #[error(transparent)]
    Config(#[from] ConfigError),
}

impl DeviceFlowError {
    /// Whether presenting the same login again could succeed.
    ///
    /// `false` for every variant here: the two recoverable states,
    /// `authorization_pending` and `slow_down`, are [`PollOutcome`]s and never
    /// become errors at all. It is a method rather than a comment because a
    /// caller that retries [`DeviceFlowError::AccessDenied`] re-prompts a user
    /// who has already refused.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the remedy is a fresh `auth login` rather than a maintainer fix.
    #[must_use]
    pub fn requires_new_login(&self) -> bool {
        matches!(self, Self::Expired | Self::IncorrectDeviceCode)
    }
}

fn transport(err: reqwest::Error) -> DeviceFlowError {
    DeviceFlowError::Transport(err.without_url())
}

// ---------------------------------------------------------------------------
// The authorization
// ---------------------------------------------------------------------------

/// What [`DeviceFlow::start`] returns: everything the login needs, with the one
/// secret in it wrapped.
///
/// `07-security.md`'s credential inventory splits the two codes deliberately:
/// "the user code is shown on screen by design, the device code never is". So
/// [`DeviceAuthorization::user_code`] hands out a plain `&str` and
/// [`DeviceAuthorization::device_code`] hands out a [`SecretString`], and
/// `Debug` is written by hand so that neither a derive nor a future field can
/// quietly change that.
#[derive(Clone)]
pub struct DeviceAuthorization {
    device_code: SecretString,
    user_code: String,
    verification_uri: Url,
    expires_in: Duration,
    interval: Duration,
}

impl DeviceAuthorization {
    /// The code the user types. Displayed by design, and only during login.
    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// The code this process proves possession of. Never displayed, never
    /// logged, never persisted.
    #[must_use]
    pub fn device_code(&self) -> &SecretString {
        &self.device_code
    }

    /// The page the user code is typed into — validated to be on GitHub's own
    /// origin by [`DeviceFlow::start`].
    #[must_use]
    pub fn verification_uri(&self) -> &Url {
        &self.verification_uri
    }

    /// How long the whole login has before the device code dies.
    #[must_use]
    pub fn expires_in(&self) -> Duration {
        self.expires_in
    }

    /// The interval GitHub asked to be polled at, before any `slow_down`.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri.as_str())
            .field("expires_in_secs", &self.expires_in.as_secs())
            .field("interval_secs", &self.interval.as_secs())
            .finish()
    }
}

/// The result of one poll.
///
/// The two recoverable states of the error matrix live here rather than in
/// [`DeviceFlowError`], which is what stops a caller from treating "the user has
/// not clicked approve yet" as a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// `authorization_pending` — keep polling at the current interval.
    Pending,
    /// `slow_down` — keep polling, at this longer interval from now on.
    SlowDown { interval: Duration },
    /// The user approved. This is the only value in the crate that carries a
    /// live credential out of the device flow.
    Approved(UserAccessToken),
}

// ---------------------------------------------------------------------------
// The flow
// ---------------------------------------------------------------------------

/// The device-flow client.
///
/// Holds no credential of its own — only the public `client_id` — which is what
/// makes it constructible before any login has ever happened.
#[derive(Debug, Clone)]
pub struct DeviceFlow {
    http: reqwest::Client,
    app: AppRegistration,
    endpoints: Endpoints,
}

impl DeviceFlow {
    /// # Errors
    /// The HTTP client failing to build.
    pub fn new(app: AppRegistration, endpoints: Endpoints) -> Result<Self, DeviceFlowError> {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .map_err(transport)?;
        Ok(Self::with_http_client(http, app, endpoints))
    }

    #[must_use]
    pub fn with_http_client(
        http: reqwest::Client,
        app: AppRegistration,
        endpoints: Endpoints,
    ) -> Self {
        Self {
            http,
            app,
            endpoints,
        }
    }

    /// The canonical page this login must be approved on, and the only
    /// device-flow URL the product ever prints.
    #[must_use]
    pub fn verification_url(&self) -> Url {
        self.endpoints.verification_url()
    }

    /// Begin a login.
    ///
    /// The request carries the public `client_id` and nothing else — no secret,
    /// no scope (a GitHub App's scopes come from its declared permissions, not
    /// from the grant), and no redirect URI.
    ///
    /// # Errors
    /// [`DeviceFlowError::Transport`], [`DeviceFlowError::Status`],
    /// [`DeviceFlowError::Decode`], [`DeviceFlowError::Malformed`], or
    /// [`DeviceFlowError::UntrustedVerificationUri`].
    pub async fn start(&self) -> Result<DeviceAuthorization, DeviceFlowError> {
        let body = form_body(&[("client_id", self.app.client_id())]);
        let response = self
            .http
            .post(self.endpoints.device_code_url())
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .map_err(transport)?;

        let status = response.status();
        let bytes = response.bytes().await.map_err(transport)?;
        if !status.is_success() {
            return Err(DeviceFlowError::Status {
                status: status.as_u16(),
                stage: "device code request",
            });
        }

        let raw: RawDeviceCode =
            serde_json::from_slice(&bytes).map_err(|source| DeviceFlowError::Decode {
                stage: "device code",
                source,
            })?;

        let verification_uri =
            Url::parse(&raw.verification_uri).map_err(|_| DeviceFlowError::Malformed {
                what: "a verification URL",
                value: raw.verification_uri.clone(),
            })?;
        // The phishing control, enforced rather than documented: the code is only
        // ever typed on GitHub's own origin.
        if verification_uri.origin() != self.endpoints.web_base().origin() {
            return Err(DeviceFlowError::UntrustedVerificationUri {
                origin: verification_uri.origin().ascii_serialization(),
            });
        }

        let authorization = DeviceAuthorization {
            device_code: SecretString::from(raw.device_code),
            user_code: raw.user_code,
            verification_uri,
            expires_in: Duration::from_secs(raw.expires_in.unwrap_or(900)),
            interval: raw
                .interval
                .map_or(DEFAULT_POLL_INTERVAL, Duration::from_secs),
        };

        // The user code is displayed by design and is the one thing a caller
        // must surface; the device code is not in this event and never will be.
        tracing::info!(
            user_code = %authorization.user_code,
            verification_url = %self.verification_url(),
            expires_in_secs = authorization.expires_in.as_secs(),
            "device login started; approve it on GitHub's own device page"
        );

        Ok(authorization)
    }

    /// Ask once whether the login has been approved.
    ///
    /// # Errors
    /// The four terminal members of the error matrix, plus transport and decode
    /// failures. `authorization_pending` and `slow_down` are **not** errors —
    /// they are [`PollOutcome`]s.
    pub async fn poll_once(
        &self,
        authorization: &DeviceAuthorization,
    ) -> Result<PollOutcome, DeviceFlowError> {
        self.poll_once_from(authorization, authorization.interval)
            .await
    }

    async fn poll_once_from(
        &self,
        authorization: &DeviceAuthorization,
        current_interval: Duration,
    ) -> Result<PollOutcome, DeviceFlowError> {
        // The device code goes in the request *body*, never in the URL: a query
        // string is logged by every proxy and appears in every access log, and
        // `07-security.md` requires the device code to stay out of all of them.
        let body = form_body(&[
            ("client_id", self.app.client_id()),
            ("device_code", authorization.device_code.expose_secret()),
            ("grant_type", DEVICE_GRANT_TYPE),
        ]);

        let response = self
            .http
            .post(self.endpoints.access_token_url())
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .map_err(transport)?;

        let status = response.status();
        let bytes = response.bytes().await.map_err(transport)?;
        let mut raw: RawTokenResponse =
            serde_json::from_slice(&bytes).map_err(|source| DeviceFlowError::Decode {
                stage: "access token",
                source,
            })?;

        // GitHub answers the pending and slow-down states with HTTP 200 and an
        // `error` field, so the body is authoritative and the status is only a
        // backstop for something outside the protocol entirely.
        if let Some(code) = raw.error.take() {
            return self.interpret_error(&code, raw.interval, current_interval);
        }
        if !status.is_success() {
            return Err(DeviceFlowError::Status {
                status: status.as_u16(),
                stage: "access token request",
            });
        }

        let Some(access_token) = raw.access_token.take() else {
            return Err(DeviceFlowError::Malformed {
                what: "an access token response",
                value: "neither an access token nor an error".to_string(),
            });
        };

        let token = UserAccessToken::from_parts(
            SecretString::from(access_token),
            raw.token_type.unwrap_or_else(|| "bearer".to_string()),
            raw.scope.filter(|s| !s.is_empty()),
        );

        // The family prefix, and nothing more. The D17 spike asserted exactly
        // this to prove it had an App user-to-server token rather than an OAuth
        // one; it is diagnostic, not secret.
        tracing::info!(
            token_family = token.family(),
            user_to_server = token.is_user_to_server(),
            "device login approved; the user access token was returned to the caller"
        );

        Ok(PollOutcome::Approved(token))
    }

    fn interpret_error(
        &self,
        code: &str,
        advertised_interval: Option<u64>,
        current_interval: Duration,
    ) -> Result<PollOutcome, DeviceFlowError> {
        match code {
            "authorization_pending" => Ok(PollOutcome::Pending),
            "slow_down" => {
                let interval = slowed(
                    current_interval,
                    advertised_interval.map(Duration::from_secs),
                );
                tracing::debug!(
                    from_secs = current_interval.as_secs(),
                    to_secs = interval.as_secs(),
                    "GitHub asked us to slow down; lengthening the poll interval"
                );
                Ok(PollOutcome::SlowDown { interval })
            }
            "expired_token" => Err(DeviceFlowError::Expired),
            "access_denied" => Err(DeviceFlowError::AccessDenied),
            "incorrect_device_code" => Err(DeviceFlowError::IncorrectDeviceCode),
            "unsupported_grant_type" | "incorrect_client_credentials" | "device_flow_disabled" => {
                Err(DeviceFlowError::AppMisconfigured {
                    code: code.to_string(),
                })
            }
            other => Err(DeviceFlowError::Unexpected {
                code: other.to_string(),
            }),
        }
    }

    /// Poll until the login is approved, refused, or expires.
    ///
    /// Waiting goes through [`Sleeper`] rather than `tokio::time::sleep`, so a
    /// test can assert on the *sequence of intervals* this produces instead of
    /// waiting them out. That is what makes "`slow_down` demonstrably increases
    /// the poll interval" an equality assertion rather than a stopwatch reading.
    ///
    /// The elapsed budget is accumulated from the intervals actually waited, so
    /// the local expiry backstop is as deterministic as the rest. GitHub's own
    /// `expired_token` remains authoritative and is checked first every round;
    /// this only catches a server that never sends it.
    ///
    /// # Errors
    /// Every terminal member of the error matrix.
    pub async fn complete(
        &self,
        authorization: &DeviceAuthorization,
        sleeper: &dyn Sleeper,
    ) -> Result<UserAccessToken, DeviceFlowError> {
        let mut interval = authorization.interval;
        let mut elapsed = Duration::ZERO;

        loop {
            // Wait first: the user has to read the code, open the page, and type
            // it. Polling before that has elapsed only spends rate limit.
            sleeper.sleep(interval).await;
            elapsed = elapsed.saturating_add(interval);

            match self.poll_once_from(authorization, interval).await? {
                PollOutcome::Approved(token) => return Ok(token),
                PollOutcome::SlowDown { interval: next } => interval = next,
                PollOutcome::Pending => {}
            }

            if elapsed >= authorization.expires_in {
                tracing::warn!(
                    waited_secs = elapsed.as_secs(),
                    expires_in_secs = authorization.expires_in.as_secs(),
                    "the device code's own lifetime elapsed before approval"
                );
                return Err(DeviceFlowError::Expired);
            }
        }
    }
}

/// The new interval after a `slow_down`.
///
/// Takes whichever is larger of GitHub's advertised interval and RFC 8628's
/// mandatory `current + 5s` floor. In practice GitHub advertises exactly the
/// floor, so the two agree; taking the maximum means a response that omits the
/// field, or under-states it, still lengthens the interval rather than leaving
/// it unchanged. An interval that failed to grow would poll GitHub at the rate
/// it just asked us to stop polling at.
fn slowed(current: Duration, advertised: Option<Duration>) -> Duration {
    let floor = current.saturating_add(SLOW_DOWN_INCREMENT);
    advertised.map_or(floor, |advertised| advertised.max(floor))
}

/// `application/x-www-form-urlencoded`, built with `url`'s own serializer.
///
/// `reqwest`'s `.form()` would do this, but it is behind the `form` feature and
/// the workspace does not enable it — and `a1` owns every manifest, so needing a
/// feature would be a reason to stop rather than to edit one. `url` is already a
/// dependency and re-exports `form_urlencoded`, so this costs nothing and
/// produces the identical wire format: the one both spikes ran against.
fn form_body(pairs: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawDeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    interval: Option<u64>,
}

/// Deliberately **not** `Debug`-derived anywhere it could be logged: it holds
/// the raw token before it reaches [`SecretString`]. It is consumed inside
/// [`DeviceFlow::poll_once_from`] and never leaves it.
#[derive(Deserialize)]
struct RawTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    error: Option<String>,
    /// Present on `slow_down`; the interval GitHub wants from now on.
    #[serde(default)]
    interval: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        FIXTURE_DEVICE_CODE, FIXTURE_TOKEN, FIXTURE_USER_CODE, RecordingSleeper, Script,
        device_code_body, error_body, token_body,
    };
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, header, method, path},
    };

    fn app() -> AppRegistration {
        AppRegistration::new("Iv23liTESTCLIENTID", "runner-manager").unwrap()
    }

    fn flow(server: &MockServer) -> DeviceFlow {
        DeviceFlow::new(app(), Endpoints::for_test_server(&server.uri()).unwrap()).unwrap()
    }

    async fn mount_start(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(device_code_body(
                &server.uri(),
                5,
                900,
            )))
            .mount(server)
            .await;
    }

    async fn mount_token(server: &MockServer, responses: Vec<ResponseTemplate>) {
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(Script::new(responses))
            .mount(server)
            .await;
    }

    // -- the happy path -----------------------------------------------------

    #[tokio::test]
    async fn a_device_flow_round_trip_against_fixtures_succeeds() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        mount_token(
            &server,
            vec![ResponseTemplate::new(200).set_body_json(token_body())],
        )
        .await;

        let flow = flow(&server);
        let authorization = flow.start().await.expect("device code");
        assert_eq!(authorization.user_code(), FIXTURE_USER_CODE);
        assert_eq!(
            authorization.device_code().expose_secret(),
            FIXTURE_DEVICE_CODE
        );
        assert_eq!(authorization.interval(), Duration::from_secs(5));
        assert_eq!(authorization.expires_in(), Duration::from_secs(900));

        let sleeper = RecordingSleeper::default();
        let token = flow
            .complete(&authorization, &sleeper)
            .await
            .expect("approved");

        assert_eq!(token.secret().expose_secret(), FIXTURE_TOKEN);
        assert_eq!(token.token_type(), "bearer");
        assert_eq!(token.family(), "ghu_");
        assert!(
            token.is_user_to_server(),
            "the published App issues user-to-server tokens; anything else means the \
             registration is not the one this product authenticates as"
        );
        assert_eq!(sleeper.recorded(), vec![Duration::from_secs(5)]);
    }

    #[tokio::test]
    async fn the_start_request_carries_the_public_client_id_and_no_secret() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .and(header("accept", "application/json"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string_contains("client_id=Iv23liTESTCLIENTID"))
            .respond_with(ResponseTemplate::new(200).set_body_json(device_code_body(
                &server.uri(),
                5,
                900,
            )))
            .expect(1)
            .mount(&server)
            .await;

        flow(&server).start().await.expect("device code");

        let sent = server.received_requests().await.unwrap();
        let body = String::from_utf8(sent[0].body.clone()).unwrap();
        assert_eq!(
            body, "client_id=Iv23liTESTCLIENTID",
            "the start request is the client id and nothing else: no secret, no scope, \
             no redirect URI"
        );
    }

    #[tokio::test]
    async fn the_device_code_travels_in_the_body_and_never_in_the_url() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        mount_token(
            &server,
            vec![ResponseTemplate::new(200).set_body_json(token_body())],
        )
        .await;

        let flow = flow(&server);
        let authorization = flow.start().await.unwrap();
        flow.complete(&authorization, &RecordingSleeper::default())
            .await
            .unwrap();

        let sent = server.received_requests().await.unwrap();
        let poll = sent
            .iter()
            .find(|r| r.url.path() == "/login/oauth/access_token")
            .expect("the poll happened");
        assert!(
            !poll.url.as_str().contains(FIXTURE_DEVICE_CODE),
            "a query string reaches every proxy and access log: {}",
            poll.url
        );
        let body = String::from_utf8(poll.body.clone()).unwrap();
        assert!(body.contains(&format!("device_code={FIXTURE_DEVICE_CODE}")));
        assert!(body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"));
    }

    // -- the four documented errors, each its own outcome -------------------

    #[tokio::test]
    async fn authorization_pending_keeps_polling_at_the_unchanged_interval() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        mount_token(
            &server,
            vec![
                // One for the standalone `poll_once` below, then three for the
                // `complete` loop.
                ResponseTemplate::new(200).set_body_json(error_body("authorization_pending", None)),
                ResponseTemplate::new(200).set_body_json(error_body("authorization_pending", None)),
                ResponseTemplate::new(200).set_body_json(error_body("authorization_pending", None)),
                ResponseTemplate::new(200).set_body_json(token_body()),
            ],
        )
        .await;

        let flow = flow(&server);
        let authorization = flow.start().await.unwrap();

        assert_eq!(
            flow.poll_once(&authorization).await.unwrap(),
            PollOutcome::Pending,
            "pending is an outcome, not a failure"
        );

        let sleeper = RecordingSleeper::default();
        flow.complete(&authorization, &sleeper).await.unwrap();
        assert_eq!(
            sleeper.recorded(),
            vec![
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5)
            ],
            "authorization_pending must not change the interval"
        );
    }

    #[tokio::test]
    async fn slow_down_demonstrably_increases_the_poll_interval() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        mount_token(
            &server,
            vec![
                ResponseTemplate::new(200).set_body_json(error_body("authorization_pending", None)),
                ResponseTemplate::new(200).set_body_json(error_body("slow_down", Some(10))),
                ResponseTemplate::new(200).set_body_json(error_body("authorization_pending", None)),
                ResponseTemplate::new(200).set_body_json(error_body("slow_down", Some(15))),
                ResponseTemplate::new(200).set_body_json(token_body()),
            ],
        )
        .await;

        let flow = flow(&server);
        let authorization = flow.start().await.unwrap();
        let sleeper = RecordingSleeper::default();
        flow.complete(&authorization, &sleeper).await.unwrap();

        let waited = sleeper.recorded();
        assert_eq!(
            waited,
            vec![
                Duration::from_secs(5),  // the advertised interval
                Duration::from_secs(5), // still 5: the first slow_down is the *answer* to this poll
                Duration::from_secs(10), // now longer
                Duration::from_secs(10),
                Duration::from_secs(15), // longer again
            ],
            "every slow_down must lengthen the interval used from then on"
        );

        // Stated as an invariant as well as a fixture, so the assertion is about
        // the behaviour and not about this particular script.
        let mut increases = 0;
        for pair in waited.windows(2) {
            assert!(
                pair[1] >= pair[0],
                "the interval must never shrink: {pair:?}"
            );
            if pair[1] > pair[0] {
                increases += 1;
            }
        }
        assert_eq!(increases, 2, "two slow_downs, two increases");
    }

    #[tokio::test]
    async fn a_slow_down_without_an_advertised_interval_still_adds_five_seconds() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        mount_token(
            &server,
            vec![
                ResponseTemplate::new(200).set_body_json(error_body("slow_down", None)),
                ResponseTemplate::new(200).set_body_json(token_body()),
            ],
        )
        .await;

        let flow = flow(&server);
        let authorization = flow.start().await.unwrap();

        assert_eq!(
            flow.poll_once(&authorization).await.unwrap(),
            PollOutcome::SlowDown {
                interval: Duration::from_secs(10)
            },
            "RFC 8628 makes the +5s increase mandatory even with no interval in the body"
        );
    }

    #[test]
    fn the_slow_down_interval_never_shrinks_whatever_the_server_advertises() {
        assert_eq!(
            slowed(Duration::from_secs(5), None),
            Duration::from_secs(10)
        );
        assert_eq!(
            slowed(Duration::from_secs(5), Some(Duration::from_secs(10))),
            Duration::from_secs(10),
            "GitHub advertises exactly the RFC floor, so the two agree"
        );
        assert_eq!(
            slowed(Duration::from_secs(5), Some(Duration::from_secs(30))),
            Duration::from_secs(30),
            "a server asking for more than the floor gets it"
        );
        assert_eq!(
            slowed(Duration::from_secs(5), Some(Duration::from_secs(1))),
            Duration::from_secs(10),
            "a server asking for LESS must not be able to speed us up: slow_down means slow down"
        );
    }

    #[tokio::test]
    async fn expired_token_is_terminal_and_asks_for_a_whole_new_login() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        mount_token(
            &server,
            vec![ResponseTemplate::new(200).set_body_json(error_body("expired_token", None))],
        )
        .await;

        let flow = flow(&server);
        let authorization = flow.start().await.unwrap();
        let err = flow
            .complete(&authorization, &RecordingSleeper::default())
            .await
            .expect_err("expired");

        assert!(matches!(err, DeviceFlowError::Expired), "{err:?}");
        assert!(!err.is_retryable());
        assert!(err.requires_new_login());
        assert!(err.to_string().contains("auth login"));
    }

    #[tokio::test]
    async fn access_denied_is_terminal_and_is_not_an_error_to_retry() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        mount_token(
            &server,
            vec![ResponseTemplate::new(200).set_body_json(error_body("access_denied", None))],
        )
        .await;

        let flow = flow(&server);
        let authorization = flow.start().await.unwrap();
        let err = flow
            .complete(&authorization, &RecordingSleeper::default())
            .await
            .expect_err("declined");

        assert!(matches!(err, DeviceFlowError::AccessDenied), "{err:?}");
        assert!(!err.is_retryable(), "the user said no; do not ask again");
        assert!(
            !err.requires_new_login(),
            "a refusal is not an expiry: `auth login` again is the operator's choice, \
             not this error's instruction"
        );
    }

    /// One table, four codes, four distinct outcomes — which is the property the
    /// Definition of Done asks for, stated in one place so that collapsing any
    /// two of them fails here.
    #[tokio::test]
    async fn the_four_documented_errors_produce_four_distinct_outcomes() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        let flow = flow(&server);
        let authorization = flow.start().await.unwrap();

        let mut described = Vec::new();
        for code in [
            "authorization_pending",
            "slow_down",
            "expired_token",
            "access_denied",
        ] {
            let scoped = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/login/oauth/access_token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(error_body(code, None)))
                .mount(&scoped)
                .await;
            let scoped_flow =
                DeviceFlow::new(app(), Endpoints::for_test_server(&scoped.uri()).unwrap()).unwrap();

            described.push(match scoped_flow.poll_once(&authorization).await {
                Ok(PollOutcome::Pending) => "pending".to_string(),
                Ok(PollOutcome::SlowDown { interval }) => {
                    format!("slow_down->{}s", interval.as_secs())
                }
                Ok(PollOutcome::Approved(_)) => "approved".to_string(),
                Err(err) => format!("error:{err:?}"),
            });
        }

        assert_eq!(
            described,
            vec![
                "pending",
                "slow_down->10s",
                "error:Expired",
                "error:AccessDenied",
            ]
        );
        let mut unique = described.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 4, "four codes must not collapse into fewer");
    }

    #[tokio::test]
    async fn an_unrecognised_error_is_reported_as_itself_rather_than_guessed_at() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        mount_token(
            &server,
            vec![
                ResponseTemplate::new(200).set_body_json(error_body("device_flow_disabled", None)),
            ],
        )
        .await;
        let flow = flow(&server);
        let authorization = flow.start().await.unwrap();

        let err = flow.poll_once(&authorization).await.expect_err("disabled");
        match err {
            DeviceFlowError::AppMisconfigured { code } => {
                assert_eq!(code, "device_flow_disabled");
            }
            other => panic!("expected a registration error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_local_deadline_backstops_a_server_that_never_says_expired() {
        let server = MockServer::start().await;
        // A 20-second lifetime and a 5-second interval: four polls fit.
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(device_code_body(
                &server.uri(),
                5,
                20,
            )))
            .mount(&server)
            .await;
        mount_token(
            &server,
            vec![
                ResponseTemplate::new(200).set_body_json(error_body("authorization_pending", None)),
            ],
        )
        .await;

        let flow = flow(&server);
        let authorization = flow.start().await.unwrap();
        let sleeper = RecordingSleeper::default();
        let err = flow
            .complete(&authorization, &sleeper)
            .await
            .expect_err("the device code's own lifetime ran out");

        assert!(matches!(err, DeviceFlowError::Expired), "{err:?}");
        assert_eq!(
            sleeper.recorded().len(),
            4,
            "the loop stops at the advertised lifetime rather than polling forever"
        );
    }

    // -- phishing -----------------------------------------------------------

    #[tokio::test]
    async fn a_verification_url_on_another_origin_is_refused_rather_than_displayed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": FIXTURE_DEVICE_CODE,
                "user_code": FIXTURE_USER_CODE,
                "verification_uri": "https://github.com.evil.example/login/device",
                "expires_in": 900,
                "interval": 5
            })))
            .mount(&server)
            .await;

        let err = flow(&server).start().await.expect_err("wrong origin");
        match err {
            DeviceFlowError::UntrustedVerificationUri { origin } => {
                assert!(origin.contains("evil.example"), "{origin}");
            }
            other => panic!("expected the phishing control to fire, got {other:?}"),
        }
    }

    #[test]
    fn the_printed_verification_url_is_the_compiled_in_canonical_one() {
        let production = DeviceFlow::new(app(), Endpoints::production()).unwrap();
        assert_eq!(
            production.verification_url().as_str(),
            "https://github.com/login/device",
            "the tool prints this and never proxies, embeds, or imitates the approval page"
        );
    }

    // -- redaction ----------------------------------------------------------

    #[tokio::test]
    async fn neither_code_nor_token_is_rendered_by_debug_or_display() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        mount_token(
            &server,
            vec![ResponseTemplate::new(200).set_body_json(token_body())],
        )
        .await;

        let flow = flow(&server);
        let authorization = flow.start().await.unwrap();
        let rendered = format!("{authorization:?}");
        assert!(
            !rendered.contains(FIXTURE_DEVICE_CODE),
            "the device code is never shown: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
        assert!(
            rendered.contains(FIXTURE_USER_CODE),
            "the user code is displayed by design, so it stays legible: {rendered}"
        );

        let token = flow
            .complete(&authorization, &RecordingSleeper::default())
            .await
            .unwrap();
        assert!(!format!("{token:?}").contains(FIXTURE_TOKEN));
        assert!(!format!("{flow:?}").contains(FIXTURE_TOKEN));

        // Every error's rendered text, too: an error message is a diagnostic and
        // `07-security.md` gates diagnostics as strictly as it gates logs.
        for err in [
            DeviceFlowError::AccessDenied,
            DeviceFlowError::Expired,
            DeviceFlowError::IncorrectDeviceCode,
            DeviceFlowError::AppMisconfigured {
                code: "device_flow_disabled".to_string(),
            },
            DeviceFlowError::Unexpected {
                code: "??".to_string(),
            },
        ] {
            let text = format!("{err} / {err:?}");
            assert!(!text.contains(FIXTURE_DEVICE_CODE), "{text}");
            assert!(!text.contains(FIXTURE_TOKEN), "{text}");
        }
    }

    #[test]
    fn the_token_family_is_diagnostic_and_exposes_nothing_else() {
        let token = UserAccessToken::new(SecretString::from("ghu_abcdefghijklmnop"));
        assert_eq!(token.family(), "ghu_");
        assert!(token.is_user_to_server());

        let oauth = UserAccessToken::new(SecretString::from("gho_abcdefghijklmnop"));
        assert_eq!(oauth.family(), "gho_");
        assert!(
            !oauth.is_user_to_server(),
            "a `gho_` token means this is not the published App's user-to-server credential"
        );

        let odd = UserAccessToken::new(SecretString::from("no-underscore-here"));
        assert_eq!(
            odd.family(),
            "",
            "never guess, and never return a prefix of the token"
        );
    }

    #[test]
    fn the_form_body_encodes_exactly_what_both_spikes_sent() {
        assert_eq!(
            form_body(&[("client_id", "Iv1"), ("grant_type", DEVICE_GRANT_TYPE)]),
            "client_id=Iv1&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
    }
}
