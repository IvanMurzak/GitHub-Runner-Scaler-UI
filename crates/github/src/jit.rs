// owner: c4-demand-and-jit-gateway

//! Just-in-time runner registration: the one call in this product that returns
//! a secret.
//!
//! ```text
//! POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig
//! POST /orgs/{org}/actions/runners/generate-jitconfig
//! body { name, runner_group_id, labels, work_folder }
//!   -> 201 { runner { … }, encoded_jit_config }
//! ```
//!
//! Two scopes, one request shape, one response shape, and — after D4 — one
//! credential. The Actions-service credential chain and message protocol this
//! replaces were disproved by `d17-user-to-server-scale-set-chain.md`; what is
//! here instead is documented, stable REST against a host and a token that
//! already exist.
//!
//! # What the live spikes settled, and what each one costs to get wrong
//!
//! `v1` ([`docs/spikes/d18-org-jit-verification.md`]) drove both scopes against
//! live GitHub. Four of its findings are load-bearing here rather than
//! interesting:
//!
//! 1. **`runner_group_id` is mandatory.** Omitting it answers `422 Invalid
//!    input: object is missing required key: runner_group_id`. There is no
//!    server-side default, so [`JitRunnerRequest`] takes it as a required `u64`
//!    rather than an `Option` — a field that cannot be omitted cannot be
//!    forgotten.
//! 2. **An unusable group answers `403` *or* `404`, depending on why.** Group
//!    `2` — the GitHub-hosted group — answered `403`; group `99999` answered
//!    `404`. Error handling keyed on `404` alone misreports the first case as "no
//!    such group" when the truth is "not yours to administer", so
//!    [`JitError::Forbidden`] and [`JitError::NotFound`] are separate outcomes
//!    and **both** name the runner group.
//! 3. **`1` is not special.** A non-default group id (`3`) also returned `201`.
//!    Nothing here may hard-code `1`.
//! 4. **No labels are added implicitly, and labels are stored lower-cased.** The
//!    `201` carries exactly the labels requested — no `self-hosted`, no OS, no
//!    architecture — so `runs-on: self-hosted` does **not** match a runner
//!    registered without that label. `b1`'s
//!    [`runner_manager_domain::policy::RoutingLabels::as_registration_labels`]
//!    is the array this module sends, and [`runner_manager_domain::model::Label`]
//!    lower-cases on construction, which is what keeps the labels this product
//!    asks for and the labels GitHub stores the same strings.
//!
//! # The encoded configuration is the one short-lived secret in the product
//!
//! `07-security.md`'s credential inventory lists exactly two sensitive values
//! after D4: the persisted user access token, and this. It is returned in
//! [`EncodedJitConfig`], whose `Debug` and `Display` redact, which does not
//! implement [`serde::Serialize`], and which zeroises its buffer on drop.
//!
//! **This crate never writes it to disk and never puts it in an error message.**
//! Every [`JitError`] is built from the *request* — target, runner group, name —
//! and from GitHub's own `message`, never from a response body. The restrictive
//! handoff to the runner process is `d1`'s primitive and `e3`'s job; the rule
//! here is only that nothing leaves this module carrying the blob except
//! [`JitRegistration`].
//!
//! ## What the wrapper does not cover, stated rather than implied
//!
//! [`crate::ApiResponse`] buffers the whole response body, so the encoded
//! configuration also exists as bytes in that buffer until the response is
//! dropped at the end of [`RestJit::generate_jit_config`]. That buffer is `c2`'s
//! and is not zeroised. The intermediate `String` serde produces **is**
//! zeroised here explicitly, immediately after the value is copied into the
//! wrapper, because that one is this module's to scrub.
//!
//! The residual exposure is therefore one heap buffer, for the duration of one
//! call, in a process that already holds the user access token. It is recorded
//! rather than papered over: claiming the blob exists in exactly one place would
//! be false, and a false claim is worse than a bounded one.
//!
//! # There is no job reservation, and this call is not one
//!
//! A JIT configuration registers a runner; it does **not** claim a job. The
//! scale-set model's `AcquireJobs` has no REST equivalent, so another host may
//! take the job this runner was started for
//! (`01-current-architecture.md`, edge case 6). The runner then receives nothing
//! and exits on its idle timeout — the surplus-runner path, which is an
//! accepted, bounded cost with a test of its own (`h1` scenario 8).
//!
//! **Do not add a claim, a lease, or a local reservation table here to
//! compensate**, and do not read this call as one.
//! `demand::tests::nothing_in_this_crate_reserves_or_claims_a_job` makes that
//! executable across the whole crate.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use runner_manager_domain::{model::ScaleTarget, policy::RoutingLabels};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretString, zeroize::Zeroize};
use serde::{Deserialize, Serialize};

use crate::{
    ApiRequest, AuthenticatedClient, GithubError,
    rest::{CancelToken, InventoryError, RateLimited},
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The runner's working directory, relative to its installation root.
///
/// `_work` is the GitHub runner's own default and the value `v1` registered
/// with. It is a constant rather than an inline literal because `e3` creates the
/// directory this names and `e2` lays the runner package out around it: three
/// tasks agreeing on a path is a shared fact, not a repeated string.
pub const DEFAULT_WORK_FOLDER: &str = "_work";

/// The endpoint suffix both scopes share.
pub const JITCONFIG_PATH: &str = "/actions/runners/generate-jitconfig";

/// What GitHub answers a successful registration with.
///
/// Named because two tests and one `debug_assert` compare against it, and
/// because `201` rather than `200` is a fact about this endpoint that a reader
/// should not have to re-derive.
pub const CREATED: u16 = 201;

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// One `generate-jitconfig` request, before a scope is chosen.
///
/// The same value registers at repository scope or organization scope: `v1`
/// established that the two forms take the identical body and answer with the
/// identical shape, so the scope is a [`ScaleTarget`] passed to
/// [`JitGateway::generate_jit_config`] rather than a property of the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitRunnerRequest {
    name: String,
    runner_group_id: u64,
    labels: Vec<String>,
    work_folder: String,
}

impl JitRunnerRequest {
    /// A registration for `name` in `runner_group_id`, carrying `labels`.
    ///
    /// `runner_group_id` is a required argument and not an `Option` on purpose:
    /// `v1` proved there is no server-side default and that omitting the field
    /// is a `422`, so the only way to send a request without one is not to be
    /// able to build it.
    ///
    /// # An empty label set is not rejected here
    ///
    /// GitHub answers `labels: []` with `422 Invalid property /labels: 1 item
    /// required; only 0 were supplied`, and that message is more useful to an
    /// operator than anything this constructor could say — it names the property
    /// and the requirement. The ordinary path cannot produce one anyway:
    /// [`Self::for_policy`] takes a [`RoutingLabels`], which is non-empty by
    /// construction because its host label has no removal path.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        runner_group_id: u64,
        labels: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            runner_group_id,
            labels: labels.into_iter().map(Into::into).collect(),
            work_folder: DEFAULT_WORK_FOLDER.to_string(),
        }
    }

    /// A registration carrying exactly the policy's routing labels.
    ///
    /// This is the constructor the product uses.
    /// [`RoutingLabels::as_registration_labels`] is documented as "`c4` sends
    /// exactly this", and exactly is the operative word: `v1` established that
    /// **no labels are added implicitly**, so a label the operator expects to be
    /// matchable has to be in this array or it does not exist on the runner.
    #[must_use]
    pub fn for_policy(name: impl Into<String>, runner_group_id: u64, labels: &RoutingLabels) -> Self {
        Self::new(name, runner_group_id, labels.as_registration_labels())
    }

    /// Override the runner's working directory.
    #[must_use]
    pub fn with_work_folder(mut self, work_folder: impl Into<String>) -> Self {
        self.work_folder = work_folder.into();
        self
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn runner_group_id(&self) -> u64 {
        self.runner_group_id
    }

    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    #[must_use]
    pub fn work_folder(&self) -> &str {
        &self.work_folder
    }

    fn body(&self) -> JitRequestBody<'_> {
        JitRequestBody {
            name: &self.name,
            runner_group_id: self.runner_group_id,
            labels: &self.labels,
            work_folder: &self.work_folder,
        }
    }
}

/// The wire body, and nothing else.
///
/// A separate type from [`JitRunnerRequest`] so that the four documented keys
/// are the whole of what is serialised. Adding an accessor, a builder field or a
/// derived trait to the public type cannot change what goes on the wire, which
/// is the property `the_request_body_is_exactly_the_four_documented_keys` pins.
///
/// No `skip_serializing_if` anywhere: `runner_group_id` is required, and an
/// attribute that could ever omit it would reintroduce the one `422` `v1` went
/// and measured.
#[derive(Debug, Serialize)]
struct JitRequestBody<'a> {
    name: &'a str,
    runner_group_id: u64,
    labels: &'a [String],
    work_folder: &'a str,
}

// ---------------------------------------------------------------------------
// The secret
// ---------------------------------------------------------------------------

/// The encoded just-in-time configuration: a short-lived credential.
///
/// `07-security.md`, credential inventory: "Restrictive temporary handoff only.
/// Delete immediately after launch; never persist." This type is what makes the
/// first half enforceable at the type level rather than by everyone remembering:
///
/// * **`Debug` and `Display` redact.** Both are hand-written. A `#[derive(Debug)]`
///   added later to a struct with a plain `String` field is precisely how this
///   control is lost, which is why `lib.rs`'s crate documentation states the rule
///   and why `tests/no_jit_config_reaches_the_logs.rs` plants that exact mistake
///   as a positive control.
/// * **It does not serialise.** There is no [`serde::Serialize`] impl, so it
///   cannot be written into a config file, a SQLite row, a `status --json`
///   payload or a structured log field by any code that compiles. The doctest
///   below is the executable form of that claim.
/// * **It zeroises on drop.** [`Drop`] calls [`Self::scrub`], which zeroes the
///   buffer through `zeroize`. `secrecy`'s [`SecretString`] also zeroises on its
///   own drop; the explicit scrub is what makes the property *testable* rather
///   than a statement about a dependency.
/// * **It is not [`Clone`].** A clone of a secret is a second copy with its own
///   lifetime, and this value's whole security property is a short one.
///
/// ```compile_fail
/// # use runner_manager_github::jit::EncodedJitConfig;
/// fn is_serialisable<T: serde::Serialize>(_: &T) {}
/// let config = EncodedJitConfig::new("not-a-real-jit-configuration");
/// // The JIT configuration must never reach a config file, a database row, a
/// // `--json` payload or a structured log field. This must not compile.
/// is_serialisable(&config);
/// ```
pub struct EncodedJitConfig(SecretString);

impl EncodedJitConfig {
    #[must_use]
    pub fn new(raw: impl Into<String>) -> Self {
        Self(SecretString::from(raw.into()))
    }

    /// The configuration itself, for the one caller that hands it to a runner
    /// process.
    ///
    /// Named `expose` rather than `as_str` so that every use site says out loud
    /// what it is doing, and so that `grep expose_jit` finds all of them.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Length in bytes, which is safe to log and useful for diagnosing a
    /// truncated handoff. `v1` observed 4,088 characters at organization scope.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Overwrite the buffer with zeroes.
    ///
    /// Exactly what [`Drop`] calls, and `pub(crate)` rather than private so that
    /// a test can invoke the *same* call and observe the result. Observing the
    /// buffer after the drop itself is not possible without reading freed
    /// memory, which is undefined behaviour; this is the strongest sound
    /// alternative, and the gap it leaves — that `drop` calls `scrub` — is one
    /// line directly below.
    pub(crate) fn scrub(&mut self) {
        self.0.expose_secret_mut().zeroize();
    }
}

impl Drop for EncodedJitConfig {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// What `Debug` and `Display` render instead of the configuration.
const REDACTED: &str = "[REDACTED JIT CONFIGURATION]";

impl fmt::Debug for EncodedJitConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The length is rendered and the value is not: a diagnostic that says
        // "0 bytes" is what distinguishes a truncated handoff from a redacted
        // one, and neither is the secret.
        f.debug_tuple("EncodedJitConfig")
            .field(&REDACTED)
            .field(&format_args!("{} bytes", self.len()))
            .finish()
    }
}

impl fmt::Display for EncodedJitConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

/// The runner GitHub registered, as it described it in the `201`.
///
/// Distinct from [`crate::rest::Runner`], which is what the *inventory* endpoint
/// reports, and deliberately so: this one carries `runner_group_id`, which the
/// inventory shape has no field for and which is the value an operator needs
/// when a later registration is refused for the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitRunner {
    pub id: u64,
    pub name: String,
    pub os: String,
    pub status: String,
    pub busy: bool,
    /// Optional in the wire schema. `v1` observed it present at both scopes; it
    /// stays optional because a missing field is not a reason to fail a
    /// registration that GitHub already accepted.
    pub runner_group_id: Option<u64>,
    /// The labels GitHub actually stored, **lower-cased** — see the module
    /// documentation. Comparing these against what was requested is how a caller
    /// learns that no labels were added implicitly.
    pub labels: Vec<String>,
}

/// A registered runner and the configuration that starts it.
///
/// `Debug` is hand-written. The configuration's own `Debug` already redacts, so
/// a derive would be safe *today*; it is written out because the field it is
/// protecting is a secret and the crate's stated rule is that such types do not
/// rely on a derive staying correct across an edit nobody reviews.
pub struct JitRegistration {
    config: EncodedJitConfig,
    runner: JitRunner,
}

impl JitRegistration {
    #[must_use]
    pub fn new(config: EncodedJitConfig, runner: JitRunner) -> Self {
        Self { config, runner }
    }

    #[must_use]
    pub fn config(&self) -> &EncodedJitConfig {
        &self.config
    }

    /// Take the configuration, leaving the runner reference behind.
    ///
    /// The handoff in `e3` wants the secret and the diagnostics separately, and
    /// moving it out rather than cloning is what keeps there being one copy.
    #[must_use]
    pub fn into_config(self) -> EncodedJitConfig {
        self.config
    }

    #[must_use]
    pub fn runner(&self) -> &JitRunner {
        &self.runner
    }
}

impl fmt::Debug for JitRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JitRegistration")
            .field("runner", &self.runner)
            .field("config", &REDACTED)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// Everything a just-in-time registration can fail with.
///
/// The three GitHub answers `c4`'s specification names are **distinct outcomes,
/// not one error**, because an operator's next action differs for each and a
/// caller's does too: `403` is terminal and needs a permissions or runner-group
/// change, `404` means the target or the group is not there, and `422` means the
/// request itself was rejected.
///
/// # None of these carries the encoded configuration
///
/// Every variant is built from the request — target, runner group, name — and
/// from GitHub's own `message` field. A failing response has no
/// `encoded_jit_config` to leak, and a `201` that fails to *decode* is reported
/// through [`GithubError::Decode`], which carries a `serde_json::Error` and not
/// the body. `an_error_never_carries_the_encoded_configuration` pins it.
#[derive(Debug, thiserror::Error)]
pub enum JitError {
    /// GitHub refused: the permission or the runner group does not allow it.
    ///
    /// **Terminal.** Nothing retries this, and nothing may: `d17` is the record
    /// of what a `403` on this family of endpoints means and what it does not.
    #[error(
        "GitHub refused just-in-time runner registration for {target} in runner group \
         {runner_group_id}{}. This is terminal — retrying will not change it. Check that the \
         App installation grants `Administration: Read and write` for a repository target or \
         `Self-hosted runners: Read and write` for an organization target, and that runner \
         group {runner_group_id} is one this installation may administer; a GitHub-hosted \
         runner group answers 403 and cannot be used",
        message.as_deref().map(|m| format!(" ({m})")).unwrap_or_default()
    )]
    Forbidden {
        target: String,
        runner_group_id: u64,
        message: Option<String>,
    },

    /// GitHub found neither the target nor the runner group.
    ///
    /// Separate from [`JitError::Forbidden`] because `v1` measured both answers
    /// from the same mistake: a group that does not exist is `404`, a group that
    /// exists but is not administrable is `403`. Collapsing them tells an
    /// operator to create a group that is already there.
    #[error(
        "GitHub could not find the just-in-time registration target {target} or runner group \
         {runner_group_id}{}. Check the target name, and that runner group \
         {runner_group_id} exists — a group id that does not exist answers 404, while one \
         that exists but cannot be administered answers 403",
        message.as_deref().map(|m| format!(" ({m})")).unwrap_or_default()
    )]
    NotFound {
        target: String,
        runner_group_id: u64,
        message: Option<String>,
    },

    /// GitHub rejected the request body: the name or the label set.
    #[error(
        "GitHub rejected the just-in-time runner registration for {target}{}. The runner name \
         or the label set is not acceptable: `labels` must hold at least one item and \
         `runner_group_id` is required",
        message.as_deref().map(|m| format!(" ({m})")).unwrap_or_default()
    )]
    Rejected {
        target: String,
        message: Option<String>,
    },

    /// GitHub is rate limiting this credential. Resolves by waiting, and is the
    /// one failure here that is not about the request.
    #[error("{0}")]
    RateLimited(RateLimited),

    /// The caller withdrew the registration before it completed.
    #[error("the just-in-time runner registration was cancelled before it completed")]
    Cancelled,

    #[error(transparent)]
    Github(#[from] GithubError),
}

impl JitError {
    /// Whether retrying this exact request could ever produce a different
    /// answer.
    ///
    /// `403`, `404` and `422` are all `true` here, and a `403` **must** be:
    /// `c4`'s specification says "a `403` must never become a retry loop", and
    /// `d17` is the record of a design that spent a spike discovering what a
    /// `403` on this family of endpoints means. A rejected credential is
    /// terminal too — it resolves by an interactive `auth login`, not by
    /// retrying.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Forbidden { .. } | Self::NotFound { .. } | Self::Rejected { .. } => true,
            // Only the rejected credential. An authentication *lockout* is not
            // terminal — it is the one 403 that resolves by waiting — and a
            // transport failure resolves when the network does.
            Self::Github(error) => matches!(error, GithubError::AuthenticationFailed),
            Self::RateLimited(_) | Self::Cancelled => false,
        }
    }

    /// The rate limit behind this failure, when there is one.
    #[must_use]
    pub fn rate_limited(&self) -> Option<&RateLimited> {
        match self {
            Self::RateLimited(limit) => Some(limit),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }

    /// What an operator can actually do about this, or `None` when there is
    /// nothing for them to do.
    ///
    /// Every terminal outcome has one, which is what "terminal and
    /// operator-actionable" means: a failure a human cannot act on and a
    /// program will not retry is a dead end. `None` is correct for a rate limit
    /// and a cancellation — both resolve without anyone doing anything.
    #[must_use]
    pub fn operator_action(&self) -> Option<String> {
        match self {
            Self::Forbidden {
                target,
                runner_group_id,
                ..
            } => Some(format!(
                "Grant the App installation `Administration: Read and write` on {target} (or \
                 `Self-hosted runners: Read and write` for an organization), and use a runner \
                 group this installation may administer — runner group {runner_group_id} \
                 answered 403, which a GitHub-hosted group always does."
            )),
            Self::NotFound {
                target,
                runner_group_id,
                ..
            } => Some(format!(
                "Check that {target} is spelled correctly and still exists, and that runner \
                 group {runner_group_id} exists in it."
            )),
            Self::Rejected { target, .. } => Some(format!(
                "Correct the runner name or the routing labels for {target}: the label set \
                 must hold at least one label."
            )),
            Self::Github(GithubError::AuthenticationFailed) => {
                Some("Run `runner-manager auth login` to sign in again.".to_string())
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// The gateway
// ---------------------------------------------------------------------------

/// Just-in-time runner registration.
///
/// A trait for [`crate::rest::InventoryGateway`]'s reason: `e3`'s launch path is
/// tested against `runner_manager_testkit::github::FakeGithub`, with no network
/// and no `wiremock` in its dependency graph. [`RestJit`] is the one
/// implementation that talks to GitHub.
#[async_trait::async_trait]
pub trait JitGateway: fmt::Debug + Send + Sync {
    /// Register one ephemeral runner and return its configuration.
    ///
    /// # Errors
    /// Every variant of [`JitError`].
    async fn generate_jit_config(
        &self,
        target: &ScaleTarget,
        request: &JitRunnerRequest,
        cancel: &CancelToken,
    ) -> Result<JitRegistration, JitError>;
}

/// [`JitGateway`] over `api.github.com`.
///
/// Holds no credential of its own: authentication is entirely
/// [`AuthenticatedClient`]'s, and this type only ever hands it an
/// [`ApiRequest`] — whose `Debug` renders the body as `[REDACTED JSON]`, which
/// matters here because this is the one place in the crate that posts one.
pub struct RestJit {
    client: Arc<AuthenticatedClient>,
    requests_issued: AtomicU64,
}

impl fmt::Debug for RestJit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RestJit")
            .field(
                "requests_issued",
                &self.requests_issued.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl RestJit {
    #[must_use]
    pub fn new(client: Arc<AuthenticatedClient>) -> Self {
        Self {
            client,
            requests_issued: AtomicU64::new(0),
        }
    }

    /// How many HTTP requests this gateway has issued.
    ///
    /// This is how "no code path retries a `403`" is asserted rather than
    /// asserted about: one refused registration must leave this at one.
    #[must_use]
    pub fn requests_issued(&self) -> u64 {
        self.requests_issued.load(Ordering::SeqCst)
    }

    /// The `generate-jitconfig` path for either scope.
    ///
    /// One function rather than a branch at each call site, because `v1`'s whole
    /// organization finding is that the two differ in nothing but this string.
    #[must_use]
    pub fn path(target: &ScaleTarget) -> String {
        match target {
            ScaleTarget::Repository(repo) => format!(
                "/repos/{}/{}{JITCONFIG_PATH}",
                repo.owner(),
                repo.repo()
            ),
            ScaleTarget::Organization(org) => {
                format!("/orgs/{}{JITCONFIG_PATH}", org.as_str())
            }
        }
    }

    /// Map a failure onto the outcome a caller branches on.
    ///
    /// Order matters. [`RateLimited::detect`] runs first because GitHub answers
    /// a secondary rate limit with a `403`, and reporting that as a permissions
    /// refusal would tell an operator to change a permission that is already
    /// correct. `c3` owns that decision procedure and this consumes it rather
    /// than writing a second one.
    fn classify(error: GithubError, target: &ScaleTarget, runner_group_id: u64) -> JitError {
        if let Some(limit) = RateLimited::detect(&error) {
            return JitError::RateLimited(limit);
        }
        let target = target.slug();
        match &error {
            GithubError::Forbidden { message, .. } => JitError::Forbidden {
                target,
                runner_group_id,
                message: message.clone(),
            },
            GithubError::Status {
                status: 404,
                message,
                ..
            } => JitError::NotFound {
                target,
                runner_group_id,
                message: message.clone(),
            },
            GithubError::Status {
                status: 422,
                message,
                ..
            } => JitError::Rejected {
                target,
                message: message.clone(),
            },
            _ => JitError::Github(error),
        }
    }

    fn from_inventory(error: InventoryError, target: &ScaleTarget, runner_group_id: u64) -> JitError {
        match error {
            InventoryError::Cancelled => JitError::Cancelled,
            InventoryError::RateLimited(limit) => JitError::RateLimited(limit),
            InventoryError::Github(error) => Self::classify(error, target, runner_group_id),
        }
    }
}

#[async_trait::async_trait]
impl JitGateway for RestJit {
    async fn generate_jit_config(
        &self,
        target: &ScaleTarget,
        request: &JitRunnerRequest,
        cancel: &CancelToken,
    ) -> Result<JitRegistration, JitError> {
        let group = request.runner_group_id();
        let api_request = ApiRequest::post_json(Self::path(target), &request.body())
            .map_err(|error| Self::classify(error, target, group))?;

        // `CancelToken` is `c3`'s, and reusing it rather than inventing a second
        // cancellation type is what lets `e1` hold one token across a refresh
        // and the registration it decides on.
        let response = cancel
            .run(async {
                // Counted inside the future for `c3`'s reason: `run`'s biased
                // `select!` answers `Cancelled` without polling this block when
                // the token is already flipped, so no socket is opened and the
                // count stays a count of requests actually attempted.
                self.requests_issued.fetch_add(1, Ordering::SeqCst);
                self.client
                    .send(&api_request)
                    .await
                    .map_err(InventoryError::from)
            })
            .await
            .map_err(|error| Self::from_inventory(error, target, group))?;

        debug_assert_eq!(
            response.status().as_u16(),
            CREATED,
            "`AuthenticatedClient::send` returns `Ok` only for a success status, and this \
             endpoint's success status is 201; anything else here means the client's \
             classification changed underneath this module"
        );

        let decoded: JitResponse = response.json().map_err(JitError::Github)?;
        // Copied into the wrapper, then the intermediate scrubbed. serde owns
        // this `String`, so it is the one copy of the secret this module can
        // actually reach; the response buffer behind it is `c2`'s and is
        // documented as the residual exposure at the top of this file.
        let mut raw = decoded.encoded_jit_config;
        let config = EncodedJitConfig::new(raw.as_str());
        raw.zeroize();

        tracing::debug!(
            target = %target,
            runner_id = decoded.runner.id,
            runner_name = %decoded.runner.name,
            runner_group_id = decoded.runner.runner_group_id,
            config_bytes = config.len(),
            "registered a just-in-time runner"
        );

        Ok(JitRegistration::new(
            config,
            JitRunner {
                id: decoded.runner.id,
                name: decoded.runner.name,
                os: decoded.runner.os,
                status: decoded.runner.status,
                busy: decoded.runner.busy,
                runner_group_id: decoded.runner.runner_group_id,
                labels: decoded
                    .runner
                    .labels
                    .into_iter()
                    .map(|label| label.name)
                    .collect(),
            },
        ))
    }
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

/// The `201` body. `v1`: "top-level keys: `runner`, `encoded_jit_config` —
/// exactly two", and "the response shape is **identical to the repository
/// form**", which is why one type serves both scopes.
#[derive(Debug, Deserialize)]
struct JitResponse {
    encoded_jit_config: String,
    runner: RawJitRunner,
}

#[derive(Debug, Deserialize)]
struct RawJitRunner {
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    busy: bool,
    runner_group_id: Option<u64>,
    #[serde(default)]
    labels: Vec<RawJitLabel>,
}

#[derive(Debug, Deserialize)]
struct RawJitLabel {
    name: String,
}

// Inline for the reason `rest.rs` records: `lib.rs`'s
// `the_confidential_credential_scan_covers_every_source_file` requires every
// `.rs` file under `src/` to appear in a list `c2` owns, so a second file here
// could only be added by editing another task's file.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FIXTURE_TOKEN, TestClock};
    use crate::{Endpoints, UserAccessToken};
    use runner_manager_domain::model::{Arch, HostLabel, Os};
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    /// Shaped like a real encoded configuration — base64url of a JSON envelope —
    /// and unmistakably not one. Long enough that a truncating leak still
    /// contains a recognisable prefix.
    const FIXTURE_JIT_CONFIG: &str = concat!(
        "eyJmaXh0dXJlIjoibm90LWEtcmVhbC1qaXQtY29uZmlndXJhdGlvbiIsIm5vdGUiOiJpZi",
        "B0aGlzIHN0cmluZyBhcHBlYXJzIGluIGEgbG9nIHRoZSByZWRhY3Rpb24gZmFpbGVkIn0"
    );

    fn repo_target() -> ScaleTarget {
        ScaleTarget::repository("octo/dashboard").expect("a valid owner/repo")
    }

    fn org_target() -> ScaleTarget {
        ScaleTarget::organization("octo-org").expect("a valid organization login")
    }

    /// Both scopes, so that every test written over this list runs against each
    /// one. `v1`'s finding is that the two differ in nothing but the path, and
    /// a list is how that stops being a claim.
    fn both_scopes() -> Vec<ScaleTarget> {
        vec![repo_target(), org_target()]
    }

    fn gateway(server: &MockServer) -> RestJit {
        let client = AuthenticatedClient::new(
            Endpoints::for_test_server(&server.uri()).expect("a valid test base"),
            UserAccessToken::new(SecretString::from(FIXTURE_TOKEN)),
            Arc::new(TestClock::default()),
        )
        .expect("the HTTP client builds");
        RestJit::new(Arc::new(client))
    }

    fn request() -> JitRunnerRequest {
        JitRunnerRequest::new(
            "rm-home-win-x64-0001",
            3,
            ["rm-home-win-x64", "self-hosted"],
        )
    }

    /// The `201` body, in the shape `v1` read back from live GitHub.
    fn created_body(labels: &[&str]) -> Value {
        json!({
            "runner": {
                "id": 73,
                "name": "rm-home-win-x64-0001",
                "os": "windows",
                "status": "offline",
                "busy": false,
                "runner_group_id": 3,
                "labels": labels
                    .iter()
                    .map(|name| json!({ "id": 1, "name": name, "type": "read-only" }))
                    .collect::<Vec<_>>()
            },
            "encoded_jit_config": FIXTURE_JIT_CONFIG
        })
    }

    async fn mount_created(server: &MockServer, target: &ScaleTarget, body: Value) {
        Mock::given(method("POST"))
            .and(path(RestJit::path(target)))
            .respond_with(ResponseTemplate::new(201).set_body_json(body))
            .mount(server)
            .await;
    }

    async fn mount_failure(server: &MockServer, target: &ScaleTarget, status: u16, message: &str) {
        Mock::given(method("POST"))
            .and(path(RestJit::path(target)))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(json!({ "message": message })),
            )
            .mount(server)
            .await;
    }

    // -- the happy path, at both scopes under one body ----------------------

    /// The documented body shape goes out and the `201` comes back decoded — at
    /// repository scope and at organization scope, under one shared test body.
    #[tokio::test]
    async fn a_201_decodes_into_the_configuration_and_the_runner_at_either_scope() {
        for target in both_scopes() {
            let server = MockServer::start().await;
            // `body_json` is an *exact* match on the whole object, so an extra
            // key, a missing key or a renamed key fails here rather than
            // silently reaching GitHub. This is the pin for "sends exactly the
            // documented body shape".
            Mock::given(method("POST"))
                .and(path(RestJit::path(&target)))
                .and(body_json(json!({
                    "name": "rm-home-win-x64-0001",
                    "runner_group_id": 3,
                    "labels": ["rm-home-win-x64", "self-hosted"],
                    "work_folder": "_work"
                })))
                .respond_with(
                    ResponseTemplate::new(201)
                        .set_body_json(created_body(&["rm-home-win-x64", "self-hosted"])),
                )
                .mount(&server)
                .await;

            let gateway = gateway(&server);
            let registration = gateway
                .generate_jit_config(&target, &request(), &CancelToken::new())
                .await
                .unwrap_or_else(|error| panic!("a 201 at {target}: {error}"));

            assert_eq!(
                registration.config().expose(),
                FIXTURE_JIT_CONFIG,
                "the encoded configuration must survive the round trip at {target}"
            );
            assert_eq!(registration.runner().id, 73);
            assert_eq!(registration.runner().name, "rm-home-win-x64-0001");
            assert_eq!(
                registration.runner().runner_group_id,
                Some(3),
                "the runner reference carries the group it was registered in, which \
                 `c3`'s inventory shape has no field for"
            );
            assert_eq!(
                registration.runner().labels,
                vec!["rm-home-win-x64".to_string(), "self-hosted".to_string()],
                "no labels are added implicitly, so the 201 carries exactly what was sent"
            );
            assert_eq!(gateway.requests_issued(), 1);
        }
    }

    /// The path differs between scopes and nothing else does.
    #[test]
    fn the_two_scopes_differ_only_in_the_path() {
        assert_eq!(
            RestJit::path(&repo_target()),
            "/repos/octo/dashboard/actions/runners/generate-jitconfig"
        );
        assert_eq!(
            RestJit::path(&org_target()),
            "/orgs/octo-org/actions/runners/generate-jitconfig"
        );
        assert!(
            RestJit::path(&repo_target()).ends_with(JITCONFIG_PATH)
                && RestJit::path(&org_target()).ends_with(JITCONFIG_PATH),
            "one suffix, two prefixes -- that is the whole of `v1`'s organization finding"
        );
    }

    /// `runner_group_id` is always on the wire, because it cannot be omitted.
    ///
    /// `v1` measured the alternative: omitting the key answers `422 Invalid
    /// input: object is missing required key: runner_group_id`. There is no
    /// server-side default, so the field is a required constructor argument and
    /// the serialised body carries no attribute that could ever drop it.
    #[test]
    fn the_request_body_is_exactly_the_four_documented_keys() {
        let body = serde_json::to_value(request().body()).expect("the body serialises");
        let object = body.as_object().expect("a JSON object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["labels", "name", "runner_group_id", "work_folder"],
            "`04-subsystem-contracts.md` types this body as {{name, runner_group_id, \
             labels, work_folder}}; an extra key is an untested request and a missing \
             `runner_group_id` is a 422"
        );
        assert_eq!(object["runner_group_id"], json!(3));
        assert_eq!(object["work_folder"], json!("_work"));

        // `1` is not special: `v1` registered successfully in group 3.
        let other = JitRunnerRequest::new("n", 99, ["a"]);
        assert_eq!(
            serde_json::to_value(other.body()).expect("serialises")["runner_group_id"],
            json!(99),
            "any administrable group id works, so nothing here may assume 1"
        );
    }

    /// The labels sent are the policy's, verbatim and lower-cased, with nothing
    /// added.
    #[test]
    fn a_policy_registers_exactly_its_own_routing_labels() {
        let labels = RoutingLabels::derive(
            &HostLabel::new("home").expect("a valid host label"),
            Os::Windows,
            Arch::X64,
        );
        let request = JitRunnerRequest::for_policy("runner-1", 1, &labels);

        assert_eq!(request.labels(), &["rm-home-win-x64".to_string()]);
        assert!(
            !request.labels().iter().any(|label| label == "self-hosted"),
            "`v1` established that no labels are added implicitly; adding one here would \
             make a runner answer a `runs-on` the operator never asked it to"
        );
        assert!(
            request.labels().iter().all(|l| l == &l.to_ascii_lowercase()),
            "GitHub stores labels lower-cased, so what is sent and what is stored must be \
             the same string"
        );
    }

    // -- the three failure modes -------------------------------------------

    /// `403`, `404` and `422` are three outcomes, not one — and none of them is
    /// retried.
    #[tokio::test]
    async fn each_failure_status_is_a_distinct_outcome_and_none_is_retried() {
        for target in both_scopes() {
            // 403: the permission or the group does not allow it.
            let server = MockServer::start().await;
            mount_failure(
                &server,
                &target,
                403,
                "GitHub hosted runner groups cannot be modified",
            )
            .await;
            let refused = gateway(&server);
            let error = refused
                .generate_jit_config(&target, &request(), &CancelToken::new())
                .await
                .expect_err("a 403 is a failure");
            assert!(
                matches!(error, JitError::Forbidden { runner_group_id: 3, .. }),
                "a 403 must be its own outcome and must name the group: {error:?}"
            );
            assert!(error.is_terminal(), "a 403 is terminal");
            assert!(
                error.operator_action().is_some(),
                "terminal and operator-actionable: a failure nobody can act on and nothing \
                 retries is a dead end"
            );
            assert_eq!(
                refused.requests_issued(),
                1,
                "no code path may retry a 403; `d17` is the record of what it means"
            );

            // 404: the target or the group is not there.
            let server = MockServer::start().await;
            mount_failure(&server, &target, 404, "Not Found").await;
            let missing = gateway(&server);
            let error = missing
                .generate_jit_config(&target, &request(), &CancelToken::new())
                .await
                .expect_err("a 404 is a failure");
            assert!(
                matches!(error, JitError::NotFound { runner_group_id: 3, .. }),
                "a 404 must be its own outcome: {error:?}"
            );
            assert!(error.is_terminal());
            assert_eq!(missing.requests_issued(), 1);

            // 422: the body was rejected.
            let server = MockServer::start().await;
            mount_failure(
                &server,
                &target,
                422,
                "Invalid property /labels: 1 item required; only 0 were supplied",
            )
            .await;
            let rejected = gateway(&server);
            let error = rejected
                .generate_jit_config(&target, &request(), &CancelToken::new())
                .await
                .expect_err("a 422 is a failure");
            assert!(
                matches!(error, JitError::Rejected { .. }),
                "a 422 must be its own outcome: {error:?}"
            );
            assert!(error.is_terminal());
            assert_eq!(rejected.requests_issued(), 1);
        }
    }

    /// An unusable runner group answers `403` **or** `404`, and the two must not
    /// be collapsed.
    ///
    /// `v1` measured both from the same operator mistake — a wrong
    /// `runner_group_id`. Group `2`, the GitHub-hosted group, answered `403`;
    /// group `99999` answered `404`. Error handling keyed on `404` alone tells
    /// an operator to create a group that already exists.
    #[tokio::test]
    async fn an_unusable_runner_group_is_reported_differently_for_403_and_404() {
        let target = org_target();

        let server = MockServer::start().await;
        mount_failure(
            &server,
            &target,
            403,
            "GitHub hosted runner groups cannot be modified",
        )
        .await;
        let hosted_group = gateway(&server)
            .generate_jit_config(&target, &JitRunnerRequest::new("n", 2, ["a"]), &CancelToken::new())
            .await
            .expect_err("group 2 is not administrable");

        let server = MockServer::start().await;
        mount_failure(&server, &target, 404, "Not Found").await;
        let missing_group = gateway(&server)
            .generate_jit_config(
                &target,
                &JitRunnerRequest::new("n", 99_999, ["a"]),
                &CancelToken::new(),
            )
            .await
            .expect_err("group 99999 does not exist");

        assert!(matches!(hosted_group, JitError::Forbidden { runner_group_id: 2, .. }));
        assert!(matches!(missing_group, JitError::NotFound { runner_group_id: 99_999, .. }));
        assert_ne!(
            hosted_group.operator_action(),
            missing_group.operator_action(),
            "the two answers need different remedies: one is a permission on an existing \
             group, the other is a group that is not there"
        );
        assert!(
            hosted_group.to_string().contains("403"),
            "the 403 message must explain that a GitHub-hosted group always answers this"
        );
        assert!(
            missing_group.to_string().contains("404"),
            "and the 404 message must explain the difference in the other direction"
        );
    }

    /// A secondary rate limit arrives as a `403`, and must not be reported as a
    /// permissions refusal.
    ///
    /// A rate limit resolves by waiting; a permissions refusal does not resolve
    /// at all. Reporting the first as the second tells an operator to change a
    /// permission that is already correct, and — worse here — marks a transient
    /// failure terminal, so the runner is never registered.
    #[tokio::test]
    async fn a_rate_limit_wearing_a_403_is_not_a_permissions_refusal() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(RestJit::path(&repo_target())))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("retry-after", "60")
                    .set_body_json(json!({
                        "message": "You have exceeded a secondary rate limit"
                    })),
            )
            .mount(&server)
            .await;

        let error = gateway(&server)
            .generate_jit_config(&repo_target(), &request(), &CancelToken::new())
            .await
            .expect_err("a rate limit is a failure");

        assert!(
            error.rate_limited().is_some(),
            "`c3`'s detector owns this decision and it said rate limit: {error:?}"
        );
        assert!(
            !error.is_terminal(),
            "a rate limit resolves by waiting; marking it terminal never registers the runner"
        );
        assert!(error.operator_action().is_none());
    }

    /// A cancelled registration opens no socket at all.
    #[tokio::test]
    async fn a_cancelled_registration_issues_no_request() {
        let server = MockServer::start().await;
        mount_created(&server, &repo_target(), created_body(&["a"])).await;
        let gateway = gateway(&server);
        let cancel = CancelToken::new();
        cancel.cancel();

        let error = gateway
            .generate_jit_config(&repo_target(), &request(), &cancel)
            .await
            .expect_err("a cancelled token withdraws the registration");
        assert!(error.is_cancelled());
        assert_eq!(
            gateway.requests_issued(),
            0,
            "the count is of requests actually attempted, and a withdrawn one is not"
        );
    }

    // -- the secret ---------------------------------------------------------

    /// The configuration is absent from `Debug` and from `Display`.
    #[test]
    fn the_configuration_is_absent_from_debug_and_display() {
        let config = EncodedJitConfig::new(FIXTURE_JIT_CONFIG);

        let debug = format!("{config:?}");
        let display = format!("{config}");
        assert!(!debug.contains(FIXTURE_JIT_CONFIG), "Debug leaked it: {debug}");
        assert!(
            !display.contains(FIXTURE_JIT_CONFIG),
            "Display leaked it: {display}"
        );
        assert!(debug.contains(REDACTED) && display.contains(REDACTED));
        assert!(
            debug.contains(&format!("{} bytes", FIXTURE_JIT_CONFIG.len())),
            "the length is useful and is not the secret: {debug}"
        );

        // And through the registration that carries it, which is what a caller
        // actually holds.
        let registration = JitRegistration::new(
            EncodedJitConfig::new(FIXTURE_JIT_CONFIG),
            JitRunner {
                id: 73,
                name: "runner".into(),
                os: "windows".into(),
                status: "offline".into(),
                busy: false,
                runner_group_id: Some(1),
                labels: vec!["rm-home-win-x64".into()],
            },
        );
        let rendered = format!("{registration:?}");
        assert!(
            !rendered.contains(FIXTURE_JIT_CONFIG),
            "the registration's Debug leaked it: {rendered}"
        );
        assert!(rendered.contains("runner"), "and still says something useful");
    }

    /// The scan above can actually see a leak.
    ///
    /// A redaction test that never had the secret in reach passes for the wrong
    /// reason. This plants the exact mistake `lib.rs`'s crate documentation
    /// names — a plain `String` field with a derived `Debug` — and requires the
    /// same assertions to catch it.
    #[test]
    fn the_redaction_assertions_would_catch_a_derived_debug_over_a_plain_string() {
        #[derive(Debug)]
        struct ConfigWithADerivedDebug {
            #[allow(dead_code)]
            encoded_jit_config: String,
        }

        let leaky = ConfigWithADerivedDebug {
            encoded_jit_config: FIXTURE_JIT_CONFIG.to_string(),
        };
        assert!(
            format!("{leaky:?}").contains(FIXTURE_JIT_CONFIG),
            "the assertions above cannot see a plain-String secret rendered through a \
             derived Debug, so every one of them is worthless"
        );
    }

    /// The wrapper's buffer is zeroised.
    ///
    /// `scrub` is exactly the call [`Drop::drop`] makes. Observing the buffer
    /// *after* the drop would mean reading freed memory, which is undefined
    /// behaviour and would be a test that proves nothing while appearing to
    /// prove everything; this invokes the same code on a live value instead.
    #[test]
    fn the_wrapper_scrubs_its_buffer() {
        let mut config = EncodedJitConfig::new(FIXTURE_JIT_CONFIG);
        assert_eq!(
            config.expose(),
            FIXTURE_JIT_CONFIG,
            "the fixture has to be really in there, or the assertion below is vacuous"
        );

        config.scrub();

        assert!(
            config.expose().bytes().all(|byte| byte == 0),
            "every byte of the buffer must be zero after a scrub, not merely unreachable"
        );
        assert!(!config.expose().contains("eyJ"));
        assert_eq!(
            config.len(),
            FIXTURE_JIT_CONFIG.len(),
            "`str::zeroize` overwrites in place rather than shortening, so the length is \
             unchanged and every byte of it is zero"
        );
    }

    /// No error value carries the encoded configuration, on any path.
    #[tokio::test]
    async fn an_error_never_carries_the_encoded_configuration() {
        // A `201` whose body cannot be decoded is the one failure that has the
        // secret in reach: the response really does carry it.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(RestJit::path(&repo_target())))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "encoded_jit_config": FIXTURE_JIT_CONFIG,
                "runner": { "name": "no id field, so this cannot decode" }
            })))
            .mount(&server)
            .await;

        let error = gateway(&server)
            .generate_jit_config(&repo_target(), &request(), &CancelToken::new())
            .await
            .expect_err("a 201 missing `runner.id` cannot decode");

        let rendered = format!("{error} {error:?}");
        assert!(
            !rendered.contains(FIXTURE_JIT_CONFIG),
            "a decode failure must not carry the body it failed to decode: {rendered}"
        );
        assert!(
            !rendered.contains("eyJ"),
            "not even a prefix of it: {rendered}"
        );

        // And the three failure statuses, each answered with a body that carries
        // an `encoded_jit_config` key it has no business carrying. GitHub does
        // not send one on a failure; the point is that a variant which ever
        // rendered a response *body* rather than its `message` would be caught
        // here rather than in production.
        for status in [403_u16, 404, 422] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(RestJit::path(&repo_target())))
                .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                    "message": "Resource not accessible by integration",
                    "encoded_jit_config": FIXTURE_JIT_CONFIG
                })))
                .mount(&server)
                .await;
            let error = gateway(&server)
                .generate_jit_config(&repo_target(), &request(), &CancelToken::new())
                .await
                .expect_err("a failure status");

            let rendered = format!("{error} {error:?}");
            assert!(
                !rendered.contains(FIXTURE_JIT_CONFIG),
                "a {status} rendered a response body verbatim: {rendered}"
            );
            // GitHub's own `message` is the opposite requirement, and both have
            // to hold at once: an error that redacted the message along with the
            // body would be safe and useless. `Resource not accessible by
            // integration` is the sentence that tells an operator which
            // permission is missing.
            assert!(
                rendered.contains("Resource not accessible by integration"),
                "GitHub's message is what makes a {status} operator-actionable and must \
                 survive: {rendered}"
            );
        }
    }

    /// A registration whose response reports different labels than were
    /// requested is still returned, and says so.
    ///
    /// `v1` observed that label *order* is not preserved and that labels come
    /// back lower-cased, so an equality check on the array would fail on a
    /// correct registration. The runner reference carries what GitHub stored, and
    /// comparing is the caller's business.
    #[tokio::test]
    async fn the_runner_reference_reports_the_labels_github_actually_stored() {
        let server = MockServer::start().await;
        mount_created(
            &server,
            &repo_target(),
            created_body(&["self-hosted", "rm-home-win-x64"]),
        )
        .await;

        let registration = gateway(&server)
            .generate_jit_config(&repo_target(), &request(), &CancelToken::new())
            .await
            .expect("a 201");

        assert_eq!(
            registration.runner().labels,
            vec!["self-hosted".to_string(), "rm-home-win-x64".to_string()],
            "what GitHub stored, in the order GitHub returned it -- `v1` established that \
             the order is not the order requested"
        );
    }
}
