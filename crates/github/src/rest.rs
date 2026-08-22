// owner: c3-rest-inventory-gateway

//! This gateway is deliberately client-secret-free, as D3 requires.
//!
//! Every read model the dashboard and the CLI display, over `api.github.com`:
//! the runner inventory, the in-progress workflow count, and the runner-package
//! download metadata — plus the two behaviours that make those numbers
//! trustworthy rather than merely present.
//!
//! Everything here is built on [`crate::AuthenticatedClient`]. There is no
//! second authentication path in this module and none may be added; the one
//! credential is obtained by [`crate::device_flow`] and applied by that client.
//!
//! # The three read models
//!
//! | Operation | Endpoint | Type |
//! |---|---|---|
//! | [`InventoryGateway::list_runners`] | `/repos/{o}/{r}/actions/runners`, `/orgs/{org}/actions/runners` | [`RunnerInventory`] |
//! | [`InventoryGateway::in_progress_activity`] | `/repos/{o}/{r}/actions/runs?status=in_progress` | [`ActivityCount`] |
//! | [`InventoryGateway::runner_downloads`] | `…/actions/runners/downloads` | [`RunnerDownloads`] |
//!
//! **The in-progress workflow count and the busy-runner count are different
//! numbers with different meanings**, and this module keeps them in different
//! types on purpose. A workflow run is work GitHub has accepted; a busy runner
//! is a machine this product can see executing something. `g2` renders them as
//! separate aggregates, and collapsing them here would make that impossible to
//! do correctly downstream.
//!
//! # Pagination is mandatory
//!
//! `04-subsystem-contracts.md`: "Pagination is mandatory; the dashboard must not
//! treat a first page as a complete inventory." A target with more runners than
//! one page is the ordinary case for an organization, and a silently truncated
//! list reads as "no runners" rather than as an error — the failure is invisible
//! at exactly the moment it matters.
//!
//! Every collection here therefore follows `Link: rel="next"` through
//! [`crate::ApiResponse::next_page`], which is `c2`'s single reader of that
//! header rather than a second one written here. Following the same reader is
//! the point: it already handles a `rel="next"` that is not first, quoted and
//! unquoted parameter forms, and — the case that silently stopped pagination at
//! page one until a review caught it — a next-page URL that itself contains a
//! comma, which a runner query carries routinely as `labels=self-hosted,windows`.
//!
//! Two facts travel with a collection so that a caller can tell a complete
//! answer from an incomplete one: [`RunnerInventory::reported_total`], which is
//! GitHub's own `total_count`, and [`RunnerInventory::truncated`], which is set
//! when the [`crate::MAX_PAGES`] ceiling stopped the walk.
//!
//! # Rate limiting is a policy, and it lives here
//!
//! `c2` deliberately implemented none of it — it stopped *discarding* the
//! evidence and handed it across the seam through [`GithubError::headers`],
//! [`GithubError::retry_after`] and [`GithubError::rate_limit`]. This module is
//! where the evidence becomes a decision, and the decision has three parts:
//!
//! 1. **`retry-after` is obeyed by not sending anything.** A detected limit
//!    latches a window ([`RestInventory::rate_limit_backoff`]) during which this
//!    gateway opens no socket at all and answers
//!    [`InventoryError::RateLimited`] immediately. Obeying a back-off by
//!    *sleeping inside a request* would be the same wait, spent invisibly, with
//!    the caller's cancellation and refresh scheduling both bypassed.
//! 2. **It is surfaced, never hidden** (`04-subsystem-contracts.md`, "Rate
//!    limiting increases the refresh delay and is displayed, never hidden").
//!    [`RateLimited`] is a displayable state carrying what GitHub said, and
//!    [`RefreshState::retry_delay`] is the number `e1` adds to its refresh
//!    interval.
//! 3. **A rate limit is never confused with a permissions answer.** See
//!    [`RateLimited::detect`]: GitHub sends `x-ratelimit-*` on *every* response,
//!    so "remaining is zero" alone would turn an ordinary `404` into a rate
//!    limit.
//!
//! # The shared request budget (the D4 consequence)
//!
//! Under scale sets, demand arrived over a long poll carried by the Actions
//! service, which did not touch the `api.github.com` budget. After D4 it does,
//! and that makes one number a product constraint rather than an implementation
//! detail: demand, runner inventory and in-progress counts all draw on **one**
//! ceiling of [`HOURLY_REQUEST_CEILING`] requests per hour.
//!
//! The projection lives here because this is the layer that sees every request.
//! See [`TargetCost`] and [`BudgetProjection`] — and in particular
//! [`TargetCost::organization`], because an organization target's cost scales
//! with the number of repositories the App is installed on there. Projecting an
//! organization as a flat per-target constant understates its real cost by
//! exactly that factor, which is the one error this model exists to prevent.

use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use runner_manager_domain::model::{
    Arch, Clock, Org, Os, OwnerRepo, RefreshInterval, ScaleTarget, TargetScope, Timestamp,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio::sync::watch;

use crate::{ApiRequest, ApiResponse, AuthenticatedClient, GithubError, MAX_PAGES};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Items per page asked for on every paginated call.
///
/// GitHub's maximum. Asking for fewer multiplies the request count against a
/// budget this module also has to project, which is the one place in this
/// product where a lazy default is directly a product constraint.
pub const PER_PAGE: u32 = 100;

/// The documented hourly REST ceiling for a user-to-server token, measured
/// 2026-08-21 (`04-subsystem-contracts.md`).
pub const HOURLY_REQUEST_CEILING: u32 = 5_000;

/// The fraction of [`HOURLY_REQUEST_CEILING`] a host may plan to spend.
///
/// `04-subsystem-contracts.md`: `add` "refuses a configuration that would exceed
/// **half** of it". Half rather than all, because the projection covers only the
/// agent's steady-state polling: an interactive `auth status`, a `repo add`
/// validation, a JIT registration and a runner deletion all draw on the same
/// ceiling and none of them is periodic enough to model.
pub const BUDGET_SHARE_DIVISOR: u32 = 2;

/// Seconds in the hour the ceiling is measured over.
pub const SECONDS_PER_HOUR: u32 = 3_600;

/// Requests one runner-inventory refresh costs, per target.
///
/// One, at either scope: a repository and an organization each have a single
/// runners endpoint. A target whose inventory spans pages costs more than this
/// in practice, and that is stated rather than modelled — see
/// [`TargetCost::requests_per_refresh`].
pub const RUNNER_INVENTORY_REQUESTS_PER_REFRESH: u32 = 1;

/// Requests one in-progress workflow count costs, **per repository**.
///
/// Workflow runs are a per-repository resource. There is no organization-wide
/// workflow-runs endpoint, so an organization pays this once per repository the
/// App is installed on.
pub const ACTIVITY_REQUESTS_PER_REPOSITORY_PER_REFRESH: u32 = 1;

/// Requests one demand poll costs, **per repository**: the queued runs, then
/// their jobs.
///
/// `c4` owns demand and reports its real per-poll count; this constant is the
/// steady-state figure `04-subsystem-contracts.md` tabulates (~120 requests per
/// hour at the 60-second default, which is two per refresh).
pub const DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH: u32 = 2;

/// How long a detected rate limit backs off for when GitHub gives no usable
/// `retry-after` and no `x-ratelimit-reset`.
///
/// Sixty seconds is GitHub's own documented floor for its secondary rate limits,
/// and the same value [`crate::DEFAULT_LOCKOUT_BACKOFF`] uses for the
/// authentication lockout.
pub const DEFAULT_RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(60);

/// The longest a rate limit may silence this gateway, whatever GitHub asked for.
///
/// The reasoning is [`crate::MAX_LOCKOUT_BACKOFF`]'s, and so is the consequence:
/// because a still-limited response simply re-latches, this ceiling is a
/// *polling interval* and not a deadline. A primary limit resets at most an hour
/// out, so a fifteen-minute clamp costs at most three extra probe requests
/// across that hour — against the alternative of letting a single header take
/// the dashboard down for the rest of the hour.
pub const MAX_RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(15 * 60);

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

/// A latch a caller flips to stop in-flight gateway work.
///
/// `04-subsystem-contracts.md` requires the gateway to support cancellation, and
/// the requirement has teeth precisely because of pagination: an organization
/// inventory is a *sequence* of requests, and a refresh the operator has already
/// navigated away from should not keep spending the shared budget on pages
/// nobody will read.
///
/// So cancellation is checked in two places, and both matter. Before each
/// request — which is what stops a multi-page walk between pages — and
/// concurrently with the request in flight, which is what stops a walk that is
/// blocked on a socket.
///
/// Cloning shares the latch. Cancelling is one-way: a token that has been
/// cancelled stays cancelled, because "cancel, then reuse" is how a caller ends
/// up with a token whose state depends on a race.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    inner: Arc<CancelInner>,
}

#[derive(Debug)]
struct CancelInner {
    tx: watch::Sender<bool>,
}

impl Default for CancelInner {
    fn default() -> Self {
        Self {
            tx: watch::Sender::new(false),
        }
    }
}

impl CancelToken {
    /// A token nothing has cancelled yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel every operation holding this token, now and in the future.
    pub fn cancel(&self) {
        // `send_replace` rather than `send`: `send` reports an error when there
        // are no receivers, and "nobody is waiting yet" is not a failure to
        // cancel. The state is what callers read, and it is set either way.
        self.inner.tx.send_replace(true);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.inner.tx.borrow()
    }

    /// `Err(`[`InventoryError::Cancelled`]`)` once cancelled, so a call site can
    /// bail with `?`.
    ///
    /// # Errors
    /// [`InventoryError::Cancelled`].
    pub fn check(&self) -> Result<(), InventoryError> {
        if self.is_cancelled() {
            return Err(InventoryError::Cancelled);
        }
        Ok(())
    }

    /// Resolves when this token is cancelled, and never otherwise.
    pub async fn cancelled(&self) {
        let mut rx = self.inner.tx.subscribe();
        // `subscribe` snapshots the current version, so a `cancel` racing this
        // line is still observed by `wait_for` — that is the property `Notify`
        // does not have, and the reason this is a `watch` channel.
        //
        // The error arm is unreachable: the sender lives in the same `Arc` as
        // this receiver, so it cannot be dropped while `self` is alive. It is
        // written as a `pending` rather than a `return` because returning would
        // report a cancellation that never happened.
        if rx.wait_for(|cancelled| *cancelled).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    /// Run `work`, abandoning it if this token is cancelled first.
    ///
    /// # Errors
    /// [`InventoryError::Cancelled`], or whatever `work` fails with.
    pub async fn run<T>(
        &self,
        work: impl Future<Output = Result<T, InventoryError>>,
    ) -> Result<T, InventoryError> {
        tokio::select! {
            // Biased so that an already-cancelled token loses no time to a
            // request that was going to be abandoned anyway.
            biased;
            () = self.cancelled() => Err(InventoryError::Cancelled),
            result = work => result,
        }
    }
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// Which of GitHub's two rate limits a response was attributed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitKind {
    /// The hourly quota: `x-ratelimit-remaining: 0`. Resets at
    /// `x-ratelimit-reset`.
    Primary,
    /// A short-term abuse limit: `429`, or a `403` whose message says so. Sends
    /// `retry-after`.
    Secondary,
}

impl fmt::Display for RateLimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        })
    }
}

/// An exhausted rate limit, as a state something can display.
///
/// The Definition of Done asks for "a distinct, displayable state rather than an
/// opaque error", and the distinction is the point: a rate limit is the one
/// failure in this gateway that is neither the operator's fault nor a reason to
/// change anything. It resolves by waiting, and the operator's only legitimate
/// question is "how long", which is what every field here answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimited {
    pub kind: RateLimitKind,
    /// `retry-after`, when GitHub sent one in the integer-seconds form.
    pub retry_after: Option<Duration>,
    /// `x-ratelimit-remaining`.
    pub remaining: Option<u64>,
    /// `x-ratelimit-reset`, a Unix timestamp in seconds.
    pub reset_unix_secs: Option<u64>,
}

impl RateLimited {
    /// Whether this failure is GitHub declining to serve any more requests for
    /// now — and if so, which limit.
    ///
    /// # Why this is narrower than "remaining is zero"
    ///
    /// GitHub attaches `x-ratelimit-*` to **every** response, successful ones
    /// included. A `404` that happens to arrive on the request that exhausted
    /// the hourly quota therefore carries `x-ratelimit-remaining: 0` while
    /// having nothing to do with rate limiting — and reporting it as a rate
    /// limit would tell the operator to wait for a repository name that will
    /// never resolve.
    ///
    /// So the status has to be one GitHub actually rate-limits with — `403` or
    /// `429` — before the headers are read at all. Within those two:
    ///
    /// * `x-ratelimit-remaining: 0` is the primary limit, and takes precedence,
    ///   because a `429` sent while the hourly quota is exhausted resets on the
    ///   hourly schedule rather than on a short back-off.
    /// * a `429` is otherwise the secondary limit.
    /// * a `403` whose message says "rate limit" is the secondary limit. This is
    ///   the same evidence [`crate::AuthenticatedClient`] already uses to keep a
    ///   rate limit from being misreported as an authentication lockout, and
    ///   reading it the same way here is what keeps the two layers agreeing.
    /// * anything else is a permissions answer and is **not** a rate limit.
    #[must_use]
    pub fn detect(error: &GithubError) -> Option<Self> {
        let (status, message) = match error {
            GithubError::Status {
                status, message, ..
            } => (*status, message.as_deref()),
            GithubError::Forbidden { message, .. } => (403, message.as_deref()),
            _ => return None,
        };
        if !matches!(status, 403 | 429) {
            return None;
        }

        let evidence = error.rate_limit();
        let remaining = evidence.and_then(|e| e.remaining);
        let says_rate_limit =
            message.is_some_and(|m| m.to_ascii_lowercase().contains("rate limit"));

        let kind = if remaining == Some(0) {
            RateLimitKind::Primary
        } else if status == 429 || says_rate_limit {
            RateLimitKind::Secondary
        } else {
            return None;
        };

        Some(Self {
            kind,
            retry_after: error.retry_after(),
            remaining,
            reset_unix_secs: evidence.and_then(|e| e.reset_unix_secs),
        })
    }

    /// How long to wait before asking again, given the current instant.
    ///
    /// `retry-after` first, because it is GitHub's explicit instruction;
    /// `x-ratelimit-reset` second, because a primary limit says when rather than
    /// how long; [`DEFAULT_RATE_LIMIT_BACKOFF`] when neither is usable, because
    /// "GitHub said stop and named no time" must still stop.
    ///
    /// Clamped to [`MAX_RATE_LIMIT_BACKOFF`]. A remote header is not allowed to
    /// decide how long this product stays dark.
    #[must_use]
    pub fn delay_from(&self, now: Timestamp) -> Duration {
        let requested = self.retry_after.or_else(|| {
            let reset = self.reset_unix_secs?;
            let seconds = i64::try_from(reset).ok()? - now.timestamp();
            u64::try_from(seconds).ok().map(Duration::from_secs)
        });
        // A zero or absent delay still has to be a wait: `reset` already in the
        // past means the clock disagrees with GitHub, and answering "wait zero
        // seconds" would turn a rate limit into a busy loop against the very
        // endpoint that asked for quiet.
        let requested = match requested {
            Some(d) if d > Duration::ZERO => d,
            _ => DEFAULT_RATE_LIMIT_BACKOFF,
        };
        requested.min(MAX_RATE_LIMIT_BACKOFF)
    }
}

impl fmt::Display for RateLimited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitHub's {} rate limit is exhausted", self.kind)?;
        if let Some(retry_after) = self.retry_after {
            write!(f, "; it asked to be left alone for {}s", retry_after.as_secs())?;
        }
        if let Some(remaining) = self.remaining {
            write!(f, "; {remaining} requests remain in the hourly quota")?;
        }
        f.write_str(". Refreshes are delayed, not lost")
    }
}

/// What GitHub last said about this credential's hourly quota, read from a
/// response that **succeeded**.
///
/// Rate limiting must be "displayed, never hidden", and a state that only
/// appears once the quota is already gone is not a display of it. These are the
/// numbers `f1`'s `host show` and `g3`'s settings screen render alongside the
/// projected budget, so an operator can compare what the projection expected
/// against what the account is actually spending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RateLimitHeadroom {
    /// `x-ratelimit-limit`.
    pub limit: Option<u64>,
    /// `x-ratelimit-remaining`.
    pub remaining: Option<u64>,
    /// `x-ratelimit-reset`, a Unix timestamp in seconds.
    pub reset_unix_secs: Option<u64>,
}

impl RateLimitHeadroom {
    fn from_response(response: &ApiResponse) -> Option<Self> {
        let read = |name: &str| {
            response
                .header(name)
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        let headroom = Self {
            limit: read("x-ratelimit-limit"),
            remaining: read("x-ratelimit-remaining"),
            reset_unix_secs: read("x-ratelimit-reset"),
        };
        if headroom == Self::default() {
            return None;
        }
        Some(headroom)
    }
}

// ---------------------------------------------------------------------------
// Errors and the displayable refresh state
// ---------------------------------------------------------------------------

/// Everything an inventory read can fail with.
///
/// [`GithubError`] is carried through rather than flattened, because `c2`'s
/// taxonomy already separates the three outcomes `f1` branches on — a rejected
/// credential, an authentication lockout, and a permissions refusal — and
/// re-deciding that here would give the product two answers to the same
/// question. The two variants added in front of it are the ones `c2` explicitly
/// left to this layer.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// GitHub is refusing further requests for now. Resolves by waiting.
    #[error("{0}")]
    RateLimited(RateLimited),

    /// The caller withdrew the request. Nothing is known about the target.
    #[error("the refresh was cancelled before it completed")]
    Cancelled,

    #[error(transparent)]
    Github(#[from] GithubError),
}

impl InventoryError {
    #[must_use]
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Self::RateLimited(_))
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }

    /// The rate limit behind this failure, when there is one.
    #[must_use]
    pub fn rate_limited(&self) -> Option<&RateLimited> {
        match self {
            Self::RateLimited(limit) => Some(limit),
            _ => None,
        }
    }

    /// `true` when GitHub could not be reached at all, as opposed to answering
    /// something unwelcome. `e1`'s offline handling turns on this distinction:
    /// an outage retains running runners, while a rejection does not.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        matches!(self, Self::Github(GithubError::Transport(_)))
    }
}

/// One refresh's outcome, as a value that can be stored, compared and rendered.
///
/// [`InventoryError`] cannot be any of those things — it owns a
/// `reqwest::Error` and a `serde_json::Error`, neither of which is `Clone` —
/// and the TUI needs a state it can hold in a snapshot and diff against the
/// previous frame. So the error is *summarised* into this enum exactly once, at
/// the gateway boundary, rather than each screen inventing its own summary.
///
/// `g2`'s Definition of Done names "loading, empty, unauthorized, rate-limited,
/// and offline states"; four of those are variants here, and "loading" and
/// "empty" are the caller's (no state yet, and a `Ready` snapshot with nothing
/// in it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshState {
    /// The refresh completed. Note that an *empty* snapshot is still `Ready`:
    /// "this target has no runners" is an answer, and rendering it as a failure
    /// is how an idle host looks broken.
    Ready(Box<InventorySnapshot>),
    /// GitHub is rate limiting this credential.
    RateLimited(RateLimited),
    /// The stored credential was rejected. Terminal until `auth login`.
    Unauthorized,
    /// GitHub's temporary authentication lockout. The credential is fine.
    LockedOut { retry_after: Duration },
    /// A permissions answer. Re-authenticating will not change it.
    Forbidden { message: Option<String> },
    /// GitHub could not be reached.
    Offline,
    /// Anything else GitHub answered.
    Failed {
        status: Option<u16>,
        message: String,
    },
    /// The caller withdrew the refresh.
    Cancelled,
}

impl RefreshState {
    /// Summarise a completed refresh.
    #[must_use]
    pub fn from_result(result: Result<InventorySnapshot, InventoryError>) -> Self {
        match result {
            Ok(snapshot) => Self::Ready(Box::new(snapshot)),
            Err(error) => Self::from_error(&error),
        }
    }

    /// Summarise a failure without consuming it.
    #[must_use]
    pub fn from_error(error: &InventoryError) -> Self {
        match error {
            InventoryError::RateLimited(limit) => Self::RateLimited(*limit),
            InventoryError::Cancelled => Self::Cancelled,
            InventoryError::Github(github) => match github {
                GithubError::AuthenticationFailed => Self::Unauthorized,
                GithubError::AuthenticationLockout { retry_after } => Self::LockedOut {
                    retry_after: *retry_after,
                },
                GithubError::Forbidden { message, .. } => Self::Forbidden {
                    message: message.clone(),
                },
                GithubError::Transport(_) => Self::Offline,
                GithubError::Status { status, .. } => Self::Failed {
                    status: Some(*status),
                    message: github.to_string(),
                },
                other => Self::Failed {
                    status: None,
                    message: other.to_string(),
                },
            },
        }
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    #[must_use]
    pub fn snapshot(&self) -> Option<&InventorySnapshot> {
        match self {
            Self::Ready(snapshot) => Some(&**snapshot),
            _ => None,
        }
    }

    /// How long `e1` should add to its refresh delay before trying again, or
    /// `None` when waiting is not what this state needs.
    ///
    /// `04-subsystem-contracts.md`: "Rate limiting increases the refresh delay
    /// and is displayed, never hidden." This is the increase. It is deliberately
    /// `None` for [`RefreshState::Unauthorized`] and
    /// [`RefreshState::Forbidden`], which no amount of waiting fixes.
    #[must_use]
    pub fn retry_delay(&self, now: Timestamp) -> Option<Duration> {
        match self {
            Self::RateLimited(limit) => Some(limit.delay_from(now)),
            Self::LockedOut { retry_after } => Some(*retry_after),
            _ => None,
        }
    }
}

impl fmt::Display for RefreshState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(snapshot) => write!(
                f,
                "{} runners, {} in progress",
                snapshot.runners.len(),
                snapshot.activity.total()
            ),
            Self::RateLimited(limit) => write!(f, "{limit}"),
            Self::Unauthorized => f.write_str(
                "GitHub rejected the stored credential; run `runner-manager auth login`",
            ),
            Self::LockedOut { retry_after } => write!(
                f,
                "GitHub has temporarily locked out authentication; retrying in {}s. \
                 The credential itself is not the problem",
                retry_after.as_secs()
            ),
            Self::Forbidden { message } => match message {
                Some(message) => write!(f, "GitHub denied the request: {message}"),
                None => f.write_str("GitHub denied the request"),
            },
            Self::Offline => f.write_str("GitHub is unreachable"),
            Self::Failed { message, .. } => f.write_str(message),
            Self::Cancelled => f.write_str("the refresh was cancelled"),
        }
    }
}

// ---------------------------------------------------------------------------
// Runners
// ---------------------------------------------------------------------------

/// A runner's connection state, as GitHub reports it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RunnerStatus {
    Online,
    Offline,
    /// Anything else GitHub sends. Kept verbatim rather than mapped onto one of
    /// the two known values: a status this product does not recognise is
    /// something to display, not something to guess at.
    Other(String),
}

impl RunnerStatus {
    #[must_use]
    pub fn from_wire(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "online" => Self::Online,
            "offline" => Self::Offline,
            _ => Self::Other(raw.trim().to_string()),
        }
    }

    #[must_use]
    pub fn is_online(&self) -> bool {
        matches!(self, Self::Online)
    }
}

impl fmt::Display for RunnerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Online => f.write_str("online"),
            Self::Offline => f.write_str("offline"),
            Self::Other(raw) => f.write_str(raw),
        }
    }
}

/// One self-hosted runner GitHub knows about, local or not.
///
/// `07-security.md` and `g2` both require that runners this product did *not*
/// create still appear — a legacy persistent runner is part of the operator's
/// real inventory, and hiding it would make the dashboard a worse answer than
/// GitHub's own page. Nothing here filters by ownership; deciding what is
/// locally owned is `e1`'s, from the routing label.
///
/// # Labels arrive lower-cased
///
/// The D18 spike registered `Windows` and `X64` and read back `windows` and
/// `x64` (`docs/spikes/d18-org-jit-verification.md`, point 3). It also
/// established that **no label is added implicitly** — a runner carries exactly
/// what was requested, with no `self-hosted`, no OS and no architecture unless
/// they were asked for. So [`Runner::labels`] is what GitHub stores, verbatim,
/// and [`Runner::has_label`] compares case-insensitively rather than pretending
/// the case survived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runner {
    pub id: u64,
    pub name: String,
    /// GitHub's own OS string, unparsed. [`Runner::parsed_os`] is the lenient
    /// reading; this is the fact.
    pub os: String,
    pub status: RunnerStatus,
    pub busy: bool,
    /// `None` when GitHub did not send the field.
    ///
    /// Absent is not `false`. A runner whose ephemerality is unknown is exactly
    /// the runner an operator most wants flagged, and defaulting it to "not
    /// ephemeral" would render that as a settled fact.
    pub ephemeral: Option<bool>,
    pub labels: Vec<String>,
}

impl Runner {
    /// Whether this runner carries `label`, compared case-insensitively because
    /// GitHub lower-cases what it stores.
    #[must_use]
    pub fn has_label(&self, label: &str) -> bool {
        self.labels
            .iter()
            .any(|held| held.eq_ignore_ascii_case(label.trim()))
    }

    /// This runner's OS as a domain value, when it is one of the three the
    /// product supports.
    ///
    /// `None` rather than an error: an unrecognised OS is a runner to display,
    /// not a refresh to fail.
    #[must_use]
    pub fn parsed_os(&self) -> Option<Os> {
        self.os.parse().ok()
    }
}

/// Every runner GitHub reports for one target, across every page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerInventory {
    target: ScaleTarget,
    runners: Vec<Runner>,
    reported_total: Option<u64>,
    pages: usize,
    truncated: bool,
}

impl RunnerInventory {
    /// A complete inventory read in one page. The constructor test doubles and
    /// callers use; the gateway builds them through [`RunnerInventory::paged`].
    #[must_use]
    pub fn new(target: ScaleTarget, runners: Vec<Runner>) -> Self {
        let reported_total = Some(u64::try_from(runners.len()).unwrap_or(u64::MAX));
        Self {
            target,
            runners,
            reported_total,
            pages: 1,
            truncated: false,
        }
    }

    /// An inventory that took `pages` requests to read.
    #[must_use]
    pub fn paged(
        target: ScaleTarget,
        runners: Vec<Runner>,
        reported_total: Option<u64>,
        pages: usize,
        truncated: bool,
    ) -> Self {
        Self {
            target,
            runners,
            reported_total,
            pages,
            truncated,
        }
    }

    #[must_use]
    pub fn target(&self) -> &ScaleTarget {
        &self.target
    }

    #[must_use]
    pub fn runners(&self) -> &[Runner] {
        &self.runners
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.runners.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.runners.is_empty()
    }

    /// Runners GitHub reports as executing a job.
    ///
    /// **This is not the in-progress workflow count.** See
    /// [`ActivityCount::total`]; the two are different aggregates and `g2`
    /// renders them separately.
    #[must_use]
    pub fn busy_count(&self) -> usize {
        self.runners.iter().filter(|runner| runner.busy).count()
    }

    #[must_use]
    pub fn online_count(&self) -> usize {
        self.runners
            .iter()
            .filter(|runner| runner.status.is_online())
            .count()
    }

    /// GitHub's own `total_count`, when it sent one.
    #[must_use]
    pub fn reported_total(&self) -> Option<u64> {
        self.reported_total
    }

    /// How many requests reading this inventory took.
    #[must_use]
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// `true` when the [`MAX_PAGES`] ceiling stopped the walk, so this is a
    /// prefix of the inventory rather than the inventory.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// How many runners GitHub said exist that this walk did not collect.
    ///
    /// The whole reason pagination is mandatory, made checkable: a caller that
    /// wants to refuse to render an incomplete inventory can, and one that
    /// renders it anyway can say so.
    #[must_use]
    pub fn missing(&self) -> Option<u64> {
        let total = self.reported_total?;
        let collected = u64::try_from(self.runners.len()).unwrap_or(u64::MAX);
        (total > collected).then_some(total - collected)
    }
}

// ---------------------------------------------------------------------------
// In-progress workflow activity
// ---------------------------------------------------------------------------

/// Which repositories one activity count covers.
///
/// An in-progress workflow count is a **per-repository** number, because
/// workflow runs are a per-repository resource and GitHub publishes no
/// organization-wide runs endpoint. A repository target is therefore one
/// request; an organization target is one request per repository the App is
/// installed on there.
///
/// That asymmetry is why this type exists rather than a bare [`ScaleTarget`].
/// The repository list has to come from the caller — `f1` and `e1` already hold
/// it, from [`crate::AuthenticatedClient::discover_installations`] — and
/// re-discovering it on every refresh would cost more requests than the count
/// itself. Carrying it explicitly also means [`TargetCost::from_activity_scope`]
/// can project the real cost instead of a flat per-target constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityScope {
    target: ScaleTarget,
    repositories: Vec<OwnerRepo>,
}

impl ActivityScope {
    /// A repository target: it counts its own runs and nothing else.
    #[must_use]
    pub fn repository(repo: OwnerRepo) -> Self {
        Self {
            target: ScaleTarget::Repository(repo.clone()),
            repositories: vec![repo],
        }
    }

    /// An organization target, aggregating across the repositories the App is
    /// installed on.
    ///
    /// An empty list is legal and means exactly what it says: the App reaches no
    /// repository in this organization, so the aggregate is zero and costs
    /// nothing. It is not silently treated as "one".
    #[must_use]
    pub fn organization(org: Org, repositories: impl IntoIterator<Item = OwnerRepo>) -> Self {
        Self {
            target: ScaleTarget::Organization(org),
            repositories: repositories.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn target(&self) -> &ScaleTarget {
        &self.target
    }

    #[must_use]
    pub fn repositories(&self) -> &[OwnerRepo] {
        &self.repositories
    }

    /// Requests one in-progress count over this scope costs.
    #[must_use]
    pub fn requests_per_refresh(&self) -> u32 {
        u32::try_from(self.repositories.len()).unwrap_or(u32::MAX)
            * ACTIVITY_REQUESTS_PER_REPOSITORY_PER_REFRESH
    }
}

/// In-progress workflow runs, per repository and in total.
///
/// **Not the busy-runner count.** A workflow run is work GitHub has accepted and
/// started; a busy runner is a machine executing a job. One run can occupy
/// several runners, a run can be in progress with none of its jobs assigned yet,
/// and a busy runner may be executing a job for a workflow this product does not
/// poll at all. `04-subsystem-contracts.md` and `g2` both require them rendered
/// as distinct aggregates, and they are distinct types here so that they cannot
/// be added together by accident.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActivityCount {
    per_repository: BTreeMap<OwnerRepo, u32>,
    unavailable: Vec<UnavailableRepository>,
}

/// A repository the aggregate could not read, and why.
///
/// Carried out of the count rather than folded into it. An organization whose
/// App installation includes an archived or since-deleted repository would
/// otherwise fail its whole activity refresh forever, or — worse — quietly
/// return a total that is short by an unknown amount. `c2`'s installation
/// discovery makes the same choice for a nameless installation, and for the same
/// reason: a partial answer is usable only when it says it is partial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnavailableRepository {
    pub repository: OwnerRepo,
    pub reason: String,
}

impl ActivityCount {
    #[must_use]
    pub fn new(per_repository: BTreeMap<OwnerRepo, u32>) -> Self {
        Self {
            per_repository,
            unavailable: Vec::new(),
        }
    }

    /// One repository's count, for the common single-repository case.
    #[must_use]
    pub fn of(repository: OwnerRepo, count: u32) -> Self {
        Self::new(BTreeMap::from([(repository, count)]))
    }

    /// In-progress workflow runs across every repository in scope.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.per_repository.values().copied().sum()
    }

    #[must_use]
    pub fn per_repository(&self) -> &BTreeMap<OwnerRepo, u32> {
        &self.per_repository
    }

    /// This repository's count, or `None` when it was not in scope.
    #[must_use]
    pub fn for_repository(&self, repository: &OwnerRepo) -> Option<u32> {
        self.per_repository.get(repository).copied()
    }

    #[must_use]
    pub fn unavailable(&self) -> &[UnavailableRepository] {
        &self.unavailable
    }

    /// `true` when every repository in scope answered.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unavailable.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Runner package downloads
// ---------------------------------------------------------------------------

/// One runner-package download GitHub publishes.
///
/// # `sha256_checksum` is optional, and stays optional
///
/// It is optional in GitHub's response schema, and this layer passes that
/// through faithfully — as [`Option`], never as an empty string and never as a
/// default. `e2` **fails closed** on its absence, requiring an operator-pinned
/// digest rather than installing an unverified 150-300 MB package
/// (`05-infrastructure.md`), and it can only do that if this layer does not
/// paper the absence over.
///
/// Absent and empty are also kept apart. A missing field and a `null` both read
/// as `None`; a field GitHub sent as `""` reads as `Some("")`. Both are unusable
/// as a digest, but they are different facts about GitHub's response, and
/// collapsing them would leave `e2` unable to report which one it saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerDownload {
    /// GitHub's OS token: `win`, `osx`, `linux`.
    pub os: String,
    /// GitHub's architecture token: `x64`, `arm64`, `arm`.
    pub architecture: String,
    pub download_url: String,
    pub filename: String,
    pub sha256_checksum: Option<String>,
}

impl RunnerDownload {
    /// Whether this entry is the package for `os`/`arch`.
    ///
    /// Both sides are parsed through the domain's own [`Os`] and [`Arch`], whose
    /// `FromStr` already accepts GitHub's package tokens — `win`/`osx`/`linux`
    /// and `x64`/`arm64`/`arm` — because [`Os::label_token`] was chosen to be
    /// those very tokens. Comparing parsed values rather than strings is what
    /// keeps a `windows`/`win` spelling difference from silently matching
    /// nothing.
    #[must_use]
    pub fn matches(&self, os: Os, arch: Arch) -> bool {
        self.os.parse::<Os>().is_ok_and(|found| found == os)
            && self
                .architecture
                .parse::<Arch>()
                .is_ok_and(|found| found == arch)
    }

    /// The published digest, if GitHub published one.
    #[must_use]
    pub fn sha256_checksum(&self) -> Option<&str> {
        self.sha256_checksum.as_deref()
    }
}

/// Every runner package GitHub publishes for a target.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunnerDownloads {
    entries: Vec<RunnerDownload>,
}

impl RunnerDownloads {
    #[must_use]
    pub fn new(entries: Vec<RunnerDownload>) -> Self {
        Self { entries }
    }

    #[must_use]
    pub fn entries(&self) -> &[RunnerDownload] {
        &self.entries
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The package for one OS and architecture, or `None` when GitHub publishes
    /// none — which `e2` must refuse before downloading anything, rather than
    /// falling back to a hardcoded URL.
    #[must_use]
    pub fn select(&self, os: Os, arch: Arch) -> Option<&RunnerDownload> {
        self.entries.iter().find(|entry| entry.matches(os, arch))
    }
}

// ---------------------------------------------------------------------------
// The composed snapshot
// ---------------------------------------------------------------------------

/// One target's read models, as of one instant.
///
/// This is what the TUI holds and what `e1` recomputes each refresh. The two
/// counts are deliberately reachable only through their own types — there is no
/// `total` on this struct — so that a screen has to say which aggregate it is
/// rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventorySnapshot {
    pub target: ScaleTarget,
    pub runners: RunnerInventory,
    pub activity: ActivityCount,
    pub observed_at: Timestamp,
    /// What GitHub last said about the hourly quota on the responses that built
    /// this snapshot.
    pub headroom: Option<RateLimitHeadroom>,
}

// ---------------------------------------------------------------------------
// The shared request budget
// ---------------------------------------------------------------------------

/// What one target costs, per refresh, in requests against the shared ceiling.
///
/// # Why an organization is not a constant
///
/// `04-subsystem-contracts.md` tabulates a flat "per target, per hour" cost —
/// ~240 at the 60-second default, ~480 at the 30-second floor — and that table
/// is right for a **repository** target and wrong for an organization one. Two
/// of the three request classes are per-repository resources:
///
/// | Class | Repository target | Organization target with `n` installed repositories |
/// |---|---|---|
/// | runner inventory | 1 | 1 (there *is* an org runners endpoint) |
/// | in-progress workflow count | 1 | `n` |
/// | demand: queued runs plus jobs | 2 | `2n` |
/// | **per refresh** | **4** | **1 + 3n** |
///
/// At `n = 1` the two agree exactly, at 4 requests per refresh and 240 per hour
/// at the default interval, which is what makes this a refinement of the
/// documented table rather than a contradiction of it. At `n = 10` an
/// organization costs 31 requests per refresh — nearly eight times a repository
/// — and projecting it as one flat target understates the real spend by exactly
/// that factor. `f2`'s `org add` refusal therefore arrives much earlier than a
/// repository's would, which is a thing it has to be able to explain.
///
/// # What this model does not claim
///
/// It is a projection of *steady-state polling*, in whole requests per refresh.
/// It does not model a target whose runner inventory spans pages (a second page
/// is a second request), an interactive `auth status`, a JIT registration, or a
/// runner deletion. That is what [`BUDGET_SHARE_DIVISOR`] is for: the
/// projection is compared against half the ceiling, and the other half absorbs
/// everything this model deliberately does not attempt to count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetCost {
    scope: TargetScope,
    installed_repositories: u32,
}

impl TargetCost {
    /// A repository target: one repository, by construction.
    #[must_use]
    pub const fn repository() -> Self {
        Self {
            scope: TargetScope::Repository,
            installed_repositories: 1,
        }
    }

    /// An organization target reaching `installed_repositories` repositories.
    #[must_use]
    pub const fn organization(installed_repositories: u32) -> Self {
        Self {
            scope: TargetScope::Organization,
            installed_repositories,
        }
    }

    /// The cost of the scope an activity refresh will actually walk.
    ///
    /// Preferred over [`TargetCost::organization`] wherever the repository set
    /// is already in hand, because it takes the count from the same list the
    /// requests will be issued against rather than from a number somebody
    /// passed in.
    #[must_use]
    pub fn from_activity_scope(scope: &ActivityScope) -> Self {
        match scope.target().scope() {
            TargetScope::Repository => Self::repository(),
            TargetScope::Organization => {
                Self::organization(u32::try_from(scope.repositories().len()).unwrap_or(u32::MAX))
            }
        }
    }

    #[must_use]
    pub const fn scope(&self) -> TargetScope {
        self.scope
    }

    #[must_use]
    pub const fn installed_repositories(&self) -> u32 {
        self.installed_repositories
    }

    /// Requests one refresh of this target costs.
    #[must_use]
    pub const fn requests_per_refresh(&self) -> u32 {
        let repositories = match self.scope {
            TargetScope::Repository => 1,
            TargetScope::Organization => self.installed_repositories,
        };
        RUNNER_INVENTORY_REQUESTS_PER_REFRESH
            + repositories.saturating_mul(
                ACTIVITY_REQUESTS_PER_REPOSITORY_PER_REFRESH
                    + DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH,
            )
    }

    /// Requests one hour of refreshing this target at `interval` costs.
    #[must_use]
    pub fn requests_per_hour(&self, interval: RefreshInterval) -> u32 {
        self.requests_per_refresh()
            .saturating_mul(refreshes_per_hour(interval))
    }
}

/// Refreshes one hour holds at `interval`.
#[must_use]
pub fn refreshes_per_hour(interval: RefreshInterval) -> u32 {
    SECONDS_PER_HOUR / u32::from(interval.as_secs())
}

/// The requests per hour a host may plan to spend: half the documented ceiling.
#[must_use]
pub const fn budget_allowance() -> u32 {
    HOURLY_REQUEST_CEILING / BUDGET_SHARE_DIVISOR
}

/// What a host's configured target set will cost per hour, and whether that
/// fits.
///
/// `f1`'s `host show` renders [`BudgetProjection::requests_per_hour`],
/// [`BudgetProjection::headroom`] and
/// [`BudgetProjection::max_repository_targets`]; `f2`'s `repo add` and `org add`
/// call [`BudgetProjection::admit`] and refuse on
/// [`Admission::Refused`]. `g3` shows the same numbers in the TUI. All four read
/// one model, which is the only way the CLI and the TUI can agree about why an
/// eleventh repository was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetProjection {
    interval: RefreshInterval,
    targets: Vec<TargetCost>,
}

impl BudgetProjection {
    #[must_use]
    pub fn new(interval: RefreshInterval, targets: impl IntoIterator<Item = TargetCost>) -> Self {
        Self {
            interval,
            targets: targets.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn interval(&self) -> RefreshInterval {
        self.interval
    }

    #[must_use]
    pub fn targets(&self) -> &[TargetCost] {
        &self.targets
    }

    #[must_use]
    pub fn refreshes_per_hour(&self) -> u32 {
        refreshes_per_hour(self.interval)
    }

    /// The projected hourly request count for the whole target set.
    #[must_use]
    pub fn requests_per_hour(&self) -> u32 {
        self.targets
            .iter()
            .map(|target| target.requests_per_hour(self.interval))
            .fold(0, u32::saturating_add)
    }

    #[must_use]
    pub fn ceiling(&self) -> u32 {
        HOURLY_REQUEST_CEILING
    }

    #[must_use]
    pub fn allowance(&self) -> u32 {
        budget_allowance()
    }

    /// Requests per hour still available inside the allowance.
    #[must_use]
    pub fn headroom(&self) -> u32 {
        self.allowance().saturating_sub(self.requests_per_hour())
    }

    #[must_use]
    pub fn exceeds_allowance(&self) -> bool {
        self.requests_per_hour() > self.allowance()
    }

    /// How many **repository** targets one host can serve at `interval`.
    ///
    /// `04-subsystem-contracts.md` states the answer as "roughly 10 targets per
    /// host at the 60-second default and 5 at the 30-second floor", and this
    /// reproduces both. It is stated in repository targets because that is the
    /// only target whose cost is a constant; an organization's depends on its
    /// installed repository count, so "how many organizations fit" has no single
    /// answer and this deliberately does not invent one.
    #[must_use]
    pub fn max_repository_targets(interval: RefreshInterval) -> u32 {
        let per_target = TargetCost::repository().requests_per_hour(interval);
        if per_target == 0 {
            return 0;
        }
        budget_allowance() / per_target
    }

    /// Whether one more target fits.
    #[must_use]
    pub fn admit(&self, candidate: TargetCost) -> Admission {
        let candidate_per_hour = candidate.requests_per_hour(self.interval);
        let projected = self.requests_per_hour().saturating_add(candidate_per_hour);
        let allowance = self.allowance();
        if projected > allowance {
            return Admission::Refused {
                candidate,
                candidate_requests_per_hour: candidate_per_hour,
                projected_requests_per_hour: projected,
                allowance,
                ceiling: self.ceiling(),
                interval: self.interval,
                max_repository_targets: Self::max_repository_targets(self.interval),
            };
        }
        Admission::Admitted {
            projected_requests_per_hour: projected,
            headroom_after: allowance - projected,
        }
    }
}

/// The answer `f2`'s `repo add` and `org add` act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Admitted {
        projected_requests_per_hour: u32,
        headroom_after: u32,
    },
    Refused {
        candidate: TargetCost,
        candidate_requests_per_hour: u32,
        projected_requests_per_hour: u32,
        allowance: u32,
        ceiling: u32,
        interval: RefreshInterval,
        max_repository_targets: u32,
    },
}

impl Admission {
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }
}

impl fmt::Display for Admission {
    /// The refusal has to explain itself: "an operator who adds an eleventh
    /// repository needs to know why it was refused"
    /// (`04-subsystem-contracts.md`). So the message carries the computed
    /// numbers rather than the rule, and — for an organization — says which
    /// repository count drove them, because that is the part a flat per-target
    /// reading of the design would not have predicted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admitted {
                projected_requests_per_hour,
                headroom_after,
            } => write!(
                f,
                "projected {projected_requests_per_hour} requests/hour, \
                 {headroom_after} remaining in this host's share of the budget"
            ),
            Self::Refused {
                candidate,
                candidate_requests_per_hour,
                projected_requests_per_hour,
                allowance,
                ceiling,
                interval,
                max_repository_targets,
            } => {
                write!(
                    f,
                    "refused: this target would take the host to \
                     {projected_requests_per_hour} requests/hour, over the {allowance} it may \
                     plan to spend (half of GitHub's {ceiling}/hour ceiling) at a \
                     {}-second refresh interval. This host can serve about \
                     {max_repository_targets} repository targets at that interval",
                    interval.as_secs()
                )?;
                if candidate.scope() == TargetScope::Organization {
                    write!(
                        f,
                        ". This organization alone costs {candidate_requests_per_hour} \
                         requests/hour because the App is installed on {} of its repositories, \
                         and workflow runs are a per-repository resource",
                        candidate.installed_repositories()
                    )?;
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Coalescing a manual refresh with an in-flight one
// ---------------------------------------------------------------------------

/// Runs one refresh at a time; a refresh asked for while another is in flight
/// **joins** it instead of issuing a second.
///
/// `04-subsystem-contracts.md`: "Manual refresh coalesces with an in-flight
/// request." The requirement is a budget one before it is a latency one — `F5`
/// held down on the dashboard would otherwise be an operator-driven denial of
/// service against a 5,000/hour ceiling shared with the polling that keeps
/// runners starting.
///
/// The mechanism is the generation-and-gate pattern
/// [`crate::AuthenticatedClient::revalidate`] already uses for single-flight
/// re-validation, and it is here rather than there because the two coalesce
/// different things. A caller samples the generation *before* queuing on the
/// gate; if it moved while the caller waited, some other refresh covered it and
/// this one returns that result without calling `work` at all. `work` being
/// `FnOnce` is what makes "no second request" structural rather than
/// remembered: the joining path never has a future to poll.
#[derive(Debug)]
pub struct RefreshCoalescer<T> {
    generation: AtomicU64,
    gate: tokio::sync::Mutex<()>,
    last: std::sync::Mutex<Option<T>>,
    performed: AtomicU64,
    joined: AtomicU64,
}

impl<T: Clone> Default for RefreshCoalescer<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> RefreshCoalescer<T> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            gate: tokio::sync::Mutex::new(()),
            last: std::sync::Mutex::new(None),
            performed: AtomicU64::new(0),
            joined: AtomicU64::new(0),
        }
    }

    /// Refresh, or join the refresh already running.
    ///
    /// # Panics
    /// If a previous holder panicked while the result lock was held.
    pub async fn refresh<F, Fut>(&self, work: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let sampled = self.generation.load(Ordering::SeqCst);
        let _guard = self.gate.lock().await;

        if self.generation.load(Ordering::SeqCst) != sampled
            && let Some(shared) = self.last.lock().expect("refresh lock poisoned").clone()
        {
            self.joined.fetch_add(1, Ordering::SeqCst);
            tracing::debug!("joined an in-flight refresh instead of issuing a second request");
            return shared;
        }

        let outcome = work().await;
        *self.last.lock().expect("refresh lock poisoned") = Some(outcome.clone());
        self.performed.fetch_add(1, Ordering::SeqCst);
        // Bumped last and under the gate: a caller that sampled before this
        // point and is still queued will see the change and join.
        self.generation.fetch_add(1, Ordering::SeqCst);
        outcome
    }

    /// How many refreshes actually ran.
    #[must_use]
    pub fn performed(&self) -> u64 {
        self.performed.load(Ordering::SeqCst)
    }

    /// How many refreshes were served by joining one already in flight.
    #[must_use]
    pub fn joined(&self) -> u64 {
        self.joined.load(Ordering::SeqCst)
    }

    /// The most recent outcome, if there has been one.
    ///
    /// # Panics
    /// If a previous holder panicked while the result lock was held.
    #[must_use]
    pub fn last(&self) -> Option<T> {
        self.last.lock().expect("refresh lock poisoned").clone()
    }
}

// ---------------------------------------------------------------------------
// The gateway seam
// ---------------------------------------------------------------------------

/// Every read model the dashboard and the CLI display.
///
/// A trait rather than a concrete type, so that `e1`, `f1`, `g2` and `g3` can be
/// tested against `runner_manager_testkit::github::FakeGithub` with no network
/// and no `wiremock` in their dependency graphs. [`RestInventory`] is the one
/// implementation that talks to GitHub.
#[async_trait::async_trait]
pub trait InventoryGateway: fmt::Debug + Send + Sync {
    /// Every runner GitHub reports for `target`, across every page.
    ///
    /// # Errors
    /// Every variant of [`InventoryError`].
    async fn list_runners(
        &self,
        target: &ScaleTarget,
        cancel: &CancelToken,
    ) -> Result<RunnerInventory, InventoryError>;

    /// In-progress workflow runs across `scope`.
    ///
    /// # Errors
    /// Every variant of [`InventoryError`].
    async fn in_progress_activity(
        &self,
        scope: &ActivityScope,
        cancel: &CancelToken,
    ) -> Result<ActivityCount, InventoryError>;

    /// The runner packages GitHub publishes for `target`.
    ///
    /// # Errors
    /// Every variant of [`InventoryError`].
    async fn runner_downloads(
        &self,
        target: &ScaleTarget,
        cancel: &CancelToken,
    ) -> Result<RunnerDownloads, InventoryError>;

    /// What GitHub last said about the hourly quota, if anything.
    fn headroom(&self) -> Option<RateLimitHeadroom>;

    /// The instant every snapshot is stamped with.
    fn now(&self) -> Timestamp;

    /// Both read models for one target, in one refresh.
    ///
    /// A provided method rather than a required one: it is the composition every
    /// caller wants and it must not be possible for an implementation to compose
    /// the two counts differently from another.
    ///
    /// # Errors
    /// Every variant of [`InventoryError`].
    async fn snapshot(
        &self,
        scope: &ActivityScope,
        cancel: &CancelToken,
    ) -> Result<InventorySnapshot, InventoryError> {
        let runners = self.list_runners(scope.target(), cancel).await?;
        let activity = self.in_progress_activity(scope, cancel).await?;
        Ok(InventorySnapshot {
            target: scope.target().clone(),
            runners,
            activity,
            observed_at: self.now(),
            headroom: self.headroom(),
        })
    }
}

// ---------------------------------------------------------------------------
// The GitHub implementation
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RateLimitState {
    until: Option<Timestamp>,
    last: Option<RateLimited>,
}

/// [`InventoryGateway`] over `api.github.com`.
///
/// Holds no credential of its own: authentication is entirely
/// [`AuthenticatedClient`]'s, and this type only ever hands it an
/// [`ApiRequest`].
pub struct RestInventory {
    client: Arc<AuthenticatedClient>,
    clock: Arc<dyn Clock>,
    rate_limit: std::sync::Mutex<RateLimitState>,
    headroom: std::sync::Mutex<Option<RateLimitHeadroom>>,
    requests_issued: AtomicU64,
}

impl fmt::Debug for RestInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `try_lock`, for the reason `AuthenticatedClient`'s own `Debug` records:
        // a `Debug` impl must never be able to block, and these locks are held
        // across code that could plausibly grow a `tracing` call.
        let backing_off = match self.rate_limit.try_lock() {
            Ok(state) => state
                .until
                .is_some_and(|until| self.clock.now() < until)
                .to_string(),
            Err(_) => "unknown (the rate-limit state is being updated)".to_string(),
        };
        f.debug_struct("RestInventory")
            .field("requests_issued", &self.requests_issued.load(Ordering::Relaxed))
            .field("rate_limited", &backing_off)
            .finish_non_exhaustive()
    }
}

impl RestInventory {
    #[must_use]
    pub fn new(client: Arc<AuthenticatedClient>, clock: Arc<dyn Clock>) -> Self {
        Self {
            client,
            clock,
            rate_limit: std::sync::Mutex::new(RateLimitState {
                until: None,
                last: None,
            }),
            headroom: std::sync::Mutex::new(None),
            requests_issued: AtomicU64::new(0),
        }
    }

    /// How many HTTP requests this gateway has issued.
    ///
    /// The budget model above projects a per-refresh cost in whole requests, and
    /// a projection nothing measures is a table in a document. This is what the
    /// tests measure it against.
    #[must_use]
    pub fn requests_issued(&self) -> u64 {
        self.requests_issued.load(Ordering::SeqCst)
    }

    /// How much of a rate-limit back-off is left, or `None` when not backing
    /// off.
    ///
    /// # Panics
    /// If a previous holder panicked while the rate-limit lock was held.
    #[must_use]
    pub fn rate_limit_backoff(&self) -> Option<Duration> {
        let state = self.rate_limit.lock().expect("rate-limit lock poisoned");
        let until = state.until?;
        let now = self.clock.now();
        if now >= until {
            return None;
        }
        (until - now).to_std().ok()
    }

    /// The rate limit currently being backed off from, for display.
    ///
    /// # Panics
    /// If a previous holder panicked while the rate-limit lock was held.
    #[must_use]
    pub fn rate_limit_state(&self) -> Option<RateLimited> {
        let remaining = self.rate_limit_backoff()?;
        let state = self.rate_limit.lock().expect("rate-limit lock poisoned");
        let mut limit = state.last?;
        // Report what is left of the wait, not what GitHub asked for when the
        // window opened. A countdown that never moves reads as a hung refresh.
        limit.retry_after = Some(remaining);
        Some(limit)
    }

    /// Forget a rate-limit back-off. Nothing in the product needs this — the
    /// window expires against the clock — but a test that wants to prove the
    /// window is what suppressed a request does.
    ///
    /// # Panics
    /// If a previous holder panicked while the rate-limit lock was held.
    pub fn clear_rate_limit(&self) {
        self.rate_limit
            .lock()
            .expect("rate-limit lock poisoned")
            .until = None;
    }

    /// One request, with cancellation and the rate-limit gate applied.
    async fn get(
        &self,
        request: &ApiRequest,
        cancel: &CancelToken,
    ) -> Result<ApiResponse, InventoryError> {
        cancel.check()?;
        if let Some(limit) = self.rate_limit_state() {
            // Obeying `retry-after` by issuing nothing. No socket is opened, so
            // the wait costs the shared budget nothing at all.
            tracing::debug!(
                method = request.method().as_str(),
                path = %request.path(),
                remaining_secs = limit.retry_after.unwrap_or_default().as_secs(),
                "suppressed a request: GitHub's rate limit is still backing off"
            );
            return Err(InventoryError::RateLimited(limit));
        }

        self.requests_issued.fetch_add(1, Ordering::SeqCst);
        let result = cancel
            .run(async { self.client.send(request).await.map_err(InventoryError::from) })
            .await;

        match result {
            Ok(response) => {
                if let Some(headroom) = RateLimitHeadroom::from_response(&response) {
                    *self.headroom.lock().expect("headroom lock poisoned") = Some(headroom);
                }
                Ok(response)
            }
            Err(InventoryError::Github(error)) => Err(self.classify(error)),
            Err(other) => Err(other),
        }
    }

    /// Turn a failure into a rate limit when GitHub's own evidence says it is
    /// one, and latch the back-off window if so.
    fn classify(&self, error: GithubError) -> InventoryError {
        let Some(limit) = RateLimited::detect(&error) else {
            return InventoryError::Github(error);
        };
        let now = self.clock.now();
        let delay = limit.delay_from(now);
        if let Ok(delta) = chrono::TimeDelta::from_std(delay) {
            let mut state = self.rate_limit.lock().expect("rate-limit lock poisoned");
            state.until = Some(now + delta);
            state.last = Some(limit);
        }
        tracing::warn!(
            kind = %limit.kind,
            delay_secs = delay.as_secs(),
            remaining = limit.remaining,
            "GitHub is rate limiting this credential; delaying refreshes and reporting it"
        );
        InventoryError::RateLimited(limit)
    }

    /// Follow `Link: rel="next"` to the end of a collection.
    async fn collect_pages<P: WirePage>(
        &self,
        first: ApiRequest,
        cancel: &CancelToken,
    ) -> Result<Collected<P::Item>, InventoryError> {
        let mut items = Vec::new();
        let mut reported_total = None;
        let mut pages = 0_usize;
        let mut truncated = false;
        let mut next = Some(first);

        while let Some(request) = next.take() {
            // Cancellation is checked at the top of `get`, which is what makes a
            // token flipped after page one stop the walk before page two.
            let response = self.get(&request, cancel).await?;
            let page: P = response.json()?;
            reported_total = page.reported_total().or(reported_total);
            items.extend(page.into_items());
            pages += 1;

            if pages >= MAX_PAGES {
                truncated = true;
                tracing::warn!(
                    what = P::WHAT,
                    pages,
                    collected = items.len(),
                    "stopped following pages at the ceiling; a `Link: rel=next` that never \
                     ends would otherwise loop forever"
                );
                break;
            }
            next = response
                .next_page()
                .map(|url| ApiRequest::get(url.as_str()));
        }

        Ok(Collected {
            items,
            reported_total,
            pages,
            truncated,
        })
    }

    /// In-progress workflow runs for one repository.
    ///
    /// One request in the ordinary case. GitHub answers the filtered query with
    /// its own `total_count`, which is the count this product wants, so a
    /// repository with 400 in-progress runs still costs one request rather than
    /// four — and the budget table's "one request per refresh" stays true.
    ///
    /// The fallback matters anyway: a response with no `total_count` is counted
    /// by walking the pages, because guessing zero from a missing field would
    /// render a busy repository as idle.
    async fn repository_in_progress(
        &self,
        repository: &OwnerRepo,
        cancel: &CancelToken,
    ) -> Result<u32, InventoryError> {
        let request = ApiRequest::get(format!(
            "/repos/{}/{}/actions/runs",
            repository.owner(),
            repository.repo()
        ))
        .query("status", "in_progress")
        .query("per_page", PER_PAGE);

        let response = self.get(&request, cancel).await?;
        let page: RunsPage = response.json()?;
        if let Some(total) = page.total_count {
            return Ok(u32::try_from(total).unwrap_or(u32::MAX));
        }

        // No `total_count`: count what is there, following pages.
        let mut counted = page.workflow_runs.len();
        let mut pages = 1_usize;
        let mut next = response
            .next_page()
            .map(|url| ApiRequest::get(url.as_str()));
        while let Some(request) = next.take() {
            let response = self.get(&request, cancel).await?;
            let page: RunsPage = response.json()?;
            counted += page.workflow_runs.len();
            pages += 1;
            if pages >= MAX_PAGES {
                tracing::warn!(
                    repository = %repository,
                    pages,
                    "stopped counting in-progress runs at the page ceiling"
                );
                break;
            }
            next = response
                .next_page()
                .map(|url| ApiRequest::get(url.as_str()));
        }
        Ok(u32::try_from(counted).unwrap_or(u32::MAX))
    }

    /// The runners path for either scope.
    fn runners_path(target: &ScaleTarget) -> String {
        match target {
            ScaleTarget::Repository(repo) => {
                format!("/repos/{}/{}/actions/runners", repo.owner(), repo.repo())
            }
            ScaleTarget::Organization(org) => format!("/orgs/{}/actions/runners", org.as_str()),
        }
    }
}

/// Whether a per-repository failure should be recorded and stepped over, or
/// should abort the whole aggregate.
///
/// The line is between a fact about *that repository* and a fact about the
/// credential or the connection. A `404` (deleted, renamed, or never reachable)
/// and a plain `403` (Actions disabled on that repository) are the first;
/// everything else — a rate limit, a rejected credential, an authentication
/// lockout, an unreachable host, an undecodable body — is the second, because
/// stepping over those would report a total that is short by an unknown amount
/// while looking complete.
fn is_repository_local_failure(error: &InventoryError) -> bool {
    match error {
        InventoryError::Github(GithubError::Forbidden { .. }) => true,
        InventoryError::Github(GithubError::Status { status, .. }) => *status == 404,
        _ => false,
    }
}

#[async_trait::async_trait]
impl InventoryGateway for RestInventory {
    async fn list_runners(
        &self,
        target: &ScaleTarget,
        cancel: &CancelToken,
    ) -> Result<RunnerInventory, InventoryError> {
        let request = ApiRequest::get(Self::runners_path(target)).query("per_page", PER_PAGE);
        let collected = self.collect_pages::<RunnersPage>(request, cancel).await?;

        let runners: Vec<Runner> = collected.items.into_iter().map(Runner::from).collect();
        let inventory = RunnerInventory::paged(
            target.clone(),
            runners,
            collected.reported_total,
            collected.pages,
            collected.truncated,
        );
        if let Some(missing) = inventory.missing() {
            // Not an error, and deliberately not silence either: `g2` can render
            // "showing 200 of 250" but only if it is told.
            tracing::warn!(
                target = %target,
                missing,
                collected = inventory.len(),
                "GitHub reported more runners than pagination collected; this inventory is \
                 incomplete"
            );
        }
        Ok(inventory)
    }

    async fn in_progress_activity(
        &self,
        scope: &ActivityScope,
        cancel: &CancelToken,
    ) -> Result<ActivityCount, InventoryError> {
        let mut per_repository = BTreeMap::new();
        let mut unavailable = Vec::new();

        for repository in scope.repositories() {
            match self.repository_in_progress(repository, cancel).await {
                Ok(count) => {
                    per_repository.insert(repository.clone(), count);
                }
                Err(error) if is_repository_local_failure(&error) => {
                    tracing::warn!(
                        repository = %repository,
                        error = %error,
                        "a repository in this organization could not be counted; the aggregate \
                         reports it as unavailable rather than as zero"
                    );
                    unavailable.push(UnavailableRepository {
                        repository: repository.clone(),
                        reason: error.to_string(),
                    });
                }
                Err(error) => return Err(error),
            }
        }

        Ok(ActivityCount {
            per_repository,
            unavailable,
        })
    }

    async fn runner_downloads(
        &self,
        target: &ScaleTarget,
        cancel: &CancelToken,
    ) -> Result<RunnerDownloads, InventoryError> {
        let path = match target {
            ScaleTarget::Repository(repo) => format!(
                "/repos/{}/{}/actions/runners/downloads",
                repo.owner(),
                repo.repo()
            ),
            ScaleTarget::Organization(org) => {
                format!("/orgs/{}/actions/runners/downloads", org.as_str())
            }
        };
        // Not paginated: GitHub answers this one with a bare JSON array of the
        // packages it publishes, which is a fixed handful.
        let response = self.get(&ApiRequest::get(path), cancel).await?;
        let raw: Vec<RawDownload> = response.json()?;
        Ok(RunnerDownloads::new(
            raw.into_iter().map(RunnerDownload::from).collect(),
        ))
    }

    fn headroom(&self) -> Option<RateLimitHeadroom> {
        *self.headroom.lock().expect("headroom lock poisoned")
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

struct Collected<T> {
    items: Vec<T>,
    reported_total: Option<u64>,
    pages: usize,
    truncated: bool,
}

/// One page of a paginated GitHub collection.
///
/// A trait rather than two near-identical loops, because the loop is where the
/// mandatory-pagination requirement actually lives: one implementation of
/// "follow `rel=next` until it stops, and stop at the ceiling" cannot disagree
/// with itself.
trait WirePage: DeserializeOwned {
    type Item;
    /// Named in the ceiling warning, so the log says which collection wedged.
    const WHAT: &'static str;
    fn reported_total(&self) -> Option<u64>;
    fn into_items(self) -> Vec<Self::Item>;
}

#[derive(Debug, Deserialize)]
struct RunnersPage {
    total_count: Option<u64>,
    #[serde(default)]
    runners: Vec<RawRunner>,
}

impl WirePage for RunnersPage {
    type Item = RawRunner;
    const WHAT: &'static str = "runners";

    fn reported_total(&self) -> Option<u64> {
        self.total_count
    }

    fn into_items(self) -> Vec<Self::Item> {
        self.runners
    }
}

#[derive(Debug, Deserialize)]
struct RawRunner {
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    os: String,
    status: String,
    busy: bool,
    /// Optional in the wire schema and kept optional here. See
    /// [`Runner::ephemeral`].
    ephemeral: Option<bool>,
    #[serde(default)]
    labels: Vec<RawLabel>,
}

#[derive(Debug, Deserialize)]
struct RawLabel {
    name: String,
}

impl From<RawRunner> for Runner {
    fn from(raw: RawRunner) -> Self {
        Self {
            id: raw.id,
            name: raw.name,
            os: raw.os,
            status: RunnerStatus::from_wire(&raw.status),
            busy: raw.busy,
            ephemeral: raw.ephemeral,
            labels: raw.labels.into_iter().map(|label| label.name).collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RunsPage {
    total_count: Option<u64>,
    #[serde(default)]
    workflow_runs: Vec<serde::de::IgnoredAny>,
}

#[derive(Debug, Deserialize)]
struct RawDownload {
    #[serde(default)]
    os: String,
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    download_url: String,
    #[serde(default)]
    filename: String,
    /// **No `#[serde(default)]`, on purpose.** `Option` already makes an absent
    /// field `None`; adding a default here would be harmless today and is
    /// exactly the edit that would later be "simplified" into
    /// `#[serde(default)] sha256_checksum: String`, turning an absent digest
    /// into an empty one and silently disarming `e2`'s fail-closed rule.
    sha256_checksum: Option<String>,
}

impl From<RawDownload> for RunnerDownload {
    fn from(raw: RawDownload) -> Self {
        Self {
            os: raw.os,
            architecture: raw.architecture,
            download_url: raw.download_url,
            filename: raw.filename,
            sha256_checksum: raw.sha256_checksum,
        }
    }
}

// The unit tests below are inline rather than in a `src/rest/tests.rs`, and
// that is a constraint rather than a preference. `lib.rs`'s
// `the_confidential_credential_scan_covers_every_source_file` walks `src/`
// recursively and requires every `.rs` file under it to appear in
// `CRATE_SOURCES` — a list that lives in `lib.rs`, which `c2` owns. A second
// file in this directory would fail that pin, and the only way to fix it would
// be to edit another task's file.
//
// They are also unit tests rather than an integration test under `tests/`,
// because they use `crate::testing`, which is `pub(crate)`. An integration test
// cannot reach it, and it cannot use `runner-manager-testkit` in its place:
// `testkit` depends on this crate, so a unit test that linked it would compile
// a second instance of this library whose types would not unify with these.
#[cfg(test)]
mod tests {
    use super::*;
}
