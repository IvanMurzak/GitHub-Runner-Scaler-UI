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
            write!(
                f,
                "; it asked to be left alone for {}s",
                retry_after.as_secs()
            )?;
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
    /// `checked_sub` rather than a `>` test and a subtraction, because
    /// collecting *more* than GitHub reported is reachable: a `rel="next"` that
    /// points back at the page it arrived on is answered by the [`MAX_PAGES`]
    /// ceiling, and by then the same page has been collected a hundred times
    /// against a `total_count` of one. The eager `then_some` this replaced
    /// panicked with a subtraction overflow on exactly that path — in a debug
    /// build, from inside the agent's reconciliation loop.
    #[must_use]
    pub fn missing(&self) -> Option<u64> {
        let total = self.reported_total?;
        let collected = u64::try_from(self.runners.len()).unwrap_or(u64::MAX);
        total.checked_sub(collected).filter(|missing| *missing > 0)
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
            .field(
                "requests_issued",
                &self.requests_issued.load(Ordering::Relaxed),
            )
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
    ///
    /// # Cancellation is consulted twice, and the two are not redundant
    ///
    /// [`CancelToken::check`] decides *before* the rate-limit gate is read, and
    /// [`CancelToken::run`] covers a token flipped while the socket is already
    /// open. Removing either one leaves a real hole: without `check`, a caller
    /// that cancelled a refresh which was also rate-limited is answered
    /// [`InventoryError::RateLimited`] — told to wait for something it has
    /// already withdrawn — and without `run`, a cancellation arriving mid-flight
    /// is not noticed until the response does.
    ///
    /// They do overlap for the between-pages case, and deliberately: it is the
    /// one the shared budget cares about, and a walk that keeps paging after the
    /// operator navigated away spends real requests. A mutation test that
    /// disables `check` alone leaves that case still guarded by `run`, which is
    /// what defence in depth is supposed to look like.
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

        let result = cancel
            .run(async {
                // Counted *inside* the future, so the count is of requests
                // actually attempted. Counting before `run` over-reported by one
                // whenever a token was flipped between the check above and the
                // first poll: `run`'s biased `select!` then answers
                // `Cancelled` without ever polling this block, so no socket is
                // opened — and a budget model measured against an over-count is
                // a budget model that drifts every time an operator cancels.
                self.requests_issued.fetch_add(1, Ordering::SeqCst);
                self.client
                    .send(request)
                    .await
                    .map_err(InventoryError::from)
            })
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
    use crate::testing::{FIXTURE_TOKEN, Script, TestClock};
    use crate::{Endpoints, UserAccessToken};
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    // -- fixtures -----------------------------------------------------------

    fn repo() -> OwnerRepo {
        OwnerRepo::parse("octo/dashboard").expect("a valid owner/repo")
    }

    fn other_repo() -> OwnerRepo {
        OwnerRepo::parse("octo/api").expect("a valid owner/repo")
    }

    fn third_repo() -> OwnerRepo {
        OwnerRepo::parse("octo/docs").expect("a valid owner/repo")
    }

    fn repo_target() -> ScaleTarget {
        ScaleTarget::Repository(repo())
    }

    fn org_target() -> ScaleTarget {
        ScaleTarget::organization("octo-org").expect("a valid organization login")
    }

    const REPO_RUNNERS: &str = "/repos/octo/dashboard/actions/runners";
    const ORG_RUNNERS: &str = "/orgs/octo-org/actions/runners";
    const REPO_RUNS: &str = "/repos/octo/dashboard/actions/runs";

    fn runners_path(target: &ScaleTarget) -> &'static str {
        match target {
            ScaleTarget::Repository(_) => REPO_RUNNERS,
            ScaleTarget::Organization(_) => ORG_RUNNERS,
        }
    }

    fn gateway(server: &MockServer, clock: Arc<TestClock>) -> RestInventory {
        let client = AuthenticatedClient::new(
            Endpoints::for_test_server(&server.uri()).expect("a valid test base"),
            UserAccessToken::new(SecretString::from(FIXTURE_TOKEN)),
            clock.clone(),
        )
        .expect("the HTTP client builds");
        RestInventory::new(Arc::new(client), clock)
    }

    /// A page of runners with ids in `ids`, all online and idle.
    fn runner_page(ids: std::ops::Range<u64>, total: u64) -> Value {
        let runners: Vec<Value> = ids
            .map(|id| {
                json!({
                    "id": id,
                    "name": format!("runner-{id:04}"),
                    "os": "win",
                    "status": "online",
                    "busy": false,
                    "ephemeral": true,
                    "labels": [{ "id": 1, "name": "rm-home-win-x64", "type": "read-only" }]
                })
            })
            .collect();
        json!({ "total_count": total, "runners": runners })
    }

    fn link_next(url: &str) -> String {
        format!("<{url}>; rel=\"next\"")
    }

    async fn requests_seen(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .expect("the mock server records requests")
            .len()
    }

    // -- pagination ---------------------------------------------------------

    /// The Definition of Done's first item, at both scopes under one body.
    ///
    /// `04-subsystem-contracts.md` forbids treating a first page as a complete
    /// inventory, and the reason it forbids it rather than merely discouraging
    /// it is that the failure is silent: 250 runners reported as 100 renders as
    /// a smaller fleet, not as an error. So the assertion is on the *whole*
    /// collection, and on the page count that proves three requests were spent
    /// getting it.
    ///
    /// One body over both targets, the way the domain's own
    /// `repository_and_organization_targets_are_equivalent` runs one body over
    /// both variants: the scopes differ in the endpoint and in nothing else, and
    /// a second copy of this test is where that stops being true.
    #[tokio::test]
    async fn a_multi_page_runner_inventory_returns_every_runner_at_both_scopes() {
        for target in [repo_target(), org_target()] {
            let server = MockServer::start().await;
            let first = runners_path(&target);
            let page_two = format!("{}/page/2", server.uri());
            let page_three = format!("{}/page/3", server.uri());

            Mock::given(method("GET"))
                .and(path(first))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("link", link_next(&page_two).as_str())
                        .set_body_json(runner_page(1..101, 250)),
                )
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/page/2"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("link", link_next(&page_three).as_str())
                        .set_body_json(runner_page(101..201, 250)),
                )
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/page/3"))
                .respond_with(ResponseTemplate::new(200).set_body_json(runner_page(201..251, 250)))
                .expect(1)
                .mount(&server)
                .await;

            let gateway = gateway(&server, Arc::new(TestClock::default()));
            let inventory = gateway
                .list_runners(&target, &CancelToken::new())
                .await
                .expect("three pages are readable");

            assert_eq!(
                inventory.len(),
                250,
                "{target}: a first page is not a complete inventory"
            );
            assert_eq!(inventory.pages(), 3, "{target}");
            assert_eq!(inventory.reported_total(), Some(250), "{target}");
            assert_eq!(
                inventory.missing(),
                None,
                "{target}: pagination collected everything GitHub said existed"
            );
            assert!(!inventory.truncated(), "{target}");
            assert_eq!(inventory.runners()[0].id, 1, "{target}");
            assert_eq!(inventory.runners()[249].id, 250, "{target}");
            assert_eq!(gateway.requests_issued(), 3, "{target}");
        }
    }

    /// The `Link` header case that silently stopped pagination at page one until
    /// a review caught it, exercised through *this* module's loop rather than
    /// only through `c2`'s parser.
    ///
    /// A runner query carries `labels=self-hosted,windows` routinely, so the
    /// next-page URL contains a comma — and a parser that splits the header on
    /// `,` first tears that URL in half and loses the relation. That this
    /// module reuses [`crate::ApiResponse::next_page`] rather than writing a
    /// second reader is what makes it immune; this test is what says so, because
    /// "we reuse it" is a claim about code that a later edit can quietly falsify.
    #[tokio::test]
    async fn a_next_page_url_containing_a_comma_does_not_truncate_the_inventory() {
        let server = MockServer::start().await;
        let page_two = format!("{}/page/2?labels=self-hosted,windows", server.uri());

        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("link", link_next(&page_two).as_str())
                    .set_body_json(runner_page(1..101, 150)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/page/2"))
            .and(query_param("labels", "self-hosted,windows"))
            .respond_with(ResponseTemplate::new(200).set_body_json(runner_page(101..151, 150)))
            .expect(1)
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let inventory = gateway
            .list_runners(&repo_target(), &CancelToken::new())
            .await
            .expect("both pages are readable");

        assert_eq!(inventory.len(), 150, "the comma ended pagination at page 1");
        assert_eq!(inventory.pages(), 2);
    }

    /// A collection shorter than GitHub's own `total_count` is reported as
    /// short, rather than as the inventory.
    #[tokio::test]
    async fn an_inventory_shorter_than_the_reported_total_says_how_short() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(ResponseTemplate::new(200).set_body_json(runner_page(1..11, 40)))
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let inventory = gateway
            .list_runners(&repo_target(), &CancelToken::new())
            .await
            .expect("one page is readable");

        assert_eq!(inventory.len(), 10);
        assert_eq!(
            inventory.missing(),
            Some(30),
            "GitHub said 40 and pagination found 10; a caller has to be able to see that"
        );
    }

    /// A `rel="next"` that never ends is stopped at the ceiling instead of
    /// wedging the agent's reconciliation loop.
    #[tokio::test]
    async fn a_self_referential_next_link_stops_at_the_page_ceiling() {
        let server = MockServer::start().await;
        let itself = format!("{}{}", server.uri(), REPO_RUNNERS);
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("link", link_next(&itself).as_str())
                    .set_body_json(runner_page(1..2, 1)),
            )
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let inventory = gateway
            .list_runners(&repo_target(), &CancelToken::new())
            .await
            .expect("the walk terminates");

        assert_eq!(inventory.pages(), MAX_PAGES);
        assert!(
            inventory.truncated(),
            "a truncated walk must say so, or it reads as a complete inventory"
        );
        assert_eq!(gateway.requests_issued() as usize, MAX_PAGES);
    }

    // -- in-progress workflow counts ----------------------------------------

    fn runs_body(total: Option<u64>, listed: usize) -> Value {
        let runs: Vec<Value> = (0..listed)
            .map(|i| json!({ "id": i + 1, "status": "in_progress" }))
            .collect();
        match total {
            Some(total) => json!({ "total_count": total, "workflow_runs": runs }),
            None => json!({ "workflow_runs": runs }),
        }
    }

    fn mount_runs(repository: &OwnerRepo, total: u64) -> Mock {
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/{}/{}/actions/runs",
                repository.owner(),
                repository.repo()
            )))
            .and(query_param("status", "in_progress"))
            .respond_with(ResponseTemplate::new(200).set_body_json(runs_body(Some(total), 0)))
    }

    /// A repository target counts its own runs, in one request, from GitHub's
    /// own `total_count`.
    #[tokio::test]
    async fn a_repository_activity_count_is_one_request_and_reads_the_reported_total() {
        let server = MockServer::start().await;
        mount_runs(&repo(), 7).expect(1).mount(&server).await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let scope = ActivityScope::repository(repo());
        let activity = gateway
            .in_progress_activity(&scope, &CancelToken::new())
            .await
            .expect("the count is readable");

        assert_eq!(activity.total(), 7);
        assert_eq!(activity.for_repository(&repo()), Some(7));
        assert!(activity.is_complete());
        assert_eq!(
            gateway.requests_issued(),
            1,
            "reading `total_count` is what keeps this at the one request the budget \
             table projects"
        );
    }

    /// An organization target aggregates across the repositories the App is
    /// installed on — because workflow runs are a per-repository resource and
    /// GitHub publishes no organization-wide runs endpoint.
    #[tokio::test]
    async fn an_organization_activity_count_aggregates_across_installed_repositories() {
        let server = MockServer::start().await;
        mount_runs(&repo(), 4).mount(&server).await;
        mount_runs(&other_repo(), 9).mount(&server).await;
        mount_runs(&third_repo(), 0).mount(&server).await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let scope = ActivityScope::organization(
            Org::new("octo-org").expect("a valid organization login"),
            [repo(), other_repo(), third_repo()],
        );
        let activity = gateway
            .in_progress_activity(&scope, &CancelToken::new())
            .await
            .expect("every repository answers");

        assert_eq!(activity.total(), 13);
        assert_eq!(activity.for_repository(&repo()), Some(4));
        assert_eq!(activity.for_repository(&other_repo()), Some(9));
        assert_eq!(
            activity.for_repository(&third_repo()),
            Some(0),
            "a repository with no in-progress runs is a zero, not an absence"
        );
        assert_eq!(
            gateway.requests_issued(),
            3,
            "one request per installed repository: this is the cost the budget model \
             projects and the reason an organization is not a flat per-target constant"
        );
    }

    /// The Definition of Done's "they are different numbers with different
    /// meanings", asserted on one snapshot where they genuinely differ.
    #[tokio::test]
    async fn the_in_progress_count_and_the_busy_runner_count_are_distinct() {
        let server = MockServer::start().await;
        let runners = json!({
            "total_count": 5,
            "runners": (1..=5).map(|id| json!({
                "id": id,
                "name": format!("runner-{id}"),
                "os": "win",
                "status": "online",
                // Three of five are executing something.
                "busy": id <= 3,
                "ephemeral": true,
                "labels": []
            })).collect::<Vec<_>>()
        });
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(ResponseTemplate::new(200).set_body_json(runners))
            .mount(&server)
            .await;
        mount_runs(&repo(), 7).mount(&server).await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let scope = ActivityScope::repository(repo());
        let snapshot = gateway
            .snapshot(&scope, &CancelToken::new())
            .await
            .expect("both read models are readable");

        assert_eq!(snapshot.runners.len(), 5);
        assert_eq!(snapshot.runners.busy_count(), 3);
        assert_eq!(snapshot.runners.online_count(), 5);
        assert_eq!(snapshot.activity.total(), 7);
        assert_ne!(
            u32::try_from(snapshot.runners.busy_count()).unwrap(),
            snapshot.activity.total(),
            "a workflow run is not a busy runner; `g2` renders them as separate \
             aggregates and cannot do that if this layer conflates them"
        );
        assert_eq!(snapshot.target, repo_target());
        assert_eq!(snapshot.observed_at, TestClock::default().now());
    }

    /// A response with no `total_count` is counted rather than guessed at.
    #[tokio::test]
    async fn an_activity_count_without_a_reported_total_counts_the_runs_instead() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REPO_RUNS))
            .respond_with(ResponseTemplate::new(200).set_body_json(runs_body(None, 4)))
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let activity = gateway
            .in_progress_activity(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("the runs are countable");

        assert_eq!(
            activity.total(),
            4,
            "a missing `total_count` must not read as an idle repository"
        );
    }

    /// One unreadable repository does not take down an organization's whole
    /// aggregate, and does not silently vanish from it either.
    #[tokio::test]
    async fn a_repository_that_cannot_be_counted_is_reported_as_unavailable_not_as_zero() {
        let server = MockServer::start().await;
        mount_runs(&repo(), 6).mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/api/actions/runs"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })),
            )
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let scope = ActivityScope::organization(
            Org::new("octo-org").expect("a valid organization login"),
            [repo(), other_repo()],
        );
        let activity = gateway
            .in_progress_activity(&scope, &CancelToken::new())
            .await
            .expect("one unreadable repository is not fatal to the aggregate");

        assert_eq!(activity.total(), 6);
        assert_eq!(activity.for_repository(&other_repo()), None);
        assert!(
            !activity.is_complete(),
            "a partial total is usable only when it says it is partial"
        );
        assert_eq!(activity.unavailable().len(), 1);
        assert_eq!(activity.unavailable()[0].repository, other_repo());
    }

    /// A rate limit hit part-way through an aggregate aborts it, because
    /// stepping over it would report a total that is short by an unknown amount
    /// while looking complete.
    #[tokio::test]
    async fn a_rate_limit_during_an_aggregate_aborts_it_rather_than_under_reporting() {
        let server = MockServer::start().await;
        mount_runs(&repo(), 6).mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/api/actions/runs"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "30")
                    .set_body_json(
                        json!({ "message": "You have exceeded a secondary rate limit" }),
                    ),
            )
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let scope = ActivityScope::organization(
            Org::new("octo-org").expect("a valid organization login"),
            [repo(), other_repo(), third_repo()],
        );
        let error = gateway
            .in_progress_activity(&scope, &CancelToken::new())
            .await
            .expect_err("a rate limit is systemic, not a fact about one repository");

        assert!(error.is_rate_limited(), "{error}");
    }

    // -- rate limiting ------------------------------------------------------

    /// The Definition of Done's `retry-after`, obeyed in the only way that costs
    /// the shared budget nothing: by issuing no request at all.
    #[tokio::test]
    async fn retry_after_is_obeyed_by_issuing_no_request_until_it_elapses() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "120")
                    .set_body_json(
                        json!({ "message": "You have exceeded a secondary rate limit" }),
                    ),
                ResponseTemplate::new(200).set_body_json(runner_page(1..2, 1)),
            ]))
            .mount(&server)
            .await;

        let clock = Arc::new(TestClock::default());
        let gateway = gateway(&server, clock.clone());
        let cancel = CancelToken::new();

        let first = gateway
            .list_runners(&repo_target(), &cancel)
            .await
            .expect_err("GitHub is rate limiting");
        let limit = first.rate_limited().expect("a distinct rate-limited state");
        assert_eq!(limit.kind, RateLimitKind::Secondary);
        assert_eq!(limit.retry_after, Some(Duration::from_secs(120)));
        assert_eq!(requests_seen(&server).await, 1);

        // The window is open. A second call must not reach the wire.
        let second = gateway
            .list_runners(&repo_target(), &cancel)
            .await
            .expect_err("the back-off is still running");
        assert!(second.is_rate_limited(), "{second}");
        assert_eq!(
            requests_seen(&server).await,
            1,
            "obeying `retry-after` means sending nothing, not sending and waiting"
        );
        assert_eq!(
            gateway.rate_limit_backoff(),
            Some(Duration::from_secs(120)),
            "the reported wait is what is left of it"
        );

        // Part-way through, still suppressed, and the countdown has moved.
        clock.advance_secs(90);
        assert!(
            gateway
                .list_runners(&repo_target(), &cancel)
                .await
                .is_err_and(|error| error.is_rate_limited())
        );
        assert_eq!(gateway.rate_limit_backoff(), Some(Duration::from_secs(30)));
        assert_eq!(requests_seen(&server).await, 1);

        // Elapsed. Traffic resumes.
        clock.advance_secs(30);
        assert_eq!(gateway.rate_limit_backoff(), None);
        let inventory = gateway
            .list_runners(&repo_target(), &cancel)
            .await
            .expect("the back-off elapsed");
        assert_eq!(inventory.len(), 1);
        assert_eq!(requests_seen(&server).await, 2);
    }

    /// The primary limit: a `403` carrying `x-ratelimit-remaining: 0`. The wait
    /// comes from `x-ratelimit-reset`, because a primary limit says *when*
    /// rather than *how long*.
    #[tokio::test]
    async fn an_exhausted_hourly_quota_is_a_distinct_displayable_state() {
        let server = MockServer::start().await;
        let now = TestClock::default().now().timestamp();
        let reset = now + 300;
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("x-ratelimit-remaining", "0")
                    .insert_header("x-ratelimit-limit", "5000")
                    .insert_header("x-ratelimit-reset", reset.to_string().as_str())
                    .set_body_json(json!({ "message": "API rate limit exceeded" })),
            )
            .mount(&server)
            .await;

        let clock = Arc::new(TestClock::default());
        let gateway = gateway(&server, clock);
        let error = gateway
            .list_runners(&repo_target(), &CancelToken::new())
            .await
            .expect_err("the quota is gone");

        let limit = *error.rate_limited().expect("a rate-limited state");
        assert_eq!(limit.kind, RateLimitKind::Primary);
        assert_eq!(limit.remaining, Some(0));
        assert_eq!(
            limit.reset_unix_secs,
            Some(u64::try_from(reset).unwrap()),
            "the reset instant is what tells an operator how long this lasts"
        );
        assert_eq!(gateway.rate_limit_backoff(), Some(Duration::from_secs(300)));

        // Displayable rather than opaque: a state, a sentence, and a delay `e1`
        // can add to its refresh interval.
        let state = RefreshState::from_error(&error);
        assert_eq!(state, RefreshState::RateLimited(limit));
        assert!(!state.is_ready());
        let rendered = state.to_string();
        assert!(rendered.contains("primary"), "{rendered}");
        assert!(rendered.contains("Refreshes are delayed"), "{rendered}");
        assert_eq!(
            state.retry_delay(TestClock::default().now()),
            Some(Duration::from_secs(300))
        );
    }

    /// The false positive this detection is narrowed to avoid.
    ///
    /// GitHub attaches `x-ratelimit-*` to **every** response. A `404` that
    /// happens to arrive on the request that exhausted the quota therefore
    /// carries `remaining: 0` while having nothing to do with rate limiting —
    /// and reporting it as one would tell an operator to wait for a repository
    /// name that will never resolve, while silently latching a back-off that
    /// suppresses every other target's refresh too.
    #[tokio::test]
    async fn a_404_carrying_an_exhausted_remaining_header_is_not_a_rate_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(
                ResponseTemplate::new(404)
                    .insert_header("x-ratelimit-remaining", "0")
                    .set_body_json(json!({ "message": "Not Found" })),
            )
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let error = gateway
            .list_runners(&repo_target(), &CancelToken::new())
            .await
            .expect_err("the repository is not there");

        assert!(!error.is_rate_limited(), "{error}");
        assert!(
            gateway.rate_limit_backoff().is_none(),
            "a 404 must not silence this gateway"
        );
        assert!(matches!(
            RefreshState::from_error(&error),
            RefreshState::Failed {
                status: Some(404),
                ..
            }
        ));
    }

    /// The other false positive: an ordinary permissions refusal.
    #[tokio::test]
    async fn a_permissions_403_is_forbidden_and_not_a_rate_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({ "message": "Resource not accessible by integration" })),
            )
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let error = gateway
            .list_runners(&repo_target(), &CancelToken::new())
            .await
            .expect_err("the installation does not grant it");

        assert!(!error.is_rate_limited(), "{error}");
        assert!(gateway.rate_limit_backoff().is_none());
        let state = RefreshState::from_error(&error);
        assert!(
            matches!(&state, RefreshState::Forbidden { message } if message.as_deref()
                == Some("Resource not accessible by integration")),
            "{state:?}: waiting does not fix a missing grant, so it must not be \
             rendered as something to wait for"
        );
        assert_eq!(
            state.retry_delay(TestClock::default().now()),
            None,
            "there is nothing to wait for"
        );
    }

    /// A rate limit that names no wait still waits: answering "retry in zero
    /// seconds" would turn a rate limit into a busy loop against the endpoint
    /// that asked for quiet.
    #[test]
    fn a_rate_limit_with_no_usable_delay_still_backs_off() {
        let now = TestClock::default().now();
        let bare = RateLimited {
            kind: RateLimitKind::Secondary,
            retry_after: None,
            remaining: None,
            reset_unix_secs: None,
        };
        assert_eq!(bare.delay_from(now), DEFAULT_RATE_LIMIT_BACKOFF);

        let stale_reset = RateLimited {
            reset_unix_secs: Some(u64::try_from(now.timestamp() - 60).unwrap()),
            ..bare
        };
        assert_eq!(
            stale_reset.delay_from(now),
            DEFAULT_RATE_LIMIT_BACKOFF,
            "a reset already in the past means the clocks disagree, not that the \
             limit has lifted"
        );

        let absurd = RateLimited {
            retry_after: Some(Duration::from_secs(86_400)),
            ..bare
        };
        assert_eq!(
            absurd.delay_from(now),
            MAX_RATE_LIMIT_BACKOFF,
            "a remote header does not get to decide how long this product stays dark"
        );
    }

    /// Rate limiting is "displayed, never hidden" — including before it bites.
    #[tokio::test]
    async fn the_hourly_quota_is_read_from_successful_responses_too() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-ratelimit-limit", "5000")
                    .insert_header("x-ratelimit-remaining", "4873")
                    .insert_header("x-ratelimit-reset", "1787274000")
                    .set_body_json(runner_page(1..3, 2)),
            )
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        assert_eq!(gateway.headroom(), None, "nothing observed yet");
        gateway
            .list_runners(&repo_target(), &CancelToken::new())
            .await
            .expect("readable");

        assert_eq!(
            gateway.headroom(),
            Some(RateLimitHeadroom {
                limit: Some(5_000),
                remaining: Some(4_873),
                reset_unix_secs: Some(1_787_274_000),
            }),
            "a quota display that only appears once the quota is gone is not a display"
        );
    }

    // -- cancellation -------------------------------------------------------

    /// A token flipped between pages stops the walk there, rather than spending
    /// the shared budget on pages nobody will read.
    #[tokio::test]
    async fn cancelling_between_pages_stops_the_walk() {
        let server = MockServer::start().await;
        let page_two = format!("{}/page/2", server.uri());
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("link", link_next(&page_two).as_str())
                    .set_body_json(runner_page(1..101, 200)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/page/2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(runner_page(101..201, 200)))
            .expect(0)
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let cancel = CancelToken::new();

        // Cancelled while page one is being read: the walk must not fetch page
        // two, even though the `Link` header offers it.
        let first = ApiRequest::get(REPO_RUNNERS).query("per_page", PER_PAGE);
        let response = gateway
            .get(&first, &cancel)
            .await
            .expect("page one is readable");
        assert!(response.next_page().is_some(), "page two is on offer");
        cancel.cancel();

        let error = gateway
            .list_runners(&repo_target(), &cancel)
            .await
            .expect_err("the token is cancelled");
        assert!(error.is_cancelled(), "{error}");
        assert_eq!(
            requests_seen(&server).await,
            1,
            "a cancelled walk spends nothing further"
        );
        assert_eq!(
            gateway.requests_issued(),
            1,
            "and the budget accounting agrees with the wire: a request that was \
             never polled is not a request that was issued"
        );
    }

    /// Cancellation of a request already on the wire, which is the case a
    /// between-pages check alone does not cover.
    #[tokio::test]
    async fn cancelling_an_in_flight_request_abandons_it() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(20))
                    .set_body_json(runner_page(1..2, 1)),
            )
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let cancel = CancelToken::new();
        let token = cancel.clone();
        let canceller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            token.cancel();
        });

        let started = std::time::Instant::now();
        let error = gateway
            .list_runners(&repo_target(), &cancel)
            .await
            .expect_err("the caller withdrew");
        let elapsed = started.elapsed();
        canceller.await.expect("the canceller completes");

        assert!(error.is_cancelled(), "{error}");
        assert!(
            elapsed < Duration::from_secs(10),
            "the request was awaited to completion rather than abandoned: {elapsed:?}"
        );
        assert!(cancel.is_cancelled());
        assert!(
            CancelToken::new().check().is_ok(),
            "a fresh token is not cancelled"
        );
    }

    // -- runner package downloads -------------------------------------------

    /// The Definition of Done's optional checksum: absent stays absent, and is
    /// distinguishable from empty.
    #[tokio::test]
    async fn an_absent_sha256_checksum_is_absent_and_an_empty_one_is_empty() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/dashboard/actions/runners/downloads"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "os": "win",
                    "architecture": "x64",
                    "download_url": "https://example.invalid/win-x64.zip",
                    "filename": "actions-runner-win-x64.zip",
                    "sha256_checksum": "abc123"
                },
                {
                    // The field is simply not there.
                    "os": "osx",
                    "architecture": "arm64",
                    "download_url": "https://example.invalid/osx-arm64.tar.gz",
                    "filename": "actions-runner-osx-arm64.tar.gz"
                },
                {
                    // The field is there and null.
                    "os": "linux",
                    "architecture": "x64",
                    "download_url": "https://example.invalid/linux-x64.tar.gz",
                    "filename": "actions-runner-linux-x64.tar.gz",
                    "sha256_checksum": null
                },
                {
                    // The field is there and empty, which is a different fact.
                    "os": "linux",
                    "architecture": "arm64",
                    "download_url": "https://example.invalid/linux-arm64.tar.gz",
                    "filename": "actions-runner-linux-arm64.tar.gz",
                    "sha256_checksum": ""
                }
            ])))
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let downloads = gateway
            .runner_downloads(&repo_target(), &CancelToken::new())
            .await
            .expect("the metadata is readable");

        let windows = downloads
            .select(Os::Windows, Arch::X64)
            .expect("selected by OS and architecture");
        assert_eq!(windows.sha256_checksum(), Some("abc123"));

        let missing = downloads.select(Os::MacOs, Arch::Arm64).expect("selected");
        assert_eq!(
            missing.sha256_checksum(),
            None,
            "`e2` fails closed on an absent digest, and can only do that if this \
             layer does not paper the absence over"
        );

        let null = downloads.select(Os::Linux, Arch::X64).expect("selected");
        assert_eq!(
            null.sha256_checksum(),
            None,
            "an explicit null is absent too"
        );

        let empty = downloads.select(Os::Linux, Arch::Arm64).expect("selected");
        assert_eq!(
            empty.sha256_checksum(),
            Some(""),
            "an empty digest is a different fact from a missing one, and \
             collapsing them would leave `e2` unable to report which it saw"
        );
        assert_ne!(
            empty.sha256_checksum(),
            missing.sha256_checksum(),
            "absent and empty must be distinguishable"
        );

        assert_eq!(
            downloads.select(Os::Windows, Arch::Arm32),
            None,
            "an unpublished pair is refused rather than substituted"
        );
        assert_eq!(gateway.requests_issued(), 1, "downloads are not paginated");
    }

    /// The organization form of the same endpoint.
    #[tokio::test]
    async fn runner_downloads_are_read_at_organization_scope_too() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/octo-org/actions/runners/downloads"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
                "os": "linux",
                "architecture": "arm",
                "download_url": "https://example.invalid/linux-arm.tar.gz",
                "filename": "actions-runner-linux-arm.tar.gz",
                "sha256_checksum": "deadbeef"
            }])))
            .expect(1)
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let downloads = gateway
            .runner_downloads(&org_target(), &CancelToken::new())
            .await
            .expect("readable");
        assert!(downloads.select(Os::Linux, Arch::Arm32).is_some());
    }

    // -- runner shape -------------------------------------------------------

    /// The D18 spike's label facts, kept true in the type.
    #[tokio::test]
    async fn labels_are_read_as_github_stores_them_and_matched_case_insensitively() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total_count": 2,
                "runners": [
                    {
                        "id": 73,
                        "name": "rm-d18-spike-ivanpc-1753",
                        "os": "win",
                        "status": "offline",
                        "busy": false,
                        "ephemeral": true,
                        // Lower-cased by GitHub, and carrying exactly what was
                        // requested — no `self-hosted`, no OS, no architecture.
                        "labels": [
                            { "id": 1, "name": "rm-home-win-x64", "type": "read-only" },
                            { "id": 2, "name": "windows", "type": "read-only" }
                        ]
                    },
                    {
                        "id": 74,
                        "name": "legacy-persistent",
                        "os": "Linux",
                        "status": "provisioning",
                        "busy": true,
                        "labels": []
                    }
                ]
            })))
            .mount(&server)
            .await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let inventory = gateway
            .list_runners(&repo_target(), &CancelToken::new())
            .await
            .expect("readable");

        let spike = &inventory.runners()[0];
        assert_eq!(spike.labels, ["rm-home-win-x64", "windows"]);
        assert!(
            spike.has_label("Windows"),
            "GitHub lower-cases what it stores"
        );
        assert!(spike.has_label("  windows  "));
        assert!(
            !spike.has_label("self-hosted"),
            "no label is added implicitly (D18, point 1)"
        );
        assert_eq!(spike.status, RunnerStatus::Offline);
        assert_eq!(spike.ephemeral, Some(true));
        assert_eq!(spike.parsed_os(), Some(Os::Windows));

        let legacy = &inventory.runners()[1];
        assert_eq!(
            legacy.status,
            RunnerStatus::Other("provisioning".to_string()),
            "an unrecognised status is something to display, not something to guess at"
        );
        assert_eq!(
            legacy.ephemeral, None,
            "absent is not `false`: a runner whose ephemerality is unknown is \
             exactly the one an operator wants flagged"
        );
        assert_eq!(legacy.parsed_os(), Some(Os::Linux));
        assert!(legacy.busy);
        assert_eq!(inventory.busy_count(), 1);
        assert_eq!(inventory.online_count(), 0);
    }

    // -- coalescing ---------------------------------------------------------

    /// The Definition of Done's coalescing item, measured where it matters: at
    /// the mock server's request log.
    ///
    /// The requirement is a budget one before it is a latency one. `F5` held
    /// down on the dashboard would otherwise be an operator-driven denial of
    /// service against a 5,000/hour ceiling shared with the polling that keeps
    /// runners starting.
    #[tokio::test]
    async fn a_manual_refresh_during_an_in_flight_one_coalesces_into_a_single_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(150))
                    .set_body_json(runner_page(1..4, 3)),
            )
            .mount(&server)
            .await;
        mount_runs(&repo(), 2).mount(&server).await;

        let gateway = Arc::new(gateway(&server, Arc::new(TestClock::default())));
        let coalescer: Arc<RefreshCoalescer<RefreshState>> = Arc::new(RefreshCoalescer::new());
        let scope = ActivityScope::repository(repo());

        let refresh = || {
            let gateway = gateway.clone();
            let coalescer = coalescer.clone();
            let scope = scope.clone();
            async move {
                coalescer
                    .refresh(|| async {
                        RefreshState::from_result(
                            gateway.snapshot(&scope, &CancelToken::new()).await,
                        )
                    })
                    .await
            }
        };

        // The scheduled poll and an operator's manual refresh, together.
        let (scheduled, manual) = tokio::join!(refresh(), refresh());

        assert_eq!(coalescer.performed(), 1, "one refresh actually ran");
        assert_eq!(coalescer.joined(), 1, "the other joined it");
        assert_eq!(scheduled, manual, "and both callers got the same answer");
        assert!(scheduled.is_ready(), "{scheduled}");
        assert_eq!(
            scheduled.snapshot().expect("ready").runners.len(),
            3,
            "joining must return the answer, not an empty placeholder"
        );
        assert_eq!(
            requests_seen(&server).await,
            2,
            "one refresh is one runners request plus one runs request; a second \
             refresh would have made it four"
        );
        assert_eq!(gateway.requests_issued(), 2);
        assert_eq!(coalescer.last(), Some(scheduled));
    }

    /// A refresh that arrives *after* the previous one finished is not a
    /// coalescing candidate — it is a new refresh, and must issue its own
    /// requests.
    #[tokio::test]
    async fn a_refresh_after_the_previous_one_completed_is_not_coalesced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REPO_RUNNERS))
            .respond_with(ResponseTemplate::new(200).set_body_json(runner_page(1..2, 1)))
            .mount(&server)
            .await;
        mount_runs(&repo(), 0).mount(&server).await;

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let coalescer: RefreshCoalescer<RefreshState> = RefreshCoalescer::new();
        let scope = ActivityScope::repository(repo());

        for _ in 0..3 {
            let state = coalescer
                .refresh(|| async {
                    RefreshState::from_result(gateway.snapshot(&scope, &CancelToken::new()).await)
                })
                .await;
            assert!(state.is_ready(), "{state}");
        }

        assert_eq!(coalescer.performed(), 3);
        assert_eq!(
            coalescer.joined(),
            0,
            "coalescing an in-flight refresh must not become caching a finished one"
        );
        assert_eq!(gateway.requests_issued(), 6);
    }

    // -- the shared request budget ------------------------------------------

    fn interval(secs: u16) -> RefreshInterval {
        RefreshInterval::from_secs(secs).expect("at or above the documented floor")
    }

    /// `04-subsystem-contracts.md`'s per-target table, reproduced exactly.
    ///
    /// | Per target, per hour | 60 s default | 30 s floor |
    /// |---|---|---|
    /// | demand | ~120 | ~240 |
    /// | runner inventory | ~60 | ~120 |
    /// | in-progress workflow count | ~60 | ~120 |
    /// | **total** | **~240** | **~480** |
    #[test]
    fn a_repository_target_costs_the_documented_number_of_requests() {
        let default = interval(RefreshInterval::DEFAULT_SECS);
        let floor = interval(RefreshInterval::MIN_SECS);

        assert_eq!(refreshes_per_hour(default), 60);
        assert_eq!(refreshes_per_hour(floor), 120);

        let target = TargetCost::repository();
        assert_eq!(target.requests_per_refresh(), 4);
        assert_eq!(
            target.requests_per_hour(default),
            240,
            "the documented per-target total at the 60-second default"
        );
        assert_eq!(
            target.requests_per_hour(floor),
            480,
            "and at the 30-second floor"
        );
    }

    /// The Definition of Done's "roughly 10 targets per host at the 60-second
    /// default and 5 at the 30-second floor".
    #[test]
    fn the_projection_reproduces_the_documented_target_ceilings() {
        assert_eq!(HOURLY_REQUEST_CEILING, 5_000);
        assert_eq!(budget_allowance(), 2_500, "half the ceiling");

        assert_eq!(
            BudgetProjection::max_repository_targets(interval(RefreshInterval::DEFAULT_SECS)),
            10
        );
        assert_eq!(
            BudgetProjection::max_repository_targets(interval(RefreshInterval::MIN_SECS)),
            5
        );

        // And the boundary is where the documented ceilings say it is.
        let default = interval(RefreshInterval::DEFAULT_SECS);
        let ten = BudgetProjection::new(default, vec![TargetCost::repository(); 10]);
        assert_eq!(ten.requests_per_hour(), 2_400);
        assert!(!ten.exceeds_allowance());
        assert_eq!(ten.headroom(), 100);

        let eleven = BudgetProjection::new(default, vec![TargetCost::repository(); 11]);
        assert_eq!(eleven.requests_per_hour(), 2_640);
        assert!(
            eleven.exceeds_allowance(),
            "the eleventh repository is the one an operator needs told about"
        );
        assert_eq!(eleven.headroom(), 0);
    }

    /// The correction this task owns: an organization is not a flat per-target
    /// constant.
    #[test]
    fn an_organization_target_costs_materially_more_than_a_repository_target() {
        let default = interval(RefreshInterval::DEFAULT_SECS);
        let repository = TargetCost::repository().requests_per_hour(default);

        assert_eq!(
            TargetCost::organization(1).requests_per_hour(default),
            repository,
            "at one installed repository the two models agree exactly, which is \
             what makes this a refinement of the documented table rather than a \
             contradiction of it"
        );

        let ten = TargetCost::organization(10);
        assert_eq!(ten.requests_per_refresh(), 31);
        assert_eq!(ten.requests_per_hour(default), 1_860);
        assert!(
            ten.requests_per_hour(default) > repository * 7,
            "an organization on ten repositories costs nearly eight times a \
             repository target; projecting it flat understates the real spend by \
             exactly that factor"
        );

        // Which is why the refusal arrives far earlier for an organization.
        let empty = BudgetProjection::new(default, Vec::new());
        assert!(empty.admit(TargetCost::repository()).is_admitted());
        assert!(empty.admit(TargetCost::organization(13)).is_admitted());
        let refusal = empty.admit(TargetCost::organization(14));
        assert!(
            !refusal.is_admitted(),
            "a single organization on fourteen repositories already exceeds a \
             host's whole share of the budget"
        );
    }

    /// `f2`'s refusal has to explain itself with the computed numbers, not with
    /// the rule.
    #[test]
    fn a_refused_configuration_states_the_numbers_and_the_maximum_target_count() {
        let default = interval(RefreshInterval::DEFAULT_SECS);
        let full = BudgetProjection::new(default, vec![TargetCost::repository(); 10]);

        let Admission::Refused {
            projected_requests_per_hour,
            allowance,
            max_repository_targets,
            ..
        } = full.admit(TargetCost::repository())
        else {
            panic!("the eleventh repository must be refused");
        };
        assert_eq!(projected_requests_per_hour, 2_640);
        assert_eq!(allowance, 2_500);
        assert_eq!(max_repository_targets, 10);

        let message = full.admit(TargetCost::repository()).to_string();
        for expected in ["2640", "2500", "5000", "60-second", "about 10 repository"] {
            assert!(
                message.contains(expected),
                "{expected:?} missing from: {message}"
            );
        }
        assert!(
            !message.contains("because the App is installed on"),
            "the organization clause belongs only on an organization refusal: {message}"
        );

        // An organization refusal says which repository count drove it, because
        // that is the part a flat per-target reading would not have predicted.
        let org_message = full.admit(TargetCost::organization(4)).to_string();
        assert!(
            org_message.contains("installed on 4 of its repositories"),
            "{org_message}"
        );

        let admitted = BudgetProjection::new(default, vec![TargetCost::repository(); 2])
            .admit(TargetCost::repository())
            .to_string();
        assert!(admitted.contains("720"), "{admitted}");
        assert!(admitted.contains("1780"), "{admitted}");
    }

    /// The projection's per-refresh constants, pinned against the requests the
    /// gateway actually issues.
    ///
    /// Without this the budget model is a table in a document that happens to be
    /// written in Rust. Demand is `c4`'s and is not issued here, so the two
    /// classes this task owns are compared on their own: an organization
    /// refresh is one runners request plus one runs request per installed
    /// repository, and the model has to say the same.
    #[tokio::test]
    async fn the_budget_model_matches_the_requests_the_gateway_really_issues() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ORG_RUNNERS))
            .respond_with(ResponseTemplate::new(200).set_body_json(runner_page(1..4, 3)))
            .mount(&server)
            .await;
        for repository in [repo(), other_repo(), third_repo()] {
            mount_runs(&repository, 1).mount(&server).await;
        }

        let gateway = gateway(&server, Arc::new(TestClock::default()));
        let scope = ActivityScope::organization(
            Org::new("octo-org").expect("a valid organization login"),
            [repo(), other_repo(), third_repo()],
        );
        gateway
            .snapshot(&scope, &CancelToken::new())
            .await
            .expect("readable");

        let cost = TargetCost::from_activity_scope(&scope);
        assert_eq!(cost.installed_repositories(), 3);
        assert_eq!(cost.scope(), TargetScope::Organization);

        let modelled_without_demand = cost.requests_per_refresh()
            - DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH * cost.installed_repositories();
        assert_eq!(
            gateway.requests_issued(),
            u64::from(modelled_without_demand),
            "the model projects {modelled_without_demand} inventory-and-activity \
             requests per refresh for this scope, and the gateway issued {}",
            gateway.requests_issued()
        );
        assert_eq!(
            modelled_without_demand,
            RUNNER_INVENTORY_REQUESTS_PER_REFRESH + scope.requests_per_refresh()
        );
    }

    /// An organization the App reaches no repository in is projected as zero
    /// repositories, not silently as one.
    #[test]
    fn an_organization_with_no_installed_repositories_is_projected_as_such() {
        let scope = ActivityScope::organization(
            Org::new("octo-org").expect("a valid organization login"),
            [],
        );
        assert_eq!(scope.requests_per_refresh(), 0);
        let cost = TargetCost::from_activity_scope(&scope);
        assert_eq!(cost.installed_repositories(), 0);
        assert_eq!(
            cost.requests_per_refresh(),
            RUNNER_INVENTORY_REQUESTS_PER_REFRESH,
            "the runners endpoint is still polled; nothing else is"
        );
    }

    /// A repository target's activity scope is its own repository, whatever a
    /// caller passes.
    #[test]
    fn a_repository_activity_scope_covers_exactly_one_repository() {
        let scope = ActivityScope::repository(repo());
        assert_eq!(scope.repositories(), [repo()]);
        assert_eq!(scope.requests_per_refresh(), 1);
        assert_eq!(scope.target(), &repo_target());
        assert_eq!(
            TargetCost::from_activity_scope(&scope),
            TargetCost::repository()
        );
    }

    // -- error summarising --------------------------------------------------

    /// Every authentication outcome `c2` separates stays separate here. `f1`
    /// reports four states and must not collapse them.
    #[test]
    fn the_authentication_taxonomy_survives_the_summary() {
        assert_eq!(
            RefreshState::from_error(&InventoryError::Github(GithubError::AuthenticationFailed)),
            RefreshState::Unauthorized
        );
        assert_eq!(
            RefreshState::from_error(&InventoryError::Github(
                GithubError::AuthenticationLockout {
                    retry_after: Duration::from_secs(60)
                }
            )),
            RefreshState::LockedOut {
                retry_after: Duration::from_secs(60)
            }
        );
        assert_eq!(
            RefreshState::from_error(&InventoryError::Cancelled),
            RefreshState::Cancelled
        );

        // A lockout is waited out; a rejected credential is not.
        let now = TestClock::default().now();
        assert_eq!(
            RefreshState::LockedOut {
                retry_after: Duration::from_secs(60)
            }
            .retry_delay(now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(RefreshState::Unauthorized.retry_delay(now), None);
        assert_eq!(RefreshState::Offline.retry_delay(now), None);
    }

    /// An empty inventory is an answer, not a failure. An idle host that
    /// rendered as broken would be a support ticket a week.
    #[test]
    fn an_empty_snapshot_is_ready_rather_than_a_failure() {
        let snapshot = InventorySnapshot {
            target: repo_target(),
            runners: RunnerInventory::new(repo_target(), Vec::new()),
            activity: ActivityCount::of(repo(), 0),
            observed_at: TestClock::default().now(),
            headroom: None,
        };
        let state = RefreshState::from_result(Ok(snapshot));
        assert!(state.is_ready());
        assert!(state.snapshot().expect("ready").runners.is_empty());
        assert_eq!(state.to_string(), "0 runners, 0 in progress");
    }
}
