// owner: e1-reconciliation-capacity

//! The loop that turns GitHub demand into a decision to start runners — and
//! that refuses to start them when it should not.
//!
//! Every ceiling in this product is enforced from here, so the module is
//! organised around the four things that can go wrong silently:
//!
//! * [`PollSchedule`] — the budget-aware interval. Demand shares one 5,000
//!   requests/hour ceiling with inventory and workflow counts, so this loop
//!   polls on a bounded interval (default 60 s, hard floor 30 s per target) and
//!   *increases* the delay under a rate-limit signal, never decreases it to
//!   catch up.
//! * [`RepositoryCache`] — the per-organization repository list, refreshed on
//!   an interval materially slower than the demand poll. Re-listing an
//!   organization at demand-poll frequency is what exhausts the shared budget
//!   the paragraph above exists to protect.
//! * [`Reconciler::reconcile`] — the allocation pass. It re-reads the attempt
//!   set **under the host-wide allocation lock, once per runtime created**, so
//!   two policies reconciling concurrently cannot both spend the same headroom.
//! * [`LifecycleEvent`] — what `g2` and the local log sink see. Every field is
//!   an identifier, a count, an enumerated state or a duration; nothing free
//!   text, and nothing that came off the wire.
//!
//! # There is no acquisition step, and none may be added
//!
//! The scale-set model called `AcquireJobs` to reserve an assignment before
//! scaling. The REST path has no equivalent (`01-current-architecture.md`, edge
//! case 6), so demand is **advisory**. Two consequences are load-bearing here
//! and neither is a defect:
//!
//! 1. **A surplus runner is an accepted outcome.** Another host serving the
//!    same labels may take the job first; this host's runner then finds no work
//!    and exits on its idle timeout, having cost one capacity slot and one cold
//!    start. That terminal outcome is
//!    [`AttemptOutcome::ExitedIdleWithoutWork`], is cleaned like any other, and
//!    is counted apart from a failure — see [`ReconcileReport::idle_exits`].
//! 2. **The same job is still `queued` on the next poll** while its runner
//!    starts. The `- active_owned_runners` term in
//!    [`HostAllocator::allocate`] is what stops that from starting a second
//!    runner, and then a third. This module's only job in that arithmetic is to
//!    hand the allocator the attempt set the host actually holds — which is why
//!    [`RunnerLauncher`] supplies both the attempts and the launch, from one
//!    supply point, for the reason `b1` gives at
//!    [`HostAllocator::from_attempts`].
//!
//! `tests::nothing_in_this_module_reserves_or_claims_a_job` is a tripwire on the
//! obvious shape of a reservation being added back.
//!
//! # Demand is measured in RUNS, and carries no routing-label filtering
//!
//! `02-target-architecture.md` writes the formula as *"queued jobs whose
//! `runs-on` matches this policy's routing labels"*. That is not what the
//! gateway this module consumes provides, and this module must not try to make
//! it so.
//!
//! A workflow **run** carries no `runs-on` — labels live on **jobs** — and an
//! owner decision forbids the per-run job listing that would be needed to see
//! them. So `crates/github/src/demand.rs` counts **queued runs** and applies no
//! label filtering whatsoever, and this module clamps that number directly. The
//! owner has accepted both consequences:
//!
//! * an **under-count** — a matrix run of eight jobs reports as one unit of
//!   demand;
//! * an **over-count** — a repository whose jobs only ever target
//!   `ubuntu-latest` or another host's labels still drives its policy toward
//!   `max_capacity`, and each runner started that way idles until it times out.
//!
//! The over-count is not a bug to engineer around here. It travels the same
//! accepted surplus-runner path described above, and it is bounded by exactly
//! the two ceilings this module enforces. `b1`'s `RoutingLabels::tally` exists
//! and is correct, and nothing feeds it today; wiring it in to "complete" the
//! picture would require the job listing the owner decision removed.
//! `tests::this_module_owns_no_label_predicate` scans this file's own source and
//! fails if it starts naming `b1`'s label vocabulary, which is the same tripwire
//! `c4` carries one layer down.
//!
//! # What is testable without a network, a filesystem, or a process
//!
//! All of it. [`DemandSource`], [`RunnerLauncher`], [`AllocationLock`],
//! [`RepositoryDirectory`], [`Jitter`] and [`EventSink`] are ports;
//! [`GatewayDemand`], [`FileAllocationLock`], [`RandomJitter`] and
//! [`TracingEvents`] are the production adapters, and every one of them is a
//! thin shell over a decision made in this file.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runner_manager_domain::attempt::{AttemptOutcome, AttemptState, FailureReason, RunnerAttempt};
use runner_manager_domain::capacity::{Allocation, HostAllocator, LimitingFactor};
use runner_manager_domain::model::{
    AttemptId, Clock, Host, Org, OwnerRepo, PolicyId, RefreshInterval, ScaleTarget, Timestamp,
};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_github::demand::{DemandGateway, QueuedDemand, demand_requests_per_poll};
use runner_manager_github::rest::{
    ActivityScope, CancelToken, InventoryError, RateLimitKind, RefreshState,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How much slower than the demand poll the per-organization repository list is
/// refreshed.
///
/// There is no organization-wide workflow-runs endpoint, so an organization
/// target costs one demand request **per repository the App is installed on**
/// (`crates/github/src/demand.rs`). Discovering that repository list costs
/// requests of its own, and it is the one input to a demand poll that changes on
/// a human timescale: repositories are added to an installation by hand, not by
/// a workflow starting.
///
/// Thirty polls is 30 minutes at the 60-second default and 15 at the 30-second
/// floor — slow enough that the list is a rounding error against the demand
/// requests it scopes, and fast enough that a repository added to the
/// installation starts being served within one coffee break rather than at the
/// next restart.
pub const REPOSITORY_LIST_REFRESH_MULTIPLE: u32 = 30;

/// The longest the *unjittered* offline back-off may grow to.
///
/// A back-off is a safety mechanism, and an unclamped one is an outage with
/// extra steps. Fifteen minutes matches
/// [`runner_manager_github::rest::MAX_RATE_LIMIT_BACKOFF`], which is the other
/// place in this product where a delay is allowed to grow, and it is far inside
/// the 24-hour bound at which GitHub cancels the queued jobs this loop exists to
/// serve.
pub const MAX_OFFLINE_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// The most the offline back-off is doubled, before the cap applies.
///
/// At the 60-second default this reaches [`MAX_OFFLINE_BACKOFF`] on the sixth
/// consecutive failure, which is roughly half an hour of outage. Past that the
/// cap holds it flat.
const MAX_BACKOFF_DOUBLINGS: u32 = 5;

/// How much of the computed back-off is jitter.
///
/// Jitter is **added** rather than subtracted, so a back-off never comes out
/// shorter than the delay it was computed from. Subtractive jitter would let the
/// first offline poll retry sooner than the nominal interval, which is the
/// opposite of backing off; it is spelled out because "add jitter" reads as
/// symmetric and is not.
const JITTER_RATIO: f64 = 0.5;

/// GitHub cancels a queued job after this long.
///
/// `01-current-architecture.md` records the measurement; `03-control-flows.md`
/// flow 3.3 requires that the offline state **states** it, because an agent
/// offline for longer than this has lost queued work and the operator cannot
/// infer that from "offline". [`OfflineState`] is where it is said.
pub const GITHUB_CANCELS_QUEUED_JOBS_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// How long [`FileAllocationLock`] waits for the host-wide allocation lock
/// before reporting contention.
///
/// Contention here is expected rather than exceptional — it is two of this
/// host's own policies creating runtimes at the same moment — and each hold
/// lasts only as long as one runtime creation. Waiting a few seconds turns the
/// common case into a short pause instead of a skipped runner.
///
/// # How many of these a poll actually costs
///
/// Exactly one per runtime created, and none for a policy that is granted
/// nothing. That is worth stating because it did not used to be true and the
/// difference only shows up here: the budget was checked *after* the lock had
/// been taken and the attempt set re-read, so a policy granted N runners took
/// N+1 holds, and `start_runners` ran for every readable autoscale policy
/// including the zero-demand ones — so an idle host with P policies took P
/// host-wide locks per poll for nothing. Free under
/// [`InProcessAllocationLock`]; under [`FileAllocationLock`] each one is a
/// `spawn_blocking` plus a filesystem lock, with this wait behind it.
///
/// [`Reconciler::start_runners`] now pre-checks lock-free and stops as soon as
/// the budget is spent. The under-lock re-read still decides.
pub const ALLOCATION_LOCK_WAIT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// What one demand poll produced
// ---------------------------------------------------------------------------

/// One target's demand poll, as a value this module can decide from.
///
/// The failure half is `c3`'s [`RefreshState`] rather than an
/// [`InventoryError`], for the reason `c3` gives: `InventoryError` owns a
/// `reqwest::Error` and a `serde_json::Error`, so it is neither `Clone` nor
/// `PartialEq` and cannot be stored, compared, or rendered. Summarising at the
/// gateway boundary — exactly once, in [`GatewayDemand`] — is what lets the
/// whole schedule below be a pure function of values a test can construct.
///
/// [`RefreshState::Ready`] never appears in [`PollOutcome::Failed`]:
/// [`RefreshState::from_error`] cannot produce it, and a demand poll returns a
/// [`QueuedDemand`] rather than the runner inventory that variant carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// GitHub answered. The count may still be a floor — see
    /// [`QueuedDemand::is_complete`].
    Ready(QueuedDemand),
    /// GitHub did not answer, or answered something this loop must slow down
    /// for.
    Failed(RefreshState),
}

impl PollOutcome {
    /// The demand reading, when there is one.
    #[must_use]
    pub const fn reading(&self) -> Option<&QueuedDemand> {
        match self {
            Self::Ready(demand) => Some(demand),
            Self::Failed(_) => None,
        }
    }

    /// The failure, when there is one.
    #[must_use]
    pub const fn failure(&self) -> Option<&RefreshState> {
        match self {
            Self::Failed(state) => Some(state),
            Self::Ready(_) => None,
        }
    }

    /// Whether GitHub could not be reached at all, as opposed to answering
    /// something unwelcome.
    ///
    /// The whole of flow 3.3 turns on this distinction: an outage retains
    /// running runners and backs off, while a rejection is a configuration
    /// problem that waiting does not fix.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        matches!(self, Self::Failed(RefreshState::Offline))
    }
}

/// Where this loop gets its demand from.
///
/// A port rather than a direct [`DemandGateway`] dependency, because the two
/// failures this loop must handle differently — unreachable and rate-limited —
/// are distinguished by [`RefreshState`], and a test that wants to drive the
/// offline path should not have to manufacture a `reqwest::Error` to do it.
/// [`GatewayDemand`] is the one adapter that talks to `c4`.
#[async_trait::async_trait]
pub trait DemandSource: fmt::Debug + Send + Sync {
    /// Queued runs across `scope`, or why there are none to report.
    async fn poll(&self, scope: &ActivityScope) -> PollOutcome;
}

/// [`DemandSource`] over `c4`'s [`DemandGateway`].
///
/// Holds the [`CancelToken`] so that a shutting-down daemon can withdraw a poll
/// that is already blocked on a socket; `f3` keeps a clone and cancels it.
#[derive(Debug)]
pub struct GatewayDemand<G> {
    gateway: G,
    cancel: CancelToken,
}

impl<G: DemandGateway> GatewayDemand<G> {
    #[must_use]
    pub const fn new(gateway: G, cancel: CancelToken) -> Self {
        Self { gateway, cancel }
    }

    #[must_use]
    pub const fn gateway(&self) -> &G {
        &self.gateway
    }
}

#[async_trait::async_trait]
impl<G: DemandGateway + 'static> DemandSource for GatewayDemand<G> {
    async fn poll(&self, scope: &ActivityScope) -> PollOutcome {
        match self.gateway.queued_demand(scope, &self.cancel).await {
            Ok(demand) => PollOutcome::Ready(demand),
            // The one place an `InventoryError` is summarised. `c3` owns the
            // mapping — including transport-to-`Offline`, which is what flow
            // 3.3 branches on — so this loop never re-decides it.
            Err(error) => PollOutcome::Failed(RefreshState::from_error(&error)),
        }
    }
}

// ---------------------------------------------------------------------------
// The repository list, cached
// ---------------------------------------------------------------------------

/// Which repositories an organization installation reaches.
///
/// `f1` already holds this, from
/// [`runner_manager_github::AuthenticatedClient::discover_installations`]. It is
/// a port here so that [`RepositoryCache`] can be tested for the property that
/// matters — how *often* it asks — without a network.
#[async_trait::async_trait]
pub trait RepositoryDirectory: fmt::Debug + Send + Sync {
    /// The repositories this credential reaches in `org`.
    ///
    /// # Errors
    /// Anything the underlying gateway reports.
    async fn repositories(&self, org: &Org) -> Result<Vec<OwnerRepo>, InventoryError>;
}

#[derive(Debug, Clone)]
struct CachedRepositories {
    repositories: Vec<OwnerRepo>,
    fetched_at: Timestamp,
}

/// The per-organization repository list, refreshed far more slowly than demand.
///
/// # Why this is not just "call the directory each poll"
///
/// An organization demand poll already costs one request per repository. Adding
/// the installation listing to every poll makes the *scoping* of a poll cost
/// requests on the same schedule as the poll itself, which is how a
/// ten-repository organization at the 30-second floor stops fitting inside the
/// half-of-5,000 allowance `f2` admits targets against. The repository list is
/// also the one input that changes on a human timescale, so refreshing it
/// [`REPOSITORY_LIST_REFRESH_MULTIPLE`] times more slowly costs nothing real.
///
/// # A repository target never consults the directory at all
///
/// Its scope is itself. That is not an optimisation; asking an installation
/// listing which repositories a single named repository covers would be asking a
/// question whose answer is already in the target.
#[derive(Debug)]
pub struct RepositoryCache {
    directory: Arc<dyn RepositoryDirectory>,
    clock: Arc<dyn Clock>,
    ttl: Duration,
    entries: Mutex<BTreeMap<Org, CachedRepositories>>,
    lookups: AtomicU64,
}

impl RepositoryCache {
    /// Build a cache whose refresh interval is `poll` slowed by
    /// [`REPOSITORY_LIST_REFRESH_MULTIPLE`].
    #[must_use]
    pub fn new(
        directory: Arc<dyn RepositoryDirectory>,
        clock: Arc<dyn Clock>,
        poll: RefreshInterval,
    ) -> Self {
        let ttl = Duration::from_secs(u64::from(poll.as_secs()))
            .saturating_mul(REPOSITORY_LIST_REFRESH_MULTIPLE);
        Self {
            directory,
            clock,
            ttl,
            entries: Mutex::new(BTreeMap::new()),
            lookups: AtomicU64::new(0),
        }
    }

    /// How long a cached repository list is reused for.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// How many times the underlying directory was actually asked.
    ///
    /// Measured rather than assumed, for the reason `c4` measures its own
    /// request count: a budget nothing counts is a table in a document.
    #[must_use]
    pub fn lookups(&self) -> u64 {
        self.lookups.load(Ordering::SeqCst)
    }

    /// The scope one demand poll of `target` covers.
    ///
    /// # Errors
    /// Whatever the directory reported, for an organization target whose list is
    /// stale or absent. A repository target cannot fail.
    pub async fn scope_for(&self, target: &ScaleTarget) -> Result<ActivityScope, InventoryError> {
        match target {
            ScaleTarget::Repository(repository) => {
                Ok(ActivityScope::repository(repository.clone()))
            }
            ScaleTarget::Organization(org) => {
                let repositories = self.repositories_of(org).await?;
                Ok(ActivityScope::organization(org.clone(), repositories))
            }
        }
    }

    async fn repositories_of(&self, org: &Org) -> Result<Vec<OwnerRepo>, InventoryError> {
        let now = self.clock.now();
        if let Some(fresh) = self.fresh_entry(org, now) {
            return Ok(fresh);
        }

        // The directory call is deliberately made with no lock held. Two
        // concurrent misses can therefore both ask, which costs one extra
        // listing on the poll that follows a restart; holding a `std::sync`
        // mutex across an `await` would cost a blocked executor thread and, on
        // a current-thread runtime, a deadlock. The cheaper mistake is the one
        // that spends a request.
        let repositories = self.directory.repositories(org).await?;
        self.lookups.fetch_add(1, Ordering::SeqCst);
        self.store(org.clone(), repositories.clone(), now);
        Ok(repositories)
    }

    fn fresh_entry(&self, org: &Org, now: Timestamp) -> Option<Vec<OwnerRepo>> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(org)?;
        let age = now.signed_duration_since(entry.fetched_at).to_std().ok()?;
        (age < self.ttl).then(|| entry.repositories.clone())
    }

    fn store(&self, org: Org, repositories: Vec<OwnerRepo>, fetched_at: Timestamp) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                org,
                CachedRepositories {
                    repositories,
                    fetched_at,
                },
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Jitter
// ---------------------------------------------------------------------------

/// The randomness in the offline back-off, as a port.
///
/// Flow 3.3 requires jittered back-off, and a jittered delay is by construction
/// not reproducible — so the source of the randomness is a port, and every test
/// below asserts the *bounds* of the delay against a fixed fraction rather than
/// asserting a number it could only have got by running the generator.
pub trait Jitter: fmt::Debug + Send + Sync {
    /// A fraction in `[0.0, 1.0)`. Values outside that range are clamped by the
    /// caller, so an implementation cannot lengthen a back-off without bound.
    fn fraction(&self) -> f64;
}

/// The production source.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomJitter;

impl Jitter for RandomJitter {
    fn fraction(&self) -> f64 {
        rand::random::<f64>()
    }
}

/// A fixed fraction, for tests and for the acceptance suite.
#[derive(Debug, Clone, Copy)]
pub struct FixedJitter(pub f64);

impl Jitter for FixedJitter {
    fn fraction(&self) -> f64 {
        self.0
    }
}

/// No jitter at all: the back-off is exactly what the schedule computed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoJitter;

impl Jitter for NoJitter {
    fn fraction(&self) -> f64 {
        0.0
    }
}

// ---------------------------------------------------------------------------
// The schedule
// ---------------------------------------------------------------------------

/// Why the next poll is when it is.
///
/// Reported rather than inferred, because
/// `04-subsystem-contracts.md` requires that rate limiting be *"displayed, never
/// hidden"* — and a delay that grew for a reason the caller cannot name is
/// hidden however visible the number is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollPace {
    /// The configured interval. Nothing is throttling this loop.
    Nominal,
    /// GitHub's rate limit is exhausted. Resolves by waiting.
    RateLimited { kind: RateLimitKind },
    /// GitHub's temporary authentication lockout. The credential is fine.
    LockedOut,
    /// GitHub could not be reached. `consecutive` counts the unbroken run of
    /// failures the back-off was computed from.
    Offline { consecutive: u32 },
    /// GitHub answered something no amount of waiting fixes — a rejected
    /// credential, a permissions refusal, or an error status. The loop keeps
    /// polling at its nominal interval so that a fix is noticed, and says that
    /// it is blocked rather than pretending the poll succeeded.
    Blocked,
}

impl PollPace {
    /// Whether this pace is a slowdown the operator should be told about.
    #[must_use]
    pub const fn is_throttled(&self) -> bool {
        !matches!(self, Self::Nominal)
    }

    /// A fixed, credential-free name for the log sink and for `g2`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::RateLimited {
                kind: RateLimitKind::Primary,
            } => "rate_limited_primary",
            Self::RateLimited {
                kind: RateLimitKind::Secondary,
            } => "rate_limited_secondary",
            Self::LockedOut => "locked_out",
            Self::Offline { .. } => "offline",
            Self::Blocked => "blocked",
        }
    }
}

impl fmt::Display for PollPace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// When to poll next, and why then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextPoll {
    pub delay: Duration,
    pub pace: PollPace,
}

/// The bounded, budget-aware poll interval.
///
/// # The floor is a rate-budget constraint, not a preference
///
/// [`RefreshInterval`] refuses anything under 30 seconds at construction, and
/// every delay this type produces is at least that — including the ones it
/// computes from a remote header. A rate limit may only ever make this loop
/// *slower*.
///
/// # `retry_delay` is an absolute floor, not an addend
///
/// `c3` documents [`RefreshState::retry_delay`] as *"the earliest time a retry
/// may occur"*: the scheduling rule is `next_attempt_at = now + retry_delay`,
/// and **not** the ordinary interval plus it. Adding the two compounds on every
/// successive retry — each new answer carries the remaining window, so an
/// addend ratchets outward — and the symptom is a dashboard that stays dark
/// long after GitHub said it could come back, which reads as a hang rather than
/// as a rate limit. So the two are combined with `max`, which is what makes the
/// floor a floor.
#[derive(Debug, Clone)]
pub struct PollSchedule {
    interval: RefreshInterval,
    consecutive_offline: u32,
    offline_since: Option<Timestamp>,
}

impl PollSchedule {
    #[must_use]
    pub const fn new(interval: RefreshInterval) -> Self {
        Self {
            interval,
            consecutive_offline: 0,
            offline_since: None,
        }
    }

    #[must_use]
    pub const fn interval(&self) -> RefreshInterval {
        self.interval
    }

    /// The nominal interval as a [`Duration`].
    #[must_use]
    pub const fn nominal(&self) -> Duration {
        Duration::from_secs(self.interval.as_secs() as u64)
    }

    /// The unbroken run of offline polls this schedule has seen.
    #[must_use]
    pub const fn consecutive_offline(&self) -> u32 {
        self.consecutive_offline
    }

    /// How long GitHub has been unreachable, or `None` when it is not.
    ///
    /// Measured from the first poll of the current run rather than inferred
    /// from [`Self::consecutive_offline`] times the interval. The two diverge
    /// as soon as the back-off starts doubling, and this is the number the
    /// 24-hour queue-cancellation warning is compared against — an estimate
    /// would make that warning fire early or late, and it is the one thing the
    /// offline state exists to say.
    #[must_use]
    pub fn offline_for(&self, now: Timestamp) -> Option<Duration> {
        let since = self.offline_since?;
        now.signed_duration_since(since).to_std().ok()
    }

    /// The hard floor no computed delay may go below.
    #[must_use]
    pub const fn floor() -> Duration {
        Duration::from_secs(RefreshInterval::MIN_SECS as u64)
    }

    /// Decide when to poll next, given how this pass ended.
    ///
    /// `failure` is the most severe failure across the targets polled this pass,
    /// or `None` when every target answered. A pass that answered resets the
    /// offline run, which is the whole of "recovery needs no bookkeeping":
    /// demand is recomputed from the current queued-run set on every poll, so
    /// there is nothing else to unwind.
    pub fn next_poll(
        &mut self,
        failure: Option<&RefreshState>,
        now: Timestamp,
        jitter: &dyn Jitter,
    ) -> NextPoll {
        let nominal = self.nominal();

        let next = match failure {
            None => {
                self.recovered();
                NextPoll {
                    delay: nominal,
                    pace: PollPace::Nominal,
                }
            }
            Some(RefreshState::Offline) => {
                self.consecutive_offline = self.consecutive_offline.saturating_add(1);
                // The instant the *run* began, not the instant of this poll.
                self.offline_since.get_or_insert(now);
                NextPoll {
                    delay: self.offline_delay(nominal, jitter),
                    pace: PollPace::Offline {
                        consecutive: self.consecutive_offline,
                    },
                }
            }
            Some(state @ RefreshState::RateLimited(limit)) => {
                self.recovered();
                NextPoll {
                    // `max`, never `+`. See the type documentation.
                    delay: retry_floor(state, now).max(nominal),
                    pace: PollPace::RateLimited { kind: limit.kind },
                }
            }
            Some(state @ RefreshState::LockedOut { .. }) => {
                self.recovered();
                NextPoll {
                    delay: retry_floor(state, now).max(nominal),
                    pace: PollPace::LockedOut,
                }
            }
            // Unauthorized, Forbidden, Failed, Cancelled. `retry_delay` is
            // `None` for all of them, and deliberately: no wait fixes a revoked
            // credential or a missing grant. Polling stops being useful but
            // does not stop, because the poll is also how a re-authentication
            // is noticed.
            Some(_) => {
                // GitHub answered, so it is reachable: whatever is wrong, it is
                // not an outage, and an outage run that was open must close.
                self.recovered();
                NextPoll {
                    delay: nominal,
                    pace: PollPace::Blocked,
                }
            }
        };

        debug_assert!(
            next.delay >= Self::floor(),
            "the 30-second floor is a rate-budget constraint and no branch may go below it"
        );
        next
    }

    /// GitHub answered something. Whatever it was, the outage run is over.
    fn recovered(&mut self) {
        self.consecutive_offline = 0;
        self.offline_since = None;
    }

    fn offline_delay(&self, nominal: Duration, jitter: &dyn Jitter) -> Duration {
        let doublings = self
            .consecutive_offline
            .saturating_sub(1)
            .min(MAX_BACKOFF_DOUBLINGS);
        let grown = nominal.saturating_mul(1_u32 << doublings);
        let capped = grown.min(MAX_OFFLINE_BACKOFF);
        // Additive, never subtractive: see `JITTER_RATIO`. The result may exceed
        // `MAX_OFFLINE_BACKOFF` by up to the jitter ratio, which is the price of
        // keeping a fleet of agents from retrying in lockstep at the plateau —
        // a cap applied *after* jitter would collapse every agent onto the same
        // instant precisely when the outage is longest.
        let spread = capped.mul_f64(JITTER_RATIO * jitter.fraction().clamp(0.0, 1.0));
        capped.saturating_add(spread).max(Self::floor())
    }
}

/// `c3`'s retry floor, with the one fallback this loop needs.
///
/// [`RefreshState::retry_delay`] answers `None` for the states no wait fixes,
/// and those never reach here — the caller matches them into
/// [`PollPace::Blocked`] first. The fallback exists so that a future
/// `RefreshState` variant added to the two arms above cannot silently schedule a
/// zero-second retry against an endpoint that asked for quiet.
fn retry_floor(state: &RefreshState, now: Timestamp) -> Duration {
    state.retry_delay(now).unwrap_or(PollSchedule::floor())
}

// ---------------------------------------------------------------------------
// Offline
// ---------------------------------------------------------------------------

/// What an operator is told while GitHub is unreachable.
///
/// Flow 3.3 requires four things of an outage — start no new runner, retain
/// existing runner processes, report `offline`, back off with jitter — and one
/// thing of the *state*: that it says GitHub cancels queued jobs after 24 hours,
/// so a prolonged outage loses queued work. That bound is stated here rather
/// than left for a reader to infer, because an operator who does not know it has
/// no reason to treat a long outage as urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineState {
    /// The unbroken run of failed polls.
    pub consecutive: u32,
    /// How long until the next attempt.
    pub retry_in: Duration,
    /// How long this loop has been unable to reach GitHub, when it is known.
    pub offline_for: Option<Duration>,
}

impl OfflineState {
    #[must_use]
    pub const fn new(consecutive: u32, retry_in: Duration) -> Self {
        Self {
            consecutive,
            retry_in,
            offline_for: None,
        }
    }

    #[must_use]
    pub const fn since(mut self, offline_for: Duration) -> Self {
        self.offline_for = Some(offline_for);
        self
    }

    /// Whether the outage has already outlasted GitHub's queue.
    ///
    /// `false` when the duration is unknown: this reports a fact, and "we cannot
    /// tell" is not the same fact as "not yet".
    #[must_use]
    pub fn has_outlasted_the_queue(&self) -> bool {
        self.offline_for
            .is_some_and(|elapsed| elapsed >= GITHUB_CANCELS_QUEUED_JOBS_AFTER)
    }
}

impl fmt::Display for OfflineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GitHub is unreachable; no new runners are being started and running \
             runners are left alone. Retrying in {}s",
            self.retry_in.as_secs()
        )?;
        if self.has_outlasted_the_queue() {
            f.write_str(
                ". This outage has lasted more than 24 hours, and GitHub cancels a queued \
                 job after 24 hours, so queued work has been lost",
            )
        } else {
            f.write_str(
                ". GitHub cancels a queued job after 24 hours, so an outage longer than \
                 that loses queued work",
            )
        }
    }
}

// ---------------------------------------------------------------------------
// The launcher port
// ---------------------------------------------------------------------------

/// What this loop asks `e3` to create.
#[derive(Debug, Clone, Copy)]
pub struct LaunchRequest<'a> {
    pub host: &'a Host,
    pub policy: &'a ScalePolicy,
}

/// Why one runner could not be started.
///
/// Carries `b1`'s [`FailureReason`] rather than a taxonomy of this module's own:
/// the reasons a runner fails to start are `e3`'s to know and `b1`'s to name,
/// and a third vocabulary here would be a third answer to a question the
/// operator asks once.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the runner could not be started: {reason}")]
pub struct LaunchFailure {
    pub reason: FailureReason,
}

impl LaunchFailure {
    #[must_use]
    pub const fn new(reason: FailureReason) -> Self {
        Self { reason }
    }
}

/// The seam between the decision to start a runner and the act of starting one.
///
/// `e3` implements this; every test in this file fakes it, which is what makes
/// the whole allocator path decidable with no process, no filesystem and no
/// network.
///
/// # Why the attempt set comes through the same port as the launch
///
/// `b1` makes this argument at [`HostAllocator::from_attempts`] and it applies
/// one layer up: the host-wide total (D9) and every per-policy count (D7) are
/// two questions asked of **one** set, and a design that let the caller supply
/// the set separately from the thing that creates its members is a design in
/// which the two can disagree. Worse, it makes `&[]` expressible — and an empty
/// attempt set is exactly the shape that drops the `- active_owned_runners`
/// term, starts a second runner for a job already being served, and reports no
/// error while doing it.
///
/// So the launcher is asked, under the allocation lock, immediately before each
/// runtime is created. There is no second supply point and no cached copy.
///
/// # The two ways an implementer can say "I hold no attempts"
///
/// The argument above closes the hole for a *caller*. It stayed open one level
/// down for the **implementer**, in two shapes that both oversubscribe the
/// machine and neither of which reports anything:
///
/// * **By failing.** `attempts()` used to be infallible, which left `e3` — which
///   reads a journal off a disk — a choice between panicking and answering
///   `vec![]` on an I/O error. An empty set is indistinguishable from an idle
///   host, so a transient read failure reads as "nothing is running" and the
///   next pass allocates the whole machine for jobs already being served. It is
///   fallible now, and [`Reconciler`] treats a failure the way it treats a lock
///   it could not take: start nothing, say so, try again next pass.
/// * **By lagging.** [`Self::launch`] returns the attempt it created rather than
///   its identifier, so the caller can carry it. See that method for the
///   measurement that made this necessary.
#[async_trait::async_trait]
pub trait RunnerLauncher: fmt::Debug + Send + Sync {
    /// Every attempt this host holds, across every policy, terminal ones
    /// included.
    ///
    /// Terminal attempts are included rather than filtered out because the
    /// caller needs both answers from one set:
    /// [`AttemptState::counts_against_capacity`] decides the ceiling, and the
    /// terminal ones are what [`RunnerLauncher::clean`] is for.
    ///
    /// # Errors
    /// [`LaunchFailure`] when the set could not be read. **Never answer `Ok`
    /// with an empty vector to signal a failure** — the caller cannot tell that
    /// from an idle host, and the two lead to opposite actions.
    async fn attempts(&self) -> Result<Vec<RunnerAttempt>, LaunchFailure>;

    /// Create exactly one runtime and start one runner, and return the attempt
    /// that now exists.
    ///
    /// Called once per grant, with the host-wide allocation lock held.
    ///
    /// # The attempt is returned, not just its identifier
    ///
    /// The host ceiling is enforced against a host-wide total, and that total is
    /// recomputed from [`Self::attempts`] on every hold. If a launch is not yet
    /// visible there when the *next* policy is allocated for — a journal write
    /// that has not landed, an asynchronous store, a cache — then that policy's
    /// grant is computed from a set missing the previous policy's runners, and
    /// it is too large.
    ///
    /// That is measured, not hypothetical. With a launcher whose attempts never
    /// became visible, two policies on a host of **three** started **six**
    /// runners, with the allocation lock held correctly throughout:
    /// `host_capacity=3, started=6, launches=6`. Serialisation was never the
    /// problem; the arithmetic under it was reading a stale set.
    ///
    /// So an implementer *should* make the new attempt visible to
    /// [`Self::attempts`] before returning — and the caller does not depend on
    /// it. [`Reconciler`] carries what this pass created and merges it, by
    /// [`RunnerAttempt::id`], with whatever the launcher reports. A launcher
    /// that honours the contract is not double-counted, and one that lags cannot
    /// oversubscribe the host.
    ///
    /// # Errors
    /// [`LaunchFailure`], carrying the [`FailureReason`] `e3` recorded.
    async fn launch(&self, request: LaunchRequest<'_>) -> Result<RunnerAttempt, LaunchFailure>;

    /// Remove a terminal attempt's runtime and mark it `cleaned`.
    ///
    /// Never called for a non-terminal attempt: capacity is reclaimed when an
    /// attempt reaches a terminal state and at no other time.
    ///
    /// # Errors
    /// [`LaunchFailure`], carrying the [`FailureReason`] `e3` recorded.
    async fn clean(&self, attempt: AttemptId) -> Result<(), LaunchFailure>;
}

// ---------------------------------------------------------------------------
// The host-wide allocation lock
// ---------------------------------------------------------------------------

/// The lock is held for as long as this value lives.
///
/// Opaque on purpose: what is being held differs between the in-process and the
/// file-backed implementation, and a caller that could see which one it has
/// would eventually branch on it.
pub struct AllocationGuard {
    _held: Box<dyn std::any::Any + Send>,
}

impl AllocationGuard {
    /// Wrap whatever the implementation holds. Dropping the guard drops it.
    #[must_use]
    pub fn new<T: Send + 'static>(held: T) -> Self {
        Self {
            _held: Box::new(held),
        }
    }
}

impl fmt::Debug for AllocationGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AllocationGuard")
    }
}

/// The host-wide allocation lock could not be taken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the host-wide allocation lock is held by another allocator; no runtime was created")]
pub struct AllocationLockBusy;

/// Flow 2.4's *"takes the host-wide allocation lock before creating each local
/// runtime"*, as a port.
///
/// # Why a lock is needed at all, given the allocator already exists
///
/// [`HostAllocator`] enforces D9 across the policies of **one** pass. It cannot
/// enforce anything across two passes running at once, and `f3` runs one
/// demand-polling loop per target: without serialisation, two loops read the
/// same headroom, each finds it sufficient, and the host ends up with the sum of
/// two grants it only ever had room for one of. The lock is what makes the
/// read-decide-create sequence atomic, and it is taken once per runtime rather
/// than once per pass so that a slow package download in one policy does not
/// hold the whole host still.
#[async_trait::async_trait]
pub trait AllocationLock: fmt::Debug + Send + Sync {
    /// Take the lock, waiting briefly for it.
    ///
    /// # Errors
    /// [`AllocationLockBusy`] when it could not be taken. A refused grant is
    /// always safe: the next pass re-reads the headroom and tries again.
    async fn acquire(&self) -> Result<AllocationGuard, AllocationLockBusy>;
}

/// The lock every task inside one agent process contends for.
///
/// This is the implementation that matters in practice, because the
/// single-instance lock (`d1`) already guarantees one agent per host: the
/// concurrency the allocation lock actually has to serialise is `f3`'s
/// per-target loops inside that one process. A `tokio` mutex rather than a
/// `std` one because it is held across the `await` that creates the runtime.
#[derive(Debug, Default)]
pub struct InProcessAllocationLock {
    mutex: Arc<tokio::sync::Mutex<()>>,
}

impl InProcessAllocationLock {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl AllocationLock for InProcessAllocationLock {
    async fn acquire(&self) -> Result<AllocationGuard, AllocationLockBusy> {
        let mutex = Arc::clone(&self.mutex);
        let guard = mutex.lock_owned().await;
        Ok(AllocationGuard::new(guard))
    }
}

/// `d1`'s file lock, which is host-wide across processes as well as across
/// tasks.
///
/// Defence in depth behind [`InProcessAllocationLock`], for the configuration
/// `d1` documents as the one where two agents can genuinely coexist: the
/// platform state directory is per-account, so a service-account daemon and an
/// interactive `daemon run` resolve different paths and do not contend for the
/// single-instance lock. They do contend here if they share a state directory.
///
/// [`runner_manager_platform::lock::HostLock::acquire`] blocks the calling
/// thread and its own documentation names this caller: *"Async callers must wrap
/// it in [`tokio::task::spawn_blocking`]"*. That is what this does, and the
/// returned `HostLock` lives inside the guard, because dropping it is the
/// release.
#[derive(Debug, Clone)]
pub struct FileAllocationLock {
    paths: Arc<runner_manager_platform::paths::AppPaths>,
    wait: Duration,
}

impl FileAllocationLock {
    #[must_use]
    pub const fn new(paths: Arc<runner_manager_platform::paths::AppPaths>) -> Self {
        Self {
            paths,
            wait: ALLOCATION_LOCK_WAIT,
        }
    }

    #[must_use]
    pub const fn with_wait(mut self, wait: Duration) -> Self {
        self.wait = wait;
        self
    }
}

#[async_trait::async_trait]
impl AllocationLock for FileAllocationLock {
    async fn acquire(&self) -> Result<AllocationGuard, AllocationLockBusy> {
        use runner_manager_platform::lock::{HostLock, LockKind};

        let paths = Arc::clone(&self.paths);
        let wait = self.wait;
        let held = tokio::task::spawn_blocking(move || {
            HostLock::acquire(&paths, LockKind::Allocation, wait)
        })
        .await;

        match held {
            Ok(Ok(lock)) => Ok(AllocationGuard::new(lock)),
            // A refused lock and a panicked blocking task are the same outcome
            // to this caller: no runtime was created and the next pass will
            // re-read the headroom. Neither is allowed to look like a grant.
            Ok(Err(_)) | Err(_) => Err(AllocationLockBusy),
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle events
// ---------------------------------------------------------------------------

/// Which terminal thing happened, as a closed vocabulary.
///
/// The distinction `g2` renders: an idle exit is the accepted surplus case and
/// **not** a failure, and showing it as one sends an operator hunting a fault
/// that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    CompletedJob,
    IdleExit,
    Failed,
    Orphaned,
}

impl OutcomeKind {
    #[must_use]
    pub const fn of(outcome: &AttemptOutcome) -> Self {
        match outcome {
            AttemptOutcome::CompletedJob => Self::CompletedJob,
            AttemptOutcome::ExitedIdleWithoutWork => Self::IdleExit,
            AttemptOutcome::Failed { .. } => Self::Failed,
            AttemptOutcome::Orphaned => Self::Orphaned,
        }
    }

    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Failed | Self::Orphaned)
    }

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CompletedJob => "completed_job",
            Self::IdleExit => "exited_idle_without_work",
            Self::Failed => "failed",
            Self::Orphaned => "orphaned",
        }
    }
}

impl fmt::Display for OutcomeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A [`FailureReason`]'s variant name, with no detail.
///
/// [`FailureReason::Other`] carries a `String` that `e3` fills in, and an event
/// is not the place for it: `07-security.md`'s log scan runs over everything
/// this loop emits, and free text is the one shape that can carry a credential
/// past a field allow-list. The operator-facing detail reaches the journal
/// through `b2` and the screen through `g2`; what reaches an *event* is the
/// variant.
#[must_use]
pub const fn failure_reason_kind(reason: &FailureReason) -> &'static str {
    match reason {
        FailureReason::JitRequestFailed => "jit_request_failed",
        FailureReason::JitExpired => "jit_expired",
        FailureReason::RunnerPackageUnverified => "runner_package_unverified",
        FailureReason::RunnerVersionRejected => "runner_version_rejected",
        FailureReason::ProcessStartFailed => "process_start_failed",
        FailureReason::ProcessExitedUnexpectedly => "process_exited_unexpectedly",
        FailureReason::RegistrationTimedOut => "registration_timed_out",
        FailureReason::TerminatedAfterRegistrationTimeout => {
            "terminated_after_registration_timeout"
        }
        FailureReason::Other(_) => "other",
    }
}

/// What `g2`'s activity view and the local log sink see.
///
/// **Every field is an identifier, a count, a duration, or a `&'static str`
/// drawn from a closed set.** There is no `String` anywhere in this enum, which
/// is what makes "no emitted event contains a token, a JIT blob, or a credential
/// header" a property of the type rather than a discipline each call site has to
/// keep. `tests::no_emitted_event_can_carry_a_credential` renders every variant
/// through `d1`'s scrubber and asserts nothing changes, with a positive control
/// so the assertion cannot pass vacuously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// A demand poll answered for one target.
    DemandObserved {
        policy: PolicyId,
        demand: u32,
        /// `false` when the count is a floor rather than a total.
        complete: bool,
    },
    /// A target could not be polled, so its policies start nothing this pass.
    TargetUnreadable {
        policy: PolicyId,
        reason: &'static str,
    },
    /// One policy's share of the pass.
    Allocated {
        policy: PolicyId,
        demand: u32,
        desired: u16,
        active_owned: u16,
        headroom: u16,
        to_start: u16,
        limiting: LimitingFactor,
    },
    /// A monitor-only policy was skipped entirely, before any demand request
    /// was issued for it (D19).
    MonitorOnlySkipped { policy: PolicyId },
    /// One runtime was created and one runner started.
    RunnerStarted {
        policy: PolicyId,
        attempt: AttemptId,
    },
    /// One runner could not be started.
    RunnerStartFailed {
        policy: PolicyId,
        reason: &'static str,
    },
    /// The allocation lock was not free, so `count` runners this policy was
    /// granted were not created this pass.
    AllocationDeferred { policy: PolicyId, count: u16 },
    /// The host's attempt set could not be read at all.
    ///
    /// Distinct from an empty set on purpose, and the whole reason
    /// [`RunnerLauncher::attempts`] is fallible: the two produce the same
    /// *number* and demand opposite actions.
    AttemptsUnreadable { reason: &'static str },
    /// A terminal attempt's runtime was removed.
    AttemptCleaned {
        policy: PolicyId,
        attempt: AttemptId,
        outcome: OutcomeKind,
    },
    /// A terminal attempt's runtime could not be removed. It will be retried on
    /// the next pass, and this is what keeps that retry from being silent.
    AttemptCleanFailed {
        policy: PolicyId,
        attempt: AttemptId,
        reason: &'static str,
    },
    /// Scale-down declined to remove a runner that is executing a job.
    ScaleDownRefused {
        policy: PolicyId,
        attempt: AttemptId,
    },
    /// When the next poll is, and why then.
    PollScheduled { retry_in_ms: u64, pace: PollPace },
}

impl LifecycleEvent {
    /// A fixed name, for the `event` field `d1`'s sink allows verbatim.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::DemandObserved { .. } => "demand_observed",
            Self::TargetUnreadable { .. } => "target_unreadable",
            Self::Allocated { .. } => "allocated",
            Self::MonitorOnlySkipped { .. } => "monitor_only_skipped",
            Self::RunnerStarted { .. } => "runner_started",
            Self::RunnerStartFailed { .. } => "runner_start_failed",
            Self::AllocationDeferred { .. } => "allocation_deferred",
            Self::AttemptsUnreadable { .. } => "attempts_unreadable",
            Self::AttemptCleaned { .. } => "attempt_cleaned",
            Self::AttemptCleanFailed { .. } => "attempt_clean_failed",
            Self::ScaleDownRefused { .. } => "scale_down_refused",
            Self::PollScheduled { .. } => "poll_scheduled",
        }
    }

    /// Which policy this event is about.
    #[must_use]
    pub const fn policy(&self) -> Option<PolicyId> {
        match self {
            Self::DemandObserved { policy, .. }
            | Self::TargetUnreadable { policy, .. }
            | Self::Allocated { policy, .. }
            | Self::MonitorOnlySkipped { policy }
            | Self::RunnerStarted { policy, .. }
            | Self::RunnerStartFailed { policy, .. }
            | Self::AllocationDeferred { policy, .. }
            | Self::AttemptCleaned { policy, .. }
            | Self::AttemptCleanFailed { policy, .. }
            | Self::ScaleDownRefused { policy, .. } => Some(*policy),
            Self::PollScheduled { .. } | Self::AttemptsUnreadable { .. } => None,
        }
    }
}

impl fmt::Display for LifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DemandObserved {
                policy,
                demand,
                complete,
            } => write!(
                f,
                "policy {policy}: {demand} queued runs{}",
                if *complete {
                    ""
                } else {
                    " (a floor, not a total)"
                }
            ),
            Self::TargetUnreadable { policy, reason } => {
                write!(f, "policy {policy}: target unreadable ({reason})")
            }
            Self::Allocated {
                policy,
                demand,
                desired,
                active_owned,
                headroom,
                to_start,
                limiting,
            } => write!(
                f,
                "policy {policy}: demand {demand}, desired {desired}, {active_owned} in \
                 flight, {headroom} free on this host, starting {to_start} ({limiting})"
            ),
            Self::MonitorOnlySkipped { policy } => {
                write!(f, "policy {policy}: monitor-only, skipped")
            }
            Self::RunnerStarted { policy, attempt } => {
                write!(f, "policy {policy}: started attempt {attempt}")
            }
            Self::RunnerStartFailed { policy, reason } => {
                write!(f, "policy {policy}: could not start a runner ({reason})")
            }
            Self::AllocationDeferred { policy, count } => write!(
                f,
                "policy {policy}: the allocation lock was held; {count} granted runners \
                 were not created"
            ),
            Self::AttemptsUnreadable { reason } => write!(
                f,
                "the host's attempt set could not be read ({reason}); nothing was started, \
                 and this is not the same as the host being idle"
            ),
            Self::AttemptCleaned {
                policy,
                attempt,
                outcome,
            } => write!(f, "policy {policy}: cleaned attempt {attempt} ({outcome})"),
            Self::AttemptCleanFailed {
                policy,
                attempt,
                reason,
            } => write!(
                f,
                "policy {policy}: attempt {attempt} could not be cleaned ({reason}); it \
                 will be retried"
            ),
            Self::ScaleDownRefused { policy, attempt } => write!(
                f,
                "policy {policy}: attempt {attempt} is executing a job and was not removed"
            ),
            Self::PollScheduled { retry_in_ms, pace } => {
                write!(f, "next poll in {retry_in_ms}ms ({pace})")
            }
        }
    }
}

/// Where lifecycle events go.
pub trait EventSink: fmt::Debug + Send + Sync {
    fn emit(&self, event: LifecycleEvent);
}

/// Discards everything. For callers that only want the report.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEvents;

impl EventSink for NoEvents {
    fn emit(&self, _event: LifecycleEvent) {}
}

/// The local log sink, through `d1`'s redacting layer.
///
/// Every field name below is on
/// [`runner_manager_platform::logging::ALLOWED_FIELDS`]; anything else would be
/// replaced with `[redacted]` and the line would lose its meaning rather than
/// its safety. `tests::every_field_name_this_sink_emits_is_one_d1_allows` keeps
/// that true.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingEvents;

impl EventSink for TracingEvents {
    fn emit(&self, event: LifecycleEvent) {
        let name = event.name();
        match event {
            LifecycleEvent::DemandObserved {
                policy,
                demand,
                complete,
            } => {
                tracing::info!(event = name, policy_id = %policy, demand, count = u64::from(complete))
            }
            LifecycleEvent::TargetUnreadable { policy, reason } => {
                tracing::warn!(event = name, policy_id = %policy, reason);
            }
            LifecycleEvent::Allocated {
                policy,
                demand,
                desired,
                active_owned,
                headroom,
                to_start,
                limiting,
            } => tracing::info!(
                event = name,
                policy_id = %policy,
                demand,
                desired,
                capacity = active_owned,
                headroom,
                count = to_start,
                reason = %limiting,
            ),
            LifecycleEvent::MonitorOnlySkipped { policy } => {
                tracing::debug!(event = name, policy_id = %policy, mode = "monitor_only");
            }
            LifecycleEvent::RunnerStarted { policy, attempt } => {
                tracing::info!(event = name, policy_id = %policy, attempt_id = %attempt);
            }
            LifecycleEvent::RunnerStartFailed { policy, reason } => {
                tracing::warn!(event = name, policy_id = %policy, reason);
            }
            LifecycleEvent::AllocationDeferred { policy, count } => {
                tracing::debug!(event = name, policy_id = %policy, lock = "allocation", count);
            }
            LifecycleEvent::AttemptsUnreadable { reason } => {
                tracing::warn!(event = name, reason);
            }
            LifecycleEvent::AttemptCleaned {
                policy,
                attempt,
                outcome,
            } => tracing::info!(
                event = name,
                policy_id = %policy,
                attempt_id = %attempt,
                outcome = outcome.as_str(),
            ),
            LifecycleEvent::AttemptCleanFailed {
                policy,
                attempt,
                reason,
            } => tracing::warn!(
                event = name,
                policy_id = %policy,
                attempt_id = %attempt,
                reason,
            ),
            LifecycleEvent::ScaleDownRefused { policy, attempt } => tracing::info!(
                event = name,
                policy_id = %policy,
                attempt_id = %attempt,
                attempt_state = "busy",
            ),
            LifecycleEvent::PollScheduled { retry_in_ms, pace } => {
                tracing::info!(event = name, retry_in_ms, state = pace.as_str());
            }
        }
    }
}

/// Keeps every event, in order.
///
/// `g2`'s activity view is a reader of this, and so is every test below.
#[derive(Debug, Default)]
pub struct EventLog {
    events: Mutex<Vec<LifecycleEvent>>,
}

impl EventLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn events(&self) -> Vec<LifecycleEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// How many events of one name were emitted.
    #[must_use]
    pub fn count_of(&self, name: &str) -> usize {
        self.events()
            .iter()
            .filter(|event| event.name() == name)
            .count()
    }
}

impl EventSink for EventLog {
    fn emit(&self, event: LifecycleEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

/// Both sinks at once: the log sink for the operator's file, the buffer for
/// `g2`'s screen.
#[derive(Debug)]
pub struct TeeEvents(pub Arc<dyn EventSink>, pub Arc<dyn EventSink>);

impl EventSink for TeeEvents {
    fn emit(&self, event: LifecycleEvent) {
        self.0.emit(event);
        self.1.emit(event);
    }
}

// ---------------------------------------------------------------------------
// The reconciler
// ---------------------------------------------------------------------------

/// Everything one reconciler needs, written down at the call site.
///
/// A struct rather than seven positional arguments, for the reason `b1` gives at
/// `PersistedAttempt`: several of these are `Arc<dyn …>` and transposing two of
/// them type-checks. Construct it with a struct literal so every port is named.
pub struct ReconcilerPorts {
    pub demand: Arc<dyn DemandSource>,
    pub launcher: Arc<dyn RunnerLauncher>,
    pub lock: Arc<dyn AllocationLock>,
    pub directory: Arc<dyn RepositoryDirectory>,
    pub clock: Arc<dyn Clock>,
    pub jitter: Arc<dyn Jitter>,
    pub events: Arc<dyn EventSink>,
}

impl fmt::Debug for ReconcilerPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconcilerPorts").finish_non_exhaustive()
    }
}

/// What one reconciliation pass did.
///
/// `started` and the allocations are reported separately on purpose: an
/// allocation is what the pass *decided* under the lock, and `started` is what
/// actually came up. They differ when a launch fails or when the lock was held,
/// and collapsing them would hide both.
#[derive(Debug, Clone, Default)]
pub struct ReconcileReport {
    /// One entry per policy that got as far as being allocated for.
    pub allocations: Vec<Allocation>,
    /// Policies skipped because they are monitor-only (D19).
    pub monitor_only: Vec<PolicyId>,
    /// Policies whose target could not be polled this pass.
    pub unreadable: Vec<PolicyId>,
    /// Runners actually started.
    pub started: u16,
    /// Terminal attempts whose runtime was removed.
    pub cleaned: u16,
    /// Of those, the surplus case: registered, got no job, exited on its idle
    /// timeout. **Not** a failure.
    pub idle_exits: u16,
    /// Of those, the ones an operator should look at.
    pub failures: u16,
    /// Runners this pass was granted but did not start because the allocation
    /// lock was held.
    ///
    /// **Grants, not policies.** It used to be incremented once per
    /// `start_runners` call that met a held lock, so a policy that launched two
    /// of five and then lost the lock reported `1` while three runners went
    /// unstarted -- a number that agreed with neither its own name nor its
    /// documentation.
    pub deferred: u16,
    /// Times the host's attempt set could not be read this pass.
    ///
    /// Non-zero means the pass decided less than it looks like it decided: a
    /// policy whose attempt set was unreadable started nothing and is *not* in
    /// [`Self::allocations`], because there was no set to compute an allocation
    /// from. It is not the same as the host being idle, which is the whole
    /// reason [`RunnerLauncher::attempts`] is fallible.
    pub attempts_unreadable: u16,
    /// Terminal attempts whose runtime could not be removed. Retried next pass.
    pub clean_failures: u16,
    /// The most severe failure across the targets polled, when there was one.
    pub failure: Option<RefreshState>,
    /// What to display while GitHub is unreachable, including how long the
    /// outage has run and therefore whether queued work has already been lost.
    pub offline: Option<OfflineState>,
    /// When to poll next, and why then.
    pub next_poll: NextPoll,
    /// Demand requests this pass projected against the shared hourly ceiling.
    pub demand_requests: u32,
}

impl Default for NextPoll {
    fn default() -> Self {
        Self {
            delay: PollSchedule::floor(),
            pace: PollPace::Nominal,
        }
    }
}

impl ReconcileReport {
    /// Whether GitHub was unreachable this pass.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        matches!(self.failure, Some(RefreshState::Offline))
    }

    /// The offline state to display, when this pass was one.
    #[must_use]
    pub const fn offline_state(&self) -> Option<&OfflineState> {
        self.offline.as_ref()
    }

    /// Attempts this pass created. The idle-host assertion reads this.
    #[must_use]
    pub const fn starts_nothing(&self) -> bool {
        self.started == 0
    }
}

/// What one scale-down request did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScaleDownReport {
    /// Terminal attempts whose runtime was removed.
    pub removed: u16,
    /// Attempts executing a job. **Removed nothing, left `busy`.**
    pub refused_busy: u16,
    /// Terminal attempts whose runtime could not be removed.
    pub clean_failures: u16,
    /// Live attempts that are not yet busy. Also removed nothing: capacity is
    /// reclaimed only when an attempt reaches a terminal state.
    pub retained: u16,
}

/// The reconciliation loop.
///
/// One per target, as `f3` runs them; they share a [`RunnerLauncher`] and an
/// [`AllocationLock`], which is what keeps the host ceiling true across all of
/// them.
#[derive(Debug)]
pub struct Reconciler {
    host: Host,
    demand: Arc<dyn DemandSource>,
    launcher: Arc<dyn RunnerLauncher>,
    lock: Arc<dyn AllocationLock>,
    repositories: RepositoryCache,
    clock: Arc<dyn Clock>,
    jitter: Arc<dyn Jitter>,
    events: Arc<dyn EventSink>,
    schedule: PollSchedule,
}

impl Reconciler {
    /// Build a reconciler polling at the host's configured interval.
    #[must_use]
    pub fn new(host: Host, ports: ReconcilerPorts) -> Self {
        let interval = host.refresh_interval;
        let repositories = RepositoryCache::new(
            Arc::clone(&ports.directory),
            Arc::clone(&ports.clock),
            interval,
        );
        Self {
            host,
            demand: ports.demand,
            launcher: ports.launcher,
            lock: ports.lock,
            repositories,
            clock: ports.clock,
            jitter: ports.jitter,
            events: ports.events,
            schedule: PollSchedule::new(interval),
        }
    }

    #[must_use]
    pub const fn host(&self) -> &Host {
        &self.host
    }

    #[must_use]
    pub const fn schedule(&self) -> &PollSchedule {
        &self.schedule
    }

    /// The repository-list cache, so `f1` can report what it has spent.
    #[must_use]
    pub const fn repositories(&self) -> &RepositoryCache {
        &self.repositories
    }

    /// One reconciliation pass over `policies`.
    ///
    /// The order of operations is `03-control-flows.md` flow 2, and the two
    /// steps most worth naming are the ones that are silent when they are wrong:
    ///
    /// * **Monitor-only policies are removed before the demand poll**, not
    ///   after. D19 says such a policy "is skipped entirely by reconciliation",
    ///   and a poll issued on its behalf would spend requests from the shared
    ///   ceiling for a policy that can never act on the answer. This is asserted
    ///   on [`ScalePolicy::owns_runners`] rather than deduced from
    ///   `max_capacity` being absent.
    /// * **The attempt set is re-read under the lock, once per runtime.** See
    ///   [`RunnerLauncher`] for why it comes from there and nowhere else.
    pub async fn reconcile(&mut self, policies: &[ScalePolicy]) -> ReconcileReport {
        let mut report = ReconcileReport::default();
        // Everything this pass has created, carried across policies so that the
        // host-wide total cannot be computed from a set that is missing it. See
        // `RunnerLauncher::launch`.
        let mut launched: Vec<RunnerAttempt> = Vec::new();

        // --- Flow 2.1-2.2: who is even asking, and what did GitHub say -------
        let mut pollable: Vec<&ScalePolicy> = Vec::new();
        for policy in policies {
            if !policy.owns_runners() {
                report.monitor_only.push(policy.id);
                self.events
                    .emit(LifecycleEvent::MonitorOnlySkipped { policy: policy.id });
                continue;
            }
            if !policy.is_owned_by(self.host.id) || !policy.may_start_runners() {
                // Ownership rule 2 and precedence rule 4. The allocator reports
                // both by name below; polling on their behalf would spend
                // requests for an answer that cannot be acted on.
                continue;
            }
            pollable.push(policy);
        }

        let readings = self.poll_targets(&pollable, &mut report).await;

        // --- Flow 2.8: terminal attempts, whatever else this pass does -------
        //
        // Run before the allocation phase so that a report's `cleaned` count
        // describes the same instant its allocations do. It does not change the
        // arithmetic: a terminal attempt already stopped counting against
        // capacity when it became terminal, which is `b1`'s
        // `counts_against_capacity`. It touches no live process, so it is also
        // safe during an outage — flow 3.3 requires that running runners be
        // retained, and nothing here can reach one.
        self.clean_terminal_attempts(&mut report).await;

        // --- Flow 2.3-2.6: the allocation -----------------------------------
        //
        // The predicates are re-tested here rather than the reading being looked
        // up by target, and that is not redundancy. **Targets are shared.** A
        // monitor-only policy watching `acme/app` alongside an autoscale policy
        // on the *same* repository finds a reading in the map that the other
        // policy paid for, and a lookup-driven loop then serves it: it emits a
        // demand observation on its behalf and clamps a number it has no
        // business seeing.
        //
        // Nothing downstream goes wrong when that happens — `may_start_runners`
        // is false for a monitor-only policy, so `HostAllocator` refuses it and
        // `to_start` is zero. It simply is not *skipped*, and D19's word is
        // "entirely".
        for policy in policies {
            if !policy.owns_runners() {
                // Already recorded and reported above, before any demand request
                // was issued. It owns no routing labels, takes no part in
                // demand, and can never be the reason a runner starts. Asserted
                // on the mode rather than deduced from `max_capacity` being
                // absent, which is what the specification requires.
                continue;
            }
            if !policy.is_owned_by(self.host.id) || !policy.may_start_runners() {
                // Ownership rule 2 and precedence rule 4. Allocated for with no
                // demand, so the refusal is reported by name rather than by
                // absence.
                match self.allocate_only(policy, 0, &launched).await {
                    Some(allocation) => {
                        self.emit_allocation(&allocation);
                        report.allocations.push(allocation);
                    }
                    None => self.report_unreadable_attempts(&mut report),
                }
                continue;
            }
            let Some(reading) = readings.get(&policy.target) else {
                // Unreachable: every policy reaching here was in `pollable`, and
                // `poll_targets` inserts an outcome for each of their targets.
                debug_assert!(false, "a pollable policy's target has no reading");
                continue;
            };
            match reading {
                PollOutcome::Failed(state) => {
                    report.unreadable.push(policy.id);
                    self.events.emit(LifecycleEvent::TargetUnreadable {
                        policy: policy.id,
                        reason: unreadable_reason(state),
                    });
                }
                PollOutcome::Ready(demand) => {
                    let count = demand_for(&policy.target, demand);
                    self.events.emit(LifecycleEvent::DemandObserved {
                        policy: policy.id,
                        demand: count,
                        complete: demand.is_complete(),
                    });
                    self.start_runners(policy, count, &mut report, &mut launched)
                        .await;
                }
            }
        }

        // --- Flow 2.1 / 3.3: when to come back ------------------------------
        let failure = readings
            .values()
            .filter_map(PollOutcome::failure)
            .max_by_key(|state| severity(state))
            .cloned();
        let now = self.clock.now();
        report.next_poll = self
            .schedule
            .next_poll(failure.as_ref(), now, self.jitter.as_ref());
        report.failure = failure;
        // Flow 3.3's fourth obligation: the offline state carries the 24-hour
        // bound, and it can only say whether that bound has passed if it is
        // given the real elapsed time rather than an estimate from the interval.
        if let PollPace::Offline { consecutive } = report.next_poll.pace {
            let state = OfflineState::new(consecutive, report.next_poll.delay);
            report.offline = Some(match self.schedule.offline_for(now) {
                Some(elapsed) => state.since(elapsed),
                None => state,
            });
        }
        self.events.emit(LifecycleEvent::PollScheduled {
            retry_in_ms: u64::try_from(report.next_poll.delay.as_millis()).unwrap_or(u64::MAX),
            pace: report.next_poll.pace,
        });

        report
    }

    /// Poll each distinct target once, however many policies share it.
    ///
    /// Two policies on one repository are one demand request, not two. That is
    /// not a micro-optimisation: the budget model in
    /// `04-subsystem-contracts.md` prices a *target*, and a loop that spent per
    /// policy would quietly exceed the projection `f2` admitted the
    /// configuration against.
    async fn poll_targets(
        &self,
        pollable: &[&ScalePolicy],
        report: &mut ReconcileReport,
    ) -> BTreeMap<ScaleTarget, PollOutcome> {
        let targets: BTreeSet<ScaleTarget> = pollable.iter().map(|p| p.target.clone()).collect();

        let mut readings = BTreeMap::new();
        for target in targets {
            let outcome = match self.repositories.scope_for(&target).await {
                Ok(scope) => {
                    report.demand_requests = report
                        .demand_requests
                        .saturating_add(demand_requests_per_poll(&scope));
                    self.demand.poll(&scope).await
                }
                // The repository list could not be refreshed, so the scope of
                // the poll is unknown. Polling a stale or empty scope would
                // report a demand number for a set of repositories nobody
                // chose, which is worse than reporting that the target could
                // not be read.
                Err(error) => PollOutcome::Failed(RefreshState::from_error(&error)),
            };
            readings.insert(target, outcome);
        }
        readings
    }

    /// Compute one policy's allocation without creating anything.
    ///
    /// Safe without the lock precisely because it cannot grant: every path that
    /// reaches here is refused by [`HostAllocator::allocate`] before any
    /// headroom is spent, so there is no read-decide-create sequence to make
    /// atomic.
    /// `None` when the attempt set could not be read, which is never the same
    /// answer as an empty one.
    async fn allocate_only(
        &self,
        policy: &ScalePolicy,
        demand: u32,
        launched: &[RunnerAttempt],
    ) -> Option<Allocation> {
        let attempts = self.host_attempts(launched).await.ok()?;
        let mut allocator = HostAllocator::from_attempts(&self.host, &attempts);
        Some(allocator.allocate(policy, demand))
    }

    /// Flow 2.4-2.6: start runners for one policy, one lock hold per runtime.
    ///
    /// # Two stopping conditions, and both are needed
    ///
    /// The loop re-reads the attempt set under every hold, so the obvious stop
    /// is "the allocator granted nothing". That condition **alone does not
    /// terminate**, and the failure is not hypothetical — it was measured.
    /// Handing the allocator a set that does not include the runners this loop
    /// just started (an empty one, a stale one, or a launcher whose journal
    /// write has not landed yet) makes every grant look like the first, and the
    /// pass starts runners until something outside it intervenes. With the set
    /// dropped entirely, the three-consecutive-polls test below does not report
    /// three attempts; it *never returns*.
    ///
    /// So the grant decided on the first hold is also a **budget**. A later hold
    /// may lower it — the host may have filled up meanwhile — and can never
    /// raise it, which bounds the pass at the number this policy was actually
    /// allocated. That is `c2`'s reasoning for `MAX_PAGES` one layer down: the
    /// reconciliation loop is the one place in this product that must not be
    /// able to wedge, so the bound is structural rather than a consequence of
    /// every input being well behaved.
    async fn start_runners(
        &self,
        policy: &ScalePolicy,
        demand: u32,
        report: &mut ReconcileReport,
        launched: &mut Vec<RunnerAttempt>,
    ) {
        // A lock-free pre-check, for one reason only: the host-wide lock should
        // not be taken by a policy that is going to be granted nothing. On an
        // idle host with P policies that was P lock acquisitions per poll --
        // free under `InProcessAllocationLock`, a `spawn_blocking` and a
        // filesystem lock apiece under `FileAllocationLock`.
        //
        // It is safe because it can only be optimistic. Anything it grants is
        // re-decided under the lock below and may be lowered there; the only
        // thing it can get wrong in the other direction is refusing a grant that
        // headroom freed a moment later would have allowed, which the next poll
        // picks up.
        let Some(intent) = self.allocate_only(policy, demand, launched).await else {
            self.report_unreadable_attempts(report);
            self.events.emit(LifecycleEvent::AttemptsUnreadable {
                reason: "attempts_unreadable",
            });
            return;
        };

        // The allocation that is *reported* is the one taken under the lock when
        // a lock was taken, because that is the one that decided anything. The
        // pre-check stands in only when no hold was ever obtained.
        let mut decided: Option<Allocation> = None;
        let mut budget = intent.to_start;

        while budget > 0 {
            let guard = match self.lock.acquire().await {
                Ok(guard) => guard,
                Err(_) => {
                    // Grants, not policies: this is what the policy was owed and
                    // did not get.
                    report.deferred = report.deferred.saturating_add(budget);
                    self.events.emit(LifecycleEvent::AllocationDeferred {
                        policy: policy.id,
                        count: budget,
                    });
                    break;
                }
            };

            // The read and the decision are both inside the hold, and so is the
            // creation below. Two concurrent passes therefore serialise on the
            // whole sequence rather than on the decision alone -- reading the
            // headroom outside the lock is the shape in which two policies both
            // find room for the last slot.
            let attempts = match self.host_attempts(launched).await {
                Ok(attempts) => attempts,
                Err(failure) => {
                    drop(guard);
                    self.report_unreadable_attempts(report);
                    self.events.emit(LifecycleEvent::AttemptsUnreadable {
                        reason: failure_reason_kind(&failure.reason),
                    });
                    break;
                }
            };
            let mut allocator = HostAllocator::from_attempts(&self.host, &attempts);
            let allocation = allocator.allocate(policy, demand);

            if decided.is_none() {
                // The under-lock decision may be smaller than the pre-check, and
                // never larger: `min` rather than assignment, so a later hold
                // cannot raise the bound either.
                budget = budget.min(allocation.to_start);
                decided = Some(allocation.clone());
            }

            // Either stop is sufficient on its own in the well-behaved case;
            // neither is sufficient when the launcher lags. See the doc comment.
            if allocation.starts_nothing() || budget == 0 {
                drop(guard);
                break;
            }

            let created = self
                .launcher
                .launch(LaunchRequest {
                    host: &self.host,
                    policy,
                })
                .await;
            drop(guard);

            match created {
                Ok(attempt) => {
                    let id = attempt.id;
                    // Carried across policies for the rest of this pass, so the
                    // host-wide total cannot be computed from a set that is
                    // missing it. See `RunnerLauncher::launch`.
                    launched.push(attempt);
                    report.started = report.started.saturating_add(1);
                    budget -= 1;
                    self.events.emit(LifecycleEvent::RunnerStarted {
                        policy: policy.id,
                        attempt: id,
                    });
                }
                Err(failure) => {
                    self.events.emit(LifecycleEvent::RunnerStartFailed {
                        policy: policy.id,
                        reason: failure_reason_kind(&failure.reason),
                    });
                    break;
                }
            }
        }

        let allocation = decided.unwrap_or(intent);
        self.emit_allocation(&allocation);
        report.allocations.push(allocation);
    }

    /// The attempt set the host holds, plus everything this pass has already
    /// created.
    ///
    /// The merge is by [`RunnerAttempt::id`], so a launcher that makes its
    /// launches visible before returning -- which
    /// [`RunnerLauncher::launch`] asks for -- contributes each attempt once, and
    /// one that lags still cannot hide a runner from the host-wide total. The
    /// ceiling therefore holds on the strength of this function rather than on
    /// the strength of an implementer honouring a comment.
    ///
    /// # Errors
    /// Whatever [`RunnerLauncher::attempts`] reported.
    async fn host_attempts(
        &self,
        launched: &[RunnerAttempt],
    ) -> Result<Vec<RunnerAttempt>, LaunchFailure> {
        let mut attempts = self.launcher.attempts().await?;
        let known: BTreeSet<AttemptId> = attempts.iter().map(|attempt| attempt.id).collect();
        attempts.extend(
            launched
                .iter()
                .filter(|attempt| !known.contains(&attempt.id))
                .cloned(),
        );
        Ok(attempts)
    }

    /// The attempt set could not be read, so nothing may be decided from it.
    ///
    /// Counted rather than swallowed for the reason the module documentation
    /// gives: an unreadable set and an idle host produce the same *number* and
    /// demand opposite actions, so the difference has to survive into the
    /// report.
    fn report_unreadable_attempts(&self, report: &mut ReconcileReport) {
        report.attempts_unreadable = report.attempts_unreadable.saturating_add(1);
    }

    /// Remove the runtimes of attempts that have already concluded.
    ///
    /// `is_concluded` and not `is_terminal`: `cleaned` is terminal and already
    /// done, and `busy` is not terminal at all. That is what makes it impossible
    /// for this path to reach a runner executing a job.
    async fn clean_terminal_attempts(&self, report: &mut ReconcileReport) {
        let attempts = match self.launcher.attempts().await {
            Ok(attempts) => attempts,
            Err(failure) => {
                self.report_unreadable_attempts(report);
                self.events.emit(LifecycleEvent::AttemptsUnreadable {
                    reason: failure_reason_kind(&failure.reason),
                });
                return;
            }
        };
        for attempt in attempts {
            if !attempt.state().is_concluded() {
                continue;
            }
            let Some(outcome) = attempt.outcome() else {
                continue;
            };
            let kind = OutcomeKind::of(outcome);
            match self.launcher.clean(attempt.id).await {
                Ok(()) => {
                    report.cleaned = report.cleaned.saturating_add(1);
                    if kind.is_failure() {
                        report.failures = report.failures.saturating_add(1);
                    } else if kind == OutcomeKind::IdleExit {
                        // The surplus case. Counted apart from a failure because
                        // `g2` renders it apart, and because an operator told
                        // that a normal surplus exit is an error goes hunting a
                        // fault that does not exist.
                        report.idle_exits = report.idle_exits.saturating_add(1);
                    }
                    self.events.emit(LifecycleEvent::AttemptCleaned {
                        policy: attempt.policy_id,
                        attempt: attempt.id,
                        outcome: kind,
                    });
                }
                // A runtime directory that cannot be removed is retried on every
                // poll. Silently, before this arm existed: no event, no counter,
                // no report field, so a cleanup that can never succeed was an
                // invisible permanent loop. It wedges no capacity -- a terminal
                // attempt already stopped counting -- but this module's
                // organising principle is the things that go wrong silently, and
                // `clean` returns a `Result` precisely so the caller can say
                // something.
                Err(failure) => {
                    report.clean_failures = report.clean_failures.saturating_add(1);
                    self.events.emit(LifecycleEvent::AttemptCleanFailed {
                        policy: attempt.policy_id,
                        attempt: attempt.id,
                        reason: failure_reason_kind(&failure.reason),
                    });
                }
            }
        }
    }

    /// Reclaim what can be reclaimed for one policy, and nothing else.
    ///
    /// **A busy attempt is never removed.** `04-subsystem-contracts.md`:
    /// *"`busy` cannot transition to cleanup due to a scale-down request"*.
    /// Capacity comes back when an attempt reaches a terminal state and at no
    /// other time, so a scale-down against a host full of busy runners removes
    /// nothing, changes nothing, and says so.
    pub async fn scale_down(&self, policy: &ScalePolicy) -> ScaleDownReport {
        let mut report = ScaleDownReport::default();
        let Ok(attempts) = self.launcher.attempts().await else {
            // The same rule as everywhere else: an unreadable set is not an
            // empty one, and scale-down removes nothing it cannot see.
            self.events.emit(LifecycleEvent::AttemptsUnreadable {
                reason: "attempts_unreadable",
            });
            return report;
        };
        for attempt in attempts {
            if attempt.policy_id != policy.id {
                continue;
            }
            match attempt.state() {
                AttemptState::Busy => {
                    report.refused_busy = report.refused_busy.saturating_add(1);
                    self.events.emit(LifecycleEvent::ScaleDownRefused {
                        policy: policy.id,
                        attempt: attempt.id,
                    });
                }
                state if state.is_concluded() => {
                    let kind = attempt
                        .outcome()
                        .map_or(OutcomeKind::Failed, OutcomeKind::of);
                    match self.launcher.clean(attempt.id).await {
                        Ok(()) => {
                            report.removed = report.removed.saturating_add(1);
                            self.events.emit(LifecycleEvent::AttemptCleaned {
                                policy: policy.id,
                                attempt: attempt.id,
                                outcome: kind,
                            });
                        }
                        Err(failure) => {
                            report.clean_failures = report.clean_failures.saturating_add(1);
                            self.events.emit(LifecycleEvent::AttemptCleanFailed {
                                policy: policy.id,
                                attempt: attempt.id,
                                reason: failure_reason_kind(&failure.reason),
                            });
                        }
                    }
                }
                AttemptState::Cleaned => {}
                // `allocated`, `jit_received`, `starting`, `idle`: live, holding
                // a slot, and not this function's to end.
                _ => report.retained = report.retained.saturating_add(1),
            }
        }
        report
    }

    fn emit_allocation(&self, allocation: &Allocation) {
        self.events.emit(LifecycleEvent::Allocated {
            policy: allocation.policy_id,
            demand: allocation.demand,
            desired: allocation.desired,
            active_owned: allocation.active_owned,
            headroom: allocation.headroom_before,
            to_start: allocation.to_start,
            limiting: allocation.limiting_factor,
        });
    }
}

/// One policy's demand, from the reading its target answered with.
///
/// A repository target reads its own count; an organization target reads the
/// aggregate its scope covered. Both are counts of **queued runs**, unfiltered
/// by any label — see the module documentation.
fn demand_for(target: &ScaleTarget, reading: &QueuedDemand) -> u32 {
    match target {
        ScaleTarget::Repository(repository) => reading.for_repository(repository).unwrap_or(0),
        ScaleTarget::Organization(_) => reading.total(),
    }
}

/// How urgently one failure should slow the loop down.
///
/// Ordering matters only for picking the worst of several targets: an outage
/// outranks a rate limit because backing off a socket that is not answering is
/// the safer error, and both outrank a per-target rejection that says nothing
/// about the credential as a whole.
const fn severity(state: &RefreshState) -> u8 {
    match state {
        RefreshState::Offline => 5,
        RefreshState::RateLimited(_) => 4,
        RefreshState::LockedOut { .. } => 3,
        RefreshState::Unauthorized => 2,
        RefreshState::Forbidden { .. } | RefreshState::Failed { .. } => 1,
        RefreshState::Cancelled | RefreshState::Ready(_) => 0,
    }
}

/// Why one target could not be read, as a fixed, credential-free name.
///
/// Deliberately not a [`PollPace`]: a pace describes the *schedule*, which is a
/// property of the whole pass, and stamping one onto a single target would have
/// meant inventing a `consecutive` count for a target that has none. What an
/// event needs here is the reason, and `c3`'s [`RefreshState`] already names it.
///
/// `RefreshState::Failed` carries GitHub's own message and
/// `RefreshState::Forbidden` may carry one too. Neither reaches the event: this
/// returns the variant, for the reason [`failure_reason_kind`] states.
const fn unreadable_reason(state: &RefreshState) -> &'static str {
    match state {
        RefreshState::Ready(_) => "ready",
        RefreshState::Offline => "offline",
        RefreshState::RateLimited(_) => "rate_limited",
        RefreshState::LockedOut { .. } => "locked_out",
        RefreshState::Unauthorized => "unauthorized",
        RefreshState::Forbidden { .. } => "forbidden",
        RefreshState::Failed { .. } => "failed",
        RefreshState::Cancelled => "cancelled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;

    use std::num::NonZeroU16;

    use runner_manager_domain::attempt::PersistedAttempt;
    use runner_manager_domain::model::{CachePolicy, HostId};
    use runner_manager_domain::policy::PolicyMode;
    use runner_manager_github::rest::RateLimited;
    use runner_manager_testkit::clock::FakeClock;
    use runner_manager_testkit::fixtures;
    use runner_manager_testkit::github::FakeGithub;

    // =======================================================================
    // Fakes
    // =======================================================================

    fn host_with(capacity: u16) -> Host {
        fixtures::host().capacity(capacity).build()
    }

    fn repo(raw: &str) -> OwnerRepo {
        OwnerRepo::parse(raw).expect("a valid OWNER/REPO")
    }

    /// An `active`, enabled autoscale policy on the fixture host.
    fn policy(id: u128, target: &str, max: u16) -> ScalePolicy {
        fixtures::policy()
            .id(PolicyId::from_u128(id))
            .repository(target)
            .autoscale("home", max)
            .active()
            .build()
    }

    /// `e3`, faked: an attempt table and a launch counter, no process anywhere.
    #[derive(Debug, Default)]
    struct FakeLauncher {
        attempts: Mutex<Vec<RunnerAttempt>>,
        next_id: AtomicU64,
        launches: AtomicUsize,
        cleaned: Mutex<Vec<AttemptId>>,
        /// Yields this many times between reading the attempt set and recording
        /// a new one, so an unserialised allocator has a window to be wrong in.
        yields_before_recording: usize,
        /// Reports success without the attempt ever becoming visible, which is
        /// the shape a slow journal write has. Every grant then looks like the
        /// first.
        forgetful: bool,
        fail_next: Mutex<Option<FailureReason>>,
        /// Reports that the attempt set cannot be read at all, which is the one
        /// answer a caller must never confuse with an idle host.
        attempts_fail: Mutex<bool>,
        /// Refuses every cleanup, so the silent-retry path has something to be
        /// loud about.
        clean_fails: bool,
    }

    impl FakeLauncher {
        fn new() -> Self {
            Self::default()
        }

        fn with_yields(mut self, yields: usize) -> Self {
            self.yields_before_recording = yields;
            self
        }

        fn forgetful() -> Self {
            Self {
                forgetful: true,
                ..Self::default()
            }
        }

        fn seeded(self, attempts: Vec<RunnerAttempt>) -> Self {
            *self.attempts.lock().unwrap() = attempts;
            self
        }

        fn launches(&self) -> usize {
            self.launches.load(Ordering::SeqCst)
        }

        fn snapshot(&self) -> Vec<RunnerAttempt> {
            self.attempts.lock().unwrap().clone()
        }

        fn live_count(&self) -> usize {
            self.snapshot()
                .iter()
                .filter(|a| a.counts_against_capacity())
                .count()
        }

        fn fail_next(&self, reason: FailureReason) {
            *self.fail_next.lock().unwrap() = Some(reason);
        }

        fn fail_attempts(&self, failing: bool) {
            *self.attempts_fail.lock().unwrap() = failing;
        }

        fn refusing_cleanup(attempts: Vec<RunnerAttempt>) -> Self {
            Self {
                clean_fails: true,
                ..Self::default()
            }
            .seeded(attempts)
        }

        fn cleaned(&self) -> Vec<AttemptId> {
            self.cleaned.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl RunnerLauncher for FakeLauncher {
        async fn attempts(&self) -> Result<Vec<RunnerAttempt>, LaunchFailure> {
            if *self.attempts_fail.lock().unwrap() {
                return Err(LaunchFailure::new(FailureReason::Other(
                    "the journal could not be read".into(),
                )));
            }
            Ok(self.snapshot())
        }

        async fn launch(&self, request: LaunchRequest<'_>) -> Result<RunnerAttempt, LaunchFailure> {
            if let Some(reason) = self.fail_next.lock().unwrap().take() {
                return Err(LaunchFailure::new(reason));
            }
            // The window an unserialised caller would lose the race in.
            for _ in 0..self.yields_before_recording {
                tokio::task::yield_now().await;
            }
            let id =
                AttemptId::from_u128(u128::from(self.next_id.fetch_add(1, Ordering::SeqCst) + 1));
            let created = RunnerAttempt::allocate(
                id,
                request.policy.id,
                "runtime/p/a",
                request.host.created_at,
            );
            self.launches.fetch_add(1, Ordering::SeqCst);
            if !self.forgetful {
                self.attempts.lock().unwrap().push(created.clone());
            }
            Ok(created)
        }

        async fn clean(&self, attempt: AttemptId) -> Result<(), LaunchFailure> {
            if self.clean_fails {
                return Err(LaunchFailure::new(FailureReason::Other(
                    "the runtime directory is locked".into(),
                )));
            }
            self.cleaned.lock().unwrap().push(attempt);
            let mut attempts = self.attempts.lock().unwrap();
            attempts.retain(|a| a.id != attempt);
            Ok(())
        }
    }

    /// A demand source a test programs directly, with no gateway underneath.
    #[derive(Debug, Default)]
    struct FakeDemand {
        outcome: Mutex<Option<PollOutcome>>,
        /// Answers programmed for one target, which beat the blanket one.
        per_target: Mutex<BTreeMap<ScaleTarget, PollOutcome>>,
        scopes: Mutex<Vec<ActivityScope>>,
    }

    impl FakeDemand {
        fn ready(count: u32, repository: &OwnerRepo) -> Self {
            let fake = Self::default();
            fake.set(PollOutcome::Ready(QueuedDemand::of(
                repository.clone(),
                count,
            )));
            fake
        }

        fn failing(state: RefreshState) -> Self {
            let fake = Self::default();
            fake.set(PollOutcome::Failed(state));
            fake
        }

        fn set(&self, outcome: PollOutcome) {
            *self.outcome.lock().unwrap() = Some(outcome);
        }

        /// Program one target's answer, overriding the blanket one.
        fn set_for(&self, target: &ScaleTarget, outcome: PollOutcome) {
            self.per_target
                .lock()
                .unwrap()
                .insert(target.clone(), outcome);
        }

        fn polls(&self) -> Vec<ActivityScope> {
            self.scopes.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl DemandSource for FakeDemand {
        async fn poll(&self, scope: &ActivityScope) -> PollOutcome {
            self.scopes.lock().unwrap().push(scope.clone());
            if let Some(outcome) = self.per_target.lock().unwrap().get(scope.target()) {
                return outcome.clone();
            }
            self.outcome
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(PollOutcome::Ready(QueuedDemand::default()))
        }
    }

    #[derive(Debug, Default)]
    struct FakeDirectory {
        repositories: Vec<OwnerRepo>,
        calls: AtomicUsize,
    }

    impl FakeDirectory {
        fn of(repositories: Vec<OwnerRepo>) -> Self {
            Self {
                repositories,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl RepositoryDirectory for FakeDirectory {
        async fn repositories(&self, _org: &Org) -> Result<Vec<OwnerRepo>, InventoryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.repositories.clone())
        }
    }

    /// A lock that grants everything and counts how many holders it had at once.
    ///
    /// The counter is the assertion: "under simulated lock contention" is only
    /// meaningful if something measures that the contention was actually
    /// serialised.
    #[derive(Debug)]
    struct CountingLock {
        inner: InProcessAllocationLock,
        concurrent: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        acquisitions: Arc<AtomicUsize>,
    }

    impl CountingLock {
        fn new() -> Self {
            Self {
                inner: InProcessAllocationLock::new(),
                concurrent: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
                acquisitions: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }

        fn acquisitions(&self) -> usize {
            self.acquisitions.load(Ordering::SeqCst)
        }
    }

    #[derive(Debug)]
    struct CountingGuard {
        _inner: AllocationGuard,
        concurrent: Arc<AtomicUsize>,
    }

    impl Drop for CountingGuard {
        fn drop(&mut self) {
            self.concurrent.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl AllocationLock for CountingLock {
        async fn acquire(&self) -> Result<AllocationGuard, AllocationLockBusy> {
            let inner = self.inner.acquire().await?;
            self.acquisitions.fetch_add(1, Ordering::SeqCst);
            let now = self.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            Ok(AllocationGuard::new(CountingGuard {
                _inner: inner,
                concurrent: Arc::clone(&self.concurrent),
            }))
        }
    }

    /// The lock that is not one: what the host looks like with the serialisation
    /// removed. Used only by the control half of the contention test.
    #[derive(Debug, Default)]
    struct NoLock;

    #[async_trait::async_trait]
    impl AllocationLock for NoLock {
        async fn acquire(&self) -> Result<AllocationGuard, AllocationLockBusy> {
            Ok(AllocationGuard::new(()))
        }
    }

    /// A lock nobody can take.
    #[derive(Debug, Default)]
    struct HeldLock;

    #[async_trait::async_trait]
    impl AllocationLock for HeldLock {
        async fn acquire(&self) -> Result<AllocationGuard, AllocationLockBusy> {
            Err(AllocationLockBusy)
        }
    }

    /// Everything one test needs, wired together.
    struct Harness {
        launcher: Arc<FakeLauncher>,
        demand: Arc<FakeDemand>,
        events: Arc<EventLog>,
        reconciler: Reconciler,
    }

    impl Harness {
        fn build(
            host: Host,
            launcher: Arc<FakeLauncher>,
            demand: Arc<FakeDemand>,
            lock: Arc<dyn AllocationLock>,
        ) -> Self {
            let events = Arc::new(EventLog::new());
            let reconciler = Reconciler::new(
                host,
                ReconcilerPorts {
                    demand: Arc::clone(&demand) as Arc<dyn DemandSource>,
                    launcher: Arc::clone(&launcher) as Arc<dyn RunnerLauncher>,
                    lock,
                    directory: Arc::new(FakeDirectory::default()),
                    clock: Arc::new(FakeClock::default()),
                    jitter: Arc::new(NoJitter) as Arc<dyn Jitter>,
                    events: Arc::clone(&events) as Arc<dyn EventSink>,
                },
            );
            Self {
                launcher,
                demand,
                events,
                reconciler,
            }
        }

        fn simple(capacity: u16, demand_count: u32, target: &str) -> Self {
            let launcher = Arc::new(FakeLauncher::new());
            let demand = Arc::new(FakeDemand::ready(demand_count, &repo(target)));
            Self::build(
                host_with(capacity),
                launcher,
                demand,
                Arc::new(InProcessAllocationLock::new()),
            )
        }
    }

    fn attempt_in(state: AttemptState, id: u128, policy: u128) -> RunnerAttempt {
        let outcome = state.is_terminal().then(|| match state {
            AttemptState::Failed => {
                AttemptOutcome::failed(FailureReason::ProcessExitedUnexpectedly)
            }
            AttemptState::Orphaned => AttemptOutcome::Orphaned,
            _ => AttemptOutcome::CompletedJob,
        });
        RunnerAttempt::from_persisted(PersistedAttempt {
            id: AttemptId::from_u128(id),
            policy_id: PolicyId::from_u128(policy),
            github_runner_id: None,
            state,
            outcome,
            process_id: None,
            runtime_path: "runtime/p/a".into(),
            created_at: fixtures::created_at(),
            terminal_at: state.is_terminal().then(fixtures::created_at),
            last_state_change_at: fixtures::created_at(),
        })
        .expect("a state/outcome pair the domain accepts")
    }

    /// A concluded attempt carrying a specific outcome.
    fn concluded(id: u128, policy: u128, outcome: AttemptOutcome) -> RunnerAttempt {
        RunnerAttempt::from_persisted(PersistedAttempt {
            id: AttemptId::from_u128(id),
            policy_id: PolicyId::from_u128(policy),
            github_runner_id: None,
            state: outcome.terminal_state(),
            outcome: Some(outcome),
            process_id: None,
            runtime_path: "runtime/p/a".into(),
            created_at: fixtures::created_at(),
            terminal_at: Some(fixtures::created_at()),
            last_state_change_at: fixtures::created_at(),
        })
        .expect("a state/outcome pair the domain accepts")
    }

    // =======================================================================
    // The in-flight term: the single most likely way this task goes wrong
    // =======================================================================

    /// `e1`'s Definition of Done, verbatim: *"A job that remains `queued` across
    /// three consecutive polls while its attempt is `starting` yields exactly
    /// one attempt — the test fails if the in-flight term is dropped from the
    /// formula."*
    ///
    /// `b1` tests the arithmetic underneath this
    /// (`capacity::tests::the_same_queued_job_on_two_polls_yields_one_attempt_
    /// not_two`). What *this* test covers is the only way `e1` can drop the
    /// term without touching `b1` at all: handing the allocator an attempt set
    /// that is not the one the host holds.
    ///
    /// # This was measured, not assumed, and the first measurement was worse
    /// # than the failure it was looking for
    ///
    /// Replacing `self.launcher.attempts().await` in
    /// [`Reconciler::start_runners`] with `Vec::new()` compiles and runs. Before
    /// that function carried a budget, this test did not go red — it **never
    /// returned**: every grant looked like the first, so the pass started
    /// runners forever inside poll 1. That is the runaway-runner failure exactly
    /// as an operator would meet it, and it is why the budget exists.
    ///
    /// With the budget in place the same injection fails cleanly and says what
    /// happened: `poll 2 … left: 2, right: 1`. Both measurements were run
    /// before this assertion was written.
    #[tokio::test]
    async fn three_polls_of_one_still_queued_run_yield_exactly_one_attempt() {
        let mut harness = Harness::simple(4, 1, "acme/app");
        let policy = policy(1, "acme/app", 4);

        for poll in 1..=3 {
            let report = harness
                .reconciler
                .reconcile(std::slice::from_ref(&policy))
                .await;
            assert_eq!(
                harness.launcher.launches(),
                1,
                "poll {poll} started another runner for a job already being served; the \
                 `- active_owned_runners` term reached `HostAllocator` as a set this host \
                 does not hold"
            );
            assert_eq!(report.allocations.len(), 1);
            let allocation = &report.allocations[0];
            assert_eq!(allocation.demand, 1, "poll {poll}: still queued at GitHub");
            if poll == 1 {
                assert_eq!(allocation.to_start, 1);
                assert_eq!(report.started, 1);
            } else {
                assert_eq!(allocation.active_owned, 1, "poll {poll}");
                assert_eq!(allocation.to_start, 0, "poll {poll}");
                assert_eq!(report.started, 0, "poll {poll}");
            }
        }
        assert_eq!(harness.launcher.live_count(), 1);
    }

    /// The other half of the measurement above: the loop must terminate even
    /// when the attempt set never catches up with it.
    ///
    /// Dropping the in-flight term made
    /// `three_polls_of_one_still_queued_run_yield_exactly_one_attempt` hang
    /// rather than fail — the loop had one stopping condition and it was the one
    /// the bug removed. A launcher whose journal write has not landed presents
    /// exactly the same shape without any bug at all, so the budget in
    /// [`Reconciler::start_runners`] bounds the pass structurally. This is what
    /// asserts the bound is really there.
    #[tokio::test]
    async fn a_launcher_whose_attempts_never_appear_cannot_wedge_the_pass() {
        let launcher = Arc::new(FakeLauncher::forgetful());
        let mut harness = Harness::build(
            host_with(64),
            Arc::clone(&launcher),
            Arc::new(FakeDemand::ready(3, &repo("acme/app"))),
            Arc::new(InProcessAllocationLock::new()),
        );

        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 8)])
            .await;

        assert_eq!(
            report.started, 3,
            "the pass is bounded by the grant it was given, not by the attempt set catching \
             up with it"
        );
        assert_eq!(launcher.launches(), 3);
        assert!(
            launcher.snapshot().is_empty(),
            "the launcher never recorded anything, which is the whole point of the fixture"
        );
    }

    /// The host-wide ceiling must hold across policies even when the launcher
    /// lags, and the per-policy budget alone does not reach that case.
    ///
    /// Review found this, with this file's own `forgetful` fixture and one more
    /// policy: the budget bounds *each policy's* loop to its own first grant,
    /// but policy B's first grant is computed from a set that does not yet
    /// contain policy A's launches, so B's bound is itself too large. Two
    /// policies on a host of three started **six** runners --
    /// `host_capacity=3, started=6, launches=6` -- with the lock held correctly
    /// throughout. Serialisation was never the problem; the arithmetic under it
    /// was reading a stale set.
    #[tokio::test]
    async fn two_policies_cannot_exceed_host_capacity_even_when_the_launcher_lags() {
        let launcher = Arc::new(FakeLauncher::forgetful());
        let demand = Arc::new(FakeDemand::default());
        demand.set_for(
            &ScaleTarget::repository("acme/left").unwrap(),
            PollOutcome::Ready(QueuedDemand::of(repo("acme/left"), 3)),
        );
        demand.set_for(
            &ScaleTarget::repository("acme/right").unwrap(),
            PollOutcome::Ready(QueuedDemand::of(repo("acme/right"), 3)),
        );
        let mut harness = Harness::build(
            host_with(3),
            Arc::clone(&launcher),
            demand,
            Arc::new(InProcessAllocationLock::new()),
        );

        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/left", 3), policy(2, "acme/right", 3)])
            .await;

        assert_eq!(
            report.started, 3,
            "host_capacity is 3 and two policies each allowed 3 started {} runners between              them; the second policy's grant was computed from a set that did not yet              contain the first policy's launches",
            report.started
        );
        assert_eq!(launcher.launches(), 3);
    }

    /// Finding 1: an attempt set that cannot be read is not an empty one.
    ///
    /// `attempts()` used to be infallible, which left `e3` — reading a journal
    /// off a disk — a choice between panicking and answering `vec![]`. The
    /// second is silent and catastrophic: an empty set is indistinguishable from
    /// an idle host, so a transient read failure reads as "nothing is running"
    /// and the pass allocates the whole machine for jobs already being served.
    ///
    /// The contrast is the assertion. Identical host, identical demand,
    /// identical policy; the only difference is whether the launcher can answer.
    #[tokio::test]
    async fn an_unreadable_attempt_set_starts_nothing_and_is_not_read_as_an_idle_host() {
        let launcher = Arc::new(FakeLauncher::new());
        let mut harness = Harness::build(
            host_with(8),
            Arc::clone(&launcher),
            Arc::new(FakeDemand::ready(4, &repo("acme/app"))),
            Arc::new(InProcessAllocationLock::new()),
        );
        let policy = policy(1, "acme/app", 8);

        launcher.fail_attempts(true);
        let unreadable = harness
            .reconciler
            .reconcile(std::slice::from_ref(&policy))
            .await;

        assert_eq!(
            unreadable.started, 0,
            "nothing may be decided from a set that was not read"
        );
        assert_eq!(launcher.launches(), 0);
        assert!(unreadable.attempts_unreadable > 0, "and the pass says so");
        assert!(
            unreadable.allocations.is_empty(),
            "no allocation is reported either: there was no set to compute one from, and \
             an allocation of zero would claim a decision nobody made"
        );
        assert!(harness.events.count_of("attempts_unreadable") > 0);

        // The same everything, with a launcher that can answer.
        launcher.fail_attempts(false);
        let readable = harness
            .reconciler
            .reconcile(std::slice::from_ref(&policy))
            .await;
        assert_eq!(
            readable.started, 4,
            "the difference between the two passes is only whether the set could be read"
        );
        assert_eq!(readable.attempts_unreadable, 0);
    }

    /// Finding 3: a cleanup that can never succeed was an invisible permanent
    /// loop.
    ///
    /// `if …clean(…).await.is_ok()` had no `else`, so a runtime directory that
    /// could not be removed was retried on every poll with no event, no counter
    /// and no report field. It wedges no capacity — a terminal attempt already
    /// stopped counting — but `clean` returns a `Result` precisely so the caller
    /// can say something, and this module's organising principle is the things
    /// that go wrong silently.
    #[tokio::test]
    async fn a_cleanup_that_cannot_succeed_is_reported_rather_than_retried_in_silence() {
        let launcher = Arc::new(FakeLauncher::refusing_cleanup(vec![concluded(
            1,
            1,
            AttemptOutcome::ExitedIdleWithoutWork,
        )]));
        let mut harness = Harness::build(
            host_with(4),
            Arc::clone(&launcher),
            Arc::new(FakeDemand::ready(0, &repo("acme/app"))),
            Arc::new(InProcessAllocationLock::new()),
        );

        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 4)])
            .await;

        assert_eq!(report.cleaned, 0);
        assert_eq!(report.clean_failures, 1);
        assert_eq!(harness.events.count_of("attempt_clean_failed"), 1);
        assert_eq!(
            harness.events.count_of("attempt_cleaned"),
            0,
            "and it is not reported as cleaned"
        );
        assert_eq!(
            launcher.snapshot().len(),
            1,
            "the attempt is still there, so the retry is real -- what changed is that it \
             is no longer silent"
        );

        // The reason is the variant, never the detail: the fixture's failure
        // carries free text and none of it reaches the event.
        let reasons: Vec<&'static str> = harness
            .events
            .events()
            .into_iter()
            .filter_map(|event| match event {
                LifecycleEvent::AttemptCleanFailed { reason, .. } => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(reasons, vec!["other"]);
    }

    /// Finding 7: the lower arm of the clamp, driven through the reconciler.
    ///
    /// `demand_below_min_capacity_starts_nothing_in_v1` runs `demand = 0`
    /// against `min_capacity = 0`, which is *at* the floor and never raises
    /// `desired` — the assertion held for a reason unrelated to the boundary it
    /// named. D7 fixes `min` at 0 for v1, but `AutoscaleConfig::new` accepts
    /// `min > 0` today, so the path is representable and was undriven.
    #[tokio::test]
    async fn demand_below_min_capacity_is_raised_to_min_capacity() {
        let mut warm = ScalePolicy::new(
            PolicyId::from_u128(1),
            ScaleTarget::repository("acme/app").unwrap(),
            1,
            fixtures::HOST_ID,
            PolicyMode::autoscale(
                fixtures::routing_labels("home"),
                2,
                NonZeroU16::new(5).expect("non-zero"),
            )
            .expect("min <= max"),
            CachePolicy::default(),
        );
        warm.activate().expect("pending -> active");

        let mut harness = Harness::simple(8, 0, "acme/app");
        let report = harness.reconciler.reconcile(&[warm]).await;

        assert_eq!(
            report.allocations[0].demand, 0,
            "GitHub reported no queued runs"
        );
        assert_eq!(
            report.allocations[0].desired, 2,
            "min_capacity raised the target above demand"
        );
        assert_eq!(
            report.allocations[0].limiting_factor,
            LimitingFactor::MinCapacity
        );
        assert_eq!(report.started, 2, "and two runners were actually started");
        assert_eq!(harness.launcher.live_count(), 2);
    }

    // =======================================================================
    // Capacity, at the boundaries
    // =======================================================================

    #[tokio::test]
    async fn demand_above_max_capacity_is_clamped_to_max_capacity() {
        let mut harness = Harness::simple(100, 10, "acme/app");
        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 3)])
            .await;

        assert_eq!(report.allocations[0].demand, 10);
        assert_eq!(
            report.allocations[0].desired, 3,
            "max_capacity beats demand"
        );
        assert_eq!(report.started, 3);
        assert_eq!(
            report.allocations[0].limiting_factor,
            LimitingFactor::MaxCapacity
        );
    }

    #[tokio::test]
    async fn demand_below_min_capacity_starts_nothing_in_v1() {
        // D7 fixes `min_capacity` at 0, so "below the floor" is "no demand", and
        // the product requirement it satisfies is "no idle runners when unused".
        let mut harness = Harness::simple(8, 0, "acme/app");
        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 4)])
            .await;

        assert_eq!(report.allocations[0].desired, 0);
        assert_eq!(report.started, 0);
        assert!(report.starts_nothing());
    }

    #[tokio::test]
    async fn zero_host_headroom_starts_nothing_at_maximum_demand() {
        let launcher = Arc::new(FakeLauncher::new().seeded(vec![
            attempt_in(AttemptState::Busy, 1, 1),
            attempt_in(AttemptState::Busy, 2, 1),
        ]));
        let demand = Arc::new(FakeDemand::ready(u32::from(u16::MAX), &repo("acme/app")));
        let mut harness = Harness::build(
            host_with(2),
            launcher,
            demand,
            Arc::new(InProcessAllocationLock::new()),
        );

        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 2)])
            .await;
        assert_eq!(report.started, 0);
        assert_eq!(report.allocations[0].headroom_before, 0);
        assert_eq!(harness.launcher.launches(), 0);
    }

    #[tokio::test]
    async fn headroom_smaller_than_the_per_policy_allowance_wins() {
        // Four slots held by *another* policy on a host of six: this policy is
        // allowed five and gets two.
        let launcher = Arc::new(FakeLauncher::new().seeded(vec![
            attempt_in(AttemptState::Busy, 1, 99),
            attempt_in(AttemptState::Busy, 2, 99),
            attempt_in(AttemptState::Idle, 3, 99),
            attempt_in(AttemptState::Starting, 4, 99),
        ]));
        let demand = Arc::new(FakeDemand::ready(5, &repo("acme/app")));
        let mut harness = Harness::build(
            host_with(6),
            launcher,
            demand,
            Arc::new(InProcessAllocationLock::new()),
        );

        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 5)])
            .await;
        assert_eq!(
            report.allocations[0].desired, 5,
            "its own ceiling allows five"
        );
        assert_eq!(report.started, 2, "the host has two slots free");
        assert_eq!(
            report.allocations[0].limiting_factor,
            LimitingFactor::HostCapacity
        );
        assert_eq!(harness.launcher.live_count(), 6);
    }

    #[tokio::test]
    async fn the_idle_host_assertion_holds() {
        // "No demand means zero runner processes and zero attempts out of
        // terminal state."
        let mut harness = Harness::simple(8, 0, "acme/app");
        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 4), policy(2, "acme/app", 4)])
            .await;

        assert_eq!(report.started, 0);
        assert_eq!(harness.launcher.launches(), 0);
        assert!(harness.launcher.snapshot().is_empty());
        assert_eq!(
            harness
                .launcher
                .snapshot()
                .iter()
                .filter(|a| !a.is_terminal())
                .count(),
            0
        );
    }

    // =======================================================================
    // D9 under concurrency: the other silent failure
    // =======================================================================

    /// `e1`'s Definition of Done: *"Two policies on one host with
    /// `host_capacity` smaller than the sum of their `max_capacity` values never
    /// exceed `host_capacity` under concurrent reconciliation — asserted under
    /// simulated lock contention, with no duplicate runners."*
    ///
    /// The contention is simulated by [`FakeLauncher::with_yields`], which puts
    /// executor yield points *between* the launcher reading the attempt set and
    /// recording the new one. Without serialisation both tasks read a headroom
    /// of three and both spend it.
    ///
    /// # Watched failing before it was made to pass
    ///
    /// Granting from this lock without taking the inner mutex — leaving every
    /// counter and every yield point exactly as they are — fails this assertion
    /// with `left: 4, right: 3`: four runners on a host of three, from two
    /// policies each individually inside their own `max_capacity`. The control
    /// test below keeps that measurement standing permanently by running the
    /// same body against [`NoLock`].
    #[tokio::test(flavor = "current_thread")]
    async fn two_policies_reconciling_concurrently_never_exceed_host_capacity() {
        let lock = Arc::new(CountingLock::new());
        let (launches, live) =
            two_policies_concurrently(Arc::clone(&lock) as Arc<dyn AllocationLock>).await;

        assert_eq!(
            launches, 3,
            "the sum across policies must never exceed host_capacity, and each policy is \
             individually within its own max_capacity of 3"
        );
        assert_eq!(live, 3, "and no duplicate runner survived the race");
        assert_eq!(
            lock.peak(),
            1,
            "the allocation lock had one holder at a time; without that the read of the \
             headroom and the creation of the runtime are not atomic"
        );
        assert!(
            (3..=5).contains(&lock.acquisitions()),
            "the lock is taken before *each* runtime, not once per pass: three runtimes \
             means at least three holds, and at most one further hold per policy to \
             discover the host filled up underneath it. It was taken {} times",
            lock.acquisitions()
        );
    }

    /// The control for the test above: the same body with the lock removed.
    ///
    /// It exists so that the assertion above cannot pass vacuously. If a future
    /// change makes the unserialised path safe by accident — a launcher that
    /// records synchronously, say — this test goes red and says so, rather than
    /// the other one silently proving nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn without_the_allocation_lock_two_policies_oversubscribe_the_host() {
        let (launches, _) =
            two_policies_concurrently(Arc::new(NoLock) as Arc<dyn AllocationLock>).await;

        assert!(
            launches > 3,
            "with no serialisation both policies must be able to spend the same headroom; \
             they started {launches} runners on a host of 3. If this is ever 3, the \
             contention window closed and `two_policies_reconciling_concurrently_never_\
             exceed_host_capacity` has stopped proving anything"
        );
    }

    /// Two policies, one host of three, each allowed three, reconciled at once.
    ///
    /// Returns `(launches, live attempts)`.
    async fn two_policies_concurrently(lock: Arc<dyn AllocationLock>) -> (usize, usize) {
        let launcher = Arc::new(FakeLauncher::new().with_yields(4));
        let host = host_with(3);

        let mut left = Harness::build(
            host.clone(),
            Arc::clone(&launcher),
            Arc::new(FakeDemand::ready(3, &repo("acme/left"))),
            Arc::clone(&lock),
        )
        .reconciler;
        let mut right = Harness::build(
            host,
            Arc::clone(&launcher),
            Arc::new(FakeDemand::ready(3, &repo("acme/right"))),
            Arc::clone(&lock),
        )
        .reconciler;

        let a = policy(1, "acme/left", 3);
        let b = policy(2, "acme/right", 3);

        let left = tokio::spawn(async move { left.reconcile(&[a]).await });
        let right = tokio::spawn(async move { right.reconcile(&[b]).await });
        let (_, _) = (left.await.unwrap(), right.await.unwrap());

        (launcher.launches(), launcher.live_count())
    }

    // =======================================================================
    // D19: monitor-only
    // =======================================================================

    /// `e1`'s Definition of Done: *"A `MonitorOnly` policy under maximum demand
    /// starts zero runners and issues no demand request."*
    ///
    /// Driven through `c4`'s real gateway fake so that "issued no demand
    /// request" is asserted against the thing that would have issued it, rather
    /// than against this module's own bookkeeping. `FakeGithub` records every
    /// call it is asked to make.
    #[tokio::test]
    async fn a_monitor_only_policy_under_maximum_demand_starts_nothing_and_polls_nothing() {
        let gateway = FakeGithub::new().with_queued_runs(repo("acme/app"), 10_000);
        let gateway = Arc::new(GatewayDemand::new(gateway, CancelToken::new()));
        let launcher = Arc::new(FakeLauncher::new());
        let events = Arc::new(EventLog::new());

        let mut reconciler = Reconciler::new(
            host_with(10),
            ReconcilerPorts {
                demand: Arc::clone(&gateway) as Arc<dyn DemandSource>,
                launcher: Arc::clone(&launcher) as Arc<dyn RunnerLauncher>,
                lock: Arc::new(InProcessAllocationLock::new()),
                directory: Arc::new(FakeDirectory::default()),
                clock: Arc::new(FakeClock::default()),
                jitter: Arc::new(NoJitter),
                events: Arc::clone(&events) as Arc<dyn EventSink>,
            },
        );

        let monitor = fixtures::policy()
            .id(PolicyId::from_u128(1))
            .repository("acme/app")
            .monitor_only()
            .active()
            .build();

        let report = reconciler.reconcile(&[monitor]).await;

        assert_eq!(report.started, 0);
        assert_eq!(launcher.launches(), 0);
        assert_eq!(report.monitor_only, vec![PolicyId::from_u128(1)]);
        assert_eq!(
            report.demand_requests, 0,
            "a monitor-only policy spends nothing from the shared hourly ceiling"
        );
        assert!(
            gateway.gateway().calls().is_empty(),
            "a monitor-only policy issued a demand request: {:?}",
            gateway.gateway().calls()
        );
        assert_eq!(events.count_of("monitor_only_skipped"), 1);
        assert_eq!(
            events.count_of("demand_observed"),
            0,
            "and it contributed no demand"
        );
    }

    /// D19 says a monitor-only policy is *"skipped entirely by
    /// reconciliation"*, and "entirely" is the load-bearing word once two
    /// policies share a target.
    ///
    /// This defect was found by review rather than by the test above, which
    /// cannot see it: there, the monitor-only policy is the *only* policy, so
    /// nobody polls its target and the lookup finds nothing. Give it a
    /// repository an autoscale policy already polls and the lookup succeeds —
    /// and the monitor-only policy was then allocated for and had a demand
    /// observation emitted on its behalf. It still started nothing, because
    /// `may_start_runners` is false for it and `HostAllocator` refuses it by
    /// name, so no ceiling was ever at risk. It simply was not skipped.
    ///
    /// Removing the `owns_runners` guard from the allocation loop was watched
    /// failing this test before it was restored:
    /// `a monitor-only policy was allocated for: [… limiting_factor:
    /// MonitorOnly]`.
    #[tokio::test]
    async fn a_monitor_only_policy_sharing_a_target_is_still_skipped_entirely() {
        let lock = Arc::new(CountingLock::new());
        let launcher = Arc::new(FakeLauncher::new());
        let events = Arc::new(EventLog::new());
        let mut reconciler = Reconciler::new(
            host_with(4),
            ReconcilerPorts {
                demand: Arc::new(FakeDemand::ready(2, &repo("acme/app"))),
                launcher: Arc::clone(&launcher) as Arc<dyn RunnerLauncher>,
                lock: Arc::clone(&lock) as Arc<dyn AllocationLock>,
                directory: Arc::new(FakeDirectory::default()),
                clock: Arc::new(FakeClock::default()),
                jitter: Arc::new(NoJitter),
                events: Arc::clone(&events) as Arc<dyn EventSink>,
            },
        );

        let watcher = fixtures::policy()
            .id(PolicyId::from_u128(2))
            .repository("acme/app")
            .monitor_only()
            .active()
            .build();

        let report = reconciler
            .reconcile(&[policy(1, "acme/app", 4), watcher])
            .await;

        assert_eq!(report.started, 2, "the autoscale policy is served normally");
        assert_eq!(report.monitor_only, vec![PolicyId::from_u128(2)]);
        assert_eq!(
            events.count_of("demand_observed"),
            1,
            "the demand observation belongs to the autoscale policy alone"
        );
        assert!(
            report
                .allocations
                .iter()
                .all(|a| a.policy_id == PolicyId::from_u128(1)),
            "a monitor-only policy was allocated for: {:?}",
            report.allocations
        );
        assert_eq!(
            lock.acquisitions(),
            2,
            "one hold per runtime created, and none on behalf of the monitor-only policy. \
             It was three before the budget was checked at the top of the loop rather than \
             after the re-read, which cost every policy a surplus hold to discover there \
             was nothing left to grant"
        );
    }

    #[tokio::test]
    async fn the_monitor_only_refusal_is_asserted_on_the_mode_not_on_a_missing_ceiling() {
        // The specification requires this to be asserted rather than deduced
        // from `max_capacity` being absent. `HostAllocator` reports it by name,
        // and this loop reaches that arm through `owns_runners`, which is a
        // question about the mode.
        let monitor = fixtures::monitor_only_policy();
        assert!(!monitor.owns_runners());
        assert_eq!(monitor.max_capacity(), None);

        let host = host_with(10);
        let attempts: Vec<RunnerAttempt> = Vec::new();
        let mut allocator = HostAllocator::from_attempts(&host, &attempts);
        let allocation = allocator.allocate(&monitor, 10_000);
        assert_eq!(allocation.limiting_factor, LimitingFactor::MonitorOnly);
        assert_eq!(allocation.to_start, 0);
        assert_eq!(
            allocator.headroom(),
            10,
            "and it consumes no headroom, so an autoscale policy on the same host is \
             unaffected"
        );
    }

    // =======================================================================
    // The surplus runner, and busy protection
    // =======================================================================

    /// `e1`'s Definition of Done: *"A surplus attempt that receives no job
    /// reaches a terminal state recorded as an idle exit, is cleaned, and is not
    /// reported as a failure."*
    #[tokio::test]
    async fn a_surplus_attempt_is_cleaned_as_an_idle_exit_and_not_as_a_failure() {
        let launcher = Arc::new(FakeLauncher::new().seeded(vec![
            concluded(1, 1, AttemptOutcome::ExitedIdleWithoutWork),
            concluded(
                2,
                1,
                AttemptOutcome::failed(FailureReason::JitRequestFailed),
            ),
            concluded(3, 1, AttemptOutcome::CompletedJob),
        ]));
        let mut harness = Harness::build(
            host_with(4),
            Arc::clone(&launcher),
            Arc::new(FakeDemand::ready(0, &repo("acme/app"))),
            Arc::new(InProcessAllocationLock::new()),
        );

        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 4)])
            .await;

        assert_eq!(report.cleaned, 3);
        assert_eq!(report.idle_exits, 1, "the surplus case, counted apart");
        assert_eq!(
            report.failures, 1,
            "only the failed attempt is a failure; the idle exit and the completed job are \
             not"
        );
        assert_eq!(launcher.cleaned().len(), 3);
        assert!(launcher.snapshot().is_empty());

        let cleaned: Vec<OutcomeKind> = harness
            .events
            .events()
            .into_iter()
            .filter_map(|event| match event {
                LifecycleEvent::AttemptCleaned { outcome, .. } => Some(outcome),
                _ => None,
            })
            .collect();
        assert!(cleaned.contains(&OutcomeKind::IdleExit));
        assert!(
            !OutcomeKind::IdleExit.is_failure(),
            "an idle exit rendered as a failure sends an operator hunting a fault that does \
             not exist"
        );
    }

    /// `e1`'s Definition of Done: *"A scale-down request with a busy attempt
    /// removes nothing and leaves the attempt `busy`."*
    #[tokio::test]
    async fn scale_down_removes_nothing_from_a_busy_attempt() {
        let busy = attempt_in(AttemptState::Busy, 1, 1);
        let launcher = Arc::new(FakeLauncher::new().seeded(vec![
            busy.clone(),
            attempt_in(AttemptState::Starting, 2, 1),
            concluded(3, 1, AttemptOutcome::CompletedJob),
        ]));
        let harness = Harness::build(
            host_with(4),
            Arc::clone(&launcher),
            Arc::new(FakeDemand::ready(0, &repo("acme/app"))),
            Arc::new(InProcessAllocationLock::new()),
        );

        let report = harness
            .reconciler
            .scale_down(&policy(1, "acme/app", 4))
            .await;

        assert_eq!(report.refused_busy, 1);
        assert_eq!(
            report.retained, 1,
            "the `starting` attempt is not ended either"
        );
        assert_eq!(report.removed, 1, "only the concluded attempt is reclaimed");

        let after = launcher.snapshot();
        let still_busy = after
            .iter()
            .find(|a| a.id == AttemptId::from_u128(1))
            .expect("the busy attempt is still there");
        assert_eq!(
            still_busy.state(),
            AttemptState::Busy,
            "scale-down removed nothing from a runner that is executing a job, and left it \
             busy"
        );
        assert!(!launcher.cleaned().contains(&AttemptId::from_u128(1)));

        // And the domain refuses it from the other side too, by name, so a
        // future caller that tried anyway would not get a generic transition
        // error.
        let mut busy = busy;
        assert!(matches!(
            busy.clean(fixtures::created_at()),
            Err(runner_manager_domain::attempt::AttemptError::BusyCannotBeCleaned)
        ));
        assert_eq!(harness.events.count_of("scale_down_refused"), 1);
    }

    // =======================================================================
    // The schedule
    // =======================================================================

    #[test]
    fn the_default_interval_is_sixty_seconds_and_the_floor_is_thirty() {
        assert_eq!(RefreshInterval::DEFAULT_SECS, 60);
        assert_eq!(RefreshInterval::MIN_SECS, 30);
        assert_eq!(PollSchedule::floor(), Duration::from_secs(30));
        assert!(
            RefreshInterval::from_secs(29).is_err(),
            "the floor is a rate-budget constraint, and a caller must not be able to write \
             a shorter interval at all"
        );

        let mut schedule = PollSchedule::new(RefreshInterval::default());
        let next = schedule.next_poll(None, fixtures::created_at(), &NoJitter);
        assert_eq!(next.delay, Duration::from_secs(60));
        assert_eq!(next.pace, PollPace::Nominal);

        let mut floored = PollSchedule::new(RefreshInterval::from_secs(30).unwrap());
        assert_eq!(
            floored
                .next_poll(None, fixtures::created_at(), &NoJitter)
                .delay,
            Duration::from_secs(30)
        );
    }

    /// `e1`'s Definition of Done: *"The poll interval … increases under a
    /// rate-limit signal, and the increase is visible in emitted state rather
    /// than silent."*
    #[test]
    fn a_rate_limit_increases_the_delay_and_names_itself() {
        let now = fixtures::created_at();
        let mut schedule = PollSchedule::new(RefreshInterval::default());

        let limited = RefreshState::RateLimited(RateLimited {
            kind: RateLimitKind::Secondary,
            retry_after: Some(Duration::from_secs(300)),
            remaining: None,
            reset_unix_secs: None,
        });
        let next = schedule.next_poll(Some(&limited), now, &NoJitter);

        assert_eq!(next.delay, Duration::from_secs(300));
        assert_eq!(
            next.pace,
            PollPace::RateLimited {
                kind: RateLimitKind::Secondary
            },
            "the increase is reported, never hidden"
        );
        assert!(next.pace.is_throttled());
        assert_eq!(next.pace.as_str(), "rate_limited_secondary");
    }

    /// Constraint on this task: *"Read `RefreshState::retry_delay` as an
    /// absolute floor, not an addend."*
    #[test]
    fn the_retry_delay_is_an_absolute_floor_and_never_an_addend() {
        let now = fixtures::created_at();
        let mut schedule = PollSchedule::new(RefreshInterval::default());

        let limited = RefreshState::RateLimited(RateLimited {
            kind: RateLimitKind::Primary,
            retry_after: Some(Duration::from_secs(300)),
            remaining: Some(0),
            reset_unix_secs: None,
        });

        // Five successive answers, each carrying the window that is *left*.
        // An addend would compound: 360, 660, 960 … and look like a hang.
        for _ in 0..5 {
            let next = schedule.next_poll(Some(&limited), now, &NoJitter);
            assert_eq!(
                next.delay,
                Duration::from_secs(300),
                "the delay is `max(interval, retry_delay)`; `interval + retry_delay` would \
                 have compounded on every successive retry"
            );
        }

        // And when GitHub asks for less than the interval, the interval wins:
        // the floor is never crossed to catch up.
        let brief = RefreshState::RateLimited(RateLimited {
            kind: RateLimitKind::Secondary,
            retry_after: Some(Duration::from_secs(5)),
            remaining: None,
            reset_unix_secs: None,
        });
        let next = schedule.next_poll(Some(&brief), now, &NoJitter);
        assert_eq!(
            next.delay,
            Duration::from_secs(60),
            "a short `retry-after` may not drop the loop below its own interval"
        );
        assert!(next.delay >= PollSchedule::floor());
    }

    #[test]
    fn no_branch_of_the_schedule_can_go_below_the_thirty_second_floor() {
        let now = fixtures::created_at();
        let states = [
            None,
            Some(RefreshState::Offline),
            Some(RefreshState::RateLimited(RateLimited {
                kind: RateLimitKind::Secondary,
                retry_after: Some(Duration::from_secs(1)),
                remaining: None,
                reset_unix_secs: None,
            })),
            Some(RefreshState::LockedOut {
                retry_after: Duration::from_secs(1),
            }),
            Some(RefreshState::Unauthorized),
            Some(RefreshState::Forbidden { message: None }),
            Some(RefreshState::Failed {
                status: Some(500),
                message: "server error".into(),
            }),
            Some(RefreshState::Cancelled),
        ];

        for state in &states {
            let mut schedule = PollSchedule::new(RefreshInterval::from_secs(30).unwrap());
            let next = schedule.next_poll(state.as_ref(), now, &NoJitter);
            assert!(
                next.delay >= PollSchedule::floor(),
                "{state:?} scheduled a poll {}ms away, under the 30-second floor",
                next.delay.as_millis()
            );
        }
    }

    #[test]
    fn an_offline_run_backs_off_with_jitter_and_a_recovery_resets_it() {
        let now = fixtures::created_at();
        let mut schedule = PollSchedule::new(RefreshInterval::default());

        // Doubling, from the nominal interval.
        let mut previous = Duration::ZERO;
        for consecutive in 1..=6_u32 {
            let next = schedule.next_poll(Some(&RefreshState::Offline), now, &NoJitter);
            assert_eq!(next.pace, PollPace::Offline { consecutive });
            assert!(
                next.delay >= previous,
                "the back-off must not shrink while the outage continues"
            );
            assert!(next.delay >= Duration::from_secs(60));
            previous = next.delay;
        }
        assert!(previous <= MAX_OFFLINE_BACKOFF, "and it is capped");

        // Jitter widens the delay rather than narrowing it, so a fleet of
        // agents does not retry in lockstep.
        let mut jittered = PollSchedule::new(RefreshInterval::default());
        let none = jittered.next_poll(Some(&RefreshState::Offline), now, &NoJitter);
        let mut jittered = PollSchedule::new(RefreshInterval::default());
        let full = jittered.next_poll(Some(&RefreshState::Offline), now, &FixedJitter(0.999));
        assert!(full.delay > none.delay);
        assert!(full.delay <= none.delay.mul_f64(1.0 + JITTER_RATIO));

        // Recovery resets the run with no bookkeeping of its own.
        assert_eq!(schedule.consecutive_offline(), 6);
        let recovered = schedule.next_poll(None, now, &NoJitter);
        assert_eq!(recovered.pace, PollPace::Nominal);
        assert_eq!(recovered.delay, Duration::from_secs(60));
        assert_eq!(schedule.consecutive_offline(), 0);
    }

    #[test]
    fn the_offline_state_states_the_twenty_four_hour_bound() {
        assert_eq!(
            GITHUB_CANCELS_QUEUED_JOBS_AFTER,
            Duration::from_secs(24 * 60 * 60)
        );

        let brief = OfflineState::new(1, Duration::from_secs(120));
        let rendered = brief.to_string();
        assert!(rendered.contains("24 hours"), "{rendered}");
        assert!(rendered.contains("Retrying in 120s"), "{rendered}");
        assert!(!brief.has_outlasted_the_queue());

        let long = brief.since(GITHUB_CANCELS_QUEUED_JOBS_AFTER + Duration::from_secs(1));
        assert!(long.has_outlasted_the_queue());
        assert!(
            long.to_string().contains("queued work has been lost"),
            "{long}"
        );

        // "We cannot tell" is not "not yet".
        assert!(!OfflineState::new(9, Duration::from_secs(60)).has_outlasted_the_queue());
    }

    // =======================================================================
    // Offline, end to end
    // =======================================================================

    /// `e1`'s Definition of Done: *"An unreachable GitHub yields `offline`, zero
    /// new runners, retained existing processes, and jittered backoff; recovery
    /// resumes polling and does not double-count a job that was already being
    /// served."*
    #[tokio::test]
    async fn an_unreachable_github_starts_nothing_retains_everything_and_backs_off() {
        let live = vec![
            attempt_in(AttemptState::Busy, 1, 1),
            attempt_in(AttemptState::Starting, 2, 1),
        ];
        let launcher = Arc::new(FakeLauncher::new().seeded(live.clone()));
        let demand = Arc::new(FakeDemand::failing(RefreshState::Offline));
        let mut harness = Harness::build(
            host_with(8),
            Arc::clone(&launcher),
            Arc::clone(&demand),
            Arc::new(InProcessAllocationLock::new()),
        );
        let policy = policy(1, "acme/app", 8);

        let report = harness
            .reconciler
            .reconcile(std::slice::from_ref(&policy))
            .await;

        assert!(report.is_offline());
        assert_eq!(report.started, 0, "no new runner during an outage");
        assert_eq!(launcher.launches(), 0);
        assert_eq!(
            launcher.snapshot(),
            live,
            "existing runner processes are retained, untouched"
        );
        assert_eq!(report.unreadable, vec![PolicyId::from_u128(1)]);
        assert_eq!(report.next_poll.pace, PollPace::Offline { consecutive: 1 });
        assert!(report.next_poll.delay >= Duration::from_secs(60));
        let offline = report.offline_state().expect("an offline state to display");
        assert!(offline.to_string().contains("24 hours"));

        // Recovery: the same job is still queued, and one runner is already
        // serving it. Demand is recomputed from the current queued set rather
        // than accumulated, so the reconnect starts nothing new.
        demand.set(PollOutcome::Ready(QueuedDemand::of(repo("acme/app"), 2)));
        let recovered = harness.reconciler.reconcile(&[policy]).await;

        assert!(!recovered.is_offline());
        assert_eq!(recovered.next_poll.pace, PollPace::Nominal);
        assert_eq!(
            recovered.started, 0,
            "two queued runs, two attempts already in flight: a reconnect cannot \
             double-count work"
        );
        assert_eq!(recovered.allocations[0].active_owned, 2);
        assert_eq!(launcher.live_count(), 2);
    }

    /// One unreachable target must not idle a whole host.
    ///
    /// The failure that decides the *schedule* is the most severe across every
    /// target polled — backing the whole loop off during an outage is the safe
    /// error, and `f3` runs one reconciler per target anyway, so in production
    /// the two are usually the same thing. What must not follow from that is
    /// refusing to serve a policy whose own target answered perfectly well, and
    /// the two are easy to conflate because the offline reading is sitting in
    /// the same map.
    #[tokio::test]
    async fn one_offline_target_does_not_stop_a_reachable_one() {
        let mut harness = Harness::simple(8, 0, "acme/app");
        harness.demand.set_for(
            &ScaleTarget::repository("acme/app").unwrap(),
            PollOutcome::Ready(QueuedDemand::of(repo("acme/app"), 2)),
        );
        harness.demand.set_for(
            &ScaleTarget::repository("acme/broken").unwrap(),
            PollOutcome::Failed(RefreshState::Offline),
        );

        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 4), policy(2, "acme/broken", 4)])
            .await;

        assert_eq!(
            report.started, 2,
            "the reachable target was served; an unreachable sibling repository must not \
             idle the host"
        );
        assert_eq!(report.unreadable, vec![PolicyId::from_u128(2)]);
        assert_eq!(harness.demand.polls().len(), 2, "both targets were polled");

        // And the schedule takes the worse of the two.
        assert!(report.is_offline());
        assert_eq!(report.next_poll.pace, PollPace::Offline { consecutive: 1 });
    }

    /// The 24-hour bound has to be reachable in production, not only in a unit
    /// test of [`OfflineState`].
    ///
    /// This was a real gap: the reconciler built its offline state from the
    /// back-off count alone, so `offline_for` was always `None` and
    /// [`OfflineState::has_outlasted_the_queue`] could never be true outside a
    /// test that constructed the value by hand. An operator whose agent had been
    /// offline for two days would have been told that an outage longer than 24
    /// hours *would* lose queued work, in the future tense, having already lost
    /// it.
    ///
    /// The elapsed time is measured from the first poll of the run rather than
    /// derived from the interval, because the back-off doubles and the two
    /// diverge immediately.
    #[tokio::test]
    async fn a_day_long_outage_says_that_queued_work_has_already_been_lost() {
        let clock = Arc::new(FakeClock::default());
        let launcher = Arc::new(FakeLauncher::new());
        let demand = Arc::new(FakeDemand::failing(RefreshState::Offline));
        let mut reconciler = Reconciler::new(
            host_with(4),
            ReconcilerPorts {
                demand: Arc::clone(&demand) as Arc<dyn DemandSource>,
                launcher: Arc::clone(&launcher) as Arc<dyn RunnerLauncher>,
                lock: Arc::new(InProcessAllocationLock::new()),
                directory: Arc::new(FakeDirectory::default()),
                clock: Arc::clone(&clock) as Arc<dyn Clock>,
                jitter: Arc::new(NoJitter),
                events: Arc::new(NoEvents),
            },
        );
        let policy = policy(1, "acme/app", 4);

        // The outage begins.
        let first = reconciler.reconcile(std::slice::from_ref(&policy)).await;
        let state = first.offline_state().expect("an offline state");
        assert!(!state.has_outlasted_the_queue());
        assert!(
            state
                .to_string()
                .contains("an outage longer than that loses"),
            "{state}"
        );

        // A day and a minute later, still unreachable.
        clock.advance_secs(24 * 60 * 60 + 60);
        let later = reconciler.reconcile(std::slice::from_ref(&policy)).await;
        let state = later.offline_state().expect("an offline state");
        assert!(state.has_outlasted_the_queue());
        assert!(
            state.to_string().contains("queued work has been lost"),
            "{state}"
        );
        assert_eq!(launcher.launches(), 0, "and still nothing was started");

        // Recovery closes the run, so a *later* outage measures from itself
        // rather than from the first one.
        demand.set(PollOutcome::Ready(QueuedDemand::of(repo("acme/app"), 0)));
        let recovered = reconciler.reconcile(std::slice::from_ref(&policy)).await;
        assert!(recovered.offline_state().is_none());
        assert_eq!(reconciler.schedule().offline_for(clock.now()), None);

        demand.set(PollOutcome::Failed(RefreshState::Offline));
        let again = reconciler.reconcile(std::slice::from_ref(&policy)).await;
        assert!(
            !again
                .offline_state()
                .expect("an offline state")
                .has_outlasted_the_queue(),
            "a new outage must not inherit the age of the one before it"
        );
    }

    /// Finding 5: the adapter, not the lock underneath it.
    ///
    /// `d1` covers `LockKind::Allocation` including a contended `acquire_at`
    /// with a wait. What that does not reach is this adapter: the
    /// `spawn_blocking` wrapper, the collapse of both a refused lock and a
    /// panicked blocking task into `AllocationLockBusy`, and — the one that
    /// would be silent — whether [`AllocationGuard`] really holds the
    /// `HostLock`, since dropping it is the only release there is. A guard that
    /// dropped the lock on the way out would make every acquisition succeed and
    /// the ceiling would hold by luck.
    ///
    /// The original disclosure said this needed a real filesystem and was
    /// therefore expensive. `AppPaths::rooted_at` plus `tempfile` — already a
    /// non-dev dependency of this crate — makes it about fifteen lines, so the
    /// reason was weaker than stated.
    #[tokio::test]
    async fn the_file_allocation_lock_excludes_a_second_holder_and_releases_on_drop() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = Arc::new(runner_manager_platform::paths::AppPaths::rooted_at(
            root.path(),
        ));
        let lock = FileAllocationLock::new(paths).with_wait(Duration::from_millis(50));

        let held = lock.acquire().await.expect("an uncontended lock is free");
        assert!(
            matches!(lock.acquire().await, Err(AllocationLockBusy)),
            "a second holder was admitted; on Unix the lock is per open file description \
             and on Windows the share mode denies write, so this must be refused even \
             from inside the same process"
        );

        drop(held);
        let regained = lock.acquire().await;
        assert!(
            regained.is_ok(),
            "dropping the guard is the only release there is, so a guard that does not \
             hold the `HostLock` leaves it held forever"
        );
    }

    #[test]
    fn tee_events_reaches_both_sinks() {
        // `f3` wires the log sink and `g2`'s buffer at once, and an event that
        // reached only one of them would be an activity view missing lines the
        // log file has, or the reverse.
        let left = Arc::new(EventLog::new());
        let right = Arc::new(EventLog::new());
        let tee = TeeEvents(
            Arc::clone(&left) as Arc<dyn EventSink>,
            Arc::clone(&right) as Arc<dyn EventSink>,
        );

        tee.emit(LifecycleEvent::MonitorOnlySkipped {
            policy: PolicyId::from_u128(1),
        });

        assert_eq!(left.count_of("monitor_only_skipped"), 1);
        assert_eq!(right.count_of("monitor_only_skipped"), 1);
    }

    // =======================================================================
    // Budget: the repository list, and the per-target poll
    // =======================================================================

    #[tokio::test]
    async fn the_repository_list_refreshes_far_more_slowly_than_the_demand_poll() {
        let clock = Arc::new(FakeClock::default());
        let directory = Arc::new(FakeDirectory::of(vec![repo("acme/one"), repo("acme/two")]));
        let cache = RepositoryCache::new(
            Arc::clone(&directory) as Arc<dyn RepositoryDirectory>,
            Arc::clone(&clock) as Arc<dyn Clock>,
            RefreshInterval::default(),
        );
        let target = ScaleTarget::organization("acme").unwrap();

        assert_eq!(
            cache.ttl(),
            Duration::from_secs(60 * u64::from(REPOSITORY_LIST_REFRESH_MULTIPLE))
        );

        // Every poll inside the window reuses the list.
        for _ in 0..REPOSITORY_LIST_REFRESH_MULTIPLE {
            let scope = cache.scope_for(&target).await.unwrap();
            assert_eq!(scope.repositories().len(), 2);
            clock.advance_secs(60);
        }
        assert_eq!(
            directory.calls(),
            1,
            "re-listing an organization at demand-poll frequency is what exhausts the \
             shared request budget"
        );
        assert_eq!(cache.lookups(), 1);

        // Past it, exactly one more.
        cache.scope_for(&target).await.unwrap();
        assert_eq!(directory.calls(), 2);
    }

    #[tokio::test]
    async fn a_repository_target_never_consults_the_directory() {
        let directory = Arc::new(FakeDirectory::of(vec![repo("acme/other")]));
        let cache = RepositoryCache::new(
            Arc::clone(&directory) as Arc<dyn RepositoryDirectory>,
            Arc::new(FakeClock::default()) as Arc<dyn Clock>,
            RefreshInterval::default(),
        );
        let target = ScaleTarget::repository("acme/app").unwrap();

        let scope = cache.scope_for(&target).await.unwrap();
        assert_eq!(scope.repositories(), &[repo("acme/app")]);
        assert_eq!(directory.calls(), 0);
    }

    #[tokio::test]
    async fn two_policies_on_one_target_cost_one_demand_poll_not_two() {
        // `04-subsystem-contracts.md` prices a *target*. A loop that spent per
        // policy would exceed the projection `f2` admitted the configuration
        // against, silently.
        let mut harness = Harness::simple(8, 4, "acme/app");
        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 2), policy(2, "acme/app", 2)])
            .await;

        assert_eq!(harness.demand.polls().len(), 1);
        assert_eq!(report.demand_requests, 1);
        assert_eq!(report.started, 4, "and both policies still get their share");
    }

    // =======================================================================
    // Failure paths
    // =======================================================================

    #[tokio::test]
    async fn a_failed_launch_stops_the_run_and_is_reported_without_free_text() {
        let launcher = Arc::new(FakeLauncher::new());
        launcher.fail_next(FailureReason::Other("token ghp_0123456789abcdef".into()));
        let mut harness = Harness::build(
            host_with(4),
            Arc::clone(&launcher),
            Arc::new(FakeDemand::ready(3, &repo("acme/app"))),
            Arc::new(InProcessAllocationLock::new()),
        );

        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 4)])
            .await;
        assert_eq!(report.started, 0);
        assert_eq!(report.allocations[0].to_start, 3, "the decision stands");

        let failures: Vec<&'static str> = harness
            .events
            .events()
            .into_iter()
            .filter_map(|event| match event {
                LifecycleEvent::RunnerStartFailed { reason, .. } => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(failures, vec!["other"]);
        assert!(
            !failures[0].contains("ghp_"),
            "an event carried a `FailureReason::Other` detail verbatim"
        );
    }

    #[tokio::test]
    async fn a_held_allocation_lock_starts_nothing_and_says_so() {
        let launcher = Arc::new(FakeLauncher::new());
        let mut harness = Harness::build(
            host_with(4),
            Arc::clone(&launcher),
            Arc::new(FakeDemand::ready(3, &repo("acme/app"))),
            Arc::new(HeldLock),
        );

        let report = harness
            .reconciler
            .reconcile(&[policy(1, "acme/app", 4)])
            .await;
        assert_eq!(report.started, 0);
        assert_eq!(
            report.deferred, 3,
            "three runners were granted and none was created; `deferred` counts grants, \
             not policies -- it reported `1` when a policy that launched two of five and \
             then lost the lock had left three unstarted"
        );
        assert_eq!(launcher.launches(), 0);
        assert_eq!(harness.events.count_of("allocation_deferred"), 1);
        assert!(
            harness
                .events
                .events()
                .iter()
                .any(|event| matches!(event, LifecycleEvent::AllocationDeferred { count: 3, .. })),
            "the event carries the same number the report does"
        );
        assert_eq!(
            report.allocations.len(),
            1,
            "the intent is still reported, so an operator staring at a queue sees why \
             nothing started"
        );
    }

    #[tokio::test]
    async fn a_foreign_or_draining_policy_is_reported_by_name_and_polls_nothing() {
        let mut harness = Harness::simple(8, 5, "acme/app");

        let foreign = fixtures::policy()
            .id(PolicyId::from_u128(1))
            .repository("acme/app")
            .host(HostId::from_u128(0xdead))
            .autoscale("office", 4)
            .active()
            .build();
        let mut draining = policy(2, "acme/app", 4);
        draining.request_disable().unwrap();

        let report = harness.reconciler.reconcile(&[foreign, draining]).await;

        assert_eq!(report.started, 0);
        assert_eq!(
            harness.demand.polls().len(),
            0,
            "neither can act on an answer"
        );
        let factors: Vec<LimitingFactor> = report
            .allocations
            .iter()
            .map(|a| a.limiting_factor)
            .collect();
        assert!(factors.contains(&LimitingFactor::ForeignHost));
        assert!(factors.contains(&LimitingFactor::NotReconciling));
    }

    #[tokio::test]
    async fn an_unreadable_repository_list_makes_the_target_unreadable_not_empty() {
        // Polling a scope nobody chose would report a demand number for the
        // wrong set of repositories, which is worse than reporting nothing.
        #[derive(Debug)]
        struct BrokenDirectory;

        #[async_trait::async_trait]
        impl RepositoryDirectory for BrokenDirectory {
            async fn repositories(&self, _org: &Org) -> Result<Vec<OwnerRepo>, InventoryError> {
                Err(InventoryError::Cancelled)
            }
        }

        let launcher = Arc::new(FakeLauncher::new());
        let events = Arc::new(EventLog::new());
        let mut reconciler = Reconciler::new(
            host_with(4),
            ReconcilerPorts {
                demand: Arc::new(FakeDemand::default()),
                launcher: Arc::clone(&launcher) as Arc<dyn RunnerLauncher>,
                lock: Arc::new(InProcessAllocationLock::new()),
                directory: Arc::new(BrokenDirectory),
                clock: Arc::new(FakeClock::default()),
                jitter: Arc::new(NoJitter),
                events: Arc::clone(&events) as Arc<dyn EventSink>,
            },
        );

        let org_policy = fixtures::policy()
            .id(PolicyId::from_u128(1))
            .organization("acme")
            .autoscale("home", 4)
            .active()
            .build();

        let report = reconciler.reconcile(&[org_policy]).await;
        assert_eq!(report.started, 0);
        assert_eq!(report.unreadable, vec![PolicyId::from_u128(1)]);
        assert_eq!(events.count_of("target_unreadable"), 1);
    }

    // =======================================================================
    // What the events may carry
    // =======================================================================

    /// One value of every [`LifecycleEvent`] variant.
    ///
    /// Hand-written, and what keeps it honest is the wildcard-free `match` in
    /// [`LifecycleEvent::name`]: adding a variant stops that compiling and puts
    /// the author here. The same residual `b1` records for `FailureReason::ALL`
    /// applies — an author who writes the `name` arm and forgets this list gets
    /// a green suite with the variant unscanned.
    fn every_event() -> Vec<LifecycleEvent> {
        let policy = PolicyId::from_u128(0xabcd_ef01);
        let attempt = AttemptId::from_u128(0x1234_5678);
        vec![
            LifecycleEvent::DemandObserved {
                policy,
                demand: u32::MAX,
                complete: false,
            },
            LifecycleEvent::TargetUnreadable {
                policy,
                reason: unreadable_reason(&RefreshState::Failed {
                    status: Some(500),
                    message: "Authorization: Bearer ghp_0123456789abcdefghijklmnopqrstuvwxyz"
                        .into(),
                }),
            },
            LifecycleEvent::Allocated {
                policy,
                demand: u32::MAX,
                desired: u16::MAX,
                active_owned: 7,
                headroom: 9,
                to_start: 2,
                limiting: LimitingFactor::HostCapacity,
            },
            LifecycleEvent::MonitorOnlySkipped { policy },
            LifecycleEvent::RunnerStarted { policy, attempt },
            LifecycleEvent::RunnerStartFailed {
                policy,
                reason: failure_reason_kind(&FailureReason::Other(
                    "Authorization: Bearer ghp_0123456789abcdefghijklmnopqrstuvwxyz".into(),
                )),
            },
            LifecycleEvent::AllocationDeferred { policy, count: 4 },
            LifecycleEvent::AttemptsUnreadable {
                reason: failure_reason_kind(&FailureReason::Other(
                    "x-api-key: ghp_0123456789abcdefghijklmnopqrstuvwxyz".into(),
                )),
            },
            LifecycleEvent::AttemptCleanFailed {
                policy,
                attempt,
                reason: failure_reason_kind(&FailureReason::ProcessExitedUnexpectedly),
            },
            LifecycleEvent::AttemptCleaned {
                policy,
                attempt,
                outcome: OutcomeKind::IdleExit,
            },
            LifecycleEvent::ScaleDownRefused { policy, attempt },
            LifecycleEvent::PollScheduled {
                retry_in_ms: 900_000,
                pace: PollPace::RateLimited {
                    kind: RateLimitKind::Primary,
                },
            },
        ]
    }

    /// `e1`'s Definition of Done: *"No emitted event contains a token, a JIT
    /// blob, or a credential header."*
    ///
    /// Asserted by rendering every variant and putting the result through `d1`'s
    /// own scrubber: if any of it looked like a credential to the redactor that
    /// guards the log file, the round trip would not be the identity. The
    /// positive control at the bottom is what stops that assertion passing
    /// because the scrubber is asleep.
    #[test]
    fn no_emitted_event_can_carry_a_credential() {
        use runner_manager_platform::logging::redact;

        for event in every_event() {
            let displayed = event.to_string();
            assert_eq!(
                redact(&displayed),
                displayed,
                "`{}` renders something `d1`'s sink would have to redact",
                event.name()
            );

            let debugged = format!("{event:?}");
            assert_eq!(
                redact(&debugged),
                debugged,
                "`{}`'s Debug renders something `d1`'s sink would have to redact",
                event.name()
            );
        }

        // The control: the scrubber is awake, and would have caught a credential
        // had one been there.
        let secret = "Authorization: Bearer ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        assert_ne!(
            redact(secret),
            secret,
            "the scan above proves nothing if `redact` no longer recognises a credential"
        );
    }

    #[test]
    fn every_field_name_this_sink_emits_is_one_d1_allows() {
        use runner_manager_platform::logging::is_field_allowed;

        // The names `TracingEvents` writes. Kept beside the sink rather than
        // derived from it, because a derived list would move with the code and
        // assert nothing.
        for field in [
            "event",
            "policy_id",
            "attempt_id",
            "attempt_state",
            "demand",
            "desired",
            "capacity",
            "headroom",
            "count",
            "reason",
            "outcome",
            "mode",
            "lock",
            "retry_in_ms",
            "state",
        ] {
            assert!(
                is_field_allowed(field),
                "`{field}` is not on `d1`'s allow-list, so this sink would emit \
                 `[redacted]` in its place and the line would lose its meaning"
            );
        }
    }

    #[test]
    fn every_failure_reason_has_a_credential_free_kind() {
        for reason in FailureReason::ALL {
            let kind = failure_reason_kind(&reason);
            assert!(!kind.is_empty());
            assert!(
                kind.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "`{kind}` is not a fixed identifier"
            );
        }
        assert_eq!(
            failure_reason_kind(&FailureReason::Other("ghp_secret".into())),
            "other",
            "the detail of an `Other` reason never reaches an event"
        );
    }

    // =======================================================================
    // The two tripwires
    // =======================================================================

    /// One source file's production half, with comment lines dropped.
    ///
    /// Both exclusions are `c4`'s, and load-bearing for the same reasons. The
    /// **test module** goes because the tests in it legitimately name the shapes
    /// they forbid — this module's own positive control is a literal
    /// `async fn acquire_jobs`, which would accuse the file of the thing it is
    /// proving it does not do. The **comments** go because this module's
    /// documentation explains the seam at length and has to name what does not
    /// exist in order to say why; a scan that forbade the explanation is a scan
    /// that gets the explanation deleted.
    fn production_half_of(source: &str) -> String {
        let production = source
            .split_once("\n#[cfg(test)]")
            .map_or(source, |(production, _)| production);
        production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// This file's own production half.
    fn this_file_above_its_tests_without_prose() -> String {
        production_half_of(include_str!("reconcile.rs"))
    }

    /// The one normalisation both halves of the scan use.
    ///
    /// # This is a second copy of `crates/github/src/demand.rs`, deliberately
    ///
    /// `production_half_of`, this function, [`FORBIDDEN`] and
    /// `forbidden_shape_in` together duplicate `demand.rs:1530-1619`. Sharing
    /// them would mean putting them in `crates/testkit`, which `e1` does not
    /// own, so the copy was the only option available to this task.
    ///
    /// **It is worth consolidating later, and here is the specific hazard.**
    /// The last defect in `c4`'s copy was two spellings of "the same"
    /// normalisation drifting apart — the haystack lower-cased and the needle
    /// not — which made three of its seven assertions vacuously true from the
    /// day they were written. Two copies is the same hazard one level up. The
    /// mitigation inside *this* copy is that one function serves both the scan
    /// and its positive control, so a normaliser that stops matching fails the
    /// control loudly rather than passing the scan silently; what that cannot
    /// catch is this copy and `c4`'s diverging from each other.
    fn normalise_for_scan(text: &str) -> String {
        text.to_ascii_lowercase().replace(['_', ' '], "")
    }

    /// The Actions-service call this design has no equivalent of, plus the
    /// shapes an implementer would invent in its place.
    ///
    /// Spelled in halves so that no needle ever appears whole in the text being
    /// scanned, and keyed to `fn`/`struct` so that the prose above may keep
    /// explaining why there is no reservation. `c4` records both trades at
    /// length; this list is its counterpart one layer up. Note that the
    /// allocation lock's own `fn acquire` is deliberately *not* matched: the
    /// needle is `acquire`-a-**job**, and a lock is not one.
    const FORBIDDEN: &[&str] = &[
        concat!("fn ", "acquire", "_job"),
        concat!("fn ", "claim", "_job"),
        concat!("fn ", "lease", "_job"),
        concat!("fn ", "reserve", "_job"),
        concat!("fn ", "ack", "nowledge"),
        concat!("struct ", "Job", "Lease"),
        concat!("struct ", "Job", "Claim"),
        concat!("struct ", "Job", "Reservation"),
    ];

    fn forbidden_shape_in(source: &str) -> Option<&'static str> {
        let haystack = normalise_for_scan(source);
        FORBIDDEN
            .iter()
            .copied()
            .find(|forbidden| haystack.contains(&normalise_for_scan(forbidden)))
    }

    /// `e1`'s Definition of Done: *"No reservation, claim, lease, or acquisition
    /// call exists in the crate; a test or review note records that this is
    /// deliberate rather than missing."*
    ///
    /// **Deliberate, not missing.** The scale-set model let a listener call
    /// `AcquireJobs` to claim an assignment before scaling; the REST path has no
    /// equivalent, so demand is advisory and two hosts serving the same labels
    /// can both start a runner for one queued run. Adding a local reservation
    /// table would not remove that — the other host cannot see it — it would
    /// only hide the surplus case from the tests that measure it. The three
    /// controls that actually bound it are host-scoped routing labels,
    /// `max_capacity`, and `host_capacity`, and the last two are enforced in
    /// this file.
    ///
    /// The scan is a tripwire on the obvious shape rather than a proof: a
    /// reservation reached through a trait method or a differently-named helper
    /// would walk past it. Review is the primary control, exactly as `c4` states
    /// for its own copy.
    ///
    /// # It scans the crate, because the bullet says "in the crate"
    ///
    /// It used to scan this file alone while quoting a crate-wide claim, which
    /// left `lifecycle.rs` — `e3`, the launcher, and by far the likeliest place
    /// for someone to "fix" the surplus-runner case with a local lease — covered
    /// by nothing. Reading another owner's file is not editing it, so ownership
    /// was never the obstacle.
    ///
    /// The walk below is `c4`'s, and it **recurses** for the reason `c4`
    /// records: a module directory (`src/reconcile/mod.rs`) arrives as an entry
    /// that does not end in `.rs`, so a flat filter drops it and takes every
    /// file underneath with it, leaving the scan passing over files it covers
    /// by nothing at all. The listed-versus-on-disk assertion is what stops
    /// `SOURCES` going stale the moment `e2` or `e3` adds a module.
    #[test]
    fn nothing_in_this_crate_reserves_or_claims_a_job() {
        const SOURCES: &[(&str, &str)] = &[
            ("lib.rs", include_str!("lib.rs")),
            ("lifecycle.rs", include_str!("lifecycle.rs")),
            ("package.rs", include_str!("package.rs")),
            ("reconcile.rs", include_str!("reconcile.rs")),
        ];

        fn walk(directory: &std::path::Path, prefix: &str, found: &mut Vec<String>) {
            for entry in std::fs::read_dir(directory).expect("the crate's own src/ is readable") {
                let entry = entry.expect("a readable directory entry");
                let name = entry.file_name().to_string_lossy().into_owned();
                // `/`-joined, which is what `include_str!` takes on every
                // platform, so the two sides compare directly.
                let joined = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                if entry.path().is_dir() {
                    walk(&entry.path(), &joined, found);
                } else if name.ends_with(".rs") {
                    found.push(joined);
                }
            }
        }

        let mut listed: Vec<&str> = SOURCES.iter().map(|(name, _)| *name).collect();
        listed.sort_unstable();
        let mut on_disk = Vec::new();
        walk(
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
            "",
            &mut on_disk,
        );
        on_disk.sort_unstable();
        assert_eq!(
            listed, on_disk,
            "a source file was added or removed; this scan claims to cover the whole crate \
             and a stale list makes that claim false"
        );

        for (name, source) in SOURCES {
            assert_eq!(
                forbidden_shape_in(&production_half_of(source)),
                None,
                "{name} names a forbidden shape: there is no `AcquireJobs` equivalent over \
                 REST, and a local lease coordinates this host with itself and with nothing \
                 else. If an owner decision restored one, that decision belongs in this \
                 module's documentation and in this test before it belongs in the code"
            );
        }

        // The control: the scan can see a shape when there is one, through the
        // same matcher the loop above uses.
        assert!(
            forbidden_shape_in("async fn acquire_jobs(&self) -> Vec<Job> { todo!() }").is_some(),
            "the scan above proves nothing if the needles no longer match"
        );
    }

    /// The other half of the owner decision this task implements: demand is a
    /// count of **runs**, and no label filtering happens anywhere on the path.
    ///
    /// `b1`'s `RoutingLabels::tally` is correct and nothing feeds it, and this
    /// module must not be what starts feeding it: doing so would need the
    /// per-run job listing the owner decision removed. `c4` carries the same
    /// scan over `crates/github/src/demand.rs`; this is its counterpart in the
    /// consumer, so that a label predicate cannot be reintroduced one layer up
    /// instead.
    #[test]
    fn this_module_owns_no_label_predicate() {
        let production = this_file_above_its_tests_without_prose();
        for owned_by_b1 in ["RoutingLabels", "DemandTally", "RunsOn"] {
            assert!(
                !production.contains(owned_by_b1),
                "the reconciliation loop names `{owned_by_b1}`, which belongs to `b1`: the \
                 demand gateway counts queued *runs* and applies no label filtering, and \
                 this module clamps that number directly. If the job listing was restored \
                 by a later owner decision, that decision belongs in this module's \
                 documentation and in this test before it belongs in the code"
            );
        }
    }

    #[test]
    fn the_accepted_over_count_is_bounded_by_the_two_ceilings_and_nothing_else() {
        // The owner decision accepts that a repository whose jobs only target
        // `ubuntu-latest` still drives its policy toward `max_capacity`. What
        // stops that being unbounded is exactly what stops any other demand
        // being unbounded, which is asserted here rather than assumed.
        let host = host_with(2);
        let policy = policy(1, "acme/app", 5);
        let attempts: Vec<RunnerAttempt> = Vec::new();
        let mut allocator = HostAllocator::from_attempts(&host, &attempts);

        let allocation = allocator.allocate(&policy, u32::MAX);
        assert_eq!(allocation.desired, 5, "max_capacity beats reported demand");
        assert_eq!(allocation.to_start, 2, "host_capacity beats max_capacity");
        assert_eq!(allocation.limiting_factor, LimitingFactor::HostCapacity);
    }
}
