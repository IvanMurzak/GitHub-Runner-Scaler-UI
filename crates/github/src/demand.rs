// owner: c4-demand-and-jit-gateway

//! How much work is waiting for a runner that does not exist yet.
//!
//! Demand is the number `e1` feeds to `clamp(demand, min_capacity,
//! max_capacity)`, so it is the number that decides how many runner processes
//! this host starts. Everything in this module exists to make that number
//! honest — and, where it cannot be, to make it *say* so rather than look
//! precise.
//!
//! ```text
//! GET /repos/{owner}/{repo}/actions/runs?status=queued&per_page=100
//! GET /repos/{owner}/{repo}/actions/runs?status=in_progress&per_page=100
//!   -> 200 { "total_count": N, "workflow_runs": [ { "id": … }, … ] }
//! GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs?filter=latest&per_page=100
//!   -> 200 { "total_count": M, "jobs": [ { "status": …, "labels": […] }, … ] }
//! ```
//!
//! # The counting unit is a **job**, and this reverses an earlier decision
//!
//! This is the single most important thing to know about this module, and it is
//! an owner decision that **replaced the opposite owner decision**. The history
//! is kept here rather than deleted, because the reasoning that produced the old
//! answer is still sound in the abstract and a later reader who only sees the
//! new code will otherwise re-derive it and revert this.
//!
//! **What the previous decision said.** `d18b-run-count-filtering.md` probed the
//! runs endpoint against live GitHub and established that its `total_count`
//! counts **workflow runs matching the query**. Counting runs costs exactly one
//! request per repository, a fixed figure the budget model
//! ([`crate::rest::TargetCost`], [`crate::rest::BudgetProjection`]) could price
//! and `f2`'s `add` refusals could be computed from. Resolving each queued run's
//! jobs costs one extra request *per run*, a variable cost scaling with queue
//! depth. The owner chose the fixed cost, accepted the resulting under-count,
//! and this module said at length: *do not "fix" this, and do not add a per-run
//! job listing*.
//!
//! **Why it was reversed.** A workflow run holds many jobs — a matrix, or a
//! `jobs:` map with several independent entries — and **each job needs its own
//! runner**. Under the run count, a single queued run holding eight jobs read as
//! demand `1`, `e1` started **one** runner, that runner took one job, and the
//! remaining seven queued behind it. The next poll saw the same run still
//! queued, still read `1`, and started one more. So a host configured for ten
//! concurrent runners served an eight-job matrix **serially, roughly one at a
//! time**, with the queue depth on GitHub growing while the machine sat idle.
//! The under-count was not a rounding error in the demand signal; on the
//! workflow shape people actually write, it was the difference between the
//! product's headline feature working and not working. That is a worse outcome
//! than a variable request cost, so the trade was re-made the other way.
//!
//! **What that means for a later reader.** The per-run job listing below is
//! deliberate and load-bearing. Removing it to restore a fixed per-repository
//! cost re-creates the serial-matrix defect described above. If a future owner
//! decision reverses this again, it belongs in this documentation and in
//! `tests::the_runs_on_predicate_is_b1s_and_this_module_only_feeds_it` before it
//! belongs in the code.
//!
//! # Both run statuses are polled, and the second one is not redundant
//!
//! `status=queued` alone is the obvious query and it is not sufficient. A run's
//! status is a property of the *run*, and a run holding both a running job and a
//! queued one has to report one value for both. Live observation on a repository
//! using this product caught a run of five jobs — two completed, one
//! `in_progress`, two `queued` — reporting `status: "queued"`, so `queued` does
//! take precedence over `in_progress` while any job is still waiting.
//!
//! That observation is what makes `status=queued` the *primary* signal, and it
//! is not what makes it sufficient. The case it does not cover is a job that
//! becomes queued **later**: `needs:` holds a job back until its dependency
//! finishes, and whether GitHub flips the run's status back to `queued` at that
//! moment is a claim about a state machine this project has not observed. A
//! `needs:`-gated job is an ordinary workflow shape, and missing one entirely
//! would be the same class of defect this module was just rewritten to fix.
//!
//! So `status=in_progress` is polled too, as a **safety net rather than a second
//! primary signal**, and it is budgeted like one: it is read after the queued
//! runs and gets the smaller of the two run caps
//! ([`MAX_IN_PROGRESS_RUNS_PER_REPOSITORY_PER_POLL`] against
//! [`MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL`]). A run appears in at most one of
//! the two lists — the queries are disjoint by construction — and only jobs
//! whose own `status` is `queued` are counted, so an in-progress run whose jobs
//! have all been dispatched contributes nothing but the request that discovered
//! that.
//!
//! `completed` and `waiting` runs are not polled. A completed run has no
//! dispatchable job left, and a `waiting` run is held by a deployment gate or a
//! concurrency group rather than by the absence of a runner — starting one for
//! it would produce a runner that idles until its timeout.
//!
//! # Routing labels ARE applied now, and the predicate is still `b1`'s
//!
//! The previous decision's second accepted cost was that **no routing-label
//! filtering happened at all**: a run carries no `runs-on`, labels live on jobs,
//! and this module fetched no jobs. Every queued run in a watched repository
//! counted, including runs whose jobs targeted `ubuntu-latest` or another host's
//! `rm-<host>-…` label, and each runner started that way idled until it timed
//! out.
//!
//! Fetching the jobs supplies the input that was missing, so that cost is paid
//! back by the same change. **This module still owns no predicate.** It reads
//! each job's `labels` array, builds a [`RunsOn`] from it, and hands that to the
//! caller. `b1` owns the matching
//! ([`runner_manager_domain::policy::RoutingLabels::matches`] and its `tally`),
//! `e1` owns applying it per policy, and
//! `tests::the_runs_on_predicate_is_b1s_and_this_module_only_feeds_it` scans
//! this file's own source to pin that no second implementation grows here.
//!
//! The filtering is deliberately **not** done in this module even though it now
//! has the input, and the reason is `e1`'s: one target can be watched by more
//! than one policy, each with its own routing labels, and `e1` polls a target
//! once for all of them. A gateway that filtered would have to be told whose
//! labels to filter by, which would make the poll per-policy and multiply its
//! request cost by the number of policies sharing the target. So the gateway
//! returns the jobs and each policy tallies them.
//!
//! # What is still approximate, stated plainly rather than left to be discovered
//!
//! * **A job listing is a snapshot.** A job that leaves the queue between the
//!   run list and the job list is counted; one that arrives after is not. The
//!   next poll corrects both, and `e1`'s per-policy `active_owned` term stops a
//!   job already being served from being served twice.
//! * **The run caps make a large queue a floor.** Past
//!   [`MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL`] the count is a *floor* rather
//!   than a total, reported through [`QueuedDemand::is_truncated`]. Scaling up
//!   from a floor is safe and successive polls converge; concluding "idle" from
//!   one is not, which is why the floor is expressible at all.
//! * **`runs-on` is not always resolvable.** `runs-on: ${{ matrix.runner }}` can
//!   only be evaluated by GitHub. `b1` reports those as
//!   [`runner_manager_domain::policy::UnresolvableRunsOn`] and they are neither
//!   counted as demand nor silently dropped.
//!
//! # There is no job reservation, and nothing here may pretend otherwise
//!
//! The scale-set model's `AcquireJobs` has no REST equivalent
//! (`d17-user-to-server-scale-set-chain.md`), so demand is **advisory**: another
//! host may take a job this host has already started a runner for
//! (`01-current-architecture.md`, edge case 6).
//!
//! **Do not add a claim, a lease, a local reservation table, or an
//! acknowledgement call to compensate.** No such call exists in this crate, and
//! `b1`'s, `e1`'s and this task's specifications all say so independently
//! because implementers keep reaching for one. The bounding controls are the
//! host-scoped labels in `b1` and the two capacity ceilings in `e1`; a local
//! lease would coordinate this host with itself and with nothing else, which is
//! the one thing the problem does not need.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use runner_manager_domain::{
    model::{Clock, OwnerRepo, TargetScope, Timestamp},
    policy::RunsOn,
};
use serde::Deserialize;

use crate::{
    ApiRequest, ApiResponse, AuthenticatedClient, GithubError,
    rest::{
        ActivityScope, CancelToken, InventoryError, PER_PAGE, RateLimited, TargetCost,
        UnavailableRepository,
    },
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The `status` filter that selects runs with a job that may still be waiting.
///
/// Stated as a constant rather than inlined because it is the whole difference
/// between this module and `c3`'s activity count, and a one-word typo here
/// produces a plausible-looking number rather than an error.
pub const QUEUED_RUN_STATUS: &str = "queued";

/// The `status` filter for the safety-net pass over runs already under way.
///
/// Not a second primary signal. The module documentation states what it covers
/// that [`QUEUED_RUN_STATUS`] does not — a `needs:`-gated job entering the queue
/// after its run has already started — and why the difference is not something
/// this project has observed its way out of needing.
pub const IN_PROGRESS_RUN_STATUS: &str = "in_progress";

/// The job `status` that means "waiting for a runner that does not exist yet".
///
/// This is the value the whole module reduces to. A job in any other state
/// either has a runner or has finished with one, and counting it would start a
/// runner for work already being done — the same mistake as reading `c3`'s
/// in-progress count as demand, one level down.
pub const QUEUED_JOB_STATUS: &str = "queued";

/// The `filter` for the jobs endpoint: the latest attempt of each job only.
///
/// The default is `latest`, and it is sent explicitly because the alternative,
/// `all`, returns every attempt of every re-run. Under `all` a job re-run three
/// times contributes three entries, and the two that are historical would be
/// counted as present demand.
pub const LATEST_JOBS_FILTER: &str = "latest";

/// Requests one demand poll costs, **per repository**, in steady state.
///
/// Four: the two run listings ([`QUEUED_RUN_STATUS`] and
/// [`IN_PROGRESS_RUN_STATUS`]), plus a job listing for each of the couple of
/// runs a repository has under way at any moment.
///
/// # Why this is a projection and not a measurement, and what bounds it
///
/// Under the previous owner decision this constant was `1` and it was exact: one
/// request per repository, always, because `total_count` on the runs query
/// answered the whole question. Counting jobs makes the cost depend on how many
/// runs are active, which is a number no constant can know. So this is the
/// steady-state figure the budget model prices, in the same spirit as
/// [`crate::rest::ACTIVITY_REQUESTS_PER_REPOSITORY_PER_REFRESH`], which is also
/// a best case with a documented worse one.
///
/// The **worst** case is `2 + MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL +
/// MAX_IN_PROGRESS_RUNS_PER_REPOSITORY_PER_POLL`, which is what
/// [`max_demand_requests_per_repository_per_poll`] returns, and it is bounded by
/// construction rather than by hope: the two caps are hard, and a repository
/// that reaches them says so through [`QueuedDemand::is_truncated`] rather than
/// spending more. [`crate::rest::BUDGET_SHARE_DIVISOR`] absorbs the gap between
/// the two figures — the projection is compared against half the documented
/// ceiling precisely so that the half nobody models has somewhere to go.
///
/// A repository is only at the worst case while it genuinely has that many runs
/// in flight, which is also exactly when spending requests to scale correctly is
/// worth more than saving them.
pub const DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL: u32 = 4;

/// The most `status=queued` runs one repository's job listing may resolve per
/// poll.
///
/// The primary signal gets the larger cap. Past it the reported count is a
/// **floor** rather than a total, which is safe in the direction that matters:
/// `e1` clamps demand to `max_capacity` and the host ceiling anyway, so a
/// repository with more than this many queued runs is one whose real demand
/// exceeds any realistic host's capacity — the allocation is already pinned at
/// the ceiling and a larger number would not change it. Successive polls resolve
/// the rest as the earlier runs drain.
pub const MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL: usize = 6;

/// The most `status=in_progress` runs one repository's job listing may resolve
/// per poll.
///
/// Smaller than [`MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL`] on purpose: this
/// pass exists to catch a `needs:`-gated job whose run has already started, and
/// on the overwhelmingly common shape it finds nothing and costs one request per
/// run to discover that. Giving the safety net the same budget as the primary
/// signal would double the worst case to buy a rarer case.
pub const MAX_IN_PROGRESS_RUNS_PER_REPOSITORY_PER_POLL: usize = 4;

/// The most pages of jobs one run's listing may walk.
///
/// A run's job count is bounded by GitHub's own matrix limit of 256, so two
/// pages at [`PER_PAGE`] cover every legal run with room to spare. The third is
/// there because a `Link: rel="next"` chain that does not terminate is a
/// runaway, and this walk is charged against a budget.
pub const MAX_JOB_PAGES_PER_RUN: usize = 3;

/// The ceiling on what one repository's demand poll may spend.
///
/// Stated as a function rather than a constant because it is the sum of three
/// constants and a reader checking the budget arithmetic should not have to
/// re-add them — and because `f1` and `f2` render the worst case beside the
/// projection.
#[must_use]
pub const fn max_demand_requests_per_repository_per_poll() -> u32 {
    // The two run listings, then one job listing per run each cap admits.
    2 + (MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL as u32)
        + (MAX_IN_PROGRESS_RUNS_PER_REPOSITORY_PER_POLL as u32)
}

// A poll that costs nothing is a poll that issued no request, and a budget line
// of zero would let `f2` admit an unbounded number of targets.
const _: () = assert!(
    DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL > 0,
    "a demand poll costs at least the requests that fetched the run lists"
);

// The projection has to sit inside the bound, or the bound is not a bound. This
// is a compile-time check rather than a test because the two numbers drifting
// apart is the defect itself rather than a symptom of one: a projection above
// the ceiling would have `f2` refuse configurations that cannot occur, and the
// arithmetic that produced it would look deliberate.
const _: () = assert!(
    DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL <= max_demand_requests_per_repository_per_poll(),
    "the projected demand cost must fit inside the worst case the caps allow"
);

// The projection must also cover the two run listings, which every poll issues
// unconditionally. A projection below that floor would under-price even a
// completely idle repository, which is the one case the model must get exactly
// right: it is what `f1`'s printed ceiling and `f2`'s `add` refusals are
// computed from.
const _: () = assert!(
    DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL >= 2,
    "every poll issues both run listings, so the projection cannot be below two"
);

// The safety net must not outgrow the signal it is backing up. If these ever
// invert, the cheaper `in_progress` pass would be resolving more runs than the
// `queued` pass that actually carries the demand.
const _: () = assert!(
    MAX_IN_PROGRESS_RUNS_PER_REPOSITORY_PER_POLL <= MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL,
    "the in-progress safety net may not be given a larger budget than the primary signal"
);

/// How far GitHub's `total_count` may exceed the single page it arrived with
/// before the disagreement stops being a race and starts being evidence.
///
/// `c3` states the reasoning in full at its own `MAX_BENIGN_TOTAL_COUNT_SKEW`,
/// which is private to `crates/github/src/rest.rs`; the value is repeated rather
/// than shared because this task does not own that file. The short form:
///
/// * A run leaving the queue between GitHub computing `total_count` and
///   serialising the page makes `total` exceed `listed` by a handful. That race
///   is documented and legitimate, and a debug build pointed at live GitHub is
///   the build most likely to meet it.
/// * The defect being hunted — `total_count` carrying the repository's
///   *unfiltered* lifetime total — is gross: thousands over a page of three.
///
/// # This is now a consistency check rather than a load-bearing one
///
/// Under the previous owner decision `total_count` **was** the demand number,
/// and being wrong about it started the wrong number of runners. It no longer
/// reaches `clamp()`: demand is counted from the jobs, and `total_count` is read
/// only to notice that a repository has more runs than the caps will resolve.
/// So the check stays — it is free, and `c3` reads the same envelope for a
/// dashboard number — but it is a `warn!` and no longer a `debug_assert!`.
/// Panicking a development build over a field the decision no longer depends on
/// would be a tripwire that cries wolf, and those get deleted.
const MAX_BENIGN_TOTAL_COUNT_SKEW: u64 = 16;

// A zero skew is `total == listed` again, which fires on a run leaving the queue
// mid-serialisation. At compile time rather than in a test because a test
// deriving its fixture from this constant moves with it and stays green at zero.
const _: () = assert!(
    MAX_BENIGN_TOTAL_COUNT_SKEW > 0,
    "a zero skew re-creates the check that trips on a run leaving the queue mid-serialisation"
);

// ---------------------------------------------------------------------------
// The demand reading
// ---------------------------------------------------------------------------

/// Queued **jobs**, per repository, each carrying the `runs-on` it requires.
///
/// **This is a count of jobs, not of runs, and it is not filtered by any
/// policy's routing labels — but it carries everything needed to filter it.**
/// Both facts are the module documentation's subject and are repeated on the
/// type because this is what a caller holds.
///
/// The unfiltered totals ([`QueuedDemand::total`],
/// [`QueuedDemand::for_repository`]) are the raw queue depth, which is what `g2`
/// renders for an operator: "what is waiting in this repository", independent of
/// which host could serve it. The number `e1` clamps is **not** either of those.
/// It comes from tallying [`QueuedDemand::jobs_for`] against one policy's
/// routing labels, and the difference between the two is exactly the jobs this
/// host cannot serve.
///
/// # A count can be short in two different ways, and both have to say so
///
/// A repository can fail to answer at all ([`QueuedDemand::unavailable`]), and a
/// repository can answer with a number that is only a **floor**
/// ([`QueuedDemand::truncated`]) — more runs were active than
/// [`MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL`] and
/// [`MAX_IN_PROGRESS_RUNS_PER_REPOSITORY_PER_POLL`] allow resolving, or one
/// run's job listing walked to [`MAX_JOB_PAGES_PER_RUN`].
/// [`QueuedDemand::is_complete`] is `false` for either.
///
/// The shape mirrors [`crate::rest::ActivityCount`] deliberately, down to the
/// method names, because `g2` renders the two side by side and a caller that has
/// learned one should not have to learn the other. They stay separate types for
/// the reason `c3` keeps the busy-runner count and the in-progress count apart:
/// a type that can hold either number is a type that will eventually add them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueuedDemand {
    per_repository: BTreeMap<OwnerRepo, Vec<RunsOn>>,
    unavailable: Vec<UnavailableRepository>,
    /// Repositories whose count is a floor rather than a total.
    truncated: BTreeSet<OwnerRepo>,
}

impl QueuedDemand {
    #[must_use]
    pub fn new(per_repository: BTreeMap<OwnerRepo, Vec<RunsOn>>) -> Self {
        Self {
            per_repository,
            unavailable: Vec::new(),
            truncated: BTreeSet::new(),
        }
    }

    /// One repository's queued jobs, for the repository-target case and for
    /// tests.
    #[must_use]
    pub fn of(repository: OwnerRepo, jobs: impl IntoIterator<Item = RunsOn>) -> Self {
        Self::new(BTreeMap::from([(
            repository,
            jobs.into_iter().collect::<Vec<_>>(),
        )]))
    }

    /// Record that `repository`'s count is a floor rather than a total.
    #[must_use]
    pub fn with_truncated(mut self, repository: OwnerRepo) -> Self {
        self.truncated.insert(repository);
        self
    }

    /// Record that `repository` could not be read at all, and why.
    ///
    /// Deliberately **not** the same as a count of zero: nothing was learned
    /// about it, and a zero would render a possibly-busy repository as idle.
    #[must_use]
    pub fn with_unavailable(mut self, repository: OwnerRepo, reason: impl Into<String>) -> Self {
        self.unavailable.push(UnavailableRepository {
            repository,
            reason: reason.into(),
        });
        self
    }

    /// Queued jobs across every repository that answered, **unfiltered**.
    ///
    /// The raw queue depth, not the demand any one policy should serve. See the
    /// type documentation for the distinction, which is the whole reason
    /// [`QueuedDemand::jobs`] exists beside this.
    ///
    /// Saturating rather than wrapping: a total wider than a `u32` is not a
    /// number to wrap around zero, and `u32::MAX` runners is refused by the
    /// capacity ceilings long before it means anything.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.per_repository.values().fold(0_u32, |sum, jobs| {
            sum.saturating_add(u32::try_from(jobs.len()).unwrap_or(u32::MAX))
        })
    }

    #[must_use]
    pub fn per_repository(&self) -> &BTreeMap<OwnerRepo, Vec<RunsOn>> {
        &self.per_repository
    }

    /// One repository's unfiltered count, or `None` when it did not answer.
    #[must_use]
    pub fn for_repository(&self, repository: &OwnerRepo) -> Option<u32> {
        self.per_repository
            .get(repository)
            .map(|jobs| u32::try_from(jobs.len()).unwrap_or(u32::MAX))
    }

    /// One repository's queued jobs, as the `runs-on` each requires.
    ///
    /// This is the input `b1`'s predicate was written for and never had. An
    /// empty slice for a repository that answered means it really is idle; a
    /// repository that did not answer is in [`QueuedDemand::unavailable`]
    /// instead, and the two must not be conflated.
    #[must_use]
    pub fn jobs_for(&self, repository: &OwnerRepo) -> &[RunsOn] {
        self.per_repository
            .get(repository)
            .map_or(&[], Vec::as_slice)
    }

    /// Every queued job across every repository that answered.
    ///
    /// What an organization target tallies, for the reason a repository target
    /// tallies [`QueuedDemand::jobs_for`]: one policy watching an organization
    /// serves any repository in it, so its demand is the whole scope's.
    pub fn jobs(&self) -> impl Iterator<Item = &RunsOn> {
        self.per_repository.values().flat_map(Vec::as_slice)
    }

    #[must_use]
    pub fn unavailable(&self) -> &[UnavailableRepository] {
        &self.unavailable
    }

    #[must_use]
    pub fn truncated(&self) -> &BTreeSet<OwnerRepo> {
        &self.truncated
    }

    #[must_use]
    pub fn is_truncated(&self, repository: &OwnerRepo) -> bool {
        self.truncated.contains(repository)
    }

    /// Whether every repository in scope answered with an exact count.
    ///
    /// `false` means the total is a **floor**. Scaling *up* from a floor is
    /// safe; concluding "idle" from one is not, which is the mistake this exists
    /// to make expressible.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unavailable.is_empty() && self.truncated.is_empty()
    }
}

/// Requests one demand poll over `scope` costs, in steady state.
///
/// Grows with the repository count, because there is no organization-wide
/// workflow-runs endpoint and an organization therefore pays per repository the
/// App is installed on. That growth *is* the product constraint after D4: every
/// added repository multiplies this policy's share of the shared hourly ceiling.
#[must_use]
pub fn demand_requests_per_poll(scope: &ActivityScope) -> u32 {
    u32::try_from(scope.repositories().len())
        .unwrap_or(u32::MAX)
        .saturating_mul(DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL)
}

/// The most requests one demand poll over `scope` may spend.
///
/// The companion to [`demand_requests_per_poll`], and the number a reader should
/// be shown when they ask why a busy hour cost more than the projection. See
/// [`DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL`] for why the model prices the
/// steady state and bounds the peak rather than trying to price the peak.
#[must_use]
pub fn max_demand_requests_per_poll(scope: &ActivityScope) -> u32 {
    u32::try_from(scope.repositories().len())
        .unwrap_or(u32::MAX)
        .saturating_mul(max_demand_requests_per_repository_per_poll())
}

/// `scope`'s budget cost with this module's demand figure substituted for
/// `c3`'s estimate.
///
/// This is the reporting seam `c4`'s specification requires — "report the
/// per-poll request count to `c3`'s budget model rather than estimating it
/// there" — and [`TargetCost::with_demand_requests_per_repository`] is where
/// `c3` left it open. Callers that project a budget (`f1`'s `host show`, `f2`'s
/// `repo add` and `org add`, `g3`'s settings) should build their
/// [`TargetCost`] through this function rather than through
/// [`TargetCost::from_activity_scope`] directly.
#[must_use]
pub fn target_cost(scope: &ActivityScope) -> TargetCost {
    TargetCost::from_activity_scope(scope)
        .with_demand_requests_per_repository(DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL)
}

// ---------------------------------------------------------------------------
// The gateway
// ---------------------------------------------------------------------------

/// The demand read model.
///
/// A trait for [`crate::rest::InventoryGateway`]'s reason: `e1` and `g2` are
/// tested against `runner_manager_testkit::github::FakeGithub` with no network
/// and no `wiremock` in their dependency graphs. [`RestDemand`] is the one
/// implementation that talks to GitHub.
///
/// # Why the scope type is `c3`'s `ActivityScope` and not a new one
///
/// The name says "activity" and this is demand, so the reuse is worth
/// justifying rather than leaving to look like an oversight.
///
/// [`ActivityScope`] is not a description of the in-progress count; it is the
/// answer to "which repositories does one per-repository workflow-runs
/// aggregate cover", and demand asks that question with exactly the same
/// answer. Both hit `/repos/{o}/{r}/actions/runs`, both have no
/// organization-wide form, and both take the repository list from the same
/// caller-held set — `c3` documents that the list "has to come from the caller,
/// \[because\] `f1` and `e1` already hold it, from
/// [`crate::AuthenticatedClient::discover_installations`], and re-discovering it
/// on every refresh would cost more requests than the count itself".
///
/// A `DemandScope` beside it would be that type with a different name, and the
/// cost of the duplicate is concrete rather than aesthetic: `e1` polls both read
/// models in one refresh, and two scope types are two chances for them to
/// disagree about which repositories are in scope — which would make the demand
/// total and the activity total describe different sets while being rendered
/// side by side. What is *not* shared is the cost function:
/// [`ActivityScope::requests_per_refresh`] prices the activity count, and
/// [`demand_requests_per_poll`] prices this one, because those really are two
/// different numbers.
#[async_trait::async_trait]
pub trait DemandGateway: fmt::Debug + Send + Sync {
    /// Queued workflow runs across `scope`.
    ///
    /// # Errors
    /// Every variant of [`InventoryError`].
    async fn queued_demand(
        &self,
        scope: &ActivityScope,
        cancel: &CancelToken,
    ) -> Result<QueuedDemand, InventoryError>;

    /// The instant a reading is stamped with.
    fn now(&self) -> Timestamp;
}

/// [`DemandGateway`] over `api.github.com`.
///
/// Holds no credential of its own: authentication is entirely
/// [`AuthenticatedClient`]'s, and this type only ever hands it an
/// [`ApiRequest`].
///
/// # Why this is not a method on `c3`'s `RestInventory`
///
/// It would be the better shape, and it is not available. `RestInventory::get`
/// — the one place cancellation, request accounting and the rate-limit gate meet
/// — is private to `crates/github/src/rest.rs`, and a sibling module cannot
/// reach a private item. Making it `pub(crate)` is an edit to `c3`'s file, which
/// this task does not own, so the choice was between duplicating `c3`'s whole
/// rate-limit *policy* here and consuming what `c3` already exports. This
/// consumes.
///
/// # What "consuming `c3`'s rate-limit policy" means precisely
///
/// [`RateLimited::detect`] is `c3`'s decision procedure for whether a failure is
/// a rate limit and which of GitHub's two it is, including the part that keeps a
/// permissions `403` landing on an exhausted quota from being misreported as
/// one. It is public, and this module calls it rather than re-deciding.
///
/// What this module deliberately does **not** copy is `c3`'s in-gateway
/// *back-off latch*, the window during which `RestInventory` opens no socket at
/// all. A second latch would be a second, quietly divergent copy of a policy
/// that only works if there is one of it. The scheduling floor is
/// [`crate::rest::RefreshState::retry_delay`], which `c3` documents as "the
/// **absolute floor** on when `e1` may try again" — an `e1` honouring it stops
/// demand polling for the same window, from the layer that owns the schedule.
///
/// The residual gap is stated rather than hidden: a rate limit whose *first*
/// evidence arrives on a demand request does not silence `RestInventory`, and
/// vice versa. Both report [`InventoryError::RateLimited`] to `e1`, which is the
/// layer that can act on either.
pub struct RestDemand {
    client: Arc<AuthenticatedClient>,
    clock: Arc<dyn Clock>,
    requests_issued: AtomicU64,
}

impl fmt::Debug for RestDemand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written for the reason `AuthenticatedClient`'s own `Debug`
        // records: nothing here may render a credential, and a derive on a type
        // holding a client is how that is lost.
        f.debug_struct("RestDemand")
            .field(
                "requests_issued",
                &self.requests_issued.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl RestDemand {
    #[must_use]
    pub fn new(client: Arc<AuthenticatedClient>, clock: Arc<dyn Clock>) -> Self {
        Self {
            client,
            clock,
            requests_issued: AtomicU64::new(0),
        }
    }

    /// How many HTTP requests this gateway has issued.
    ///
    /// [`demand_requests_per_poll`] projects a cost and this measures it. A
    /// projection nothing measures is a table in a document, which is why `c3`
    /// exposes the same counter and why the tests below assert one against the
    /// other.
    #[must_use]
    pub fn requests_issued(&self) -> u64 {
        self.requests_issued.load(Ordering::SeqCst)
    }

    /// One request, with cancellation applied and a rate limit recognised.
    ///
    /// Cancellation is consulted twice for `c3`'s reason, and the two are not
    /// redundant: [`CancelToken::check`] stops a multi-page walk *between*
    /// pages, and [`CancelToken::run`] stops one already blocked on a socket.
    async fn get(
        &self,
        request: &ApiRequest,
        cancel: &CancelToken,
    ) -> Result<ApiResponse, InventoryError> {
        cancel.check()?;

        let result = cancel
            .run(async {
                // Counted inside the future, so the count is of requests
                // actually attempted: `run`'s biased `select!` answers
                // `Cancelled` without polling this block when the token is
                // already flipped, and no socket is opened.
                self.requests_issued.fetch_add(1, Ordering::SeqCst);
                self.client
                    .send(request)
                    .await
                    .map_err(InventoryError::from)
            })
            .await;

        match result {
            Ok(response) => Ok(response),
            Err(InventoryError::Github(error)) => Err(Self::classify(error)),
            Err(other) => Err(other),
        }
    }

    /// Turn a failure into a rate limit when GitHub's own evidence says it is
    /// one, using `c3`'s decision procedure rather than a second one.
    fn classify(error: GithubError) -> InventoryError {
        let Some(limit) = RateLimited::detect(&error) else {
            return InventoryError::Github(error);
        };
        tracing::warn!(
            kind = %limit.kind,
            remaining = limit.remaining,
            "GitHub is rate limiting this credential; demand for this poll is unknown, not zero"
        );
        InventoryError::RateLimited(limit)
    }

    /// Queued **jobs** for one repository, each with the `runs-on` it requires.
    ///
    /// Two run listings, then one job listing per run either cap admits. See
    /// [`DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL`] for what that costs in steady
    /// state and [`max_demand_requests_per_repository_per_poll`] for the bound.
    ///
    /// # The order of the two passes is load-bearing
    ///
    /// Queued runs are resolved first and in-progress runs second, because the
    /// caps are spent in that order and the first pass carries the signal. A
    /// repository busy enough to exhaust the queued cap gets no in-progress pass
    /// at all, which is the right trade: its count is already a floor above any
    /// realistic host ceiling, and one more `needs:`-gated job cannot change the
    /// allocation.
    async fn repository_queued(
        &self,
        repository: &OwnerRepo,
        cancel: &CancelToken,
    ) -> Result<RepositoryDemand, InventoryError> {
        let mut jobs: Vec<RunsOn> = Vec::new();
        let mut exact = true;

        for (status, cap) in [
            (QUEUED_RUN_STATUS, MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL),
            (
                IN_PROGRESS_RUN_STATUS,
                MAX_IN_PROGRESS_RUNS_PER_REPOSITORY_PER_POLL,
            ),
        ] {
            let listing = self.active_runs(repository, status, cap, cancel).await?;
            exact &= listing.complete;

            for run_id in listing.run_ids {
                let run = self.queued_jobs_of_run(repository, run_id, cancel).await?;
                exact &= run.complete;
                jobs.extend(run.jobs);
            }
        }

        Ok(RepositoryDemand { jobs, exact })
    }

    /// The ids of one repository's runs in `status`, up to `cap`.
    ///
    /// **One request, never a page walk.** Both caps are far below [`PER_PAGE`],
    /// so the first page always carries more run ids than this may use, and a
    /// second page could only contain runs that are already past the cap. That
    /// is the whole reason the caps are stated in *runs* rather than in pages:
    /// it turns the run listing back into the fixed one-request cost the
    /// previous owner decision valued, and spends the variable cost only where
    /// it buys the job-level count.
    async fn active_runs(
        &self,
        repository: &OwnerRepo,
        status: &str,
        cap: usize,
        cancel: &CancelToken,
    ) -> Result<RunListing, InventoryError> {
        let request = ApiRequest::get(format!(
            "/repos/{}/{}/actions/runs",
            repository.owner(),
            repository.repo()
        ))
        .query("status", status)
        .query("per_page", PER_PAGE);

        let response = self.get(&request, cancel).await?;
        let has_next_page = response.next_page().is_some();
        let page: QueuedRunsPage = response.json()?;

        let listed = page.workflow_runs.len();
        if let Some(total) = page.total_count
            && !has_next_page
            && total != listed as u64
        {
            // Free, and no longer load-bearing: see `MAX_BENIGN_TOTAL_COUNT_SKEW`
            // for why this is a `warn!` and not the `debug_assert!` it was while
            // `total_count` *was* the demand number.
            let gross = total > (listed as u64).saturating_add(MAX_BENIGN_TOTAL_COUNT_SKEW);
            tracing::warn!(
                repository = %repository,
                status,
                total_count = total,
                listed,
                gross,
                "GitHub's `total_count` disagrees with the single page it sent for a \
                 filtered query; demand is counted from the jobs and does not depend on \
                 this field, but a gross disagreement means it is not the filtered count"
            );
        }

        let run_ids: Vec<u64> = page
            .workflow_runs
            .iter()
            .take(cap)
            .map(|run| run.id)
            .collect();

        Ok(RunListing {
            // More runs exist than this pass will resolve, so the job count it
            // produces is a floor. Both conditions matter: `listed > cap` is the
            // ordinary case, and `has_next_page` catches a repository whose
            // first page was itself short of the whole filtered set.
            complete: listed <= cap && !has_next_page,
            run_ids,
        })
    }

    /// One run's jobs that are still waiting for a runner.
    ///
    /// Jobs in any other state are dropped here rather than downstream, because
    /// "queued" is what makes a job demand and a caller holding a mixed list
    /// would have to re-derive that. The `runs-on` is rebuilt from the job's
    /// `labels` array — which is the array form, so [`RunsOn::from_job_labels`]
    /// is the constructor `b1` provides for exactly this.
    async fn queued_jobs_of_run(
        &self,
        repository: &OwnerRepo,
        run_id: u64,
        cancel: &CancelToken,
    ) -> Result<RunJobs, InventoryError> {
        let mut request = Some(
            ApiRequest::get(format!(
                "/repos/{}/{}/actions/runs/{run_id}/jobs",
                repository.owner(),
                repository.repo()
            ))
            .query("filter", LATEST_JOBS_FILTER)
            .query("per_page", PER_PAGE),
        );

        let mut jobs = Vec::new();
        let mut pages = 0_usize;

        while let Some(next) = request.take() {
            if pages >= MAX_JOB_PAGES_PER_RUN {
                tracing::warn!(
                    repository = %repository,
                    run_id,
                    pages,
                    "stopped listing one run's jobs at the page budget; the queued-job \
                     count for this repository is a floor, not a total"
                );
                return Ok(RunJobs {
                    jobs,
                    complete: false,
                });
            }

            let response = self.get(&next, cancel).await?;
            let following = response
                .next_page()
                .map(|url| ApiRequest::get(url.as_str()));
            let page: RunJobsPage = response.json()?;
            pages += 1;

            jobs.extend(
                page.jobs
                    .into_iter()
                    .filter(|job| job.status == QUEUED_JOB_STATUS)
                    .map(|job| RunsOn::from_job_labels(job.labels)),
            );

            request = following;
        }

        Ok(RunJobs {
            jobs,
            complete: true,
        })
    }
}

/// Whether a per-repository failure should be recorded and stepped over, or
/// should abort the whole aggregate.
///
/// The same line `c3` draws in its private `is_repository_local_failure`, and
/// repeated here rather than shared because that function lives in a file this
/// task does not own. The line is between a fact about *that repository* — a
/// `404` for one deleted or renamed, a plain `403` for one with Actions disabled
/// — and a fact about the credential or the connection, which stepping over
/// would turn into a total short by an unknown amount while looking complete.
///
/// It applies to an aggregate only. Stepping over the only repository in scope
/// would turn a permissions failure into demand `0`, and `e1` would then read
/// "nothing queued" for a target it cannot see at all — so the caller checks
/// [`TargetScope`] first.
fn is_repository_local_failure(error: &InventoryError) -> bool {
    match error {
        InventoryError::Github(GithubError::Forbidden { .. }) => true,
        InventoryError::Github(GithubError::Status { status, .. }) => *status == 404,
        _ => false,
    }
}

#[async_trait::async_trait]
impl DemandGateway for RestDemand {
    async fn queued_demand(
        &self,
        scope: &ActivityScope,
        cancel: &CancelToken,
    ) -> Result<QueuedDemand, InventoryError> {
        let mut demand = QueuedDemand::default();
        // Only an aggregate steps over a bad repository; see
        // `is_repository_local_failure`.
        let aggregating = scope.target().scope() == TargetScope::Organization;

        for repository in scope.repositories() {
            match self.repository_queued(repository, cancel).await {
                Ok(reading) => {
                    demand
                        .per_repository
                        .insert(repository.clone(), reading.jobs);
                    if !reading.exact {
                        // A floor travels with the aggregate rather than being
                        // flattened into it: one truncated repository makes the
                        // total a floor too, and nothing downstream has another
                        // way to know.
                        demand.truncated.insert(repository.clone());
                    }
                }
                Err(error) if aggregating && is_repository_local_failure(&error) => {
                    tracing::warn!(
                        repository = %repository,
                        error = %error,
                        "a repository in this organization could not be polled for demand; \
                         the aggregate reports it as unavailable rather than as zero"
                    );
                    demand.unavailable.push(UnavailableRepository {
                        repository: repository.clone(),
                        reason: error.to_string(),
                    });
                }
                Err(error) => return Err(error),
            }
        }

        Ok(demand)
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

/// One repository's queued jobs, and whether that set is the whole truth.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RepositoryDemand {
    /// The `runs-on` of every job still waiting for a runner.
    jobs: Vec<RunsOn>,
    /// `false` when `jobs` is a **floor**: a run cap or a job page budget
    /// stopped the walk before the whole queue had been seen.
    exact: bool,
}

/// One run listing's ids, and whether the cap left any behind.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunListing {
    run_ids: Vec<u64>,
    complete: bool,
}

/// One run's queued jobs, and whether the page budget saw all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunJobs {
    jobs: Vec<RunsOn>,
    complete: bool,
}

/// One page of `GET …/actions/runs?status=…`.
///
/// Only the `id` is read, and it is read because the job listing needs it. That
/// is the field the previous owner decision deliberately did not have — the
/// module documentation used to point at `jobs_url` and ask nobody to follow it
/// — and reversing that decision is what put it here.
#[derive(Debug, Deserialize)]
struct QueuedRunsPage {
    total_count: Option<u64>,
    #[serde(default)]
    workflow_runs: Vec<QueuedRun>,
}

/// One workflow run, reduced to the identifier its jobs are fetched by.
#[derive(Debug, Deserialize)]
struct QueuedRun {
    id: u64,
}

/// One page of `GET …/actions/runs/{run_id}/jobs`.
#[derive(Debug, Deserialize)]
struct RunJobsPage {
    #[serde(default)]
    jobs: Vec<RunJob>,
}

/// One job of a run: whether it is still waiting, and what it needs.
///
/// `labels` is GitHub's flat array form of `runs-on`, which is why
/// [`RunsOn::from_job_labels`] exists on `b1`'s side. It defaults to empty
/// rather than being required, because a job with no labels is a real answer —
/// `b1` reports it as [`runner_manager_domain::policy::UnresolvableRunsOn`] —
/// and a missing field should not fail the whole repository's poll.
#[derive(Debug, Deserialize)]
struct RunJob {
    #[serde(default)]
    status: String,
    #[serde(default)]
    labels: Vec<String>,
}

// The unit tests below are inline rather than in a `src/demand/tests.rs`, and
// that is a constraint rather than a preference: `lib.rs`'s
// `the_confidential_credential_scan_covers_every_source_file` walks `src/`
// recursively and requires every `.rs` file under it to appear in
// `CRATE_SOURCES` — a list in `lib.rs`, which `c2` owns. A second file in this
// directory would fail that pin, and the only fix would be editing another
// task's file.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FIXTURE_TOKEN, TestClock};
    use crate::{Endpoints, UserAccessToken};
    use runner_manager_domain::{
        model::{Arch, HostLabel, Label, Org, Os},
        policy::{RoutingLabels, RunsOn, RunsOnMatch, UnresolvableRunsOn},
    };
    use secrecy::SecretString;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    fn repo() -> OwnerRepo {
        OwnerRepo::parse("octo/dashboard").expect("a valid owner/repo")
    }

    fn other_repo() -> OwnerRepo {
        OwnerRepo::parse("octo/api").expect("a valid owner/repo")
    }

    fn third_repo() -> OwnerRepo {
        OwnerRepo::parse("octo/tools").expect("a valid owner/repo")
    }

    fn org_scope(repositories: impl IntoIterator<Item = OwnerRepo>) -> ActivityScope {
        ActivityScope::organization(
            Org::new("octo-org").expect("a valid organization login"),
            repositories,
        )
    }

    fn gateway(server: &MockServer) -> RestDemand {
        let endpoints = Endpoints::for_test_server(&server.uri()).expect("a test server base");
        let token = UserAccessToken::from_stored(SecretString::from(FIXTURE_TOKEN));
        let client = AuthenticatedClient::new(endpoints, token, Arc::new(TestClock::default()))
            .expect("a client over the test server");
        RestDemand::new(Arc::new(client), Arc::new(TestClock::default()))
    }

    // -- fixtures -----------------------------------------------------------

    /// A run list carrying `ids`, and a `total_count` that agrees with it.
    fn runs_body(ids: &[u64]) -> serde_json::Value {
        json!({
            "total_count": ids.len(),
            "workflow_runs": ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>()
        })
    }

    /// An empty run list, which is what an idle repository answers.
    fn no_runs() -> serde_json::Value {
        runs_body(&[])
    }

    /// A jobs page: `queued` jobs carrying `labels`, then `running` that do not
    /// count.
    fn jobs_body(labels: &[&str], queued: usize, running: usize) -> serde_json::Value {
        let mut jobs = Vec::new();
        for _ in 0..queued {
            jobs.push(json!({ "status": "queued", "labels": labels }));
        }
        for _ in 0..running {
            jobs.push(json!({ "status": "in_progress", "labels": labels }));
        }
        json!({ "total_count": jobs.len(), "jobs": jobs })
    }

    fn runs_path(repository: &OwnerRepo) -> String {
        format!(
            "/repos/{}/{}/actions/runs",
            repository.owner(),
            repository.repo()
        )
    }

    fn jobs_path(repository: &OwnerRepo, run_id: u64) -> String {
        format!("{}/{run_id}/jobs", runs_path(repository))
    }

    /// Mount one repository's run list for one status filter.
    async fn mount_runs(
        server: &MockServer,
        repository: &OwnerRepo,
        status: &str,
        body: serde_json::Value,
    ) {
        Mock::given(method("GET"))
            .and(path(runs_path(repository)))
            .and(query_param("status", status))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    /// Mount one run's job list.
    async fn mount_jobs(
        server: &MockServer,
        repository: &OwnerRepo,
        run_id: u64,
        body: serde_json::Value,
    ) {
        Mock::given(method("GET"))
            .and(path(jobs_path(repository, run_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    /// The ordinary shape: one queued run of `queued` + `running` jobs, and an
    /// empty in-progress list.
    async fn mount_one_queued_run(
        server: &MockServer,
        repository: &OwnerRepo,
        labels: &[&str],
        queued: usize,
        running: usize,
    ) {
        mount_runs(server, repository, QUEUED_RUN_STATUS, runs_body(&[100])).await;
        mount_runs(server, repository, IN_PROGRESS_RUN_STATUS, no_runs()).await;
        mount_jobs(server, repository, 100, jobs_body(labels, queued, running)).await;
    }

    /// A repository with nothing waiting: two run listings, no job listings.
    async fn mount_idle(server: &MockServer, repository: &OwnerRepo) {
        mount_runs(server, repository, QUEUED_RUN_STATUS, no_runs()).await;
        mount_runs(server, repository, IN_PROGRESS_RUN_STATUS, no_runs()).await;
    }

    /// The routing labels of a realistic policy on this host.
    ///
    /// Deliberately **not** a bare [`RoutingLabels::derive`]. That produces the
    /// derived host label alone, and a job written `runs-on: [self-hosted,
    /// windows]` — the shape people actually write — requires labels a bare
    /// derived set does not carry, so it would not match. An operator adds those
    /// with `repo add --label`, and a fixture that skipped them would test the
    /// filtering against a policy nobody configures.
    fn host_labels() -> RoutingLabels {
        RoutingLabels::from_parts(
            Label::new("rm-home-win-x64").expect("a valid label"),
            [
                Label::new("self-hosted").expect("a valid label"),
                Label::new("windows").expect("a valid label"),
            ],
        )
    }

    // -- the count itself ---------------------------------------------------

    /// The defect this module was rewritten for, as an executable statement.
    ///
    /// One queued run holding eight matrix jobs. Under the previous owner
    /// decision this repository reported demand `1`, `e1` started one runner,
    /// and the other seven jobs waited for a machine that was sitting idle. It
    /// must now report `8`.
    #[tokio::test]
    async fn a_matrix_run_of_eight_jobs_is_eight_units_of_demand_and_not_one() {
        let server = MockServer::start().await;
        mount_one_queued_run(&server, &repo(), &["rm-home-win-x64"], 8, 0).await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a queued-job count");

        assert_eq!(
            demand.total(),
            8,
            "eight jobs in one run are eight runners' worth of work; reading the run \
             count here is the defect that forced the owner decision back"
        );
        assert_eq!(demand.for_repository(&repo()), Some(8));
        assert!(demand.is_complete());
        assert_eq!(
            gateway.requests_issued(),
            3,
            "two run listings and one job listing for the single active run"
        );
    }

    /// A job that already has a runner is not demand.
    ///
    /// The run-level mistake one level down: `status=in_progress` work already
    /// has a runner, and counting it would start a second for the same job.
    #[tokio::test]
    async fn only_jobs_still_queued_are_counted() {
        let server = MockServer::start().await;
        mount_one_queued_run(&server, &repo(), &["rm-home-win-x64"], 3, 5).await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a queued-job count");

        assert_eq!(
            demand.total(),
            3,
            "five of the eight jobs already have a runner and are not waiting for one"
        );
    }

    /// The labels travel with the job, which is the input `b1`'s predicate never
    /// had.
    #[tokio::test]
    async fn each_queued_job_carries_the_runs_on_it_requires() {
        let server = MockServer::start().await;
        mount_runs(&server, &repo(), QUEUED_RUN_STATUS, runs_body(&[100, 101])).await;
        mount_runs(&server, &repo(), IN_PROGRESS_RUN_STATUS, no_runs()).await;
        mount_jobs(
            &server,
            &repo(),
            100,
            jobs_body(&["self-hosted", "windows"], 2, 0),
        )
        .await;
        mount_jobs(&server, &repo(), 101, jobs_body(&["ubuntu-latest"], 4, 0)).await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a queued-job count");

        assert_eq!(
            demand.total(),
            6,
            "the unfiltered depth is every queued job"
        );

        // And the number `e1` clamps, which is the unfiltered depth put through
        // `b1`'s predicate. This gateway does not compute it; it supplies it.
        let tally = host_labels().tally(demand.jobs_for(&repo()));
        assert_eq!(
            tally.demand(),
            2,
            "the four `ubuntu-latest` jobs are somebody else's work; before the job \
             listing existed all six would have driven this policy toward max_capacity"
        );
        assert_eq!(tally.not_matched, 4);
    }

    /// The two run statuses are both on the wire, and the job filter with them.
    ///
    /// The queries are one word apart and answer different questions, so a
    /// gateway that sent the wrong one would return a plausible number. The
    /// mocks match on the exact status, so sending anything else 404s here
    /// rather than passing.
    #[tokio::test]
    async fn both_run_statuses_are_polled_and_the_jobs_request_asks_for_the_latest_attempt() {
        let server = MockServer::start().await;
        mount_one_queued_run(&server, &repo(), &["rm-home-win-x64"], 1, 0).await;
        let gateway = gateway(&server);

        gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("both filters are mounted");

        let requests = server.received_requests().await.expect("recorded requests");
        assert_eq!(requests.len(), 3);

        let queries: Vec<String> = requests
            .iter()
            .map(|r| r.url.query().unwrap_or_default().to_string())
            .collect();

        assert!(
            queries.iter().any(|q| q.contains("status=queued")),
            "the primary signal is the queued run list; sent {queries:?}"
        );
        assert!(
            queries.iter().any(|q| q.contains("status=in_progress")),
            "the safety net catches a `needs:`-gated job whose run has already \
             started; sent {queries:?}"
        );
        assert!(
            queries
                .iter()
                .any(|q| q.contains(&format!("filter={LATEST_JOBS_FILTER}"))),
            "`filter=all` would count every attempt of a re-run job as present \
             demand; sent {queries:?}"
        );
        assert!(
            queries
                .iter()
                .all(|q| q.contains(&format!("per_page={PER_PAGE}"))),
            "asking for fewer than GitHub's maximum multiplies the request count \
             against the budget this module projects; sent {queries:?}"
        );
    }

    /// The queued run list is read before the in-progress one.
    ///
    /// The order is what spends the caps on the signal rather than on the safety
    /// net, and it is the kind of thing that is only true until somebody
    /// reorders a literal.
    #[tokio::test]
    async fn the_queued_run_list_is_read_before_the_in_progress_one() {
        let server = MockServer::start().await;
        mount_idle(&server, &repo()).await;
        let gateway = gateway(&server);

        gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("an idle repository still answers");

        let requests = server.received_requests().await.expect("recorded requests");
        let queries: Vec<String> = requests
            .iter()
            .map(|r| r.url.query().unwrap_or_default().to_string())
            .collect();
        assert_eq!(queries.len(), 2, "an idle repository lists no run's jobs");
        assert!(
            queries[0].contains("status=queued"),
            "the primary signal is read first; sent {queries:?}"
        );
        assert!(
            queries[1].contains("status=in_progress"),
            "the safety net is read second; sent {queries:?}"
        );
    }

    /// An idle repository costs the two listings and nothing more.
    ///
    /// The steady-state figure the budget model prices, asserted against what
    /// the gateway really spends rather than left as a claim in a doc comment.
    #[tokio::test]
    async fn an_idle_repository_costs_only_the_two_run_listings() {
        let server = MockServer::start().await;
        mount_idle(&server, &repo()).await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("an idle repository answers zero rather than failing");

        assert_eq!(demand.total(), 0);
        assert!(
            demand.is_complete(),
            "zero from a repository that answered is a measurement, not a floor"
        );
        assert_eq!(gateway.requests_issued(), 2);
        assert!(
            gateway.requests_issued() <= u64::from(DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL),
            "the idle case must sit inside the projection, which is the number `f2`'s \
             refusals are computed from"
        );
    }

    /// A run whose jobs have all been dispatched is found and costs one request.
    ///
    /// The safety net's ordinary outcome, and the reason it is capped lower than
    /// the primary signal: on the common shape it finds nothing.
    #[tokio::test]
    async fn an_in_progress_run_with_no_queued_job_contributes_only_its_request() {
        let server = MockServer::start().await;
        mount_runs(&server, &repo(), QUEUED_RUN_STATUS, no_runs()).await;
        mount_runs(&server, &repo(), IN_PROGRESS_RUN_STATUS, runs_body(&[200])).await;
        mount_jobs(&server, &repo(), 200, jobs_body(&["rm-home-win-x64"], 0, 4)).await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a queued-job count");

        assert_eq!(demand.total(), 0);
        assert!(demand.is_complete());
        assert_eq!(gateway.requests_issued(), 3);
    }

    /// A `needs:`-gated job whose run has already started is still demand.
    ///
    /// This is the whole reason the in-progress pass exists. Live sampling of a
    /// repository using this product never caught GitHub reporting a run as
    /// `in_progress` while one of its jobs was queued — 44 samples, 25 of them
    /// with a queued job — so the primary signal covers everything that was
    /// observed. It does not cover a job that becomes queued *after* its run
    /// started, which is what `needs:` produces and what this pins.
    #[tokio::test]
    async fn a_job_that_enters_the_queue_after_its_run_started_is_still_found() {
        let server = MockServer::start().await;
        mount_runs(&server, &repo(), QUEUED_RUN_STATUS, no_runs()).await;
        mount_runs(&server, &repo(), IN_PROGRESS_RUN_STATUS, runs_body(&[200])).await;
        // One job running, one released by `needs:` and now waiting.
        mount_jobs(&server, &repo(), 200, jobs_body(&["rm-home-win-x64"], 1, 1)).await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a queued-job count");

        assert_eq!(
            demand.total(),
            1,
            "polling only `status=queued` runs would report zero here and the \
             `needs:`-gated job would wait for a machine that is idle"
        );
    }

    // -- the caps -----------------------------------------------------------

    /// More queued runs than the cap resolves makes the answer a floor.
    #[tokio::test]
    async fn more_queued_runs_than_the_cap_report_a_floor_rather_than_a_total() {
        let server = MockServer::start().await;
        let ids: Vec<u64> = (0..(MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL as u64 + 4))
            .map(|i| 100 + i)
            .collect();
        mount_runs(&server, &repo(), QUEUED_RUN_STATUS, runs_body(&ids)).await;
        mount_runs(&server, &repo(), IN_PROGRESS_RUN_STATUS, no_runs()).await;
        for id in &ids {
            mount_jobs(&server, &repo(), *id, jobs_body(&["rm-home-win-x64"], 1, 0)).await;
        }
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a bounded poll still answers");

        assert_eq!(
            demand.total() as usize,
            MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL,
            "one job resolved per run the cap admits"
        );
        assert!(
            !demand.is_complete(),
            "a count clipped by the run cap is a floor and must say so; concluding \
             `idle` from one would be the mistake the flag exists to prevent"
        );
        assert!(demand.is_truncated(&repo()));
    }

    /// The caps bound what one repository can spend, whatever GitHub sends.
    ///
    /// The projection is a steady-state figure and the worst case is what keeps
    /// it honest, so the worst case has to be a real ceiling rather than an
    /// estimate. A repository with a hundred active runs must not spend a
    /// hundred requests.
    #[tokio::test]
    async fn a_repository_cannot_spend_more_than_the_documented_worst_case() {
        let server = MockServer::start().await;
        let queued: Vec<u64> = (0..40).map(|i| 100 + i).collect();
        let running: Vec<u64> = (0..40).map(|i| 500 + i).collect();
        mount_runs(&server, &repo(), QUEUED_RUN_STATUS, runs_body(&queued)).await;
        mount_runs(
            &server,
            &repo(),
            IN_PROGRESS_RUN_STATUS,
            runs_body(&running),
        )
        .await;
        for id in queued.iter().chain(running.iter()) {
            mount_jobs(&server, &repo(), *id, jobs_body(&["rm-home-win-x64"], 2, 0)).await;
        }
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a bounded poll still answers");

        assert_eq!(
            gateway.requests_issued(),
            u64::from(max_demand_requests_per_repository_per_poll()),
            "the measured ceiling must equal the projected one, or the bound is a \
             sentence in a doc comment"
        );
        assert_eq!(
            demand.total(),
            2 * (MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL
                + MAX_IN_PROGRESS_RUNS_PER_REPOSITORY_PER_POLL) as u32
        );
        assert!(!demand.is_complete());
    }

    /// The queued pass is served before the in-progress one when both are over
    /// their caps.
    #[tokio::test]
    async fn the_primary_signal_is_resolved_before_the_safety_net() {
        let server = MockServer::start().await;
        let queued: Vec<u64> = (0..40).map(|i| 100 + i).collect();
        let running: Vec<u64> = (0..40).map(|i| 500 + i).collect();
        mount_runs(&server, &repo(), QUEUED_RUN_STATUS, runs_body(&queued)).await;
        mount_runs(
            &server,
            &repo(),
            IN_PROGRESS_RUN_STATUS,
            runs_body(&running),
        )
        .await;
        // Queued runs hold this host's work; in-progress runs hold another
        // host's. If the caps were spent in the other order the demand would be
        // made of the wrong jobs.
        for id in &queued {
            mount_jobs(&server, &repo(), *id, jobs_body(&["rm-home-win-x64"], 1, 0)).await;
        }
        for id in &running {
            mount_jobs(&server, &repo(), *id, jobs_body(&["ubuntu-latest"], 1, 0)).await;
        }
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a bounded poll still answers");

        let tally = host_labels().tally(demand.jobs_for(&repo()));
        assert_eq!(
            tally.demand() as usize,
            MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL,
            "the queued cap is spent in full on the primary signal"
        );
        assert_eq!(
            tally.not_matched as usize, MAX_IN_PROGRESS_RUNS_PER_REPOSITORY_PER_POLL,
            "and the safety net gets its own smaller cap, not a share of the first"
        );
    }

    /// One run's job listing follows pages, and stops at its budget.
    #[tokio::test]
    async fn a_runs_job_listing_walks_pages_and_stops_at_its_budget() {
        let server = MockServer::start().await;
        let base = server.uri();
        let path_100 = jobs_path(&repo(), 100);

        mount_runs(&server, &repo(), QUEUED_RUN_STATUS, runs_body(&[100])).await;
        mount_runs(&server, &repo(), IN_PROGRESS_RUN_STATUS, no_runs()).await;
        // Every page points at another, forever.
        Mock::given(method("GET"))
            .and(path(path_100.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(jobs_body(&["rm-home-win-x64"], 100, 0))
                    .insert_header(
                        "link",
                        format!("<{base}{path_100}?page=9>; rel=\"next\"").as_str(),
                    ),
            )
            .mount(&server)
            .await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a bounded walk still answers");

        assert_eq!(
            gateway.requests_issued() as usize,
            2 + MAX_JOB_PAGES_PER_RUN,
            "an endless `Link` chain must stop at the job page budget rather than \
             spending the hourly ceiling on one run"
        );
        assert_eq!(demand.total() as usize, 100 * MAX_JOB_PAGES_PER_RUN);
        assert!(
            !demand.is_complete(),
            "a count clipped by the page bound is a floor and must say so"
        );
        assert!(demand.is_truncated(&repo()));
    }

    // -- the `total_count` tripwire ----------------------------------------

    /// The zero-cost check that `total_count` is the *filtered* count.
    ///
    /// A repository with 3 queued runs out of 5,000 lifetime runs would answer
    /// `len() == 3`, no `Link`, and `total_count == 5000`. The demand number no
    /// longer comes from that field, so the contradiction is a `warn!` rather
    /// than a `debug_assert!` — but it still means GitHub is not answering the
    /// question this module asked, and it is free to notice.
    #[tokio::test]
    async fn a_total_count_that_disagrees_with_its_only_page_does_not_derail_the_count() {
        let server = MockServer::start().await;
        mount_runs(
            &server,
            &repo(),
            QUEUED_RUN_STATUS,
            json!({
                "total_count": 5_000,
                "workflow_runs": [{ "id": 100 }]
            }),
        )
        .await;
        mount_runs(&server, &repo(), IN_PROGRESS_RUN_STATUS, no_runs()).await;
        mount_jobs(&server, &repo(), 100, jobs_body(&["rm-home-win-x64"], 2, 0)).await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a wrong `total_count` no longer decides anything here");

        assert_eq!(
            demand.total(),
            2,
            "the count comes from the jobs of the runs that were actually listed, so a \
             `total_count` carrying the unfiltered lifetime total cannot inflate it"
        );
        assert!(
            demand.is_complete(),
            "one listed run, no next page, and the cap not reached"
        );
    }

    // -- organization aggregation ------------------------------------------

    /// An organization aggregates across its installed repositories, and the
    /// request count grows with that repository count.
    #[tokio::test]
    async fn an_organization_aggregates_its_repositories_and_pays_per_repository() {
        let server = MockServer::start().await;
        mount_one_queued_run(&server, &repo(), &["rm-home-win-x64"], 2, 0).await;
        mount_one_queued_run(&server, &other_repo(), &["rm-home-win-x64"], 5, 0).await;
        mount_idle(&server, &third_repo()).await;
        let gateway = gateway(&server);

        let two = org_scope([repo(), other_repo()]);
        let three = org_scope([repo(), other_repo(), third_repo()]);

        assert_eq!(
            demand_requests_per_poll(&two),
            2 * DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL,
            "there is no organization-wide workflow-runs endpoint, so the cost is \
             per repository"
        );
        assert!(
            demand_requests_per_poll(&three) > demand_requests_per_poll(&two),
            "a projection that did not grow with the repository count would understate \
             an organization's real spend by exactly that factor"
        );

        let demand = gateway
            .queued_demand(&three, &CancelToken::new())
            .await
            .expect("an aggregate");

        assert_eq!(demand.total(), 7);
        assert_eq!(demand.for_repository(&repo()), Some(2));
        assert_eq!(demand.for_repository(&other_repo()), Some(5));
        assert_eq!(
            demand.for_repository(&third_repo()),
            Some(0),
            "a repository that answered zero is present as a zero, unlike one that \
             could not answer at all"
        );
        assert_eq!(
            host_labels().tally(demand.jobs()).demand(),
            7,
            "an organization policy serves any repository in its scope, so its demand \
             is the whole aggregate's rather than one repository's"
        );
        assert!(
            gateway.requests_issued() <= u64::from(max_demand_requests_per_poll(&three)),
            "the measured cost must sit inside the projected ceiling, or the budget \
             model is a table in a document"
        );
    }

    /// The measured cost is reported to `c3`'s budget model through the seam
    /// `c3` left for it, rather than inheriting the estimate.
    #[test]
    fn the_measured_demand_cost_is_reported_through_c3s_seam() {
        use crate::rest::DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH;

        let scope = org_scope([repo(), other_repo(), third_repo()]);
        let estimated = TargetCost::from_activity_scope(&scope);
        let measured = target_cost(&scope);

        assert_eq!(
            DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH, 2,
            "`c3`'s estimate prices the runs request and one jobs request; this module \
             now issues both, plus the in-progress listing and a jobs request per \
             additional active run, so the measured figure is higher rather than lower"
        );
        assert_ne!(
            measured, estimated,
            "the seam must actually replace the estimate; a `target_cost` that returned \
             `from_activity_scope` unchanged would report the estimate as measured"
        );
        // 1 inventory request + 3 repositories * (1 activity + 4 demand).
        assert_eq!(measured.requests_per_refresh(), 16);
        // 1 + 3 * (1 + 2), `c3`'s estimate.
        assert_eq!(estimated.requests_per_refresh(), 10);
        assert!(
            measured.requests_per_refresh() > estimated.requests_per_refresh(),
            "restoring the per-run job listing added requests; a measured cost that was \
             not higher would mean this module is not issuing them"
        );
    }

    /// **A known gap, pinned so it stays visible.** `f2`'s refusal *decision*
    /// can consume the measured demand cost; the number it prints alongside the
    /// refusal cannot.
    ///
    /// [`crate::rest::BudgetProjection::admit`] takes the candidate
    /// [`TargetCost`] from its caller, so an `f2` that builds it through
    /// [`target_cost`] gets an admission computed from the real cost.
    /// [`crate::rest::BudgetProjection::max_repository_targets`] builds
    /// [`TargetCost::repository`] internally, which cannot see the seam and
    /// therefore still prices demand at `c3`'s estimate of two.
    ///
    /// The two then disagree, and an operator sees both. **The direction of the
    /// disagreement inverted when this module started counting jobs**, and that
    /// is why this test matters more than it did: the printed ceiling used to be
    /// conservative, and is now optimistic. It says a host fits ten repository
    /// targets when the cost this module really issues fits six, so an operator
    /// planning against the printed number can configure a host that spends more
    /// than the projection admitted.
    ///
    /// What keeps that from being a live budget overrun is
    /// `BUDGET_SHARE_DIVISOR`: the projection is compared against half of
    /// GitHub's hourly ceiling, so the gap is spent out of the half deliberately
    /// left unplanned. It is a reporting defect with a safety margin under it,
    /// not a correctness one — and `f1`'s `host show` prints the caveat beside
    /// the number.
    ///
    /// It is not fixable from this file. Both remedies — changing
    /// [`crate::rest::DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH`], or giving
    /// `max_repository_targets` a [`TargetCost`] argument — are edits to
    /// `crates/github/src/rest.rs`, which `c3` owns. This test records the
    /// discrepancy with its arithmetic so that whoever holds that file can act on
    /// it, and fails if it is ever closed, at which point this test and the note
    /// above should go.
    #[test]
    fn the_printed_target_ceiling_still_projects_c3s_estimate() {
        use crate::rest::{BudgetProjection, budget_allowance};
        use runner_manager_domain::model::RefreshInterval;

        let interval = RefreshInterval::default();
        let printed = BudgetProjection::max_repository_targets(interval);
        let per_hour_estimated = TargetCost::repository().requests_per_hour(interval);
        let per_hour_measured = TargetCost::repository()
            .with_demand_requests_per_repository(DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL)
            .requests_per_hour(interval);

        // 4 requests per refresh * 60 refreshes, against 6 * 60.
        assert_eq!(per_hour_estimated, 240);
        assert_eq!(per_hour_measured, 360);
        assert_eq!(
            printed, 10,
            "the printed ceiling is `04-subsystem-contracts.md`'s figure, computed from \
             `c3`'s estimate"
        );
        assert_eq!(
            budget_allowance() / per_hour_measured,
            6,
            "while the cost this module actually issues allows six"
        );
        assert!(
            printed > budget_allowance() / per_hour_measured,
            "the gap now runs in the optimistic direction: the printed ceiling is larger \
             than the measured cost supports. `BUDGET_SHARE_DIVISOR` is what absorbs it \
             -- see this test's documentation before treating the inequality as harmless"
        );
    }

    /// One archived repository must not take down an organization's whole
    /// demand poll — and must not read as zero either.
    #[tokio::test]
    async fn an_organization_steps_over_a_repository_local_failure_without_reading_it_as_zero() {
        let server = MockServer::start().await;
        mount_one_queued_run(&server, &repo(), &["rm-home-win-x64"], 4, 0).await;
        Mock::given(method("GET"))
            .and(path(runs_path(&other_repo())))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })),
            )
            .mount(&server)
            .await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&org_scope([repo(), other_repo()]), &CancelToken::new())
            .await
            .expect("an aggregate steps over a repository it cannot read");

        assert_eq!(demand.total(), 4);
        assert_eq!(demand.unavailable().len(), 1);
        assert_eq!(demand.unavailable()[0].repository, other_repo());
        assert_eq!(
            demand.for_repository(&other_repo()),
            None,
            "a repository that could not be polled is absent from the map, not present \
             as a zero"
        );
        assert!(
            demand.jobs_for(&other_repo()).is_empty(),
            "and its job list is empty rather than absent, so a caller tallying it \
             cannot accidentally read an unavailable repository as demand"
        );
        assert!(
            !demand.is_complete(),
            "an aggregate missing a repository is not a complete reading"
        );
    }

    /// The same `404`, on a repository *target*, propagates instead.
    ///
    /// Stepping over the only repository in scope would answer demand `0` for a
    /// target this host cannot see at all, and `e1` would then correctly start
    /// no runners for the wrong reason — with no error anywhere to explain it.
    #[tokio::test]
    async fn a_repository_target_propagates_the_failure_rather_than_reporting_zero_demand() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(runs_path(&repo())))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })),
            )
            .mount(&server)
            .await;
        let gateway = gateway(&server);

        let error = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect_err("a scope of one has no aggregate to step over into");
        assert!(matches!(
            error,
            InventoryError::Github(GithubError::Status { status: 404, .. })
        ));
    }

    /// A failure on the *job* listing is a failure of the whole poll, not a
    /// silently short count.
    ///
    /// The job listing is where the new requests are, so it is where a new way
    /// to under-count could enter: a gateway that swallowed a failed job listing
    /// would report the run's jobs as zero, which is indistinguishable from a
    /// run whose jobs have all been dispatched.
    #[tokio::test]
    async fn a_failed_job_listing_is_not_read_as_a_run_with_no_queued_jobs() {
        let server = MockServer::start().await;
        mount_runs(&server, &repo(), QUEUED_RUN_STATUS, runs_body(&[100])).await;
        mount_runs(&server, &repo(), IN_PROGRESS_RUN_STATUS, no_runs()).await;
        Mock::given(method("GET"))
            .and(path(jobs_path(&repo(), 100)))
            .respond_with(
                ResponseTemplate::new(500).set_body_json(json!({ "message": "Server Error" })),
            )
            .mount(&server)
            .await;
        let gateway = gateway(&server);

        let error = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect_err("a job listing that failed is not a run with nothing queued");
        assert!(matches!(
            error,
            InventoryError::Github(GithubError::Status { status: 500, .. })
        ));
    }

    /// A credential failure aborts the aggregate rather than being stepped over.
    ///
    /// A revoked token is a fact about the credential, not about the repository:
    /// stepping over it would report every remaining repository as unavailable
    /// and the total as a number, when in truth nothing can be read at all.
    #[tokio::test]
    async fn a_rate_limit_aborts_the_aggregate_rather_than_being_stepped_over() {
        let server = MockServer::start().await;
        mount_one_queued_run(&server, &repo(), &["rm-home-win-x64"], 1, 0).await;
        Mock::given(method("GET"))
            .and(path(runs_path(&other_repo())))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "42")
                    .set_body_json(json!({
                        "message": "You have exceeded a secondary rate limit"
                    })),
            )
            .mount(&server)
            .await;
        let gateway = gateway(&server);

        let error = gateway
            .queued_demand(&org_scope([repo(), other_repo()]), &CancelToken::new())
            .await
            .expect_err("a rate limit is a fact about the credential, not the repository");

        let limit = error
            .rate_limited()
            .expect("`c3`'s detector is what decides this, and it decided rate limit");
        assert_eq!(limit.retry_after, Some(std::time::Duration::from_secs(42)));
    }

    // -- cancellation -------------------------------------------------------

    /// A token flipped between requests stops the poll before the next one.
    #[tokio::test]
    async fn cancellation_between_requests_stops_the_poll() {
        let server = MockServer::start().await;
        mount_one_queued_run(&server, &repo(), &["rm-home-win-x64"], 3, 0).await;

        let gateway = gateway(&server);
        let cancel = CancelToken::new();

        let first = gateway
            .repository_queued(&repo(), &cancel)
            .await
            .is_ok_and(|reading| reading.jobs.len() == 3);
        assert!(first, "the uncancelled poll reads both lists and the jobs");
        assert_eq!(gateway.requests_issued(), 3);

        cancel.cancel();
        let error = gateway
            .repository_queued(&repo(), &cancel)
            .await
            .expect_err("a cancelled token opens no socket at all");
        assert!(error.is_cancelled());
        assert_eq!(
            gateway.requests_issued(),
            3,
            "a cancelled poll must spend nothing; the count is of requests attempted"
        );
    }

    // -- the seam this module does not own ---------------------------------

    /// The `runs-on` predicate is `b1`'s. This module builds its **input** and
    /// implements no part of the matching.
    ///
    /// # Read this before concluding the test is in the wrong file
    ///
    /// `c4`'s specification asks for "a `runs-on` table covering forms that must
    /// match, forms that must not, and an unresolvable expression, delegating
    /// the predicate to `b1`". For a while that table had no input: an owner
    /// decision had removed the per-run job listing, a workflow *run* carries no
    /// `runs-on`, and this gateway therefore produced nothing to match. That
    /// decision has been reversed — the module documentation says why — so the
    /// table has its input back and this test asserts both halves of the seam
    /// rather than only the delegation half.
    ///
    /// The division of labour is: `c4` reads each queued job's `labels` array
    /// and builds a [`RunsOn`], `b1` decides what matches, and `e1` applies the
    /// decision per policy. Constructing a `RunsOn` here is the correct side of
    /// that line; comparing labels here is not.
    ///
    /// # How the second half of that claim is asserted, and how far it reaches
    ///
    /// By reading this file's own source, because nothing done to `b1` can prove
    /// anything about what *this* module contains: every assertion in the body
    /// below would pass unchanged with a full label matcher sitting beside it.
    /// The scan takes the production half — everything above `#[cfg(test)]`,
    /// with comment lines dropped so that the module documentation may keep
    /// explaining the seam — and requires that it names none of `b1`'s
    /// *decision* vocabulary.
    ///
    /// `RunsOn` is no longer in the forbidden set, and could not be: this module
    /// constructs one per queued job, which is the whole point of the reversal.
    /// What stays forbidden is everything that would mean deciding rather than
    /// describing — `RoutingLabels`, whose `matches` and `tally` are the
    /// predicate, and `DemandTally`, which is the predicate's result. A `c4`
    /// that named either would be filtering, and filtering here would make the
    /// poll per-policy rather than per-target; the module documentation explains
    /// why that trade is refused.
    ///
    /// Like the needles in `nothing_in_this_crate_reserves_or_claims_a_job`, it
    /// is a tripwire on the obvious shape rather than a proof: a hand-rolled
    /// comparison of raw label strings that never names a `policy` type would
    /// walk past it. Stated rather than implied, for the same reason it is
    /// stated there.
    #[test]
    fn the_runs_on_predicate_is_b1s_and_this_module_only_feeds_it() {
        let labels = RoutingLabels::derive(
            &HostLabel::new("home").expect("a valid host label"),
            Os::Windows,
            Arch::X64,
        );
        let host = labels.host_label().as_str().to_string();
        assert_eq!(host, "rm-home-win-x64");

        // Must match: the host label alone, in each documented form.
        for form in [
            RunsOn::Single(host.clone()),
            RunsOn::Many(vec![host.clone()]),
            RunsOn::Grouped {
                group: Some("Default".into()),
                labels: runner_manager_domain::policy::RunsOnLabels::One(host.clone()),
            },
        ] {
            assert!(
                labels.matches(&form).is_match(),
                "a job requiring only this policy's own label must match: {form:?}"
            );
        }

        // Must not match: GitHub-hosted, and another host's label.
        for form in [
            RunsOn::Single("ubuntu-latest".into()),
            RunsOn::Many(vec![host.clone(), "rm-office-win-x64".into()]),
        ] {
            assert!(
                !labels.matches(&form).is_match(),
                "a job requiring a label this policy does not carry must not match: {form:?}"
            );
        }

        // Unresolvable: an expression only GitHub can evaluate. Never demand and
        // never discarded.
        let expression = RunsOn::Single("${{ matrix.runner }}".into());
        assert!(matches!(
            labels.matches(&expression),
            RunsOnMatch::Unresolvable(UnresolvableRunsOn::Expression { .. })
        ));

        // And the tally keeps the three apart, which is what `e1` clamps.
        let tally = labels.tally(&[
            RunsOn::Single(host.clone()),
            RunsOn::Single("ubuntu-latest".into()),
            expression,
        ]);
        assert_eq!(tally.demand(), 1);
        assert_eq!(tally.not_matched, 1);
        assert_eq!(tally.unresolvable.len(), 1);
        assert_eq!(tally.total_seen(), 3);

        // The form this gateway actually builds is the array one, because that
        // is the shape the jobs API returns. Pinned so that a `RunsOn` built
        // from a job's `labels` really is a value `b1`'s predicate accepts,
        // rather than one that happens to compile.
        assert_eq!(
            RunsOn::from_job_labels(["self-hosted", host.as_str()]),
            RunsOn::Many(vec!["self-hosted".into(), host.clone()])
        );
        assert!(
            labels
                .matches(&RunsOn::from_job_labels([host.as_str()]))
                .is_match()
        );
        // And the direction that surprises people: a bare derived set does not
        // carry `self-hosted`, so the shape most workflows are written in --
        // `runs-on: [self-hosted, windows]` -- does **not** match a policy whose
        // operator never added those labels. That is `b1`'s superset rule
        // working as specified rather than a gap, and it is asserted here
        // because the job listing is what finally made it observable.
        assert!(
            !labels
                .matches(&RunsOn::from_job_labels(["self-hosted", host.as_str()]))
                .is_match(),
            "a job requiring `self-hosted` needs a policy carrying `self-hosted`"
        );

        // And the other half of this test's title, which everything above leaves
        // untouched: that the predicate exercised here has no second
        // implementation in this file. See the documentation on this test for
        // what the scan covers, what it does not, and why `RunsOn` is absent
        // from the list.
        let production = this_file_above_its_tests_without_prose();
        for owned_by_b1 in ["RoutingLabels", "DemandTally"] {
            assert!(
                !production.contains(owned_by_b1),
                "the demand gateway names `{owned_by_b1}`, which belongs to `b1`: this \
                 module builds the predicate's input and does not apply it. Filtering \
                 here would make the poll per-policy rather than per-target and multiply \
                 its request cost by the number of policies sharing a target -- if an \
                 owner decision changed that, it belongs in this module's documentation \
                 and in this test before it belongs in the code"
            );
        }
        assert!(
            production.contains("RunsOn"),
            "and the gateway must still *build* a `RunsOn` per queued job; a production \
             half that named none would mean the job listing had been removed again and \
             the serial-matrix defect restored"
        );
    }

    /// This file's source above its test module, with comment lines dropped.
    ///
    /// Two exclusions, each load-bearing. The **test module** goes because the
    /// tests above legitimately drive `b1`'s predicate and would accuse the file
    /// of owning what they are proving it delegates. The **comments** go because
    /// this module's documentation explains the seam at length and names the
    /// types to do it — a scan that forbade the explanation would get the
    /// explanation deleted, which is the trade
    /// `nothing_in_this_crate_reserves_or_claims_a_job` records making in the
    /// other direction.
    fn this_file_above_its_tests_without_prose() -> String {
        let (production, _) = include_str!("demand.rs")
            .split_once("\n#[cfg(test)]")
            .expect("this file has a test module, and the scan is meaningless without one");
        production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The one normalisation both halves of the reservation scan use.
    ///
    /// Shared rather than written twice, because the defect it closes was two
    /// spellings of "the same" normalisation drifting apart: the haystack was
    /// lower-cased and the needle was not, so every needle carrying a capital —
    /// which is every type-shaped one — could not match a lower-cased haystack,
    /// and three of the seven assertions were vacuously true from the day they
    /// were written. One function cannot disagree with itself.
    fn normalise_for_scan(text: &str) -> String {
        text.to_ascii_lowercase().replace(['_', ' '], "")
    }

    // The Actions-service call this design has no equivalent of, plus the shapes
    // an implementer would invent in its place. Matched case-insensitively with
    // `_` and spaces removed, so one needle catches the snake, camel and Pascal
    // spellings of an identifier at once — and so that the singular needle
    // catches the plural.
    //
    // # Why every needle carries `fn` or `struct`
    //
    // A bare `acquirejobs` fires on this crate's own prose, and it was written
    // that way first: three modules explain *why* there is no job reservation,
    // and each has to name the call that does not exist in order to say so. A
    // scan that forbids the explanation is a scan that gets the explanation
    // deleted, which costs more than it protects. Requiring the item keyword
    // narrows the needle to a *definition*, which is what the rule is actually
    // about.
    //
    // What this therefore does **not** catch is stated rather than implied: a
    // reservation reached through a trait method, a closure, or a
    // differently-named helper. It is a tripwire on the obvious shape, and
    // `c4`'s Definition of Done names review as the primary control.
    //
    // # And why every needle is spelled in halves
    //
    // `lib.rs`'s confidential-credential scan solves the same problem the same
    // way: a needle written out whole would appear in this file's own source and
    // the scan would accuse itself. Normalising
    // `concat!("fn ", "acquire", "_job")` leaves the quote-comma-quote between
    // the halves, so no needle ever appears whole in the text being scanned.
    const FORBIDDEN: &[&str] = &[
        concat!("fn ", "acquire", "_job"),
        concat!("fn ", "claim", "_job"),
        concat!("fn ", "lease", "_job"),
        concat!("fn ", "reserve", "_job"),
        // The acknowledgement this test's own title names alongside the other
        // three, and which the list did not actually carry. Spelled to the verb
        // rather than to a `_job` suffix, because the shape an implementer
        // reaches for acknowledges a *message* or an *assignment* as readily as
        // a job, and a suffixed needle would walk straight past those.
        concat!("fn ", "ack", "nowledge"),
        concat!("struct ", "Job", "Lease"),
        concat!("struct ", "Job", "Claim"),
        concat!("struct ", "Job", "Reservation"),
    ];

    /// Which forbidden shape a source text names, if any.
    ///
    /// The whole-crate scan and its positive control both go through here, so a
    /// normalisation that cannot see a shape fails the control loudly instead of
    /// passing the scan silently. That is the entire point of the indirection:
    /// the arrangement this replaced had the control re-deriving the needle
    /// itself, and a copy that agrees with a buggy original proves nothing — it
    /// re-derived the needle the same wrong way and went green.
    fn forbidden_shape_in(source: &str) -> Option<&'static str> {
        let haystack = normalise_for_scan(source);
        FORBIDDEN
            .iter()
            .copied()
            .find(|forbidden| haystack.contains(&normalise_for_scan(forbidden)))
    }

    /// No reservation, claim, lease, or acknowledgement call exists anywhere in
    /// this crate.
    ///
    /// `AcquireJobs` had no REST replacement, so a well-meaning implementer
    /// reaches for a local lease to "fix" the surplus-runner case. Three
    /// specifications say not to; this makes the instruction executable, over
    /// the whole crate rather than only this file, because the edit would most
    /// likely land in a new module rather than here.
    #[test]
    fn nothing_in_this_crate_reserves_or_claims_a_job() {
        const SOURCES: &[(&str, &str)] = &[
            ("demand.rs", include_str!("demand.rs")),
            ("device_flow.rs", include_str!("device_flow.rs")),
            ("jit.rs", include_str!("jit.rs")),
            ("lib.rs", include_str!("lib.rs")),
            ("rest.rs", include_str!("rest.rs")),
        ];
        // `SOURCES` is a snapshot, and a snapshot makes "anywhere in the crate"
        // false the moment a file is added. The walk below turns the claim back
        // into a claim.
        //
        // It **recurses**, and that is not incidental. `lib.rs` records the
        // defect a single `read_dir` produced for the same pin: a module
        // directory (`src/rest/mod.rs`) arrives as the entry `rest`, which does
        // not end in `.rs`, so a flat filter drops it and takes every file
        // underneath with it — leaving the pin passing while the files it exists
        // to cover are scanned by nothing at all.
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
            "a source file was added or removed; this scan claims to cover the whole \
             crate and a stale list makes that claim false"
        );

        for (name, source) in SOURCES {
            assert_eq!(
                forbidden_shape_in(source),
                None,
                "{name} names a forbidden shape: there is no job reservation on the REST \
                 path, and a local lease coordinates this host with itself and with \
                 nothing else"
            );
        }
    }

    /// The scan above can actually see the things it forbids.
    ///
    /// A substring scan that never matches passes for the wrong reason. This
    /// plants the exact shapes and runs them through [`forbidden_shape_in`] —
    /// the same matcher the scan uses, rather than a second copy of it.
    ///
    /// # Why one planted shape was not enough
    ///
    /// It planted only the `fn` form, and that form is the one that could not
    /// fail: a `fn` needle is already lower-case, so it survived a
    /// normalisation that lower-cased the haystack and not the needle. Every
    /// type-shaped needle carries capitals and therefore could never match the
    /// lower-cased haystack — all three of them were un-catchable, and their
    /// three assertions vacuously true, while this control stayed green. (They
    /// are not written out here for the reason the list itself is spelled in
    /// halves: a literal would make this file fail its own gate.) Both kinds
    /// are planted now, and the case-shape of the plant is the property under
    /// test rather than an incidental detail of it.
    #[test]
    fn the_reservation_scan_catches_an_injected_reservation() {
        // Assembled from fragments rather than written out, because the scan
        // above reads this very file: a literal here would make the crate fail
        // its own gate, which is the trap that forced the needles to carry an
        // item keyword in the first place.
        let call = format!(
            "    async {} {}{}(&self) -> Result<Vec<Job>, InventoryError> {{",
            "fn", "acquire", "_jobs"
        );
        let item = format!("{} {}{} {{ id: u64 }}", "struct", "Job", "Lease");
        let acknowledgement = format!(
            "    async {} {}{}(&self, id: u64) {{",
            "fn", "ack", "nowledge_assignment"
        );

        for (planted, expected) in [
            (&call, concat!("fn ", "acquire", "_job")),
            (&item, concat!("struct ", "Job", "Lease")),
            (&acknowledgement, concat!("fn ", "ack", "nowledge")),
        ] {
            assert_eq!(
                forbidden_shape_in(planted),
                Some(expected),
                "the scan's own matcher cannot see {planted:?}, so every negative \
                 assertion it makes about that shape is worthless"
            );
        }

        // And the plural really is caught by the singular needle, which is the
        // one thing about the list above that is not obvious from reading it.
        assert!(
            call.contains("acquire_jobs"),
            "the planted shape is the plural the Actions-service protocol used"
        );
        // Likewise the acknowledgement needle stops at the verb, so it catches
        // the shapes that acknowledge something other than a job by name.
        assert!(
            acknowledgement.contains("_assignment"),
            "the planted acknowledgement names no job, which is why the needle \
             carrying a `_job` suffix would have missed it"
        );
    }
}
