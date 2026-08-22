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
//!   -> 200 { "total_count": N, "workflow_runs": [ … ] }
//! ```
//!
//! One request per repository. An organization target has no organization-wide
//! workflow-runs endpoint, so it pays that once per repository the App is
//! installed on there; see [`demand_requests_per_poll`].
//!
//! # The counting unit is a **run**, not a job
//!
//! This is the single most important thing to know about this module, it is an
//! owner decision rather than an implementation accident, and it is **accepted
//! product behaviour rather than a defect**.
//!
//! `d18b-run-count-filtering.md` probed the endpoint above against live GitHub
//! and established that `total_count` counts **workflow runs matching the
//! query**. A workflow run can hold many jobs — a matrix, or a `jobs:` map with
//! several independent entries — and **each job needs its own runner**. So a
//! single queued run holding eight matrix jobs reads here as demand `1`, `e1`
//! starts **one** runner, that runner takes one job, and the remaining seven
//! queue behind it and are served serially as further polls observe the run
//! still queued.
//!
//! The alternative was resolving each queued run's jobs through
//! `GET /repos/{o}/{r}/actions/runs/{run_id}/jobs`, which costs **one extra
//! request per queued run** — a variable cost scaling with queue depth, against
//! a budget ([`crate::rest::TargetCost`], [`crate::rest::BudgetProjection`])
//! whose whole design is a fixed per-refresh figure that `f2` computes its `add`
//! refusals from. The owner chose the fixed cost and the resulting under-count.
//!
//! **So: do not "fix" this, and do not add a per-run job listing.** It is
//! written here at length precisely so that a later reader rediscovering the
//! under-count recognises it as a decision with a reason rather than as a bug
//! with an obvious patch.
//!
//! # What that costs, stated plainly rather than left to be discovered
//!
//! A workflow *run* carries no `runs-on`. Labels live on **jobs**, and this
//! module fetches no jobs — so **routing-label filtering is not applied to
//! demand here at all**. Every queued run in a watched repository counts,
//! including runs whose jobs target `ubuntu-latest`, another host's
//! `rm-<host>-…` label, or a label set this policy does not carry.
//!
//! `b1` owns the predicate that *would* filter it
//! ([`runner_manager_domain::policy::RoutingLabels::matches`] and
//! [`runner_manager_domain::policy::RoutingLabels::tally`]), this module
//! deliberately re-implements none of it, and
//! `the_runs_on_forms_b1_matches_are_the_predicate_this_module_does_not_own`
//! below pins that the predicate is `b1`'s. What is missing is not the
//! predicate but its **input**: nothing on the fixed-cost path produces a
//! `RunsOn` to feed it.
//!
//! The bounding controls are therefore the ones that do not need a job listing,
//! and they are named in `02-target-architecture.md` and implemented elsewhere:
//! the per-policy `max_capacity`, the host-wide `host_capacity`, and the fact
//! that a runner registered with host-scoped labels is never *assigned* a job it
//! does not match. A runner started for demand this host cannot serve is the
//! surplus-runner case — an accepted, bounded cost with an idle-timeout exit
//! (`01-current-architecture.md`, edge case 6; `h1` scenario 8), not a runner
//! that steals work.
//!
//! # Why `status=queued` and not `c3`'s in-progress count
//!
//! [`crate::rest::InventoryGateway::in_progress_activity`] answers a different
//! question and is not reusable here. `status=in_progress` **excludes** queued
//! runs, and a queued run is precisely one waiting for a runner that does not
//! exist — which is the definition of demand. An in-progress run already has a
//! runner; counting it as demand would start a second one for work already
//! being done.
//!
//! The exclusion is inferred from GitHub's documented status vocabulary rather
//! than observed: `d18b`'s two fixtures never produced a queued run, so both
//! `queued` and `in_progress` read `0` there and neither could discriminate.
//! It is recorded as an inference on purpose.
//!
//! # `total_count` is trusted, and the trust is checked for free
//!
//! `d18b` verified against public data that `total_count` on a filtered query is
//! the filtered count: `1` beside a live in-progress run on a 58-run
//! repository, `0` on a 680-run one, invariant under `per_page` at 1, 100 and
//! `page=5`, and an exact partition of a 680-run fixture across three
//! conclusions. So one request yields the whole count.
//!
//! That is an assumption about a live API, and this is the layer where being
//! wrong about it is most expensive — `c3` reads the same envelope for a
//! dashboard number, and this one reaches `clamp()`. So the same zero-cost
//! tripwire `c3` wrote is reused: when there is no `rel="next"`, the whole
//! filtered set is on this page, so `total_count` **must** equal
//! `workflow_runs.len()`. A disagreement is always warned about, and past
//! `MAX_BENIGN_TOTAL_COUNT_SKEW` it `debug_assert!`s — see that constant for
//! why the two thresholds differ.
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

use runner_manager_domain::model::{Clock, OwnerRepo, TargetScope, Timestamp};
use serde::Deserialize;

use crate::{
    ApiRequest, ApiResponse, AuthenticatedClient, GithubError, MAX_PAGES,
    rest::{
        ActivityScope, CancelToken, InventoryError, PER_PAGE, RateLimited, TargetCost,
        UnavailableRepository,
    },
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The `status` filter that selects runs waiting for a runner.
///
/// Stated as a constant rather than inlined because it is the whole difference
/// between this module and `c3`'s activity count, and a one-word typo here
/// produces a plausible-looking number rather than an error.
pub const QUEUED_RUN_STATUS: &str = "queued";

/// Requests one demand poll costs, **per repository**.
///
/// **One**, not the `2` that [`crate::rest::DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH`]
/// estimates and `04-subsystem-contracts.md` tabulates as "queued runs plus
/// their jobs (~120/hour)". That estimate priced a jobs request alongside the
/// runs request; the owner decision this module implements removed the jobs
/// request entirely, so the measured cost is half the estimate.
///
/// This is what [`target_cost`] reports through
/// [`TargetCost::with_demand_requests_per_repository`] — the seam `c3` left
/// open for exactly this, so that reporting a measured cost does not mean
/// editing a constant in a file this task does not own.
///
/// # This is the best case, and it says so for the same reason `c3`'s does
///
/// One request is what a repository costs **when GitHub sends `total_count`**,
/// which `d18b` observed on every response it made. When it is absent the count
/// falls back to walking pages and may spend up to
/// [`MAX_DEMAND_FALLBACK_PAGES`], so the true worst case per repository per poll
/// is **four**. That gap is stated rather than modelled, exactly as
/// [`crate::rest::ACTIVITY_REQUESTS_PER_REPOSITORY_PER_REFRESH`] states its own,
/// and it is absorbed by [`crate::rest::BUDGET_SHARE_DIVISOR`]: the projection
/// is compared against half the ceiling precisely so the half nobody models has
/// somewhere to go. A repository that walked to the bound also **says** it did
/// — it lands in [`QueuedDemand::truncated`] — so an overrun is visible rather
/// than silent.
pub const DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL: u32 = 1;

/// The most pages one repository's demand count may walk when GitHub sends no
/// `total_count`.
///
/// [`crate::MAX_PAGES`] is the wrong ceiling for this walk and the reasoning is
/// `c3`'s, in [`crate::rest::MAX_ACTIVITY_FALLBACK_PAGES`]: `MAX_PAGES` exists
/// to stop a `Link: rel="next"` cycle looping forever and is not a number
/// anything budgeted for, while this walk is charged against
/// [`DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL`], which is one.
///
/// It matters more here than there. `c3`'s number renders on a dashboard; this
/// one reaches `clamp()`, so an unbounded walk would spend the whole hourly
/// ceiling deciding how many runners to start, and a silently clipped one would
/// under-start. Four pages counts 400 queued runs exactly; past that the answer
/// stops being exact and says so through [`QueuedDemand::is_truncated`].
pub const MAX_DEMAND_FALLBACK_PAGES: usize = 4;

// Enforced at compile time rather than by a test, for `c3`'s reason: the two
// ceilings collapsing back into one is the defect itself, not a symptom of one.
const _: () = assert!(
    MAX_DEMAND_FALLBACK_PAGES < MAX_PAGES,
    "the demand page budget must stay below the runaway `Link`-cycle ceiling"
);

// A poll that costs nothing is a poll that issued no request, and a budget line
// of zero would let `f2` admit an unbounded number of targets.
const _: () = assert!(
    DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL > 0,
    "a demand poll costs at least the request that fetched the queued runs"
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
/// So the `warn!` fires on any disagreement and the `debug_assert!` only past
/// this threshold. An assert that fired on both would panic a development build
/// over a race its own documentation calls legitimate, and a tripwire that cries
/// wolf is a tripwire the next reader deletes.
const MAX_BENIGN_TOTAL_COUNT_SKEW: u64 = 16;

// A zero skew is `total == listed` again, which is the check that panicked on
// the documented race. At compile time rather than in a test because a test
// deriving its fixture from this constant moves with it and stays green at zero.
const _: () = assert!(
    MAX_BENIGN_TOTAL_COUNT_SKEW > 0,
    "a zero skew re-creates the assert that trips on a run leaving the queue mid-serialisation"
);

// ---------------------------------------------------------------------------
// The demand reading
// ---------------------------------------------------------------------------

/// Queued workflow runs, per repository and in total.
///
/// **This is a count of runs, not of jobs, and it is not filtered by any
/// policy's routing labels.** Both facts are the module documentation's subject
/// and are repeated on the type because this is what a caller holds: reading
/// [`QueuedDemand::total`] as "jobs this policy should serve" is wrong in two
/// independent directions at once, and nothing downstream can recover either.
///
/// # A count can be short in two different ways, and both have to say so
///
/// A repository can fail to answer at all ([`QueuedDemand::unavailable`]), and a
/// repository can answer with a number that is only a **floor**
/// ([`QueuedDemand::truncated`]) — the fallback walk stopped at
/// [`MAX_DEMAND_FALLBACK_PAGES`], or GitHub's own total was wider than the `u32`
/// this product renders. [`QueuedDemand::is_complete`] is `false` for either.
///
/// The shape mirrors [`crate::rest::ActivityCount`] deliberately, down to the
/// method names, because `g2` renders the two side by side and a caller that has
/// learned one should not have to learn the other. They stay separate types for
/// the reason `c3` keeps the busy-runner count and the in-progress count apart:
/// a type that can hold either number is a type that will eventually add them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueuedDemand {
    per_repository: BTreeMap<OwnerRepo, u32>,
    unavailable: Vec<UnavailableRepository>,
    /// Repositories whose count is a floor rather than a total.
    truncated: BTreeSet<OwnerRepo>,
}

impl QueuedDemand {
    #[must_use]
    pub fn new(per_repository: BTreeMap<OwnerRepo, u32>) -> Self {
        Self {
            per_repository,
            unavailable: Vec::new(),
            truncated: BTreeSet::new(),
        }
    }

    /// One repository's count, for the repository-target case and for tests.
    #[must_use]
    pub fn of(repository: OwnerRepo, count: u32) -> Self {
        Self::new(BTreeMap::from([(repository, count)]))
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

    /// Queued runs across every repository that answered.
    ///
    /// Saturating rather than wrapping: a total wider than a `u32` is not a
    /// number to wrap around zero, and `u32::MAX` runners is refused by the
    /// capacity ceilings long before it means anything.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.per_repository
            .values()
            .fold(0_u32, |sum, count| sum.saturating_add(*count))
    }

    #[must_use]
    pub fn per_repository(&self) -> &BTreeMap<OwnerRepo, u32> {
        &self.per_repository
    }

    /// One repository's count, or `None` when it did not answer.
    #[must_use]
    pub fn for_repository(&self, repository: &OwnerRepo) -> Option<u32> {
        self.per_repository.get(repository).copied()
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

/// Requests one demand poll over `scope` costs.
///
/// Grows with the repository count, because there is no organization-wide
/// workflow-runs endpoint and an organization therefore pays per repository the
/// App is installed on. That growth *is* the product constraint after D4: every
/// added repository multiplies this policy's share of the shared hourly ceiling.
#[must_use]
pub fn demand_requests_per_poll(scope: &ActivityScope) -> u32 {
    u32::try_from(scope.repositories().len()).unwrap_or(u32::MAX)
        * DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL
}

/// `scope`'s budget cost with this module's **measured** demand figure
/// substituted for `c3`'s estimate.
///
/// This is the reporting seam `c4`'s specification requires — "report the
/// per-poll request count to `c3`'s budget model rather than estimating it
/// there" — and [`TargetCost::with_demand_requests_per_repository`] is where
/// `c3` left it open. Callers that project a budget (`f1`'s `host show`, `f2`'s
/// `repo add` and `org add`, `g3`'s settings) should build their
/// [`TargetCost`] through this function rather than through
/// [`TargetCost::from_activity_scope`] directly, or they will project the
/// pre-decision estimate of two requests per repository.
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

    /// Queued workflow runs for one repository.
    ///
    /// One request in the ordinary case, because GitHub answers the filtered
    /// query with its own `total_count` and `d18b` established that the number
    /// is the filtered count.
    async fn repository_queued(
        &self,
        repository: &OwnerRepo,
        cancel: &CancelToken,
    ) -> Result<RepositoryDemand, InventoryError> {
        let request = ApiRequest::get(format!(
            "/repos/{}/{}/actions/runs",
            repository.owner(),
            repository.repo()
        ))
        .query("status", QUEUED_RUN_STATUS)
        .query("per_page", PER_PAGE);

        let response = self.get(&request, cancel).await?;
        let page: QueuedRunsPage = response.json()?;

        if let Some(total) = page.total_count {
            let listed = page.workflow_runs.len() as u64;
            if response.next_page().is_none() && total != listed {
                tracing::warn!(
                    repository = %repository,
                    total_count = total,
                    listed,
                    "GitHub's `total_count` disagrees with the single page it sent for a \
                     filtered query; this layer reads `total_count` as the count of the \
                     filtered set, and that reading looks wrong"
                );
                // Asymmetric on purpose; see `MAX_BENIGN_TOTAL_COUNT_SKEW`. A
                // handful over is the documented race, thousands over is the
                // unfiltered total this was written to catch — and unlike `c3`'s
                // copy of this check, the number being read here is the one that
                // decides how many runner processes start.
                debug_assert!(
                    total <= listed.saturating_add(MAX_BENIGN_TOTAL_COUNT_SKEW),
                    "`total_count` ({total}) exceeds the {listed} queued run(s) on the only \
                     page of a filtered query by more than {MAX_BENIGN_TOTAL_COUNT_SKEW}, \
                     which is far past the run-leaving-the-queue race; `total_count` is not \
                     the filtered count, and demand is being read off the wrong field"
                );
            }
            return Ok(RepositoryDemand::from_reported_total(total, repository));
        }

        // No `total_count`: count what is there, following pages. Guessing zero
        // from a missing field would render a backed-up queue as idle and start
        // no runners at all.
        let mut counted = page.workflow_runs.len();
        let mut pages = 1_usize;
        let mut next = response
            .next_page()
            .map(|url| ApiRequest::get(url.as_str()));
        while let Some(request) = next.take() {
            if pages >= MAX_DEMAND_FALLBACK_PAGES {
                tracing::warn!(
                    repository = %repository,
                    pages,
                    counted,
                    "stopped counting queued runs at the demand page budget; the count \
                     reported for this repository is a floor, not a total"
                );
                return Ok(RepositoryDemand::floor(counted));
            }
            let response = self.get(&request, cancel).await?;
            let page: QueuedRunsPage = response.json()?;
            counted += page.workflow_runs.len();
            pages += 1;
            next = response
                .next_page()
                .map(|url| ApiRequest::get(url.as_str()));
        }
        Ok(RepositoryDemand::exact(counted))
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
                        .insert(repository.clone(), reading.count);
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

/// One repository's queued-run count, and whether that number is the whole
/// truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepositoryDemand {
    count: u32,
    /// `false` when `count` is a **floor**: the page budget stopped the walk, or
    /// GitHub's own total was wider than the `u32` this product renders.
    exact: bool,
}

impl RepositoryDemand {
    fn exact(count: usize) -> Self {
        Self {
            // A count assembled here one page at a time cannot exceed
            // `MAX_DEMAND_FALLBACK_PAGES * PER_PAGE`, so the saturation is
            // unreachable rather than lossy.
            count: u32::try_from(count).unwrap_or(u32::MAX),
            exact: true,
        }
    }

    fn floor(count: usize) -> Self {
        Self {
            count: u32::try_from(count).unwrap_or(u32::MAX),
            exact: false,
        }
    }

    /// GitHub's own `total_count`, narrowed to the width this product uses.
    ///
    /// A total that does not fit a `u32` is still a *floor* — the real count is
    /// larger, not smaller — so it is reported as one rather than saturated
    /// silently into something that looks like a measurement.
    fn from_reported_total(total: u64, repository: &OwnerRepo) -> Self {
        match u32::try_from(total) {
            Ok(count) => Self { count, exact: true },
            Err(_) => {
                tracing::warn!(
                    repository = %repository,
                    total_count = total,
                    "GitHub reported a queued-run total wider than this product uses; it is \
                     clamped and reported as a floor rather than as a count"
                );
                Self {
                    count: u32::MAX,
                    exact: false,
                }
            }
        }
    }
}

/// One page of `GET …/actions/runs?status=queued`.
///
/// The runs themselves are discarded: this module counts them and reads nothing
/// out of them. `IgnoredAny` rather than a struct is what makes that literally
/// true — there is no field here to start depending on, and in particular no
/// `jobs_url` for a later reader to follow, which is the edit the module
/// documentation asks nobody to make.
#[derive(Debug, Deserialize)]
struct QueuedRunsPage {
    total_count: Option<u64>,
    #[serde(default)]
    workflow_runs: Vec<serde::de::IgnoredAny>,
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
    use crate::testing::{FIXTURE_TOKEN, Script, TestClock};
    use crate::{Endpoints, UserAccessToken};
    use runner_manager_domain::{
        model::{Arch, HostLabel, Org, Os},
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

    /// A `?status=queued` response carrying its own filtered `total_count`.
    fn queued_body(total: u64, listed: usize) -> serde_json::Value {
        json!({
            "total_count": total,
            "workflow_runs": (0..listed)
                .map(|i| json!({ "id": 100 + i, "status": "queued" }))
                .collect::<Vec<_>>()
        })
    }

    /// The same shape with **no** `total_count`, which is what forces the
    /// page-walking fallback.
    fn queued_body_without_total(listed: usize) -> serde_json::Value {
        json!({
            "workflow_runs": (0..listed)
                .map(|i| json!({ "id": 200 + i, "status": "queued" }))
                .collect::<Vec<_>>()
        })
    }

    async fn mount_queued(server: &MockServer, repository: &OwnerRepo, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/{}/{}/actions/runs",
                repository.owner(),
                repository.repo()
            )))
            .and(query_param("status", QUEUED_RUN_STATUS))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    // -- the count itself ---------------------------------------------------

    /// The ordinary path: one request, and the number is GitHub's own filtered
    /// total.
    #[tokio::test]
    async fn a_queued_run_fixture_yields_the_filtered_total_in_one_request() {
        let server = MockServer::start().await;
        mount_queued(&server, &repo(), queued_body(7, 7)).await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a queued-run count");

        assert_eq!(demand.total(), 7);
        assert_eq!(demand.for_repository(&repo()), Some(7));
        assert!(demand.is_complete());
        assert_eq!(
            gateway.requests_issued(),
            1,
            "the whole filtered count arrives in one request, which is what \
             DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL projects"
        );
    }

    /// The filter is on the wire, not merely in the doc comment.
    ///
    /// `status=in_progress` and `status=queued` are one word apart and answer
    /// opposite questions — an in-progress run already *has* a runner — so a
    /// gateway that sent the wrong one would return a plausible number that
    /// starts runners for work already being done. The mock matches on
    /// `status=queued`, so sending anything else 404s here rather than passing.
    #[tokio::test]
    async fn the_request_filters_on_queued_and_not_on_in_progress() {
        let server = MockServer::start().await;
        // Mounted *only* for `status=queued`. Anything else reaches no mock and
        // wiremock answers 404, which surfaces as a failure rather than a count.
        mount_queued(&server, &repo(), queued_body(3, 3)).await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("the queued filter is what this gateway sends");
        assert_eq!(demand.total(), 3);

        let requests = server.received_requests().await.expect("recorded requests");
        assert_eq!(requests.len(), 1);
        let query = requests[0].url.query().unwrap_or_default();
        assert!(
            query.contains("status=queued"),
            "the demand poll must filter on queued runs; sent {query:?}"
        );
        assert!(
            !query.contains("in_progress"),
            "in-progress runs already have a runner and are not demand; sent {query:?}"
        );
        assert!(
            query.contains(&format!("per_page={PER_PAGE}")),
            "asking for fewer than GitHub's maximum multiplies the request count \
             against the budget this module projects; sent {query:?}"
        );
    }

    // -- pagination ---------------------------------------------------------

    /// A truncated first page never reads as low demand.
    ///
    /// With no `total_count` the walk has to follow `Link: rel="next"`. A
    /// gateway that read page one and stopped would report 100 where the answer
    /// is 250 — and 100 is a plausible number, so nothing downstream could
    /// notice.
    #[tokio::test]
    async fn a_first_page_is_never_mistaken_for_the_whole_queue() {
        let server = MockServer::start().await;
        let base = server.uri();
        let runs_path = format!("/repos/{}/{}/actions/runs", repo().owner(), repo().repo());

        // Page 1 -> page 2 -> page 3, no `total_count` anywhere.
        Mock::given(method("GET"))
            .and(path(runs_path.clone()))
            .and(query_param("page", "3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(queued_body_without_total(50)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(runs_path.clone()))
            .and(query_param("page", "2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(queued_body_without_total(100))
                    .insert_header(
                        "link",
                        format!("<{base}{runs_path}?status=queued&page=3>; rel=\"next\"").as_str(),
                    ),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(runs_path.clone()))
            .and(query_param("status", QUEUED_RUN_STATUS))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(queued_body_without_total(100))
                    .insert_header(
                        "link",
                        format!("<{base}{runs_path}?status=queued&page=2>; rel=\"next\"").as_str(),
                    ),
            )
            .mount(&server)
            .await;

        let gateway = gateway(&server);
        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a walked count");

        assert_eq!(
            demand.total(),
            250,
            "the walk must sum every page; stopping at the first would report 100"
        );
        assert!(
            demand.is_complete(),
            "a walk that reached the end of the collection is exact"
        );
        assert_eq!(gateway.requests_issued(), 3, "one request per page walked");
    }

    /// The walk is bounded, and stopping at the bound makes the answer inexact
    /// rather than merely smaller.
    #[tokio::test]
    async fn a_walk_stopped_at_the_page_budget_reports_a_floor_rather_than_a_total() {
        let server = MockServer::start().await;
        let base = server.uri();
        let runs_path = format!("/repos/{}/{}/actions/runs", repo().owner(), repo().repo());

        // Every page points at a next page, forever.
        Mock::given(method("GET"))
            .and(path(runs_path.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(queued_body_without_total(100))
                    .insert_header(
                        "link",
                        format!("<{base}{runs_path}?status=queued&page=9>; rel=\"next\"").as_str(),
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
            MAX_DEMAND_FALLBACK_PAGES,
            "an endless `Link` chain must stop at the demand page budget rather than \
             spending the hourly ceiling on one repository"
        );
        assert_eq!(demand.total(), 400);
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
    /// `len() == 3`, no `Link`, and `total_count == 5000`. That contradiction is
    /// visible on the first response and is what `d18b` went to live GitHub to
    /// rule out; discarding it would leave the assumption falsifiable only by an
    /// operator noticing that far too many runners started.
    #[tokio::test]
    #[should_panic(expected = "is not the filtered count")]
    async fn a_total_count_that_disagrees_with_its_only_page_is_caught() {
        let server = MockServer::start().await;
        mount_queued(&server, &repo(), queued_body(5_000, 3)).await;
        let gateway = gateway(&server);

        let _ = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await;
    }

    /// The documented race is *not* an assertion failure.
    ///
    /// A run leaving the queue between GitHub computing `total_count` and
    /// serialising the page makes `total` exceed `listed` by a handful. Pinned
    /// to literals rather than to `MAX_BENIGN_TOTAL_COUNT_SKEW` so that widening
    /// the constant cannot silently widen this test with it.
    #[tokio::test]
    async fn a_benign_skew_between_total_count_and_its_page_is_not_a_panic() {
        let server = MockServer::start().await;
        mount_queued(&server, &repo(), queued_body(12, 4)).await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a handful of skew is the documented race, not a defect");
        assert_eq!(
            demand.total(),
            12,
            "GitHub's own total is still the answer; the skew is in the page, not the count"
        );
    }

    /// A total wider than the width this product uses is a floor, not a
    /// measurement.
    #[tokio::test]
    async fn a_total_wider_than_u32_is_reported_as_a_floor() {
        let server = MockServer::start().await;
        let base = server.uri();
        let runs_path = format!("/repos/{}/{}/actions/runs", repo().owner(), repo().repo());
        // The `Link: rel="next"` is what makes this fixture coherent rather than
        // merely convenient: four billion runs do not fit on one page, and
        // without the header the single-page tripwire would — correctly — fire
        // on `total_count` disagreeing with the page it arrived with.
        Mock::given(method("GET"))
            .and(path(runs_path.clone()))
            .and(query_param("status", QUEUED_RUN_STATUS))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(queued_body(u64::from(u32::MAX) + 1, 100))
                    .insert_header(
                        "link",
                        format!("<{base}{runs_path}?status=queued&page=2>; rel=\"next\"").as_str(),
                    ),
            )
            .mount(&server)
            .await;
        let gateway = gateway(&server);

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("an over-wide total is still an answer");

        assert_eq!(demand.total(), u32::MAX);
        assert!(
            !demand.is_complete(),
            "a clamped total is a floor: the real count is larger, not smaller"
        );
    }

    // -- organization aggregation ------------------------------------------

    /// An organization aggregates across its installed repositories, and the
    /// request count grows with that repository count.
    #[tokio::test]
    async fn an_organization_aggregates_its_repositories_and_pays_per_repository() {
        let server = MockServer::start().await;
        mount_queued(&server, &repo(), queued_body(2, 2)).await;
        mount_queued(&server, &other_repo(), queued_body(5, 5)).await;
        mount_queued(&server, &third_repo(), queued_body(0, 0)).await;
        let gateway = gateway(&server);

        let two = org_scope([repo(), other_repo()]);
        let three = org_scope([repo(), other_repo(), third_repo()]);

        assert_eq!(
            demand_requests_per_poll(&two),
            2,
            "there is no organization-wide workflow-runs endpoint, so the cost is \
             per repository"
        );
        assert_eq!(
            demand_requests_per_poll(&three),
            3,
            "and it grows with every repository the App is installed on"
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
            gateway.requests_issued(),
            u64::from(demand_requests_per_poll(&three)),
            "the measured cost must equal the projected one, or the budget model is \
             a table in a document"
        );
    }

    /// The measured cost is reported to `c3`'s budget model through the seam
    /// `c3` left for it, rather than inheriting the estimate of two.
    #[test]
    fn the_measured_demand_cost_is_reported_through_c3s_seam() {
        use crate::rest::DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH;

        let scope = org_scope([repo(), other_repo(), third_repo()]);
        let estimated = TargetCost::from_activity_scope(&scope);
        let measured = target_cost(&scope);

        assert_eq!(
            DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH, 2,
            "`c3`'s estimate priced a jobs request alongside the runs request; if it \
             ever changes, the sentence in DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL's \
             documentation explaining the difference has to change with it"
        );
        assert_ne!(
            measured, estimated,
            "the seam must actually replace the estimate; a `target_cost` that returned \
             `from_activity_scope` unchanged would report the estimate as measured"
        );
        // 1 inventory request + 3 repositories * (1 activity + 1 demand).
        assert_eq!(measured.requests_per_refresh(), 7);
        // 1 + 3 * (1 + 2), the pre-decision estimate.
        assert_eq!(estimated.requests_per_refresh(), 10);
        assert!(
            measured.requests_per_refresh() < estimated.requests_per_refresh(),
            "removing the per-run job listing removed requests; a measured cost that \
             was not lower would mean this module is still spending them"
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
    /// therefore still prices demand at the pre-decision estimate of two.
    ///
    /// The two then disagree, and an operator sees both: the projection says
    /// "roughly 10 repository targets per host" — the figure
    /// `04-subsystem-contracts.md` quotes — while `admit` will actually take
    /// thirteen. The direction is the safe one (the printed limit is
    /// conservative, so nothing is admitted that should not be), but the numbers
    /// contradict each other in the same output.
    ///
    /// It is not fixable from this file. Both remedies —
    /// changing [`crate::rest::DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH`] to
    /// one, or giving `max_repository_targets` a [`TargetCost`] argument — are
    /// edits to `crates/github/src/rest.rs`, which `c3` owns. This test records
    /// the discrepancy with its arithmetic so that whoever holds that file can
    /// act on it, and fails if it is ever closed, at which point this test and
    /// the note above should go.
    #[test]
    fn the_printed_target_ceiling_still_projects_the_pre_decision_estimate() {
        use crate::rest::{BudgetProjection, budget_allowance};
        use runner_manager_domain::model::RefreshInterval;

        let interval = RefreshInterval::default();
        let printed = BudgetProjection::max_repository_targets(interval);
        let per_hour_estimated = TargetCost::repository().requests_per_hour(interval);
        let per_hour_measured = TargetCost::repository()
            .with_demand_requests_per_repository(DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL)
            .requests_per_hour(interval);

        // 4 requests per refresh * 60 refreshes, against 3 * 60.
        assert_eq!(per_hour_estimated, 240);
        assert_eq!(per_hour_measured, 180);
        assert_eq!(
            printed, 10,
            "the printed ceiling is `04-subsystem-contracts.md`'s figure, computed from \
             the estimate"
        );
        assert_eq!(
            budget_allowance() / per_hour_measured,
            13,
            "while the cost this module actually issues would allow thirteen"
        );
        assert!(
            printed < budget_allowance() / per_hour_measured,
            "the gap is in the conservative direction, which is why this is a reporting \
             discrepancy rather than a budget overrun -- if it ever inverts, the printed \
             ceiling would be admitting targets the budget cannot pay for"
        );
    }

    /// One archived repository must not take down an organization's whole
    /// demand poll — and must not read as zero either.
    #[tokio::test]
    async fn an_organization_steps_over_a_repository_local_failure_without_reading_it_as_zero() {
        let server = MockServer::start().await;
        mount_queued(&server, &repo(), queued_body(4, 4)).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/{}/{}/actions/runs",
                other_repo().owner(),
                other_repo().repo()
            )))
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
            .and(path(format!(
                "/repos/{}/{}/actions/runs",
                repo().owner(),
                repo().repo()
            )))
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

    /// A credential failure aborts the aggregate rather than being stepped over.
    ///
    /// A revoked token is a fact about the credential, not about the repository:
    /// stepping over it would report every remaining repository as unavailable
    /// and the total as a number, when in truth nothing can be read at all.
    #[tokio::test]
    async fn a_rate_limit_aborts_the_aggregate_rather_than_being_stepped_over() {
        let server = MockServer::start().await;
        mount_queued(&server, &repo(), queued_body(1, 1)).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/{}/{}/actions/runs",
                other_repo().owner(),
                other_repo().repo()
            )))
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

    /// A token flipped between pages stops the walk before the next request.
    #[tokio::test]
    async fn cancellation_between_pages_stops_the_walk() {
        let server = MockServer::start().await;
        let base = server.uri();
        let runs_path = format!("/repos/{}/{}/actions/runs", repo().owner(), repo().repo());
        Mock::given(method("GET"))
            .and(path(runs_path.clone()))
            .respond_with(Script::new(vec![
                ResponseTemplate::new(200)
                    .set_body_json(queued_body_without_total(100))
                    .insert_header(
                        "link",
                        format!("<{base}{runs_path}?status=queued&page=2>; rel=\"next\"").as_str(),
                    ),
                ResponseTemplate::new(200).set_body_json(queued_body_without_total(100)),
            ]))
            .mount(&server)
            .await;

        let gateway = gateway(&server);
        let cancel = CancelToken::new();

        // The first page is fetched, then the caller withdraws.
        let first = gateway
            .repository_queued(&repo(), &cancel)
            .await
            .is_ok_and(|reading| reading.count == 200);
        assert!(first, "the uncancelled walk reads both pages");
        assert_eq!(gateway.requests_issued(), 2);

        cancel.cancel();
        let error = gateway
            .repository_queued(&repo(), &cancel)
            .await
            .expect_err("a cancelled token opens no socket at all");
        assert!(error.is_cancelled());
        assert_eq!(
            gateway.requests_issued(),
            2,
            "a cancelled poll must spend nothing; the count is of requests attempted"
        );
    }

    // -- the seam this module does not own ---------------------------------

    /// The `runs-on` predicate is `b1`'s, and this module re-implements no part
    /// of it.
    ///
    /// # Read this before concluding the test is in the wrong file
    ///
    /// `c4`'s specification asks for "a `runs-on` table covering forms that must
    /// match, forms that must not, and an unresolvable expression, delegating
    /// the predicate to `b1`", as part of a demand path that resolved each
    /// queued run's jobs. The owner decision recorded at length in this module's
    /// documentation removed that job resolution, and a workflow *run* carries
    /// no `runs-on` — so on the fixed-cost path there is no `RunsOn` to match
    /// and **the table has no input from this gateway**.
    ///
    /// What remains true, and what this pins, is the delegation half: the
    /// predicate, its three outcomes and its unresolvable taxonomy all live in
    /// `runner_manager_domain::policy`, this file contains no label comparison of
    /// its own, and a future `c4` that re-implements one will find this test
    /// already asserting the opposite. The table is exercised against `b1`
    /// directly so that the forms are enumerated where `c4` would have needed
    /// them, and so that the seam is loud rather than absent if the job listing
    /// is ever restored by a later owner decision.
    ///
    /// # How the second half of that claim is asserted, and how far it reaches
    ///
    /// By reading this file's own source, because nothing done to `b1` can
    /// prove anything about what *this* module contains: every assertion in the
    /// body below would pass unchanged with a full label matcher sitting beside
    /// it, which is what the claim used to amount to. The scan takes the
    /// production half — everything above `#[cfg(test)]`, with comment lines
    /// dropped so that the module documentation may keep explaining the seam —
    /// and requires that it names none of `b1`'s label vocabulary.
    ///
    /// It forbids the label types and not `runner_manager_domain::policy` as a
    /// whole, because that module also holds `ScalePolicy` and
    /// `AutoscaleConfig`, which this file could legitimately come to need. And
    /// like the needles in
    /// `nothing_in_this_crate_reserves_or_claims_a_job`, it is a tripwire on the
    /// obvious shape rather than a proof: a hand-rolled comparison of raw label
    /// strings that never names a `policy` type would walk past it. Stated
    /// rather than implied, for the same reason it is stated there.
    #[test]
    fn the_runs_on_forms_b1_matches_are_the_predicate_this_module_does_not_own() {
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

        // And the tally keeps the three apart, which is what `e1` would clamp if
        // the job listing were ever restored.
        let tally = labels.tally(&[
            RunsOn::Single(host.clone()),
            RunsOn::Single("ubuntu-latest".into()),
            expression,
        ]);
        assert_eq!(tally.demand(), 1);
        assert_eq!(tally.not_matched, 1);
        assert_eq!(tally.unresolvable.len(), 1);
        assert_eq!(tally.total_seen(), 3);

        // And the other half of this test's title, which everything above leaves
        // untouched: that the predicate exercised here has no second
        // implementation in this file. See the documentation on this test for
        // what the scan covers and what it does not.
        let production = this_file_above_its_tests_without_prose();
        for owned_by_b1 in ["RoutingLabels", "RunsOn", "DemandTally"] {
            assert!(
                !production.contains(owned_by_b1),
                "the demand gateway names `{owned_by_b1}`, which belongs to `b1`: the \
                 `runs-on` predicate has exactly one implementation and this module is \
                 not it. If the job listing was restored by a later owner decision, that \
                 decision belongs in this module's documentation and in this test before \
                 it belongs in the code"
            );
        }
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
