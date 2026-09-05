// owner: c3-rest-inventory-gateway
//
// c3 creates the fake gateway; c4 extends it with demand and JIT fixtures.

//! The fake GitHub gateway, so that groups E, F and G can be tested without a
//! network.
//!
//! [`FakeGithub`] implements `runner_manager_github::rest::InventoryGateway`.
//! It is the stand-in `e1`'s reconciliation loop, `f1`'s `host show`, `g2`'s
//! screens and `g3`'s settings are driven against — none of which should own an
//! HTTP fixture, a `wiremock` dependency, or an opinion about GitHub's wire
//! format.
//!
//! # What is programmable
//!
//! * **Inventory and activity.** Any runner set for any target, and any
//!   in-progress workflow count per repository. The two are separate knobs on
//!   purpose: they are different aggregates, and a test that can only set them
//!   together cannot catch a screen that conflates them.
//! * **Pagination.** [`FakeGithub::with_page_size`] sets how many runners a page
//!   holds, and the inventory a caller receives reports the resulting
//!   `pages()` and counts that many against
//!   [`FakeGithub::requests_issued`]. A consumer test can therefore assert that
//!   it received a complete multi-page inventory and what that inventory cost.
//!
//!   What this fake does **not** do is re-implement `Link`-header parsing: it
//!   hands back the whole collection and reports the page accounting, because
//!   the collection is what a consumer sees. The wire-level walk — a
//!   `rel="next"` that is not first, a next-page URL containing a comma, the
//!   `MAX_PAGES` ceiling — is proven against real HTTP in
//!   `crates/github/src/rest.rs`, which is the only place it can be proven.
//! * **Demand.** [`FakeGithub::with_queued_jobs`] sets a repository's queued
//!   jobs — the set `e1` tallies against a policy's routing labels. It is a
//!   separate knob from the in-progress count for the same reason those two are
//!   separate aggregates: a queued job is work waiting for a runner that does
//!   not exist, and `status=in_progress` is work that already has one. A
//!   consumer that polled the wrong one is caught by [`FakeCall`] rather than by
//!   a wrong number.
//!
//!   **The count is of runs, not of jobs.** That under-count is an owner
//!   decision, documented at length in `runner_manager_github::demand`, and this
//!   fake models the product rather than the API it wishes it had. Job-level
//!   `runs-on` fixtures are `b1`'s — [`crate::fixtures::queued_job`] and its
//!   neighbours — because after the decision no endpoint here returns jobs.
//!
//!   [`FakeGithub::with_truncated_queued_jobs`] and
//!   [`FakeGithub::with_unavailable_demand`] produce the two ways a count can be
//!   short, which a consumer rendering "unknown" rather than "idle" needs.
//! * **Just-in-time registration.** [`FakeGithub::with_jit_config`] sets what
//!   `generate-jitconfig` hands back; the registered runner reports exactly the
//!   labels and runner group the request asked for, because `v1` established
//!   that GitHub adds none and stores them lower-cased.
//! * **Failures.** [`FakeFailure`] covers a rate limit at either of GitHub's two
//!   limits, a revoked token's `401`, the authentication lockout's `403`, a
//!   permissions `403`, any other status, and cancellation.
//!   [`FakeGithub::fail_next`] queues one; [`FakeGithub::fail_always`] latches.
//!   [`FakeGithub::fail_next_registration`] queues one for the registration path
//!   specifically, which is what lets a test refuse a registration while demand
//!   still answers — and the same `FakeFailure` maps onto `c4`'s three distinct
//!   registration outcomes, so a `403`, a `404` and a `422` stay three answers
//!   rather than one.
//!
//! # What is observable
//!
//! [`FakeGithub::calls`] records every call in order, and
//! [`FakeGithub::requests_issued`] counts the REST requests a real gateway would
//! have spent. The second one exists because after D4 the request count *is* a
//! product constraint: an organization's cost scales with its installed
//! repository count, and a test that cannot see the count cannot notice a
//! consumer that started polling per repository when it used to poll per target.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use runner_manager_domain::{
    model::{Clock, OwnerRepo, ScaleTarget, TargetScope, Timestamp},
    policy::RunsOn,
};
use runner_manager_github::{
    GithubError, HeaderMap,
    demand::{DemandGateway, QueuedDemand},
    jit::{EncodedJitConfig, JitError, JitGateway, JitRegistration, JitRunner, JitRunnerRequest},
    rest::{
        ActivityCount, ActivityScope, CancelToken, InventoryError, InventoryGateway,
        RateLimitHeadroom, RateLimitKind, RateLimited, Runner, RunnerDownload, RunnerDownloads,
        RunnerInventory, RunnerStatus,
    },
};

use crate::clock::FakeClock;

/// Runners per page unless [`FakeGithub::with_page_size`] says otherwise.
/// GitHub's own maximum, which is what the real gateway asks for.
pub const DEFAULT_PAGE_SIZE: usize = 100;

/// What [`FakeGithub`] hands back as an encoded just-in-time configuration.
///
/// Shaped like the real thing — base64url of a JSON envelope, which is what
/// `v1` observed at 4,088 characters — and unmistakably not one. A consumer's
/// secret-scan test needs a value it can search *for*, so this is a constant
/// rather than a random string, and it says in its own plaintext what its
/// appearance in a log would mean.
pub const DEFAULT_JIT_CONFIG: &str = concat!(
    "eyJmaXh0dXJlIjoibm90LWEtcmVhbC1qaXQtY29uZmlndXJhdGlvbiIsIm5vdGUiOiJpZi",
    "B0aGlzIHN0cmluZyBhcHBlYXJzIGluIGEgbG9nIHRoZSByZWRhY3Rpb24gZmFpbGVkIn0"
);

/// The GitHub runner id the first registration reports.
///
/// `73` is the id `v1` was assigned at organization scope. It starts high enough
/// that it cannot be confused with an index, and it increments per registration
/// so that two runners in one test are distinguishable.
pub const FIRST_RUNNER_ID: u64 = 73;

// ---------------------------------------------------------------------------
// Programmable failures
// ---------------------------------------------------------------------------

/// A failure a test programs into [`FakeGithub`].
///
/// Each variant maps onto exactly one outcome a consumer has to handle
/// differently, and they are separate variants for the same reason `c2`'s error
/// taxonomy is: a CLI that collapses "your credential was revoked" into "GitHub
/// said no" tells an operator to fix the wrong thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeFailure {
    /// GitHub is rate limiting. Resolves by waiting.
    RateLimited {
        kind: RateLimitKind,
        retry_after_secs: Option<u64>,
        remaining: Option<u64>,
        reset_unix_secs: Option<u64>,
    },
    /// A `401` whose re-validation confirmed the credential is gone. Terminal
    /// until an interactive `auth login`.
    RevokedToken,
    /// GitHub's temporary authentication lockout: a `403` after `401`s. Back
    /// off; the credential is not the problem.
    AuthenticationLockout { retry_after_secs: u64 },
    /// A permissions `403`. Re-authenticating will not change it.
    Forbidden { message: Option<String> },
    /// Any other status GitHub can answer with.
    Status {
        status: u16,
        message: Option<String>,
    },
    /// The caller withdrew the request.
    Cancelled,
}

impl FakeFailure {
    /// The hourly quota, exhausted, resetting at `reset_unix_secs`.
    #[must_use]
    pub fn primary_rate_limit(reset_unix_secs: u64) -> Self {
        Self::RateLimited {
            kind: RateLimitKind::Primary,
            retry_after_secs: None,
            remaining: Some(0),
            reset_unix_secs: Some(reset_unix_secs),
        }
    }

    /// The short-term abuse limit, which sends `retry-after`.
    #[must_use]
    pub fn secondary_rate_limit(retry_after_secs: u64) -> Self {
        Self::RateLimited {
            kind: RateLimitKind::Secondary,
            retry_after_secs: Some(retry_after_secs),
            remaining: None,
            reset_unix_secs: None,
        }
    }

    /// A `404`, which is what a deleted or misspelled target answers.
    #[must_use]
    pub fn not_found() -> Self {
        Self::Status {
            status: 404,
            message: Some("Not Found".to_string()),
        }
    }

    fn into_error(self, path: &str) -> InventoryError {
        let github = |error| InventoryError::Github(error);
        match self {
            Self::RateLimited {
                kind,
                retry_after_secs,
                remaining,
                reset_unix_secs,
            } => InventoryError::RateLimited(RateLimited {
                kind,
                retry_after: retry_after_secs.map(Duration::from_secs),
                remaining,
                reset_unix_secs,
            }),
            Self::RevokedToken => github(GithubError::AuthenticationFailed),
            Self::AuthenticationLockout { retry_after_secs } => {
                github(GithubError::AuthenticationLockout {
                    retry_after: Duration::from_secs(retry_after_secs),
                })
            }
            // The headers are empty rather than reconstructed. `c2` carries them
            // so that rate-limit *policy* has evidence to read, and this fake
            // programs the policy's outcome directly — synthesising headers here
            // would be a second, quietly divergent encoding of the same rule.
            Self::Forbidden { message } => github(GithubError::Forbidden {
                method: "GET".to_string(),
                path: path.to_string(),
                message,
                headers: Box::new(HeaderMap::new()),
            }),
            Self::Status { status, message } => github(GithubError::Status {
                status,
                method: "GET".to_string(),
                path: path.to_string(),
                message,
                headers: Box::new(HeaderMap::new()),
            }),
            Self::Cancelled => InventoryError::Cancelled,
        }
    }

    /// The same programmed failure, as the registration path reports it.
    ///
    /// A second mapping rather than a conversion from [`InventoryError`], because
    /// the two taxonomies genuinely differ at the point that matters: a `403`,
    /// a `404` and a `422` are one `InventoryError::Github` between them and
    /// three separate [`JitError`] variants, and the whole reason `c4` split them
    /// is that an operator's next action differs for each. Routing a
    /// registration failure through the inventory taxonomy first would collapse
    /// exactly the distinction a consumer is testing.
    ///
    /// `target` and `runner_group_id` are the request's own, which is where the
    /// real gateway takes them from too: a failing response has nothing in it to
    /// name the group that was refused.
    fn into_jit_error(self, target: &ScaleTarget, runner_group_id: u64) -> JitError {
        let slug = target.slug();
        match self {
            Self::RateLimited {
                kind,
                retry_after_secs,
                remaining,
                reset_unix_secs,
            } => JitError::RateLimited(RateLimited {
                kind,
                retry_after: retry_after_secs.map(Duration::from_secs),
                remaining,
                reset_unix_secs,
            }),
            Self::Forbidden { message } => JitError::Forbidden {
                target: slug,
                runner_group_id,
                message,
            },
            Self::Status {
                status: 404,
                message,
            } => JitError::NotFound {
                target: slug,
                runner_group_id,
                message,
            },
            Self::Status {
                status: 422,
                message,
            } => JitError::Rejected {
                target: slug,
                message,
            },
            Self::Cancelled => JitError::Cancelled,
            Self::RevokedToken => JitError::Github(GithubError::AuthenticationFailed),
            Self::AuthenticationLockout { retry_after_secs } => {
                JitError::Github(GithubError::AuthenticationLockout {
                    retry_after: Duration::from_secs(retry_after_secs),
                })
            }
            Self::Status { status, message } => JitError::Github(GithubError::Status {
                status,
                method: "POST".to_string(),
                path: slug,
                message,
                headers: Box::new(HeaderMap::new()),
            }),
        }
    }
}

/// One call a consumer made, in the order it made them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeCall {
    ListRunners(ScaleTarget),
    InProgressActivity(ScaleTarget),
    RunnerDownloads(ScaleTarget),
    /// A demand poll. Distinct from [`FakeCall::InProgressActivity`] because the
    /// two ask GitHub different questions — `status=queued` against
    /// `status=in_progress` — and a consumer that polled the wrong one would
    /// otherwise look identical here.
    QueuedDemand(ScaleTarget),
    /// A registration deletion, with the runner id that was asked for.
    ///
    /// The id travels because that is the whole content of the call, and a
    /// consumer that deleted the *wrong* runner — another attempt's, or one of
    /// the operator's own long-lived registrations — would otherwise be
    /// indistinguishable here from one that deleted the right one.
    RemoveRunner(ScaleTarget, u64),
    /// A just-in-time registration, with the request that was sent.
    ///
    /// The whole request travels rather than only the target, because the two
    /// things most worth asserting about a registration are in it: the labels
    /// (`v1`: none are added implicitly, so what is asked for is what exists)
    /// and the runner group id (mandatory, with no server-side default).
    GenerateJitConfig(ScaleTarget, JitRunnerRequest),
}

// ---------------------------------------------------------------------------
// The fake
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeState {
    runners: BTreeMap<ScaleTarget, Vec<Runner>>,
    activity: BTreeMap<OwnerRepo, u32>,
    /// Repositories whose count is a **floor**, as the bounded fallback walk
    /// leaves them.
    truncated_activity: BTreeSet<OwnerRepo>,
    /// Repositories that cannot be counted at all, and the reason each gives.
    unavailable_activity: BTreeMap<OwnerRepo, String>,
    downloads: Vec<RunnerDownload>,
    /// Queued **jobs** per repository, each with the `runs-on` it requires —
    /// the demand signal.
    ///
    /// Deliberately a separate map from `activity`, and not because the numbers
    /// might differ by accident: they answer different questions. `activity` is
    /// `status=in_progress`, which is work that already has a runner; this is
    /// the set of jobs waiting for one that does not exist. A fixture that could
    /// only set them together could not catch a consumer that read the wrong
    /// one.
    ///
    /// The unit is a **job** rather than a run, which is what the real gateway
    /// counts now that the owner decision recorded in
    /// `runner_manager_github::demand` has been reversed. Each entry carries its
    /// labels so that a consumer applying `RoutingLabels::tally` can be tested
    /// against a fixture that really does distinguish this host's jobs from
    /// another host's.
    queued: BTreeMap<OwnerRepo, Vec<RunsOn>>,
    /// Repositories whose queued count is a **floor**, as a run cap or a job
    /// page budget leaves them.
    truncated_queued: BTreeSet<OwnerRepo>,
    /// Repositories that cannot be polled at all, and the reason each gives.
    unavailable_queued: BTreeMap<OwnerRepo, String>,
    /// What `generate-jitconfig` answers with.
    jit_config: String,
    /// The id the next registration reports, incremented per call so that two
    /// registrations in one test are distinguishable.
    next_runner_id: u64,
    /// Registration failures, kept apart from `queued_failures` so that a test
    /// can refuse a registration while demand still answers — which is the
    /// ordinary case an `e1` test needs and the one a shared queue cannot
    /// express.
    queued_jit_failures: VecDeque<FakeFailure>,
    calls: Vec<FakeCall>,
    requests_issued: u64,
    headroom: Option<RateLimitHeadroom>,
    queued_failures: VecDeque<FakeFailure>,
    latched_failure: Option<FakeFailure>,
}

/// A GitHub gateway that answers from what a test put in it.
#[derive(Debug)]
pub struct FakeGithub {
    state: Mutex<FakeState>,
    page_size: usize,
    clock: Arc<dyn Clock>,
}

impl Default for FakeGithub {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeGithub {
    /// A gateway that knows about nothing: every target is empty and every count
    /// is zero.
    ///
    /// Empty rather than pre-populated, because "no runners" is a state screens
    /// have to render correctly and a fixture that never produces it is a
    /// fixture that hides the empty-state bug.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(FakeState {
                jit_config: DEFAULT_JIT_CONFIG.to_string(),
                next_runner_id: FIRST_RUNNER_ID,
                ..FakeState::default()
            }),
            page_size: DEFAULT_PAGE_SIZE,
            clock: Arc::new(FakeClock::default()),
        }
    }

    /// How many runners one page holds, for the page accounting a consumer sees.
    ///
    /// # Panics
    /// If `page_size` is zero: a page that holds nothing paginates forever, and
    /// a fixture that silently did so would look like a hang rather than a
    /// mistake.
    #[must_use]
    pub fn with_page_size(mut self, page_size: usize) -> Self {
        assert!(page_size > 0, "a page must hold at least one runner");
        self.page_size = page_size;
        self
    }

    /// Drive [`InventoryGateway::now`] from a clock the test controls.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The runners this target reports.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn with_runners(self, target: ScaleTarget, runners: Vec<Runner>) -> Self {
        self.lock().runners.insert(target, runners);
        self
    }

    /// This repository's in-progress workflow count.
    ///
    /// Set per repository, including for an organization target, because that is
    /// how the real gateway reads it: there is no organization-wide workflow-runs
    /// endpoint, so an organization's number is the sum of its repositories'.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn with_in_progress(self, repository: OwnerRepo, count: u32) -> Self {
        self.lock().activity.insert(repository, count);
        self
    }

    /// This repository's in-progress count as a **floor** rather than a total.
    ///
    /// What the real gateway produces when GitHub sends no `total_count` and the
    /// fallback walk stops at its page bound: the repository answered, `floor`
    /// runs were counted, and there may be more.
    ///
    /// # Why this exists
    ///
    /// [`ActivityCount::is_complete`] has two causes for `false` and, until this
    /// builder, the fake could produce **neither**. `ActivityCount::new` and
    /// `::of` were the only public constructors, both yield an empty `truncated`
    /// *and* an empty `unavailable`, and the fields are private — so every count
    /// this fake returned was unconditionally complete, and a consumer rendering
    /// the incomplete path could not write a test for it at all.
    ///
    /// Pair with [`Self::with_unavailable_repository`], and keep the two
    /// distinct: a floor is a lower bound that is safe to scale **up** from, an
    /// unavailable repository is unknown and is not.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn with_truncated_in_progress(self, repository: OwnerRepo, floor: u32) -> Self {
        let mut state = self.lock();
        state.activity.insert(repository.clone(), floor);
        state.truncated_activity.insert(repository);
        drop(state);
        self
    }

    /// A repository the activity count cannot read at all, and why.
    ///
    /// Reported through [`ActivityCount::unavailable`] rather than as a zero,
    /// which is the distinction the real aggregate makes and the one a consumer
    /// most needs a fixture for: a repository that could not be counted is
    /// unknown, not idle. It is therefore left **out** of
    /// [`ActivityCount::per_repository`] entirely, exactly as the real gateway
    /// leaves it, so a consumer that reads the map directly sees the same
    /// absence in the fake as in production.
    ///
    /// The request is still charged. The real gateway spends one before learning
    /// the repository is unreadable, and a fixture that charged nothing would
    /// under-report the budget a consumer is asserting against.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn with_unavailable_repository(
        self,
        repository: OwnerRepo,
        reason: impl Into<String>,
    ) -> Self {
        self.lock()
            .unavailable_activity
            .insert(repository, reason.into());
        self
    }

    /// The runner packages this gateway publishes.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn with_downloads(self, downloads: Vec<RunnerDownload>) -> Self {
        self.lock().downloads = downloads;
        self
    }

    /// This repository's queued jobs — its demand signal.
    ///
    /// # This is a set of jobs, not a count of runs
    ///
    /// The real gateway lists each active run's jobs and keeps the ones still
    /// queued, so the unit `e1` clamps is a job. A run holding eight matrix jobs
    /// is eight entries here, which is the whole point: under the previous owner
    /// decision it was `1`, and the resulting serial-matrix defect is what
    /// `runner_manager_github::demand` now documents at length.
    ///
    /// Build the entries with `b1`'s fixtures —
    /// [`crate::fixtures::queued_job`], [`crate::fixtures::queued_jobs`] and
    /// [`crate::fixtures::unresolvable_job`] — because the labels are what
    /// `RoutingLabels::tally` matches, and a fixture whose jobs all carried this
    /// host's labels could not catch a consumer that forgot to filter.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn with_queued_jobs(
        self,
        repository: OwnerRepo,
        jobs: impl IntoIterator<Item = RunsOn>,
    ) -> Self {
        self.lock()
            .queued
            .insert(repository, jobs.into_iter().collect());
        self
    }

    /// This repository's queued jobs as a **floor** rather than a total.
    ///
    /// What the real gateway produces when a repository has more active runs
    /// than its per-poll caps will resolve, or when one run's job listing walks
    /// to its page budget. Pair with [`Self::with_unavailable_demand`] and keep
    /// the two distinct: a floor is a lower bound that is safe to scale **up**
    /// from, an unavailable repository is unknown and is not.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn with_truncated_queued_jobs(
        self,
        repository: OwnerRepo,
        floor: impl IntoIterator<Item = RunsOn>,
    ) -> Self {
        let mut state = self.lock();
        state
            .queued
            .insert(repository.clone(), floor.into_iter().collect());
        state.truncated_queued.insert(repository);
        drop(state);
        self
    }

    /// A repository whose demand cannot be polled at all, and why.
    ///
    /// **What this produces depends on the scope of the target being polled,
    /// because it does in the real gateway.**
    ///
    /// At **organization** scope the poll succeeds and the repository is
    /// reported through [`QueuedDemand::unavailable`] rather than as a zero,
    /// which is the distinction that matters most on this read model: a zero
    /// tells `e1` there is nothing to serve, and `e1` acts on that by starting
    /// no runners. It is left **out** of [`QueuedDemand::per_repository`]
    /// entirely, exactly as the real gateway leaves it.
    ///
    /// At **repository** scope the poll **fails**. Stepping over the only
    /// repository in scope would flatten the whole reading to `0`, which is the
    /// confusion the paragraph above exists to prevent — so `RestDemand` gates
    /// the step-over on the target's scope, and this fake reads the same gate.
    /// A fixture that answered `Ok(total 0)` where production answers `Err`
    /// would leave a consumer's test green over exactly the bug it was written
    /// to catch.
    ///
    /// The request is still charged either way — the real gateway spends one
    /// before learning the repository is unreadable.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn with_unavailable_demand(self, repository: OwnerRepo, reason: impl Into<String>) -> Self {
        self.lock()
            .unavailable_queued
            .insert(repository, reason.into());
        self
    }

    /// The encoded configuration `generate-jitconfig` hands back.
    ///
    /// Defaults to [`DEFAULT_JIT_CONFIG`]. Override it when a test needs to
    /// distinguish two registrations, or needs a value its own log scan searches
    /// for.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn with_jit_config(self, config: impl Into<String>) -> Self {
        self.lock().jit_config = config.into();
        self
    }

    /// Fail the next **registration**, then recover.
    ///
    /// Separate from [`FakeGithub::fail_next`] on purpose: the ordinary case an
    /// `e1` test needs is a target whose demand answers normally and whose
    /// registration is refused, and one shared queue cannot express it — the
    /// demand poll would consume the failure before the registration ever ran.
    ///
    /// [`FakeGithub::fail_always`] still latches across **both**, because the
    /// failures it is for — a revoked token, an exhausted quota — really are
    /// facts about the credential rather than about one endpoint.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    pub fn fail_next_registration(&self, failure: FakeFailure) {
        self.lock().queued_jit_failures.push_back(failure);
    }

    /// What [`InventoryGateway::headroom`] reports.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn with_headroom(self, headroom: RateLimitHeadroom) -> Self {
        self.lock().headroom = Some(headroom);
        self
    }

    /// Fail the next call, then recover. Queued failures are consumed in order.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    pub fn fail_next(&self, failure: FakeFailure) {
        self.lock().queued_failures.push_back(failure);
    }

    /// Fail every call until [`FakeGithub::recover`]. This is the shape of a
    /// revoked token or an exhausted quota, which do not clear because one
    /// request went by.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    pub fn fail_always(&self, failure: FakeFailure) {
        self.lock().latched_failure = Some(failure);
    }

    /// Forget every programmed failure, latched and queued.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    pub fn recover(&self) {
        let mut state = self.lock();
        state.latched_failure = None;
        state.queued_failures.clear();
        state.queued_jit_failures.clear();
    }

    /// Every call a consumer made, in order.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn calls(&self) -> Vec<FakeCall> {
        self.lock().calls.clone()
    }

    /// How many REST requests a real gateway would have spent answering the
    /// calls made so far.
    ///
    /// This is the number the shared 5,000/hour budget is measured in, so a
    /// consumer that quietly started costing one request per repository where it
    /// used to cost one per target has somewhere to be caught.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn requests_issued(&self) -> u64 {
        self.lock().requests_issued
    }

    /// How many pages this target's programmed inventory spans.
    ///
    /// # Panics
    /// If a previous holder panicked while the state lock was held.
    #[must_use]
    pub fn pages_for(&self, target: &ScaleTarget) -> usize {
        let state = self.lock();
        let count = state.runners.get(target).map_or(0, Vec::len);
        self.pages_for_count(count)
    }

    fn pages_for_count(&self, count: usize) -> usize {
        // An empty collection still costs the request that discovered it was
        // empty, which is why this floors at one rather than at zero.
        count.div_ceil(self.page_size).max(1)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().expect("FakeGithub state lock poisoned")
    }

    /// Record the call, then decide whether it fails.
    fn begin(&self, call: FakeCall, path: &str) -> Result<(), InventoryError> {
        let mut state = self.lock();
        state.calls.push(call);
        if let Some(latched) = state.latched_failure.clone() {
            return Err(latched.into_error(path));
        }
        match state.queued_failures.pop_front() {
            Some(failure) => Err(failure.into_error(path)),
            None => Ok(()),
        }
    }

    /// The registration path's counterpart, over the registration taxonomy.
    ///
    /// The latched failure is shared with [`Self::begin`] and the one-shot queue
    /// is not; see [`FakeGithub::fail_next_registration`] for why the two are
    /// split that way.
    fn begin_registration(
        &self,
        target: &ScaleTarget,
        request: &JitRunnerRequest,
    ) -> Result<(), JitError> {
        let mut state = self.lock();
        state
            .calls
            .push(FakeCall::GenerateJitConfig(target.clone(), request.clone()));
        if let Some(latched) = state.latched_failure.clone() {
            return Err(latched.into_jit_error(target, request.runner_group_id()));
        }
        match state.queued_jit_failures.pop_front() {
            Some(failure) => Err(failure.into_jit_error(target, request.runner_group_id())),
            None => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

/// A runner, built one property at a time.
///
/// Defaults are the boring case — online, idle, non-ephemeral, unlabelled — so
/// that a test states only what it is about.
#[derive(Debug, Clone)]
pub struct RunnerBuilder {
    runner: Runner,
}

/// A runner named `name` with id `id`, online and idle.
#[must_use]
pub fn runner(id: u64, name: impl Into<String>) -> RunnerBuilder {
    RunnerBuilder {
        runner: Runner {
            id,
            name: name.into(),
            os: "win".to_string(),
            status: RunnerStatus::Online,
            busy: false,
            ephemeral: Some(true),
            labels: Vec::new(),
        },
    }
}

impl RunnerBuilder {
    #[must_use]
    pub fn busy(mut self) -> Self {
        self.runner.busy = true;
        self
    }

    #[must_use]
    pub fn offline(mut self) -> Self {
        self.runner.status = RunnerStatus::Offline;
        self
    }

    #[must_use]
    pub fn status(mut self, status: RunnerStatus) -> Self {
        self.runner.status = status;
        self
    }

    #[must_use]
    pub fn os(mut self, os: impl Into<String>) -> Self {
        self.runner.os = os.into();
        self
    }

    /// `None` models a GitHub response that omitted the field, which is a
    /// different fact from "not ephemeral".
    #[must_use]
    pub fn ephemeral(mut self, ephemeral: Option<bool>) -> Self {
        self.runner.ephemeral = ephemeral;
        self
    }

    /// Labels as GitHub stores them — **lower-cased**, and with nothing added
    /// implicitly (`docs/spikes/d18-org-jit-verification.md`, point 3). This
    /// lower-cases what it is given so a fixture cannot accidentally assert a
    /// casing GitHub does not preserve.
    #[must_use]
    pub fn labels<I, S>(mut self, labels: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.runner.labels = labels
            .into_iter()
            .map(|label| label.as_ref().trim().to_ascii_lowercase())
            .collect();
        self
    }

    #[must_use]
    pub fn build(self) -> Runner {
        self.runner
    }
}

/// `count` distinct runners, for testing a collection rather than a runner.
///
/// Deterministic ids and names, so a snapshot of them is reproducible.
#[must_use]
pub fn runners(count: usize) -> Vec<Runner> {
    (0..count)
        .map(|i| {
            let id = u64::try_from(i).unwrap_or(u64::MAX) + 1;
            runner(id, format!("runner-{id:04}")).build()
        })
        .collect()
}

/// A published runner package with a digest.
#[must_use]
pub fn download(os: impl Into<String>, architecture: impl Into<String>) -> RunnerDownload {
    let os = os.into();
    let architecture = architecture.into();
    RunnerDownload {
        filename: format!("actions-runner-{os}-{architecture}-2.330.0.zip"),
        download_url: format!(
            "https://github.com/actions/runner/releases/download/v2.330.0/\
             actions-runner-{os}-{architecture}-2.330.0.zip"
        ),
        // Not a real digest, and shaped like one: 64 hex characters.
        sha256_checksum: Some("0".repeat(64)),
        os,
        architecture,
    }
}

/// A published runner package with **no** digest.
///
/// `sha256_checksum` is optional in GitHub's schema, and `e2` must fail closed
/// when it is absent rather than skipping verification
/// (`05-infrastructure.md`). This is the fixture that makes that path
/// reachable — without it, the fail-closed branch is unreachable in every test
/// and the product ships a control nothing exercised.
#[must_use]
pub fn download_without_checksum(
    os: impl Into<String>,
    architecture: impl Into<String>,
) -> RunnerDownload {
    RunnerDownload {
        sha256_checksum: None,
        ..download(os, architecture)
    }
}

// ---------------------------------------------------------------------------
// The gateway implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl InventoryGateway for FakeGithub {
    async fn list_runners(
        &self,
        target: &ScaleTarget,
        cancel: &CancelToken,
    ) -> Result<RunnerInventory, InventoryError> {
        cancel.check()?;
        self.begin(FakeCall::ListRunners(target.clone()), &target.slug())?;

        let mut state = self.lock();
        let runners = state.runners.get(target).cloned().unwrap_or_default();
        let pages = self.pages_for_count(runners.len());
        state.requests_issued += u64::try_from(pages).unwrap_or(u64::MAX);
        let total = u64::try_from(runners.len()).unwrap_or(u64::MAX);
        Ok(RunnerInventory::paged(
            target.clone(),
            runners,
            Some(total),
            pages,
            false,
        ))
    }

    async fn remove_runner(
        &self,
        target: &ScaleTarget,
        runner_id: u64,
        cancel: &CancelToken,
    ) -> Result<(), InventoryError> {
        cancel.check()?;
        self.begin(
            FakeCall::RemoveRunner(target.clone(), runner_id),
            &target.slug(),
        )?;

        let mut state = self.lock();
        state.requests_issued += 1;
        // Deleting an absent registration is a success, exactly as the real
        // gateway's `404` arm is; the postcondition is that it is gone.
        if let Some(runners) = state.runners.get_mut(target) {
            runners.retain(|runner| runner.id != runner_id);
        }
        Ok(())
    }

    async fn in_progress_activity(
        &self,
        scope: &ActivityScope,
        cancel: &CancelToken,
    ) -> Result<ActivityCount, InventoryError> {
        cancel.check()?;
        self.begin(
            FakeCall::InProgressActivity(scope.target().clone()),
            &scope.target().slug(),
        )?;

        let mut state = self.lock();
        // One request per repository, exactly as the real gateway spends them.
        // An organization reaching ten repositories costs ten, and a consumer
        // asserting otherwise should fail here rather than in production.
        state.requests_issued += u64::try_from(scope.repositories().len()).unwrap_or(u64::MAX);

        // An unavailable repository is left out of the counts rather than
        // folded in as zero, which is what the real aggregate does: nothing was
        // learned about it, and a missing count is not an idle one.
        let counts = scope
            .repositories()
            .iter()
            .filter(|repository| !state.unavailable_activity.contains_key(*repository))
            .map(|repository| {
                let count = state.activity.get(repository).copied().unwrap_or(0);
                (repository.clone(), count)
            })
            .collect();

        let mut activity = ActivityCount::new(counts);
        for repository in scope.repositories() {
            if let Some(reason) = state.unavailable_activity.get(repository) {
                activity = activity.with_unavailable(repository.clone(), reason.clone());
            } else if state.truncated_activity.contains(repository) {
                activity = activity.with_truncated(repository.clone());
            }
        }
        Ok(activity)
    }

    async fn runner_downloads(
        &self,
        target: &ScaleTarget,
        cancel: &CancelToken,
    ) -> Result<RunnerDownloads, InventoryError> {
        cancel.check()?;
        self.begin(FakeCall::RunnerDownloads(target.clone()), &target.slug())?;

        let mut state = self.lock();
        state.requests_issued += 1;
        Ok(RunnerDownloads::new(state.downloads.clone()))
    }

    fn headroom(&self) -> Option<RateLimitHeadroom> {
        self.lock().headroom
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }
}

#[async_trait::async_trait]
impl DemandGateway for FakeGithub {
    async fn queued_demand(
        &self,
        scope: &ActivityScope,
        cancel: &CancelToken,
    ) -> Result<QueuedDemand, InventoryError> {
        cancel.check()?;
        self.begin(
            FakeCall::QueuedDemand(scope.target().clone()),
            &scope.target().slug(),
        )?;

        let mut state = self.lock();
        // One request per repository, exactly as the real gateway spends them.
        // An organization reaching ten repositories costs ten, and this is the
        // number `f2`'s `add` refusals are computed from, so a consumer that
        // quietly started costing more should fail here rather than in
        // production.
        state.requests_issued += u64::try_from(scope.repositories().len()).unwrap_or(u64::MAX);

        // Only an *aggregate* steps over a repository it cannot poll, and
        // `RestDemand` gates that on exactly this comparison. A repository
        // target has one repository in scope, so stepping over it would turn a
        // permissions or existence failure into demand `0` — and `e1` reads a
        // zero as "start no runners for a target we can see", when the truth is
        // "we cannot see this target at all". Production returns `Err` there;
        // so does this.
        //
        // The status is `404` rather than a programmed one because
        // `with_unavailable_demand` programs the *outcome* — unreadable — and
        // not which of the two answers produced it. `RestDemand` steps over a
        // `403` and a `404` alike, so a fake that made the caller choose would
        // be offering a distinction the read model does not have. Same reason
        // the headers are empty above.
        if scope.target().scope() != TargetScope::Organization
            && let Some((repository, reason)) = scope.repositories().iter().find_map(|repository| {
                state
                    .unavailable_queued
                    .get(repository)
                    .map(|reason| (repository.clone(), reason.clone()))
            })
        {
            return Err(InventoryError::Github(GithubError::Status {
                status: 404,
                method: "GET".to_string(),
                path: format!(
                    "/repos/{}/{}/actions/runs",
                    repository.owner(),
                    repository.repo()
                ),
                message: Some(reason),
                headers: Box::new(HeaderMap::new()),
            }));
        }

        let jobs = scope
            .repositories()
            .iter()
            .filter(|repository| !state.unavailable_queued.contains_key(*repository))
            .map(|repository| {
                let jobs = state.queued.get(repository).cloned().unwrap_or_default();
                (repository.clone(), jobs)
            })
            .collect();

        let mut demand = QueuedDemand::new(jobs);
        for repository in scope.repositories() {
            if let Some(reason) = state.unavailable_queued.get(repository) {
                demand = demand.with_unavailable(repository.clone(), reason.clone());
            } else if state.truncated_queued.contains(repository) {
                demand = demand.with_truncated(repository.clone());
            }
        }
        Ok(demand)
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }
}

#[async_trait::async_trait]
impl JitGateway for FakeGithub {
    async fn generate_jit_config(
        &self,
        target: &ScaleTarget,
        request: &JitRunnerRequest,
        cancel: &CancelToken,
    ) -> Result<JitRegistration, JitError> {
        if cancel.is_cancelled() {
            return Err(JitError::Cancelled);
        }
        self.begin_registration(target, request)?;

        let mut state = self.lock();
        state.requests_issued += 1;
        let id = state.next_runner_id;
        state.next_runner_id += 1;
        let config = EncodedJitConfig::new(state.jit_config.clone());

        Ok(JitRegistration::new(
            config,
            JitRunner {
                id,
                name: request.name().to_string(),
                os: "windows".to_string(),
                // `v1` read back `offline`: the runner is registered but its
                // process has not started, which is the state `e3` finds it in.
                status: "offline".to_string(),
                busy: false,
                runner_group_id: Some(request.runner_group_id()),
                // Exactly the labels requested, lower-cased — the two facts `v1`
                // established about what GitHub stores. A fake that added
                // `self-hosted` here would let a consumer's test pass on a
                // runner the real GitHub never creates.
                labels: request
                    .labels()
                    .iter()
                    .map(|label| label.to_ascii_lowercase())
                    .collect(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runner_manager_github::rest::CancelToken;

    fn repo() -> OwnerRepo {
        OwnerRepo::parse("octo/dashboard").expect("a valid owner/repo")
    }

    fn other_repo() -> OwnerRepo {
        OwnerRepo::parse("octo/api").expect("a valid owner/repo")
    }

    fn target() -> ScaleTarget {
        ScaleTarget::Repository(repo())
    }

    fn org_scope(repositories: impl IntoIterator<Item = OwnerRepo>) -> ActivityScope {
        ActivityScope::organization(
            runner_manager_domain::model::Org::new("octo-org").expect("a valid organization login"),
            repositories,
        )
    }

    /// The fake can produce an **incomplete** count, which until now it could
    /// not do at all.
    ///
    /// `ActivityCount`'s only public constructors both yield empty `truncated`
    /// and empty `unavailable` over private fields, so every count this fake
    /// returned was unconditionally complete and `is_complete() == false` was
    /// unreachable from any consumer's test. A fixture that cannot produce a
    /// state is a fixture that hides every bug in rendering it.
    #[tokio::test]
    async fn a_truncated_count_is_a_floor_that_says_so() {
        let gateway = FakeGithub::new().with_truncated_in_progress(repo(), 400);

        let activity = gateway
            .in_progress_activity(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("a truncated count is an answer, not a failure");

        assert_eq!(activity.total(), 400, "the floor is still a number");
        assert!(
            !activity.is_complete(),
            "a count clipped by the page bound must not read as exact"
        );
        assert!(activity.is_truncated(&repo()));
        assert!(
            activity.unavailable().is_empty(),
            "truncated is not unavailable: this repository answered, and its answer is a \
             floor that is safe to scale up from"
        );
        assert_eq!(gateway.requests_issued(), 1);
    }

    /// The other cause of `is_complete() == false`, and the one with the
    /// opposite remedy: unknown rather than a lower bound.
    #[tokio::test]
    async fn an_unavailable_repository_is_reported_as_unknown_not_as_zero() {
        let gateway = FakeGithub::new()
            .with_in_progress(repo(), 3)
            .with_unavailable_repository(other_repo(), "repository archived");

        let activity = gateway
            .in_progress_activity(&org_scope([repo(), other_repo()]), &CancelToken::new())
            .await
            .expect("an aggregate steps over a repository it cannot read");

        assert!(!activity.is_complete());
        assert!(
            activity.truncated().is_empty(),
            "unavailable is not truncated: nothing at all was learned here"
        );
        assert_eq!(activity.unavailable().len(), 1);
        assert_eq!(activity.unavailable()[0].repository, other_repo());
        assert_eq!(activity.unavailable()[0].reason, "repository archived");
        assert_eq!(
            activity.for_repository(&other_repo()),
            None,
            "a repository that could not be counted is absent from the map, not present \
             as a zero -- a zero would render a possibly-busy repository as idle"
        );
        assert_eq!(activity.total(), 3, "and the total is only what was read");
        assert_eq!(
            gateway.requests_issued(),
            2,
            "the request that discovered the repository was unreadable was still spent"
        );
    }

    /// The default stays complete, so the incomplete path is something a test
    /// opts into rather than something it trips over.
    #[tokio::test]
    async fn an_unprogrammed_count_is_complete() {
        let gateway = FakeGithub::new().with_in_progress(repo(), 2);

        let activity = gateway
            .in_progress_activity(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("readable");

        assert!(activity.is_complete());
        assert!(activity.truncated().is_empty());
        assert!(activity.unavailable().is_empty());
    }

    /// The page accounting a consumer's budget assertions rest on.
    #[tokio::test]
    async fn the_page_count_follows_the_programmed_page_size() {
        let gateway = FakeGithub::new()
            .with_page_size(10)
            .with_runners(target(), runners(25));

        assert_eq!(
            gateway.pages_for(&target()),
            3,
            "25 at 10 a page is 3 pages"
        );

        let inventory = gateway
            .list_runners(&target(), &CancelToken::new())
            .await
            .expect("readable");
        assert_eq!(inventory.len(), 25);
        assert_eq!(inventory.pages(), 3);
        assert_eq!(inventory.reported_total(), Some(25));
        assert_eq!(gateway.requests_issued(), 3);
    }

    /// An empty target still costs the request that discovered it was empty.
    /// Charging zero would let a consumer poll an idle host for free, which is
    /// not how the shared budget works.
    #[tokio::test]
    async fn an_empty_target_still_costs_one_request() {
        let gateway = FakeGithub::new();
        assert_eq!(gateway.pages_for(&target()), 1);

        let inventory = gateway
            .list_runners(&target(), &CancelToken::new())
            .await
            .expect("readable");
        assert!(inventory.is_empty());
        assert_eq!(inventory.pages(), 1);
        assert_eq!(gateway.requests_issued(), 1);
    }

    #[test]
    #[should_panic(expected = "a page must hold at least one runner")]
    fn a_zero_page_size_is_refused_rather_than_paginating_forever() {
        let _ = FakeGithub::new().with_page_size(0);
    }

    /// A latched failure wins over a queued one: an exhausted quota does not
    /// take turns with a `404`.
    #[tokio::test]
    async fn a_latched_failure_takes_precedence_over_the_queue() {
        let gateway = FakeGithub::new();
        gateway.fail_next(FakeFailure::not_found());
        gateway.fail_always(FakeFailure::RevokedToken);

        for _ in 0..2 {
            let error = gateway
                .list_runners(&target(), &CancelToken::new())
                .await
                .expect_err("latched");
            assert!(
                matches!(
                    &error,
                    InventoryError::Github(GithubError::AuthenticationFailed)
                ),
                "{error}"
            );
        }

        gateway.recover();
        assert!(
            gateway
                .list_runners(&target(), &CancelToken::new())
                .await
                .is_ok(),
            "`recover` clears the queue as well as the latch"
        );
    }

    /// Queued failures are consumed in order, one per call.
    #[tokio::test]
    async fn queued_failures_are_consumed_in_order() {
        let gateway = FakeGithub::new();
        gateway.fail_next(FakeFailure::not_found());
        gateway.fail_next(FakeFailure::secondary_rate_limit(30));

        let first = gateway
            .list_runners(&target(), &CancelToken::new())
            .await
            .expect_err("the first queued failure");
        assert!(!first.is_rate_limited(), "{first}");

        let second = gateway
            .list_runners(&target(), &CancelToken::new())
            .await
            .expect_err("the second queued failure");
        assert!(second.is_rate_limited(), "{second}");

        assert!(
            gateway
                .list_runners(&target(), &CancelToken::new())
                .await
                .is_ok(),
            "the queue is empty again"
        );
        assert_eq!(
            gateway.calls().len(),
            3,
            "a failed call is still a call, and a consumer asserting on call \
             counts needs to see it"
        );
    }

    /// A failed call spends no request, because no request reached the wire.
    #[tokio::test]
    async fn a_failed_call_costs_no_request() {
        let gateway = FakeGithub::new().with_runners(target(), runners(5));
        gateway.fail_next(FakeFailure::RevokedToken);
        let _ = gateway.list_runners(&target(), &CancelToken::new()).await;
        assert_eq!(gateway.requests_issued(), 0);
    }

    /// The builder's defaults and the two facts D18 established about labels.
    #[test]
    fn the_runner_builder_stores_labels_the_way_github_does() {
        let built = runner(73, "rm-d18-spike-ivanpc-1753")
            .labels(["RM-Home-Win-X64", " Windows "])
            .build();

        assert_eq!(
            built.labels,
            ["rm-home-win-x64", "windows"],
            "GitHub lower-cases what it stores (D18, point 3), and a fixture that \
             kept the casing would let a consumer assert one GitHub does not keep"
        );
        assert!(built.has_label("WINDOWS"));
        assert!(
            !built.has_label("self-hosted"),
            "no label is added implicitly (D18, point 1)"
        );
        assert_eq!(built.status, RunnerStatus::Online);
        assert!(!built.busy);
        assert_eq!(built.ephemeral, Some(true));

        let unknown = runner(1, "legacy").ephemeral(None).offline().build();
        assert_eq!(
            unknown.ephemeral, None,
            "absent is a fact a fixture must be able to express, because absent \
             is not `false`"
        );
        assert_eq!(unknown.status, RunnerStatus::Offline);
    }

    /// Fixtures are reproducible, so a `g2` snapshot of them is too.
    #[test]
    fn generated_runners_are_deterministic() {
        let first = runners(3);
        assert_eq!(first, runners(3));
        assert_eq!(
            first.iter().map(|r| r.id).collect::<Vec<_>>(),
            [1, 2, 3],
            "ids start at one; a zero id would collide with `Default`"
        );
        assert_eq!(first[0].name, "runner-0001");
        assert!(runners(0).is_empty());
    }

    /// The download fixtures differ in exactly the field `e2` fails closed on.
    #[test]
    fn the_download_fixtures_differ_only_in_the_published_digest() {
        let with = download("win", "x64");
        let without = download_without_checksum("win", "x64");

        assert_eq!(with.sha256_checksum().map(str::len), Some(64));
        assert_eq!(without.sha256_checksum(), None);
        assert_eq!(with.os, without.os);
        assert_eq!(with.architecture, without.architecture);
        assert_eq!(with.download_url, without.download_url);
        assert_eq!(with.filename, without.filename);
    }

    /// `headroom` is programmable, so `f1` and `g3` can render a quota display
    /// without a network.
    #[test]
    fn the_reported_headroom_is_what_the_test_programmed() {
        let headroom = RateLimitHeadroom {
            limit: Some(5_000),
            remaining: Some(120),
            reset_unix_secs: Some(1_787_274_000),
        };
        let gateway = FakeGithub::new().with_headroom(headroom);
        assert_eq!(gateway.headroom(), Some(headroom));
        assert_eq!(
            FakeGithub::new().headroom(),
            None,
            "nothing observed is not the same as a full quota"
        );
    }

    // -- demand and just-in-time registration -------------------------------

    /// The reconciliation loop `e1` will write, driven entirely against this
    /// fake: read demand, clamp it against the policy's ceiling, and register
    /// that many runners.
    ///
    /// This is the test `c4`'s Definition of Done asks for — "the fake gateway
    /// … is used by an `e1` test". `crates/agent/src/reconcile.rs` is still a
    /// one-line stub owned by `e1`, so the test lives here, where it can be
    /// written without editing another task's file. What it proves is what `e1`
    /// needs the fake to be able to express: a demand number, a clamp, a
    /// registration per runner, and a request count that matches the budget
    /// model.
    #[tokio::test]
    async fn a_reconciliation_loop_reads_demand_clamps_it_and_registers_that_many_runners() {
        use crate::fixtures;
        use runner_manager_domain::capacity::{HostAllocator, LimitingFactor};
        use runner_manager_github::jit::JitRunnerRequest;

        let gateway = FakeGithub::new()
            .with_queued_jobs(
                repo(),
                crate::fixtures::queued_jobs(&["rm-home-win-x64"], 5),
            )
            .with_queued_jobs(
                other_repo(),
                crate::fixtures::queued_jobs(&["rm-home-win-x64"], 2),
            );
        let scope = org_scope([repo(), other_repo()]);
        let cancel = CancelToken::new();

        let demand = gateway
            .queued_demand(&scope, &cancel)
            .await
            .expect("a demand reading");
        assert_eq!(
            demand.total(),
            7,
            "the aggregate is the sum of its repositories"
        );
        assert!(demand.is_complete());

        // `b1`'s real allocator, not an inline `clamp`: `max_capacity` beats
        // reported demand and `host_capacity` beats `max_capacity`
        // (`04-subsystem-contracts.md`, precedence rules 5 and 6), and driving
        // the fake's number through the type that enforces both is what makes
        // this an `e1`-shaped test rather than an arithmetic one.
        let host = fixtures::host().capacity(8).build();
        let policy = fixtures::policy().autoscale("home", 3).active().build();
        let mut allocator = HostAllocator::from_attempts(&host, []);
        let allocation = allocator.allocate(&policy, demand.total());

        assert_eq!(
            allocation.desired, 3,
            "seven queued runs against a ceiling of three"
        );
        assert_eq!(allocation.to_start, 3);
        assert_eq!(
            allocation.limiting_factor,
            LimitingFactor::MaxCapacity,
            "the ceiling bound before the host did, and an operator has to be told which"
        );

        let wanted = allocation.to_start;
        for index in 0..wanted {
            let request = JitRunnerRequest::new(
                format!("rm-home-win-x64-{index:04}"),
                1,
                ["rm-home-win-x64"],
            );
            let registration = gateway
                .generate_jit_config(scope.target(), &request, &cancel)
                .await
                .expect("a registration");
            assert_eq!(
                registration.runner().id,
                FIRST_RUNNER_ID + u64::from(index),
                "each registration reports a distinct runner id, or a consumer cannot \
                 tell two attempts apart"
            );
            assert_eq!(registration.config().expose(), DEFAULT_JIT_CONFIG);
        }

        assert_eq!(
            gateway.requests_issued(),
            2 + u64::from(wanted),
            "one request per repository for demand, plus one per registration -- the \
             number `f2` computes its `add` refusals from"
        );
        assert_eq!(
            gateway.calls().len(),
            1 + wanted as usize,
            "one demand poll over the whole scope, then one call per runner"
        );
        assert!(matches!(gateway.calls()[0], FakeCall::QueuedDemand(_)));
    }

    /// Demand and the in-progress count are separate knobs, and a consumer that
    /// reads the wrong one is visible in `calls()`.
    #[tokio::test]
    async fn queued_demand_and_in_progress_activity_are_different_numbers() {
        let gateway = FakeGithub::new()
            .with_queued_jobs(
                repo(),
                crate::fixtures::queued_jobs(&["rm-home-win-x64"], 4),
            )
            .with_in_progress(repo(), 11);
        let scope = ActivityScope::repository(repo());
        let cancel = CancelToken::new();

        let demand = gateway
            .queued_demand(&scope, &cancel)
            .await
            .expect("demand");
        let activity = gateway
            .in_progress_activity(&scope, &cancel)
            .await
            .expect("activity");

        assert_eq!(
            demand.total(),
            4,
            "work waiting for a runner that does not exist"
        );
        assert_eq!(activity.total(), 11, "work that already has one");
        assert_ne!(
            demand.total(),
            activity.total(),
            "a fixture that could only set them together could not catch a consumer \
             that conflated them"
        );
        assert_eq!(
            gateway.calls(),
            vec![
                FakeCall::QueuedDemand(scope.target().clone()),
                FakeCall::InProgressActivity(scope.target().clone()),
            ]
        );
    }

    /// A demand count can be short in two ways, and the fake can produce both.
    ///
    /// And an unreadable repository is short in a third way that is not a count
    /// at all — see the repository-scope half below, which is the case where
    /// this fake and `RestDemand` used to disagree outright.
    #[tokio::test]
    async fn a_demand_reading_can_be_a_floor_or_can_be_missing_a_repository() {
        let gateway = FakeGithub::new()
            .with_truncated_queued_jobs(
                repo(),
                crate::fixtures::queued_jobs(&["rm-home-win-x64"], 400),
            )
            .with_unavailable_demand(other_repo(), "repository archived");

        let demand = gateway
            .queued_demand(&org_scope([repo(), other_repo()]), &CancelToken::new())
            .await
            .expect("an aggregate steps over a repository it cannot poll");

        assert_eq!(demand.total(), 400);
        assert!(!demand.is_complete());
        assert!(demand.is_truncated(&repo()));
        assert_eq!(demand.unavailable().len(), 1);
        assert_eq!(
            demand.for_repository(&other_repo()),
            None,
            "a repository that could not be polled is absent from the map, not present \
             as a zero -- `e1` would read a zero as `start no runners`"
        );
        assert_eq!(
            gateway.requests_issued(),
            2,
            "the request that discovered the repository was unreadable was still spent"
        );

        // The same programming at *repository* scope, which is a failure and not
        // a reading. `RestDemand` gates the step-over on the target's scope, and
        // a fixture that ignored the gate would answer `Ok(total 0)` where
        // production answers `Err` -- handing a consumer's test a green over the
        // one confusion the aggregate path exists to prevent.
        let scoped = FakeGithub::new().with_unavailable_demand(repo(), "repository archived");
        let error = scoped
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect_err(
                "a repository target whose only repository cannot be polled knows nothing \
                 about that target, which is not the same as knowing it has no demand",
            );
        assert!(
            !error.is_cancelled() && !error.is_rate_limited(),
            "the failure is the repository-local one production propagates, not a \
             cancellation or a rate limit: {error}"
        );
        assert!(
            error.to_string().contains("repository archived"),
            "the programmed reason survives into the failure, so a consumer can see why: \
             {error}"
        );
        assert_eq!(
            scoped.requests_issued(),
            1,
            "the request that discovered the repository was unreadable was still spent, \
             exactly as on the aggregate path"
        );
    }

    /// Each registration failure mode is a distinct outcome the fake can
    /// program, and none of them is the same value as another.
    #[tokio::test]
    async fn every_registration_failure_mode_is_programmable_and_distinct() {
        use runner_manager_github::jit::{JitError, JitRunnerRequest};

        let request = JitRunnerRequest::new("runner-1", 2, ["rm-home-win-x64"]);
        let target = ScaleTarget::Organization(
            runner_manager_domain::model::Org::new("octo-org").expect("a valid login"),
        );

        /// The outcome a consumer is expected to branch on for one programmed
        /// failure. Named rather than written inline because `clippy` refuses
        /// the tuple otherwise, and because the name is what says the predicate
        /// is a *consumer's* `match` arm rather than an equality check.
        type ExpectedOutcome = fn(&JitError) -> bool;

        let cases: Vec<(FakeFailure, ExpectedOutcome)> = vec![
            (
                FakeFailure::Forbidden {
                    message: Some("GitHub hosted runner groups cannot be modified".into()),
                },
                |error| {
                    matches!(
                        error,
                        JitError::Forbidden {
                            runner_group_id: 2,
                            ..
                        }
                    )
                },
            ),
            (FakeFailure::not_found(), |error| {
                matches!(
                    error,
                    JitError::NotFound {
                        runner_group_id: 2,
                        ..
                    }
                )
            }),
            (
                FakeFailure::Status {
                    status: 422,
                    message: Some("Invalid property /labels".into()),
                },
                |error| matches!(error, JitError::Rejected { .. }),
            ),
            (FakeFailure::secondary_rate_limit(60), |error| {
                error.rate_limited().is_some()
            }),
            (FakeFailure::RevokedToken, |error| {
                error.is_terminal() && error.rate_limited().is_none()
            }),
            (FakeFailure::Cancelled, JitError::is_cancelled),
        ];

        for (failure, expected) in cases {
            let gateway = FakeGithub::new();
            gateway.fail_next_registration(failure.clone());
            let error = gateway
                .generate_jit_config(&target, &request, &CancelToken::new())
                .await
                .expect_err("the programmed failure");
            assert!(
                expected(&error),
                "{failure:?} did not produce the outcome a consumer branches on: {error:?}"
            );

            // And the failure is one-shot: the next call succeeds, which is what
            // `fail_next` means and what a recovery test depends on.
            gateway
                .generate_jit_config(&target, &request, &CancelToken::new())
                .await
                .expect("a queued failure is consumed once");
        }
    }

    /// A refused registration must not need demand to fail with it.
    ///
    /// This is why the registration queue is separate from the inventory one: a
    /// shared queue would have the demand poll consume the failure, and the
    /// scenario `e1` most needs — demand answers, registration is refused —
    /// would be unwritable.
    #[tokio::test]
    async fn a_registration_can_be_refused_while_demand_still_answers() {
        let gateway = FakeGithub::new().with_queued_jobs(
            repo(),
            crate::fixtures::queued_jobs(&["rm-home-win-x64"], 3),
        );
        gateway.fail_next_registration(FakeFailure::Forbidden {
            message: Some("Resource not accessible by integration".into()),
        });

        let demand = gateway
            .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
            .await
            .expect("demand is unaffected by a registration failure");
        assert_eq!(demand.total(), 3);

        let error = gateway
            .generate_jit_config(
                &target(),
                &runner_manager_github::jit::JitRunnerRequest::new("r", 1, ["a"]),
                &CancelToken::new(),
            )
            .await
            .expect_err("the registration is refused");
        assert!(error.is_terminal());
    }

    /// A latched failure is a fact about the credential and reaches both paths.
    #[tokio::test]
    async fn a_latched_failure_reaches_the_registration_path_too() {
        let gateway = FakeGithub::new();
        gateway.fail_always(FakeFailure::RevokedToken);

        assert!(
            gateway
                .queued_demand(&ActivityScope::repository(repo()), &CancelToken::new())
                .await
                .is_err()
        );
        assert!(
            gateway
                .generate_jit_config(
                    &target(),
                    &runner_manager_github::jit::JitRunnerRequest::new("r", 1, ["a"]),
                    &CancelToken::new()
                )
                .await
                .is_err(),
            "a revoked token is not a property of one endpoint"
        );

        gateway.recover();
        assert!(
            gateway
                .generate_jit_config(
                    &target(),
                    &runner_manager_github::jit::JitRunnerRequest::new("r", 1, ["a"]),
                    &CancelToken::new()
                )
                .await
                .is_ok()
        );
    }

    /// The registered runner reports exactly the labels asked for, lower-cased,
    /// with nothing added.
    ///
    /// `v1`'s finding, modelled here rather than assumed: a fake that added
    /// `self-hosted` would let a consumer's test pass against a runner the real
    /// GitHub never creates, and the workflow would then not match in
    /// production.
    #[tokio::test]
    async fn the_fake_adds_no_labels_of_its_own_and_lower_cases_what_it_is_given() {
        let gateway = FakeGithub::new();
        let request = runner_manager_github::jit::JitRunnerRequest::new(
            "runner-1",
            7,
            ["RM-Home-Win-X64", "Windows"],
        );

        let registration = gateway
            .generate_jit_config(&target(), &request, &CancelToken::new())
            .await
            .expect("a registration");

        assert_eq!(
            registration.runner().labels,
            vec!["rm-home-win-x64".to_string(), "windows".to_string()],
            "GitHub stores labels lower-cased"
        );
        assert!(
            !registration
                .runner()
                .labels
                .iter()
                .any(|label| label == "self-hosted"),
            "no labels are added implicitly"
        );
        assert_eq!(registration.runner().runner_group_id, Some(7));
    }
}
