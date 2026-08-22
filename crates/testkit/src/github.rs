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
//! * **Failures.** [`FakeFailure`] covers a rate limit at either of GitHub's two
//!   limits, a revoked token's `401`, the authentication lockout's `403`, a
//!   permissions `403`, any other status, and cancellation.
//!   [`FakeGithub::fail_next`] queues one; [`FakeGithub::fail_always`] latches.
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

use runner_manager_domain::model::{Clock, OwnerRepo, ScaleTarget, Timestamp};
use runner_manager_github::{
    GithubError, HeaderMap,
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
}

/// One call a consumer made, in the order it made them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeCall {
    ListRunners(ScaleTarget),
    InProgressActivity(ScaleTarget),
    RunnerDownloads(ScaleTarget),
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
    queued_failures: VecDeque<FakeFailure>,
    latched_failure: Option<FakeFailure>,
    calls: Vec<FakeCall>,
    requests_issued: u64,
    headroom: Option<RateLimitHeadroom>,
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
            state: Mutex::new(FakeState::default()),
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
}
