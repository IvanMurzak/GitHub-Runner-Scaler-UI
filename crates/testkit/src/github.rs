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
    collections::{BTreeMap, VecDeque},
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
        let counts = scope
            .repositories()
            .iter()
            .map(|repository| {
                let count = state.activity.get(repository).copied().unwrap_or(0);
                (repository.clone(), count)
            })
            .collect();
        Ok(ActivityCount::new(counts))
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
