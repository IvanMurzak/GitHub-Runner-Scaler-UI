// owner: e3-jit-lifecycle-recovery

//! One ephemeral runner, from an allocation decision to a scrubbed runtime.
//!
//! The ordering in this module is intentional.  An attempt is written before
//! the package or GitHub is touched, the JIT value exists only in a restrictive
//! handoff, and a registration-timeout termination is journalled before the
//! process is signalled.  Recovery uses the same code as ordinary supervision;
//! startup merely supplies the first observation.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use runner_manager_domain::attempt::{
    AttemptOutcome, AttemptState, FailureReason, GithubRunnerObservation, RecoveryDecision,
    RecoveryObservation, RecoveryTimeouts, RunnerAttempt, authorize, recovery_decision,
};
use runner_manager_domain::model::{AttemptId, Clock, HostId, PolicyId, ScaleTarget};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::Store;
use runner_manager_github::jit::{
    EncodedJitConfig, JitError, JitGateway, JitRegistration, JitRunnerRequest,
};
use runner_manager_github::rest::{CancelToken, InventoryGateway};
use runner_manager_platform::process::{
    Adoption, ChildProcess, ProcessIdentity, RestrictiveHandoff, SpawnSpec, Termination,
};
use secrecy::SecretString;

use crate::package::{PackageCache, PackageError, RunnerVersion};
use crate::reconcile::{
    AllocationGuard, EventSink, LaunchFailure, LaunchRequest, LifecycleEvent, OutcomeKind,
    RunnerLauncher,
};

const IDENTITY_FILE: &str = ".runner-process.json";
const RUNNER_ID_FILE: &str = ".github-runner-id";
const TERMINATE_INTENT_FILE: &str = ".terminate-registration-timeout";

/// Retry bounds for failures that can resolve without operator action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial: Duration,
    pub maximum: Duration,
}

impl RetryPolicy {
    #[must_use]
    pub const fn bounded(max_attempts: u32, initial: Duration, maximum: Duration) -> Self {
        Self {
            max_attempts,
            initial,
            maximum,
        }
    }

    fn delay(self, failure_index: u32) -> Duration {
        let shift = failure_index.saturating_sub(1).min(31);
        self.initial
            .saturating_mul(1_u32 << shift)
            .min(self.maximum)
    }
}

/// Non-secret lifecycle evidence.  Payloads are identifiers and closed enums;
/// neither the encoded configuration nor child output can enter this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptEvent {
    State {
        attempt: AttemptId,
        state: AttemptState,
    },
    Retry {
        attempt: AttemptId,
        operation: &'static str,
        delay: Duration,
    },
    Adopted {
        attempt: AttemptId,
    },
    TerminateIntent {
        attempt: AttemptId,
    },
    Terminated {
        attempt: AttemptId,
    },
    Concluded {
        attempt: AttemptId,
        outcome: OutcomeKind,
    },
    Cleaned {
        attempt: AttemptId,
        outcome: OutcomeKind,
    },
}

pub trait AttemptEventSink: fmt::Debug + Send + Sync {
    fn emit(&self, event: AttemptEvent);
}

#[derive(Debug, Default)]
pub struct AttemptEventLog(Mutex<Vec<AttemptEvent>>);

impl AttemptEventLog {
    #[must_use]
    pub fn events(&self) -> Vec<AttemptEvent> {
        self.0
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

impl AttemptEventSink for AttemptEventLog {
    fn emit(&self, event: AttemptEvent) {
        if let Ok(mut events) = self.0.lock() {
            events.push(event);
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoAttemptEvents;

impl AttemptEventSink for NoAttemptEvents {
    fn emit(&self, _event: AttemptEvent) {}
}

/// Whether the demand that justified a retry still exists.
#[async_trait]
pub trait DemandPersistence: fmt::Debug + Send + Sync {
    async fn persists(&self, policy: PolicyId) -> bool;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PersistentDemand;

#[async_trait]
impl DemandPersistence for PersistentDemand {
    async fn persists(&self, _policy: PolicyId) -> bool {
        true
    }
}

#[async_trait]
pub trait RetryDelay: fmt::Debug + Send + Sync {
    async fn wait(&self, duration: Duration);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TokioRetryDelay;

#[async_trait]
impl RetryDelay for TokioRetryDelay {
    async fn wait(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitRequestFailure {
    pub terminal: bool,
    pub reason: FailureReason,
    pub retry_after: Option<Duration>,
}

/// The two GitHub views the lifecycle needs, combined so one fake can drive
/// registration and authoritative runner telemetry.
#[async_trait]
pub trait LifecycleGithub: fmt::Debug + Send + Sync {
    async fn register(
        &self,
        target: &ScaleTarget,
        request: &JitRunnerRequest,
        cancel: &CancelToken,
    ) -> Result<JitRegistration, JitRequestFailure>;

    async fn observe(
        &self,
        target: &ScaleTarget,
        attempt: AttemptId,
        cancel: &CancelToken,
    ) -> GithubRunnerObservation;
}

#[async_trait]
impl<T> LifecycleGithub for T
where
    T: JitGateway + InventoryGateway + fmt::Debug + Send + Sync,
{
    async fn register(
        &self,
        target: &ScaleTarget,
        request: &JitRunnerRequest,
        cancel: &CancelToken,
    ) -> Result<JitRegistration, JitRequestFailure> {
        self.generate_jit_config(target, request, cancel)
            .await
            .map_err(|error| {
                let reason = if matches!(&error, JitError::Forbidden { .. }) {
                    FailureReason::Other(
                        "GitHub refused JIT registration with 403; check the App's runner permission and runner-group access"
                            .into(),
                    )
                } else {
                    FailureReason::JitRequestFailed
                };
                JitRequestFailure {
                    terminal: error.is_terminal(),
                    reason,
                    retry_after: error
                        .rate_limited()
                        .map(|limit| limit.delay_from(self.now())),
                }
            })
    }

    async fn observe(
        &self,
        target: &ScaleTarget,
        attempt: AttemptId,
        cancel: &CancelToken,
    ) -> GithubRunnerObservation {
        let expected_name = runner_name(attempt);
        match self.list_runners(target, cancel).await {
            Ok(inventory) => inventory
                .runners()
                .iter()
                .find(|runner| runner.name == expected_name)
                .map_or(GithubRunnerObservation::NotRegistered, |runner| {
                    GithubRunnerObservation::Registered { busy: runner.busy }
                }),
            Err(_) => GithubRunnerObservation::Unreachable,
        }
    }
}

/// Package/cache operations used by one attempt.
#[async_trait]
pub trait RuntimePackages: fmt::Debug + Send + Sync {
    async fn materialize(&self, attempt: &RunnerAttempt) -> Result<RunnerVersion, FailureReason>;
    fn release(&self, attempt: AttemptId) -> Result<(), FailureReason>;
    fn prune(
        &self,
        version: &RunnerVersion,
        attempts: &[RunnerAttempt],
    ) -> Result<(), FailureReason>;
}

/// Production package adapter.  It takes an e2 lease before returning, so a
/// cache entry can never look unused while its runtime is starting.
#[derive(Debug)]
pub struct CachedRuntimePackages {
    cache: Arc<PackageCache>,
}

impl CachedRuntimePackages {
    #[must_use]
    pub fn new(cache: Arc<PackageCache>) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl RuntimePackages for CachedRuntimePackages {
    async fn materialize(&self, attempt: &RunnerAttempt) -> Result<RunnerVersion, FailureReason> {
        let installed = self
            .cache
            .ensure_installed()
            .await
            .map_err(package_failure)?;
        copy_package_tree(installed.root(), attempt.runtime_path())
            .map_err(|_| FailureReason::ProcessStartFailed)?;
        if let Err(error) = self.cache.lease(attempt, installed.version()) {
            let _ = fs::remove_dir_all(attempt.runtime_path());
            return Err(package_failure(error));
        }
        Ok(installed.version().clone())
    }

    fn release(&self, attempt: AttemptId) -> Result<(), FailureReason> {
        self.cache.release(attempt).map_err(package_failure)
    }

    fn prune(
        &self,
        version: &RunnerVersion,
        attempts: &[RunnerAttempt],
    ) -> Result<(), FailureReason> {
        self.cache.prune(version, attempts).map_err(package_failure)
    }
}

fn package_failure(error: PackageError) -> FailureReason {
    error.failure_reason().unwrap_or(FailureReason::Other(
        "runner package cache operation failed".into(),
    ))
}

fn copy_package_tree(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_package_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Process operations are attempt-addressed so a recovered process and a child
/// started in this invocation are supervised through one port.
pub trait ProcessSupervisor: fmt::Debug + Send + Sync {
    fn spawn(
        &self,
        attempt: &RunnerAttempt,
        config: &EncodedJitConfig,
    ) -> Result<u32, FailureReason>;
    fn is_alive(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason>;
    /// True only for a child this invocation owned and reaped with a successful
    /// exit status.  A recovered process that is merely gone answers false.
    fn completed_successfully(&self, attempt: &RunnerAttempt) -> bool;
    fn record_terminate_intent(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason>;
    fn has_terminate_intent(&self, attempt: &RunnerAttempt) -> bool;
    fn terminate(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason>;
}

/// Native process supervision.  The start token is stored beside the runtime;
/// recovery never trusts a recycled PID merely because SQLite contains it.
#[derive(Debug, Default)]
pub struct NativeProcesses {
    children: Mutex<BTreeMap<AttemptId, ChildProcess>>,
    successful_exits: Mutex<BTreeMap<AttemptId, bool>>,
}

impl NativeProcesses {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn identity_path(attempt: &RunnerAttempt) -> PathBuf {
        attempt.runtime_path().join(IDENTITY_FILE)
    }

    fn intent_path(attempt: &RunnerAttempt) -> PathBuf {
        attempt.runtime_path().join(TERMINATE_INTENT_FILE)
    }

    fn read_identity(attempt: &RunnerAttempt) -> Result<Option<ProcessIdentity>, FailureReason> {
        match fs::read(Self::identity_path(attempt)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| FailureReason::Other("process identity journal is unreadable".into())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(FailureReason::Other(
                "process identity journal could not be read".into(),
            )),
        }
    }
}

impl ProcessSupervisor for NativeProcesses {
    fn spawn(
        &self,
        attempt: &RunnerAttempt,
        config: &EncodedJitConfig,
    ) -> Result<u32, FailureReason> {
        let handoff = RestrictiveHandoff::create(
            attempt.runtime_path(),
            SecretString::from(config.expose().to_owned()),
        )
        .map_err(|_| FailureReason::ProcessStartFailed)?;
        let handoff_path = handoff.path().to_path_buf();
        #[cfg(windows)]
        let program = attempt
            .runtime_path()
            .join("bin")
            .join("Runner.Listener.exe");
        #[cfg(not(windows))]
        let program = attempt.runtime_path().join("bin").join("Runner.Listener");
        // Checked after the handoff exists on purpose: the error path below is
        // a real post-handoff launch failure, and unwinding must delete it.
        if !program.is_file() {
            return Err(FailureReason::ProcessStartFailed);
        }
        let spec = SpawnSpec::new(program)
            .arg("run")
            .arg("--jit-config-file")
            .arg(&handoff_path)
            .working_dir(attempt.runtime_path());
        let mut child = spec
            .spawn_with_handoff(&handoff)
            .map_err(|_| FailureReason::ProcessStartFailed)?;
        // The payload is gone before any state saying "starting" is persisted.
        handoff
            .delete()
            .map_err(|_| FailureReason::ProcessStartFailed)?;
        let identity =
            serde_json::to_vec(child.identity()).map_err(|_| FailureReason::ProcessStartFailed)?;
        if fs::write(Self::identity_path(attempt), identity).is_err() {
            let _ = child.stop(Duration::from_secs(1));
            return Err(FailureReason::ProcessStartFailed);
        }
        let pid = child.pid();
        self.children
            .lock()
            .map_err(|_| FailureReason::ProcessStartFailed)?
            .insert(attempt.id, child);
        Ok(pid)
    }

    fn is_alive(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
        if let Ok(mut children) = self.children.lock()
            && let Some(child) = children.get_mut(&attempt.id)
        {
            return match child
                .try_exit_status()
                .map_err(|_| FailureReason::Other("runner process could not be observed".into()))?
            {
                None => Ok(true),
                Some(status) => {
                    if let Ok(mut exits) = self.successful_exits.lock() {
                        exits.insert(attempt.id, status.success());
                    }
                    Ok(false)
                }
            };
        }
        let Some(identity) = Self::read_identity(attempt)? else {
            return Ok(false);
        };
        match identity.recheck() {
            Ok(Adoption::Live) => Ok(true),
            Ok(Adoption::Gone | Adoption::PidRecycled { .. }) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    fn completed_successfully(&self, attempt: &RunnerAttempt) -> bool {
        self.successful_exits
            .lock()
            .ok()
            .and_then(|exits| exits.get(&attempt.id).copied())
            .unwrap_or(false)
    }

    fn record_terminate_intent(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason> {
        let path = Self::intent_path(attempt);
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .map_err(|_| FailureReason::Other("terminate intent could not be journalled".into()))?;
        file.write_all(b"registration-timeout\n")
            .and_then(|()| file.sync_all())
            .map_err(|_| FailureReason::Other("terminate intent could not be journalled".into()))
    }

    fn has_terminate_intent(&self, attempt: &RunnerAttempt) -> bool {
        Self::intent_path(attempt).is_file()
    }

    fn terminate(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason> {
        if let Ok(mut children) = self.children.lock()
            && let Some(child) = children.get_mut(&attempt.id)
        {
            child
                .stop(Duration::from_secs(10))
                .map_err(|_| FailureReason::Other("runner process could not be stopped".into()))?;
            return Ok(());
        }
        let Some(identity) = Self::read_identity(attempt)? else {
            return Ok(());
        };
        match identity
            .terminate(Duration::from_secs(10))
            .map_err(|_| FailureReason::Other("runner process could not be stopped".into()))?
        {
            Termination::Terminated | Termination::AlreadyGone => Ok(()),
            Termination::RefusedPidRecycled { .. } => Err(FailureReason::Other(
                "runner PID was recycled; refusing to signal it".into(),
            )),
        }
    }
}

pub struct LifecyclePorts {
    pub store: Arc<dyn Store>,
    pub github: Arc<dyn LifecycleGithub>,
    pub packages: Arc<dyn RuntimePackages>,
    pub processes: Arc<dyn ProcessSupervisor>,
    pub clock: Arc<dyn Clock>,
    pub demand: Arc<dyn DemandPersistence>,
    pub delay: Arc<dyn RetryDelay>,
    pub events: Arc<dyn AttemptEventSink>,
    pub reconcile_events: Arc<dyn EventSink>,
}

impl fmt::Debug for LifecyclePorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LifecyclePorts")
            .field("store", &self.store)
            .field("github", &self.github)
            .field("packages", &self.packages)
            .field("processes", &self.processes)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("attempt journal operation failed")]
    Journal,
    #[error("attempt {0} is not in the journal")]
    Missing(AttemptId),
    #[error("attempt lifecycle transition was refused")]
    Transition,
    #[error("startup recovery has not completed")]
    RecoveryIncomplete,
    #[error("runner lifecycle failed: {0}")]
    Failed(FailureReason),
}

impl LifecycleError {
    fn reason(&self) -> FailureReason {
        match self {
            Self::Failed(reason) => reason.clone(),
            Self::RecoveryIncomplete => FailureReason::Other("startup recovery incomplete".into()),
            Self::Journal => FailureReason::Other("attempt journal operation failed".into()),
            Self::Missing(_) => FailureReason::Other("attempt disappeared from the journal".into()),
            Self::Transition => FailureReason::Other("attempt transition was refused".into()),
        }
    }
}

/// Production implementation of e1's launcher port.
#[derive(Debug)]
pub struct LifecycleLauncher {
    host_id: HostId,
    runtime_root: PathBuf,
    diagnostics_root: PathBuf,
    runner_group_id: u64,
    timeouts: RecoveryTimeouts,
    retry: RetryPolicy,
    cancel: CancelToken,
    ports: LifecyclePorts,
    recovery_complete: Mutex<bool>,
    versions: Mutex<BTreeMap<AttemptId, RunnerVersion>>,
}

impl LifecycleLauncher {
    #[must_use]
    pub fn new(
        host_id: HostId,
        runtime_root: impl Into<PathBuf>,
        diagnostics_root: impl Into<PathBuf>,
        runner_group_id: u64,
        timeouts: RecoveryTimeouts,
        retry: RetryPolicy,
        ports: LifecyclePorts,
    ) -> Self {
        Self {
            host_id,
            runtime_root: runtime_root.into(),
            diagnostics_root: diagnostics_root.into(),
            runner_group_id,
            timeouts,
            retry,
            cancel: CancelToken::new(),
            ports,
            recovery_complete: Mutex::new(false),
            versions: Mutex::new(BTreeMap::new()),
        }
    }

    /// Reconcile the entire journal before allowing a launch.  Unknown-policy
    /// attempts are left untouched rather than being acted on without an
    /// ownership proof.
    pub async fn recover_startup(&self, policies: &[ScalePolicy]) -> Result<(), LifecycleError> {
        let by_id: BTreeMap<_, _> = policies.iter().map(|policy| (policy.id, policy)).collect();
        let attempts = self
            .ports
            .store
            .attempts()
            .map_err(|_| LifecycleError::Journal)?;
        for attempt in attempts {
            let Some(policy) = by_id.get(&attempt.policy_id) else {
                continue;
            };
            authorize(self.host_id, policy, &attempt).map_err(|_| LifecycleError::Journal)?;
            self.reconcile_one(policy, attempt).await?;
        }
        *self
            .recovery_complete
            .lock()
            .map_err(|_| LifecycleError::Journal)? = true;
        Ok(())
    }

    /// Supervise all attempts of one policy during an ordinary poll.
    pub async fn supervise(&self, policy: &ScalePolicy) -> Result<(), LifecycleError> {
        let attempts = self
            .ports
            .store
            .attempts_for_policy(policy.id)
            .map_err(|_| LifecycleError::Journal)?;
        for attempt in attempts {
            authorize(self.host_id, policy, &attempt).map_err(|_| LifecycleError::Journal)?;
            self.reconcile_one(policy, attempt).await?;
        }
        Ok(())
    }

    async fn reconcile_one(
        &self,
        policy: &ScalePolicy,
        mut attempt: RunnerAttempt,
    ) -> Result<(), LifecycleError> {
        if attempt.state() == AttemptState::Cleaned {
            return Ok(());
        }
        if attempt.is_terminal() {
            return self.clean_attempt(&mut attempt);
        }
        let process_alive = self
            .ports
            .processes
            .is_alive(&attempt)
            .map_err(LifecycleError::Failed)?;
        let github = self
            .ports
            .github
            .observe(&policy.target, attempt.id, &self.cancel)
            .await;

        // A one-shot child owned by this invocation exited successfully after
        // GitHub had already reported it busy, and its ephemeral registration
        // is now gone.  This concludes the *runner attempt*, never the workflow
        // outcome; GitHub remains authoritative for that outcome.
        if attempt.state() == AttemptState::Busy
            && !process_alive
            && github == GithubRunnerObservation::NotRegistered
            && self.ports.processes.completed_successfully(&attempt)
        {
            self.conclude(&mut attempt, AttemptOutcome::CompletedJob)?;
            return self.clean_attempt(&mut attempt);
        }

        // This durable mark is more authoritative than a later observation
        // which cannot distinguish an agent kill from a crash.
        if self.ports.processes.has_terminate_intent(&attempt) && !process_alive {
            self.conclude(
                &mut attempt,
                AttemptOutcome::failed(FailureReason::TerminatedAfterRegistrationTimeout),
            )?;
            return self.clean_attempt(&mut attempt);
        }

        match recovery_decision(
            &attempt,
            RecoveryObservation {
                process_alive,
                github,
            },
            self.timeouts,
            self.ports.clock.as_ref(),
        ) {
            RecoveryDecision::Nothing | RecoveryDecision::Wait | RecoveryDecision::Defer => Ok(()),
            RecoveryDecision::Adopt => {
                self.ports.events.emit(AttemptEvent::Adopted {
                    attempt: attempt.id,
                });
                Ok(())
            }
            RecoveryDecision::Clean => self.clean_attempt(&mut attempt),
            RecoveryDecision::Observe(state) => {
                let runner_id = attempt
                    .github_runner_id()
                    .or_else(|| read_runner_id(attempt.runtime_path()))
                    .ok_or(LifecycleError::Transition)?;
                match state {
                    AttemptState::JitReceived => attempt
                        .jit_received(self.ports.clock.now())
                        .map_err(|_| LifecycleError::Transition)?,
                    AttemptState::Starting => {
                        let pid = attempt.process_id().ok_or(LifecycleError::Transition)?;
                        attempt
                            .started(pid, self.ports.clock.now())
                            .map_err(|_| LifecycleError::Transition)?;
                    }
                    AttemptState::Idle => attempt
                        .registered_idle(runner_id, self.ports.clock.now())
                        .map_err(|_| LifecycleError::Transition)?,
                    AttemptState::Busy => attempt
                        .assigned_job(runner_id, self.ports.clock.now())
                        .map_err(|_| LifecycleError::Transition)?,
                    _ => return Err(LifecycleError::Transition),
                }
                self.record(&attempt)
            }
            RecoveryDecision::Conclude(outcome) => {
                self.conclude(&mut attempt, outcome)?;
                self.clean_attempt(&mut attempt)
            }
            RecoveryDecision::Terminate(_payload) => {
                // The mark is synced first.  Do not use `_payload` to conclude:
                // Terminate and Conclude carry the same type and doing so would
                // make an ordering test pass without proving the process died.
                self.ports
                    .processes
                    .record_terminate_intent(&attempt)
                    .map_err(LifecycleError::Failed)?;
                self.ports.events.emit(AttemptEvent::TerminateIntent {
                    attempt: attempt.id,
                });
                self.ports
                    .processes
                    .terminate(&attempt)
                    .map_err(LifecycleError::Failed)?;
                if self
                    .ports
                    .processes
                    .is_alive(&attempt)
                    .map_err(LifecycleError::Failed)?
                {
                    return Ok(());
                }
                self.ports.events.emit(AttemptEvent::Terminated {
                    attempt: attempt.id,
                });
                self.conclude(
                    &mut attempt,
                    AttemptOutcome::failed(FailureReason::TerminatedAfterRegistrationTimeout),
                )?;
                self.clean_attempt(&mut attempt)
            }
        }
    }

    fn record(&self, attempt: &RunnerAttempt) -> Result<(), LifecycleError> {
        self.ports
            .store
            .record_attempt(attempt)
            .map_err(|_| LifecycleError::Journal)?;
        self.ports.events.emit(AttemptEvent::State {
            attempt: attempt.id,
            state: attempt.state(),
        });
        Ok(())
    }

    fn conclude(
        &self,
        attempt: &mut RunnerAttempt,
        outcome: AttemptOutcome,
    ) -> Result<(), LifecycleError> {
        attempt
            .conclude(outcome.clone(), self.ports.clock.now())
            .map_err(|_| LifecycleError::Transition)?;
        self.record(attempt)?;
        self.ports.events.emit(AttemptEvent::Concluded {
            attempt: attempt.id,
            outcome: OutcomeKind::of(&outcome),
        });
        Ok(())
    }

    fn clean_attempt(&self, attempt: &mut RunnerAttempt) -> Result<(), LifecycleError> {
        let outcome = attempt
            .outcome()
            .cloned()
            .ok_or(LifecycleError::Transition)?;
        self.preserve_diagnostics(attempt, &outcome)?;
        match fs::remove_dir_all(attempt.runtime_path()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(LifecycleError::Failed(FailureReason::Other(
                    "attempt workspace could not be removed".into(),
                )));
            }
        }
        self.ports
            .packages
            .release(attempt.id)
            .map_err(LifecycleError::Failed)?;
        attempt
            .clean(self.ports.clock.now())
            .map_err(|_| LifecycleError::Transition)?;
        self.record(attempt)?;
        let kind = OutcomeKind::of(&outcome);
        self.ports.events.emit(AttemptEvent::Cleaned {
            attempt: attempt.id,
            outcome: kind,
        });
        self.ports
            .reconcile_events
            .emit(LifecycleEvent::AttemptCleaned {
                policy: attempt.policy_id,
                attempt: attempt.id,
                outcome: kind,
            });
        Ok(())
    }

    fn preserve_diagnostics(
        &self,
        attempt: &RunnerAttempt,
        outcome: &AttemptOutcome,
    ) -> Result<(), LifecycleError> {
        fs::create_dir_all(&self.diagnostics_root).map_err(|_| {
            LifecycleError::Failed(FailureReason::Other(
                "diagnostics directory could not be created".into(),
            ))
        })?;
        // Intentionally constructed from typed local facts, not runner output.
        // Raw child output can contain workflow secrets and is never copied.
        let diagnostic = format!(
            "attempt_id={}\npolicy_id={}\noutcome={}\n",
            attempt.id,
            attempt.policy_id,
            OutcomeKind::of(outcome).as_str()
        );
        fs::write(
            self.diagnostics_root.join(format!("{}.log", attempt.id)),
            diagnostic,
        )
        .map_err(|_| {
            LifecycleError::Failed(FailureReason::Other(
                "redacted diagnostics could not be preserved".into(),
            ))
        })
    }

    async fn register_with_retry(
        &self,
        policy: &ScalePolicy,
        attempt: AttemptId,
        request: &JitRunnerRequest,
    ) -> Result<JitRegistration, LifecycleError> {
        let mut issued = 0_u32;
        loop {
            issued = issued.saturating_add(1);
            match self
                .ports
                .github
                .register(&policy.target, request, &self.cancel)
                .await
            {
                Ok(registration) => return Ok(registration),
                Err(error) if error.terminal => {
                    return Err(LifecycleError::Failed(error.reason));
                }
                Err(error) if issued >= self.retry.max_attempts.max(1) => {
                    return Err(LifecycleError::Failed(error.reason));
                }
                Err(error) if !self.ports.demand.persists(policy.id).await => {
                    return Err(LifecycleError::Failed(error.reason));
                }
                Err(error) => {
                    let delay = error
                        .retry_after
                        .unwrap_or_else(|| self.retry.delay(issued));
                    self.ports.events.emit(AttemptEvent::Retry {
                        attempt,
                        operation: "jit_request",
                        delay,
                    });
                    self.ports.delay.wait(delay).await;
                }
            }
        }
    }

    async fn launch_attempt(
        &self,
        request: LaunchRequest<'_>,
    ) -> Result<RunnerAttempt, LifecycleError> {
        if !*self
            .recovery_complete
            .lock()
            .map_err(|_| LifecycleError::Journal)?
        {
            return Err(LifecycleError::RecoveryIncomplete);
        }
        let labels = request
            .policy
            .routing_labels()
            .ok_or(LifecycleError::Failed(FailureReason::JitRequestFailed))?;
        let id = AttemptId::new_random();
        let runtime = self
            .runtime_root
            .join(request.policy.id.to_string())
            .join(id.to_string());
        fs::create_dir_all(&runtime)
            .map_err(|_| LifecycleError::Failed(FailureReason::ProcessStartFailed))?;
        let mut attempt =
            RunnerAttempt::allocate(id, request.policy.id, runtime, self.ports.clock.now());
        // This is deliberately the first effect after directory allocation.
        self.record(&attempt)?;

        let version = match self.ports.packages.materialize(&attempt).await {
            Ok(version) => version,
            Err(reason) => return self.fail_launch(&mut attempt, reason),
        };
        self.versions
            .lock()
            .map_err(|_| LifecycleError::Journal)?
            .insert(id, version);

        let jit_request =
            JitRunnerRequest::for_policy(runner_name(id), self.runner_group_id, labels);
        let registration = match self
            .register_with_retry(request.policy, id, &jit_request)
            .await
        {
            Ok(registration) => registration,
            Err(error) => return self.fail_launch(&mut attempt, error.reason()),
        };
        attempt
            .jit_received(self.ports.clock.now())
            .map_err(|_| LifecycleError::Transition)?;
        self.record(&attempt)?;
        let runner_id = registration.runner().id;
        fs::write(
            attempt.runtime_path().join(RUNNER_ID_FILE),
            runner_id.to_string(),
        )
        .map_err(|_| LifecycleError::Failed(FailureReason::ProcessStartFailed))?;
        let config = registration.into_config();
        let mut issued = 0_u32;
        let pid = loop {
            issued = issued.saturating_add(1);
            match self.ports.processes.spawn(&attempt, &config) {
                Ok(pid) => break pid,
                Err(reason)
                    if issued >= self.retry.max_attempts.max(1)
                        || !self.ports.demand.persists(request.policy.id).await =>
                {
                    return self.fail_launch(&mut attempt, reason);
                }
                Err(_) => {
                    let delay = self.retry.delay(issued);
                    self.ports.events.emit(AttemptEvent::Retry {
                        attempt: attempt.id,
                        operation: "process_start",
                        delay,
                    });
                    self.ports.delay.wait(delay).await;
                }
            }
        };
        attempt
            .started(pid, self.ports.clock.now())
            .map_err(|_| LifecycleError::Transition)?;
        self.record(&attempt)?;
        Ok(attempt)
    }

    fn fail_launch<T>(
        &self,
        attempt: &mut RunnerAttempt,
        reason: FailureReason,
    ) -> Result<T, LifecycleError> {
        self.conclude(attempt, AttemptOutcome::failed(reason.clone()))?;
        Err(LifecycleError::Failed(reason))
    }

    /// e2's prune guard is invoked only with e1's allocation guard borrowed.
    /// The otherwise-unused argument is a compile-time witness of the ordering.
    pub fn prune_under_allocation_lock(
        &self,
        _guard: &AllocationGuard,
        version: &RunnerVersion,
    ) -> Result<(), LifecycleError> {
        let attempts = self
            .ports
            .store
            .attempts()
            .map_err(|_| LifecycleError::Journal)?;
        self.ports
            .packages
            .prune(version, &attempts)
            .map_err(LifecycleError::Failed)
    }
}

#[async_trait]
impl RunnerLauncher for LifecycleLauncher {
    async fn attempts(&self) -> Result<Vec<RunnerAttempt>, LaunchFailure> {
        self.ports.store.attempts().map_err(|_| {
            LaunchFailure::new(FailureReason::Other(
                "attempt journal could not be read".into(),
            ))
        })
    }

    async fn launch(&self, request: LaunchRequest<'_>) -> Result<RunnerAttempt, LaunchFailure> {
        self.launch_attempt(request)
            .await
            .map_err(|error| LaunchFailure::new(error.reason()))
    }

    async fn clean(&self, id: AttemptId) -> Result<(), LaunchFailure> {
        let mut attempt = self
            .ports
            .store
            .attempt(id)
            .map_err(|_| {
                LaunchFailure::new(FailureReason::Other(
                    "attempt journal could not be read".into(),
                ))
            })?
            .ok_or_else(|| {
                LaunchFailure::new(FailureReason::Other(
                    "attempt disappeared from the journal".into(),
                ))
            })?;
        self.clean_attempt(&mut attempt)
            .map_err(|error| LaunchFailure::new(error.reason()))
    }
}

fn runner_name(attempt: AttemptId) -> String {
    format!("runner-manager-{attempt}")
}

fn read_runner_id(runtime: &Path) -> Option<u64> {
    fs::read_to_string(runtime.join(RUNNER_ID_FILE))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use runner_manager_domain::model::Elapsed;
    use runner_manager_domain::store::SqliteStore;
    use runner_manager_github::jit::JitRunner;
    use runner_manager_testkit::clock::FakeClock;
    use runner_manager_testkit::fixtures;

    const JIT: &str = "eyJzZWNyZXQiOiJnaHBfRE9fTk9UX0xFQUsifQ==";

    #[derive(Debug, Default)]
    struct FakeGithubLifecycle {
        registration_failures: Mutex<VecDeque<bool>>,
        observations: Mutex<VecDeque<GithubRunnerObservation>>,
        registrations: AtomicUsize,
        remaining_runners: AtomicUsize,
    }

    impl FakeGithubLifecycle {
        fn fail(mut self, terminal: bool) -> Self {
            self.registration_failures
                .get_mut()
                .expect("unpoisoned")
                .push_back(terminal);
            self
        }

        fn observe(&self, observation: GithubRunnerObservation) {
            self.observations.lock().unwrap().push_back(observation);
        }
    }

    #[async_trait]
    impl LifecycleGithub for FakeGithubLifecycle {
        async fn register(
            &self,
            _target: &ScaleTarget,
            request: &JitRunnerRequest,
            _cancel: &CancelToken,
        ) -> Result<JitRegistration, JitRequestFailure> {
            self.registrations.fetch_add(1, Ordering::SeqCst);
            if let Some(terminal) = self.registration_failures.lock().unwrap().pop_front() {
                return Err(JitRequestFailure {
                    terminal,
                    reason: if terminal {
                        FailureReason::Other("GitHub refused JIT registration with 403".into())
                    } else {
                        FailureReason::JitRequestFailed
                    },
                    retry_after: None,
                });
            }
            self.remaining_runners.store(1, Ordering::SeqCst);
            Ok(JitRegistration::new(
                EncodedJitConfig::new(JIT),
                JitRunner {
                    id: 73,
                    name: request.name().to_string(),
                    os: "windows".into(),
                    status: "offline".into(),
                    busy: false,
                    runner_group_id: Some(1),
                    labels: request.labels().to_vec(),
                },
            ))
        }

        async fn observe(
            &self,
            _target: &ScaleTarget,
            _attempt: AttemptId,
            _cancel: &CancelToken,
        ) -> GithubRunnerObservation {
            let observation = self
                .observations
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(GithubRunnerObservation::NotRegistered);
            if observation == GithubRunnerObservation::NotRegistered {
                self.remaining_runners.store(0, Ordering::SeqCst);
            }
            observation
        }
    }

    #[derive(Debug)]
    struct FakePackages {
        version: RunnerVersion,
        leases: Mutex<BTreeSet<AttemptId>>,
        releases: AtomicUsize,
        prunes: AtomicUsize,
    }

    impl Default for FakePackages {
        fn default() -> Self {
            Self {
                version: RunnerVersion::parse("2.330.0").unwrap(),
                leases: Mutex::new(BTreeSet::new()),
                releases: AtomicUsize::new(0),
                prunes: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl RuntimePackages for FakePackages {
        async fn materialize(
            &self,
            attempt: &RunnerAttempt,
        ) -> Result<RunnerVersion, FailureReason> {
            fs::create_dir_all(attempt.runtime_path()).unwrap();
            fs::write(attempt.runtime_path().join("runner-package"), b"verified").unwrap();
            self.leases.lock().unwrap().insert(attempt.id);
            Ok(self.version.clone())
        }

        fn release(&self, attempt: AttemptId) -> Result<(), FailureReason> {
            self.leases.lock().unwrap().remove(&attempt);
            self.releases.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn prune(
            &self,
            _version: &RunnerVersion,
            _attempts: &[RunnerAttempt],
        ) -> Result<(), FailureReason> {
            self.prunes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeProcesses {
        alive: AtomicBool,
        completed_successfully: AtomicBool,
        spawns: AtomicUsize,
        spawn_failures: AtomicUsize,
        terminations: AtomicUsize,
        intent: AtomicBool,
        actions: Mutex<Vec<&'static str>>,
        saw_secret: AtomicBool,
    }

    impl FakeProcesses {
        fn fail_spawns(&self, count: usize) {
            self.spawn_failures.store(count, Ordering::SeqCst);
        }

        fn set_alive(&self, alive: bool) {
            self.alive.store(alive, Ordering::SeqCst);
        }

        fn finish_successfully(&self) {
            self.completed_successfully.store(true, Ordering::SeqCst);
            self.alive.store(false, Ordering::SeqCst);
        }
    }

    impl ProcessSupervisor for FakeProcesses {
        fn spawn(
            &self,
            attempt: &RunnerAttempt,
            config: &EncodedJitConfig,
        ) -> Result<u32, FailureReason> {
            self.spawns.fetch_add(1, Ordering::SeqCst);
            // Model the production handoff on both paths: the sensitive file is
            // scoped to this call and absent when it returns.
            let handoff = RestrictiveHandoff::create(
                attempt.runtime_path(),
                SecretString::from(config.expose().to_owned()),
            )
            .unwrap();
            self.saw_secret
                .store(config.expose() == JIT, Ordering::SeqCst);
            let handoff_path = handoff.path().to_path_buf();
            let failing = self
                .spawn_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    if left > 0 { Some(left - 1) } else { None }
                })
                .is_ok();
            drop(handoff);
            assert!(!handoff_path.exists(), "handoff must be absent on return");
            if failing {
                return Err(FailureReason::ProcessStartFailed);
            }
            self.alive.store(true, Ordering::SeqCst);
            Ok(4242)
        }

        fn is_alive(&self, _attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
            self.actions.lock().unwrap().push("observe_process");
            Ok(self.alive.load(Ordering::SeqCst))
        }

        fn completed_successfully(&self, _attempt: &RunnerAttempt) -> bool {
            self.completed_successfully.load(Ordering::SeqCst)
        }

        fn record_terminate_intent(&self, _attempt: &RunnerAttempt) -> Result<(), FailureReason> {
            self.actions.lock().unwrap().push("terminate_intent");
            self.intent.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn has_terminate_intent(&self, _attempt: &RunnerAttempt) -> bool {
            self.intent.load(Ordering::SeqCst)
        }

        fn terminate(&self, _attempt: &RunnerAttempt) -> Result<(), FailureReason> {
            assert!(
                self.intent.load(Ordering::SeqCst),
                "the durable intent must exist before signalling"
            );
            self.actions.lock().unwrap().push("terminate");
            self.terminations.fetch_add(1, Ordering::SeqCst);
            self.alive.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeDemand {
        answers: Mutex<VecDeque<bool>>,
    }

    impl FakeDemand {
        fn answering(answers: impl IntoIterator<Item = bool>) -> Self {
            Self {
                answers: Mutex::new(answers.into_iter().collect()),
            }
        }
    }

    #[async_trait]
    impl DemandPersistence for FakeDemand {
        async fn persists(&self, _policy: PolicyId) -> bool {
            self.answers.lock().unwrap().pop_front().unwrap_or(true)
        }
    }

    #[derive(Debug, Default)]
    struct FakeDelay(Mutex<Vec<Duration>>);

    #[async_trait]
    impl RetryDelay for FakeDelay {
        async fn wait(&self, duration: Duration) {
            self.0.lock().unwrap().push(duration);
        }
    }

    struct Harness {
        _root: tempfile::TempDir,
        launcher: LifecycleLauncher,
        store: Arc<SqliteStore>,
        github: Arc<FakeGithubLifecycle>,
        packages: Arc<FakePackages>,
        processes: Arc<FakeProcesses>,
        clock: Arc<FakeClock>,
        events: Arc<AttemptEventLog>,
        reconcile_events: Arc<crate::reconcile::EventLog>,
        delay: Arc<FakeDelay>,
        host: runner_manager_domain::model::Host,
        policy: ScalePolicy,
    }

    impl Harness {
        fn new(github: FakeGithubLifecycle, demand: Arc<dyn DemandPersistence>) -> Self {
            let root = tempfile::tempdir().unwrap();
            let paths = runner_manager_platform::paths::AppPaths::rooted_at(root.path());
            paths.create_all().unwrap();
            let policy = fixtures::policy()
                .repository("octo/repo")
                .autoscale("home", 2)
                .active()
                .build();
            let host = fixtures::host().build();
            let store = Arc::new(SqliteStore::open_in_memory().unwrap());
            let github = Arc::new(github);
            let packages = Arc::new(FakePackages::default());
            let processes = Arc::new(FakeProcesses::default());
            let clock = Arc::new(FakeClock::default());
            let events = Arc::new(AttemptEventLog::default());
            let reconcile_events = Arc::new(crate::reconcile::EventLog::new());
            let delay = Arc::new(FakeDelay::default());
            let ports = LifecyclePorts {
                store: Arc::clone(&store) as Arc<dyn Store>,
                github: Arc::clone(&github) as Arc<dyn LifecycleGithub>,
                packages: Arc::clone(&packages) as Arc<dyn RuntimePackages>,
                processes: Arc::clone(&processes) as Arc<dyn ProcessSupervisor>,
                clock: Arc::clone(&clock) as Arc<dyn Clock>,
                demand,
                delay: Arc::clone(&delay) as Arc<dyn RetryDelay>,
                events: Arc::clone(&events) as Arc<dyn AttemptEventSink>,
                reconcile_events: Arc::clone(&reconcile_events) as Arc<dyn EventSink>,
            };
            let launcher = LifecycleLauncher::new(
                policy.host_id,
                paths.runtime_dir(),
                paths.logs_dir(),
                1,
                RecoveryTimeouts::new(
                    Elapsed::seconds(10),
                    Elapsed::seconds(10),
                    Elapsed::seconds(10),
                ),
                RetryPolicy::bounded(3, Duration::from_millis(10), Duration::from_millis(25)),
                ports,
            );
            Self {
                _root: root,
                launcher,
                store,
                github,
                packages,
                processes,
                clock,
                events,
                reconcile_events,
                delay,
                host,
                policy,
            }
        }

        async fn ready(&self) {
            self.launcher
                .recover_startup(std::slice::from_ref(&self.policy))
                .await
                .unwrap();
        }

        async fn launch(&self) -> RunnerAttempt {
            self.launcher
                .launch(LaunchRequest {
                    host: &self.host,
                    policy: &self.policy,
                })
                .await
                .unwrap()
        }

        fn only_attempt(&self) -> RunnerAttempt {
            self.store.attempts().unwrap().into_iter().next().unwrap()
        }
    }

    #[tokio::test]
    async fn a_job_walks_every_state_and_cleans_every_artifact() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.ready().await;
        let started = harness.launch().await;
        assert_eq!(started.state(), AttemptState::Starting);
        assert_eq!(read_runner_id(started.runtime_path()), Some(73));

        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: false });
        harness.launcher.supervise(&harness.policy).await.unwrap();
        assert_eq!(harness.only_attempt().state(), AttemptState::Idle);

        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: true });
        harness.launcher.supervise(&harness.policy).await.unwrap();
        assert_eq!(harness.only_attempt().state(), AttemptState::Busy);

        harness.processes.finish_successfully();
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        harness.launcher.supervise(&harness.policy).await.unwrap();
        let cleaned = harness.only_attempt();
        assert_eq!(cleaned.state(), AttemptState::Cleaned);
        assert_eq!(cleaned.outcome(), Some(&AttemptOutcome::CompletedJob));
        assert!(!started.runtime_path().exists());
        assert_eq!(harness.packages.releases.load(Ordering::SeqCst), 1);
        assert_eq!(harness.github.remaining_runners.load(Ordering::SeqCst), 0);

        let states: Vec<_> = harness
            .events
            .events()
            .into_iter()
            .filter_map(|event| match event {
                AttemptEvent::State { state, .. } => Some(state),
                _ => None,
            })
            .collect();
        assert_eq!(
            states,
            vec![
                AttemptState::Allocated,
                AttemptState::JitReceived,
                AttemptState::Starting,
                AttemptState::Idle,
                AttemptState::Busy,
                AttemptState::Finished,
                AttemptState::Cleaned,
            ]
        );
    }

    #[tokio::test]
    async fn an_idle_exit_is_not_a_failure_in_the_journal_or_events() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.ready().await;
        let started = harness.launch().await;
        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: false });
        harness.launcher.supervise(&harness.policy).await.unwrap();
        harness.clock.advance_secs(11);
        harness.processes.set_alive(false);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        harness.launcher.supervise(&harness.policy).await.unwrap();

        let cleaned = harness.only_attempt();
        assert!(cleaned.outcome().unwrap().is_idle_exit());
        assert!(!cleaned.outcome().unwrap().is_failure());
        assert!(!started.runtime_path().exists());
        assert!(
            harness
                .reconcile_events
                .events()
                .iter()
                .any(|event| matches!(
                    event,
                    LifecycleEvent::AttemptCleaned {
                        outcome: OutcomeKind::IdleExit,
                        ..
                    }
                ))
        );
        assert!(!harness.events.events().iter().any(|event| matches!(
            event,
            AttemptEvent::Concluded {
                outcome: OutcomeKind::Failed,
                ..
            }
        )));
    }

    #[tokio::test]
    async fn handoff_is_absent_after_success_and_every_failed_spawn_retry() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.processes.fail_spawns(2);
        harness.ready().await;
        let attempt = harness.launch().await;
        assert_eq!(harness.processes.spawns.load(Ordering::SeqCst), 3);
        assert!(harness.processes.saw_secret.load(Ordering::SeqCst));
        let names: Vec<_> = fs::read_dir(attempt.runtime_path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| !name.to_string_lossy().starts_with("jit-")),
            "JIT artifact survived: {names:?}"
        );
        assert_eq!(
            *harness.delay.0.lock().unwrap(),
            vec![Duration::from_millis(10), Duration::from_millis(20)]
        );
    }

    #[tokio::test]
    async fn jit_retry_stops_with_demand_and_a_terminal_403_never_retries() {
        let gone = Harness::new(
            FakeGithubLifecycle::default().fail(false),
            Arc::new(FakeDemand::answering([false])),
        );
        gone.ready().await;
        assert!(
            gone.launcher
                .launch(LaunchRequest {
                    host: &gone.host,
                    policy: &gone.policy
                })
                .await
                .is_err()
        );
        assert_eq!(gone.github.registrations.load(Ordering::SeqCst), 1);
        assert!(gone.delay.0.lock().unwrap().is_empty());

        let forbidden = Harness::new(
            FakeGithubLifecycle::default().fail(true),
            Arc::new(PersistentDemand),
        );
        forbidden.ready().await;
        assert!(
            forbidden
                .launcher
                .launch(LaunchRequest {
                    host: &forbidden.host,
                    policy: &forbidden.policy,
                })
                .await
                .is_err()
        );
        assert_eq!(forbidden.github.registrations.load(Ordering::SeqCst), 1);
        assert!(forbidden.delay.0.lock().unwrap().is_empty());
        assert!(matches!(
            forbidden.only_attempt().outcome(),
            Some(AttemptOutcome::Failed {
                reason: FailureReason::Other(action)
            }) if action.contains("403")
        ));

        let transient = Harness::new(
            FakeGithubLifecycle::default().fail(false).fail(false),
            Arc::new(PersistentDemand),
        );
        transient.ready().await;
        transient.launch().await;
        assert_eq!(transient.github.registrations.load(Ordering::SeqCst), 3);
        assert_eq!(
            *transient.delay.0.lock().unwrap(),
            vec![Duration::from_millis(10), Duration::from_millis(20)]
        );
    }

    #[tokio::test]
    async fn two_attempts_never_share_a_workspace_even_after_failure() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.ready().await;
        let first = harness.launch().await;
        fs::write(first.runtime_path().join("hostile-leftover"), b"first job").unwrap();
        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: false });
        harness.launcher.supervise(&harness.policy).await.unwrap();
        harness.clock.advance_secs(11);
        harness.processes.set_alive(false);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        harness.launcher.supervise(&harness.policy).await.unwrap();
        assert!(!first.runtime_path().exists());

        let second = harness.launch().await;
        assert_ne!(first.runtime_path(), second.runtime_path());
        assert!(!second.runtime_path().join("hostile-leftover").exists());

        fs::write(
            second.runtime_path().join("hostile-on-failure"),
            b"second job",
        )
        .unwrap();
        harness.processes.set_alive(false);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        harness.launcher.supervise(&harness.policy).await.unwrap();
        assert!(
            !second.runtime_path().exists(),
            "failed workspace was retained"
        );
    }

    #[tokio::test]
    async fn exit_before_acceptance_concludes_and_persistent_demand_gets_a_fresh_attempt() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.ready().await;
        let first = harness.launch().await;
        harness.processes.set_alive(false);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        harness.launcher.supervise(&harness.policy).await.unwrap();
        let failed = harness.store.attempt(first.id).unwrap().unwrap();
        assert!(matches!(
            failed.outcome(),
            Some(AttemptOutcome::Failed {
                reason: FailureReason::ProcessExitedUnexpectedly
            })
        ));
        assert!(!first.runtime_path().exists());

        // This is the next e1 grant after demand was recomputed and remained.
        let replacement = harness.launch().await;
        assert_ne!(replacement.id, first.id);
        assert_eq!(harness.github.registrations.load(Ordering::SeqCst), 2);
        assert_eq!(harness.processes.spawns.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn expired_jit_is_removed_and_does_not_reregister_after_demand_disappears() {
        let harness = Harness::new(
            FakeGithubLifecycle::default(),
            Arc::new(FakeDemand::answering([false])),
        );
        let id = AttemptId::new_random();
        let runtime = harness
            .launcher
            .runtime_root
            .join(harness.policy.id.to_string())
            .join(id.to_string());
        fs::create_dir_all(&runtime).unwrap();
        let mut attempt =
            RunnerAttempt::allocate(id, harness.policy.id, &runtime, harness.clock.now());
        attempt.jit_received(harness.clock.now()).unwrap();
        harness.store.record_attempt(&attempt).unwrap();
        harness.clock.advance_secs(11);
        harness
            .launcher
            .recover_startup(std::slice::from_ref(&harness.policy))
            .await
            .unwrap();

        let cleaned = harness.store.attempt(id).unwrap().unwrap();
        assert_eq!(cleaned.state(), AttemptState::Cleaned);
        assert!(matches!(
            cleaned.outcome(),
            Some(AttemptOutcome::Failed {
                reason: FailureReason::JitExpired
            })
        ));
        assert!(!runtime.exists());
        assert_eq!(harness.github.registrations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn startup_adopts_a_live_process_and_refuses_launch_before_recovery() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let before = harness
            .launcher
            .launch(LaunchRequest {
                host: &harness.host,
                policy: &harness.policy,
            })
            .await;
        assert!(before.is_err());
        assert_eq!(harness.processes.spawns.load(Ordering::SeqCst), 0);

        let id = AttemptId::new_random();
        let runtime = harness.launcher.runtime_root.join("adopt");
        fs::create_dir_all(&runtime).unwrap();
        let mut attempt =
            RunnerAttempt::allocate(id, harness.policy.id, runtime, harness.clock.now());
        attempt.jit_received(harness.clock.now()).unwrap();
        attempt.started(4242, harness.clock.now()).unwrap();
        harness.store.record_attempt(&attempt).unwrap();
        harness.processes.set_alive(true);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        harness
            .launcher
            .recover_startup(std::slice::from_ref(&harness.policy))
            .await
            .unwrap();
        assert_eq!(harness.processes.spawns.load(Ordering::SeqCst), 0);
        assert!(
            harness
                .events
                .events()
                .contains(&AttemptEvent::Adopted { attempt: id })
        );
    }

    #[tokio::test]
    async fn a_dead_busy_process_unknown_to_github_is_orphaned_and_cleaned() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let id = AttemptId::new_random();
        let runtime = harness.launcher.runtime_root.join("orphan");
        fs::create_dir_all(&runtime).unwrap();
        let mut attempt =
            RunnerAttempt::allocate(id, harness.policy.id, &runtime, harness.clock.now());
        attempt.jit_received(harness.clock.now()).unwrap();
        attempt.started(4242, harness.clock.now()).unwrap();
        attempt.assigned_job(73, harness.clock.now()).unwrap();
        harness.store.record_attempt(&attempt).unwrap();
        harness.processes.set_alive(false);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        harness
            .launcher
            .recover_startup(std::slice::from_ref(&harness.policy))
            .await
            .unwrap();
        let cleaned = harness.store.attempt(id).unwrap().unwrap();
        assert_eq!(cleaned.state(), AttemptState::Cleaned);
        assert_eq!(cleaned.outcome(), Some(&AttemptOutcome::Orphaned));
        assert!(!runtime.exists());
    }

    #[tokio::test]
    async fn registration_timeout_journals_intent_stops_then_concludes_with_dead_reason() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let id = AttemptId::new_random();
        let runtime = harness.launcher.runtime_root.join("timeout");
        fs::create_dir_all(&runtime).unwrap();
        let mut attempt =
            RunnerAttempt::allocate(id, harness.policy.id, runtime, harness.clock.now());
        attempt.jit_received(harness.clock.now()).unwrap();
        attempt.started(4242, harness.clock.now()).unwrap();
        harness.store.record_attempt(&attempt).unwrap();
        harness.clock.advance_secs(11);
        harness.processes.set_alive(true);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        harness
            .launcher
            .recover_startup(std::slice::from_ref(&harness.policy))
            .await
            .unwrap();

        assert_eq!(harness.processes.terminations.load(Ordering::SeqCst), 1);
        assert!(!harness.processes.alive.load(Ordering::SeqCst));
        let actions = harness.processes.actions.lock().unwrap().clone();
        let intent = actions
            .iter()
            .position(|action| *action == "terminate_intent")
            .unwrap();
        let signal = actions
            .iter()
            .position(|action| *action == "terminate")
            .unwrap();
        assert!(
            intent < signal,
            "intent was not durable before signal: {actions:?}"
        );

        let cleaned = harness.store.attempt(id).unwrap().unwrap();
        assert!(matches!(
            cleaned.outcome(),
            Some(AttemptOutcome::Failed {
                reason: FailureReason::TerminatedAfterRegistrationTimeout
            })
        ));
        let events = harness.events.events();
        let intent = events
            .iter()
            .position(|event| matches!(event, AttemptEvent::TerminateIntent { .. }))
            .unwrap();
        let stopped = events
            .iter()
            .position(|event| matches!(event, AttemptEvent::Terminated { .. }))
            .unwrap();
        let concluded = events
            .iter()
            .position(|event| matches!(event, AttemptEvent::Concluded { .. }))
            .unwrap();
        assert!(intent < stopped && stopped < concluded, "{events:?}");
    }

    #[tokio::test]
    async fn diagnostics_survive_cleanup_without_the_jit_or_a_token() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.ready().await;
        let attempt = harness.launch().await;
        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: false });
        harness.launcher.supervise(&harness.policy).await.unwrap();
        harness.clock.advance_secs(11);
        harness.processes.set_alive(false);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        harness.launcher.supervise(&harness.policy).await.unwrap();
        let diagnostic = fs::read_to_string(
            harness
                .launcher
                .diagnostics_root
                .join(format!("{}.log", attempt.id)),
        )
        .unwrap();
        assert!(diagnostic.contains("exited_idle_without_work"));
        assert!(!diagnostic.contains(JIT));
        assert!(!diagnostic.contains("ghp_"));
        assert!(!attempt.runtime_path().exists());
    }

    #[test]
    fn native_process_listing_never_contains_jit_and_handoffs_never_survive() {
        let root = tempfile::tempdir().unwrap();
        let policy = fixtures::policy()
            .repository("octo/repo")
            .autoscale("home", 1)
            .active()
            .build();
        let runtime = root.path().join("successful");
        fs::create_dir_all(&runtime).unwrap();
        let processes = NativeProcesses::new();
        let config = EncodedJitConfig::new(JIT);
        let handoff =
            RestrictiveHandoff::create(&runtime, SecretString::from(config.expose().to_owned()))
                .unwrap();
        let mut child = native_inspection_spec(handoff.path())
            .spawn_with_handoff(&handoff)
            .expect("native child starts");
        let pid = child.pid();
        handoff.delete().unwrap();
        let command_line = native_command_line(pid);
        assert!(
            !command_line.contains(JIT),
            "the encoded JIT configuration appeared in the native process listing"
        );
        assert_no_jit_file(&runtime);
        child
            .stop(Duration::from_secs(1))
            .expect("native child stops");

        let failed_runtime = root.path().join("failed");
        fs::create_dir_all(&failed_runtime).unwrap();
        let failed = RunnerAttempt::allocate(
            AttemptId::new_random(),
            policy.id,
            &failed_runtime,
            FakeClock::default().now(),
        );
        assert!(
            processes
                .spawn(&failed, &EncodedJitConfig::new(JIT))
                .is_err(),
            "a runtime with no runner executable must fail"
        );
        assert_no_jit_file(&failed_runtime);
    }

    #[tokio::test]
    async fn package_prune_is_reached_only_with_the_host_allocation_guard() {
        use crate::reconcile::{AllocationLock, InProcessAllocationLock};

        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let lock = InProcessAllocationLock::new();
        let guard = lock.acquire().await.expect("host allocation lock");
        harness
            .launcher
            .prune_under_allocation_lock(&guard, &harness.packages.version)
            .unwrap();
        assert_eq!(harness.packages.prunes.load(Ordering::SeqCst), 1);
    }

    fn assert_no_jit_file(runtime: &Path) {
        for entry in fs::read_dir(runtime).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = fs::read(&path).unwrap();
                assert!(
                    !bytes
                        .windows(JIT.len())
                        .any(|window| window == JIT.as_bytes()),
                    "a JIT payload survived in a runtime file"
                );
            }
        }
    }

    #[cfg(windows)]
    fn native_inspection_spec(handoff: &Path) -> SpawnSpec {
        SpawnSpec::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ])
            .arg("--jit-config-file")
            .arg(handoff)
    }

    #[cfg(unix)]
    fn native_inspection_spec(handoff: &Path) -> SpawnSpec {
        SpawnSpec::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .arg("--jit-config-file")
            .arg(handoff)
    }

    #[cfg(windows)]
    fn native_command_line(pid: u32) -> String {
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("(Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}').CommandLine"),
            ])
            .output()
            .expect("PowerShell can inspect the native child");
        assert!(output.status.success(), "native process inspection failed");
        String::from_utf8(output.stdout).expect("Windows command lines are Unicode")
    }

    #[cfg(target_os = "linux")]
    fn native_command_line(pid: u32) -> String {
        fs::read(format!("/proc/{pid}/cmdline"))
            .map(|bytes| String::from_utf8_lossy(&bytes).replace('\0', " "))
            .expect("/proc exposes the native child command line")
    }

    #[cfg(target_os = "macos")]
    fn native_command_line(pid: u32) -> String {
        let output = std::process::Command::new("ps")
            .args(["-o", "command=", "-p", &pid.to_string()])
            .output()
            .expect("ps can inspect the native child");
        assert!(output.status.success(), "native process inspection failed");
        String::from_utf8(output.stdout).expect("the command line is UTF-8")
    }
}
