// owner: e3-jit-lifecycle-recovery

//! One ephemeral runner, from an allocation decision to a scrubbed runtime.
//!
//! The ordering in this module is intentional.  An attempt is written before
//! the package or GitHub is touched, the JIT value exists only in a restrictive
//! handoff, and a registration-timeout termination is journalled before the
//! process is signalled.  Recovery uses the same code as ordinary supervision;
//! startup merely supplies the first observation.

#[cfg(test)]
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::Write;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use runner_manager_domain::attempt::{
    AttemptOutcome, AttemptState, FailureReason, GithubRunnerObservation, RecoveryDecision,
    RecoveryObservation, RecoveryTimeouts, RunnerAttempt, authorize, recovery_decision,
};
use runner_manager_domain::model::{AttemptId, Clock, HostId, PolicyId, ScaleTarget};
use runner_manager_domain::path::LocalAbsolutePath;
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_domain::workspace::{AttemptWorkspace, WorkspacePolicy};
use runner_manager_github::jit::{
    DEFAULT_WORK_FOLDER, EncodedJitConfig, JitError, JitGateway, JitRegistration, JitRunnerRequest,
};
use runner_manager_github::rest::{CancelToken, InventoryGateway};
use runner_manager_platform::process::{
    Adoption, ChildProcess, ProcessIdentity, RestrictiveHandoff, SpawnSpec, Termination,
};
use runner_manager_platform::runner_root::{
    self, RootOwner, RootPreflight, RunnerRootError, default_runner_root,
};
use secrecy::SecretString;

use crate::package::{PackageCache, PackageError, RunnerVersion};
use crate::reconcile::{
    AllocationGuard, EventSink, LaunchFailure, LaunchRequest, LifecycleEvent, OutcomeKind,
    ReplacementIntent, RunnerLauncher,
};

const IDENTITY_FILE: &str = ".runner-process.json";
const FALLBACK_IDENTITY_FILE: &str = ".runner-process.recovery.json";
const UNRESOLVED_PROCESS_FILE: &str = ".runner-process.unresolved";
const RUNNER_ID_FILE: &str = ".github-runner-id";
const TERMINATE_INTENT_FILE: &str = ".terminate-registration-timeout";
const MAX_POST_SPAWN_STOP_ATTEMPTS: usize = 3;
#[cfg(test)]
const TEST_LISTENER_READY: &str = ".test-listener-ready";

/// GitHub Runner v2.336.0 accepts JIT configuration for `run` through its
/// secret `ACTIONS_RUNNER_INPUT_JITCONFIG` input. The platform spawn boundary
/// supplies that input from the restrictive handoff; the listener command line
/// must contain only the supported `run` command.
fn runner_listener_spec(program: PathBuf, runtime: &Path) -> SpawnSpec {
    SpawnSpec::new(program).arg("run").working_dir(runtime)
}

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
    RemoteIdentityRecovered {
        attempt: AttemptId,
        runner_id: u64,
    },
    TerminateIntent {
        attempt: AttemptId,
    },
    Terminated {
        attempt: AttemptId,
    },
    /// The attempt's GitHub registration was removed by this agent. Carries the
    /// runner id because that is the identifier an operator sees in the
    /// target's runner settings, and the attempt id is not shown there.
    Deregistered {
        attempt: AttemptId,
        runner_id: u64,
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

/// GitHub's authoritative runner state plus the identity returned by inventory.
/// The id is carried independently of the local sidecar so recovery can close
/// the crash boundary immediately after a successful remote registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleGithubObservation {
    pub status: GithubRunnerObservation,
    pub runner_id: Option<u64>,
}

impl LifecycleGithubObservation {
    #[must_use]
    pub const fn unreachable() -> Self {
        Self {
            status: GithubRunnerObservation::Unreachable,
            runner_id: None,
        }
    }

    #[must_use]
    pub const fn not_registered() -> Self {
        Self {
            status: GithubRunnerObservation::NotRegistered,
            runner_id: None,
        }
    }

    #[must_use]
    pub const fn registered(runner_id: u64, busy: bool) -> Self {
        Self {
            status: GithubRunnerObservation::Registered { busy },
            runner_id: Some(runner_id),
        }
    }
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
    ) -> LifecycleGithubObservation;

    /// Remove one runner registration this agent created.
    ///
    /// Answers whether the registration is gone, and is deliberately not
    /// fallible in the `Result` sense: no caller may abandon a conclusion
    /// because GitHub was unreachable. See
    /// [`LifecycleLauncher::deregister_runner`].
    async fn deregister(&self, target: &ScaleTarget, runner_id: u64, cancel: &CancelToken) -> bool;
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
    ) -> LifecycleGithubObservation {
        let expected_name = runner_name(attempt);
        match self.list_runners(target, cancel).await {
            Ok(inventory) => inventory
                .runners()
                .iter()
                .find(|runner| runner.name == expected_name)
                .map_or(LifecycleGithubObservation::not_registered(), |runner| {
                    LifecycleGithubObservation::registered(runner.id, runner.busy)
                }),
            Err(_) => LifecycleGithubObservation::unreachable(),
        }
    }

    async fn deregister(&self, target: &ScaleTarget, runner_id: u64, cancel: &CancelToken) -> bool {
        self.remove_runner(target, runner_id, cancel).await.is_ok()
    }
}

/// Package/cache operations used by one attempt.
#[async_trait]
pub trait RuntimePackages: fmt::Debug + Send + Sync {
    async fn materialize(&self, attempt: &RunnerAttempt) -> Result<RunnerVersion, FailureReason>;
    fn release(&self, attempt: AttemptId) -> Result<(), FailureReason>;
    fn prune_obsolete_guarded(
        &self,
        authority: PruneAuthority<'_>,
        current: &RunnerVersion,
        attempts: &[RunnerAttempt],
    ) -> Result<(), FailureReason>;
}

/// Unforgeable evidence that pruning was reached through e1's launch request.
/// The type is public only because it appears in the public adapter trait; its
/// private field and constructor prevent callers from substituting a guard
/// acquired from an unrelated lock.
pub struct PruneAuthority<'a> {
    _guard: &'a AllocationGuard,
}

impl fmt::Debug for PruneAuthority<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PruneAuthority")
    }
}

impl<'a> PruneAuthority<'a> {
    fn from_launch_request(guard: &'a AllocationGuard) -> Self {
        Self { _guard: guard }
    }
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
            // Undoing the copy must not undo the *job* workspace: a persistent
            // slot's `_work` is retained across attempts, and this rollback
            // runs before the attempt that would have owned it ever started.
            let _ = remove_materialized_package(attempt);
            return Err(package_failure(error));
        }
        Ok(installed.version().clone())
    }

    fn release(&self, attempt: AttemptId) -> Result<(), FailureReason> {
        self.cache.release(attempt).map_err(package_failure)
    }

    fn prune_obsolete_guarded(
        &self,
        _authority: PruneAuthority<'_>,
        current: &RunnerVersion,
        attempts: &[RunnerAttempt],
    ) -> Result<(), FailureReason> {
        for installed in self.cache.installed().map_err(package_failure)? {
            if installed.version() != current {
                match self.cache.prune(installed.version(), attempts) {
                    Ok(()) | Err(PackageError::VersionInUse { .. }) => {}
                    Err(error) => return Err(package_failure(error)),
                }
            }
        }
        Ok(())
    }
}

fn package_failure(error: PackageError) -> FailureReason {
    error.failure_reason().unwrap_or(FailureReason::Other(
        "runner package cache operation failed".into(),
    ))
}

fn package_failure_is_terminal(reason: &FailureReason) -> bool {
    matches!(
        reason,
        FailureReason::RunnerPackageUnverified | FailureReason::RunnerVersionRejected
    )
}

/// How many hex characters of the attempt id name its workspace.
///
/// # Why this is not the whole identifier, and why the policy is not in the path
///
/// Windows refuses a path over `MAX_PATH`, and the runner writes deep inside
/// this directory: `_work/<repo>/<repo>/.git/objects/pack/pack-<40 hex>.keep`
/// is 100 characters on its own before the repository is named twice. The
/// layout used to add two full identifiers -- the policy's and the attempt's,
/// 74 characters between them -- and that was enough to put a real checkout
/// over the line. Measured, not guessed: this repository's own CI failed here
/// three times in a row at 264 characters against a limit of 260, with
/// `fatal: cannot write keep file ...: Filename too long`. A repository whose
/// name is ten characters longer would have missed by fourteen.
///
/// The policy identifier is simply redundant -- an attempt identifier is
/// unique on its own, and nothing reads the directory tree to find a policy's
/// attempts, because [`crate::lifecycle::LifecycleLauncher`] asks the journal.
/// Twelve hex characters of the attempt is 48 bits, which for the handful of
/// directories one host holds at once is not a collision anybody will see, and
/// the journal keeps the full identifier either way.
///
/// Together that is 61 characters returned to the repository name.
const WORKSPACE_NAME_LEN: usize = 12;

/// The directory name for one attempt's workspace.
fn workspace_name(id: AttemptId) -> String {
    let full = id.to_string();
    full.chars()
        .filter(|c| *c != '-')
        .take(WORKSPACE_NAME_LEN)
        .collect()
}

/// Where one attempt's files go, and which cleanup algorithm they are owed.
///
/// The pair travels together because journalling them apart is exactly the bug
/// `AttemptWorkspace` exists to prevent: a `runtime_path` under a persistent
/// root recorded as ephemeral would be removed whole, taking the retained job
/// workspace with it.
#[derive(Debug, Clone)]
struct Placement {
    runtime: PathBuf,
    workspace: AttemptWorkspace,
}

/// A runner-root refusal, rendered for the operator who has to fix it.
///
/// `RunnerRootError`'s `Display` already names the path, the relation and the
/// remediation command, and none of its variants can carry a credential — they
/// are paths, and `03-migration-rollout.md` requires the remediation command to
/// reach the operator verbatim.
fn root_failure(error: RunnerRootError) -> LifecycleError {
    LifecycleError::Failed(FailureReason::Other(error.to_string()))
}

/// The lowest positive slot inside `ceiling` that no uncleaned attempt holds.
///
/// `leases` is the journal's answer to "which slots are leased"
/// (`Store::slot_leases_for_policy`), which deliberately includes a terminal
/// attempt whose cleanup has not finished: that attempt still owns its
/// directory, so its slot is not free even though it no longer counts against
/// host capacity. `None` means the ceiling is reached, which is a refusal and
/// not a reason to allocate `s(ceiling + 1)`.
fn lowest_free_slot(leases: &[RunnerAttempt], ceiling: NonZeroU16) -> Option<NonZeroU16> {
    let held: BTreeSet<u16> = leases
        .iter()
        .filter_map(|attempt| attempt.workspace().slot_number())
        .collect();
    (1..=ceiling.get())
        .find(|slot| !held.contains(slot))
        .and_then(NonZeroU16::new)
}

/// Create `<root>/sN`, or prove that what is already there is a real directory.
///
/// A symlink, junction or reparse point standing where the slot should be is
/// refused rather than followed: it is the one thing that could put an attempt's
/// files outside the root the operator configured, and
/// `04-security-recovery.md` requires that case to fail closed rather than to
/// be repaired here.
fn create_or_validate_slot(slot: &Path) -> Result<(), LifecycleError> {
    match fs::symlink_metadata(slot) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(slot_refusal(
            slot,
            "is a symbolic link, junction or other reparse point, which could place runner \
             files outside the configured root",
        )),
        Ok(metadata) if !metadata.is_dir() => Err(slot_refusal(slot, "is not a directory")),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(slot)
            .map_err(|source| slot_refusal(slot, format!("could not be created: {source}"))),
        Err(source) => Err(slot_refusal(
            slot,
            format!("could not be inspected: {source}"),
        )),
    }
}

/// Accept a slot for reuse only when it is empty or holds one real `_work`.
///
/// `02-target-architecture.md`: "Before materialization, a reusable slot must
/// contain only a valid real `_work` directory or be empty." Everything else —
/// a leftover `bin/`, a link-shaped `_work`, a stray file — is refused here
/// rather than cleaned, because deciding whether those bytes are safe is
/// cleanup's and recovery's job (`c3`), and quietly reusing them would hand one
/// repository's retained state to the next attempt without anybody choosing to.
///
/// The inspection is one level deep and uses `symlink_metadata`, so nothing is
/// followed while it is being judged.
fn accept_reusable_slot(slot: &Path) -> Result<(), LifecycleError> {
    let unreadable =
        |source: std::io::Error| slot_refusal(slot, format!("could not be read: {source}"));
    let entries = fs::read_dir(slot).map_err(unreadable)?;
    let mut refused: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(unreadable)?;
        let name = entry.file_name();
        let metadata = fs::symlink_metadata(entry.path()).map_err(|source| {
            slot_refusal(
                slot,
                format!("entry {name:?} could not be inspected: {source}"),
            )
        })?;
        // `symlink_metadata` reports a link as a link, so `is_dir` here is
        // already "a real directory" and the link test is the message, not the
        // rule.
        if is_work_folder(&name) && metadata.is_dir() {
            continue;
        }
        refused.push(name.to_string_lossy().into_owned());
    }
    if refused.is_empty() {
        return Ok(());
    }
    refused.sort();
    Err(slot_refusal(
        slot,
        format!(
            "holds {} that this attempt may not reuse: [{}]. A reusable slot is empty or holds \
             one real `{DEFAULT_WORK_FOLDER}` directory and nothing else; remove or move the \
             entries listed, or let cleanup and recovery resolve them",
            if refused.len() == 1 {
                "an entry"
            } else {
                "entries"
            },
            refused.join(", ")
        ),
    ))
}

fn slot_refusal(slot: &Path, detail: impl fmt::Display) -> LifecycleError {
    LifecycleError::Failed(FailureReason::Other(format!(
        "the persistent slot {} {detail}",
        slot.display()
    )))
}

/// Whether a directory entry names the retained job workspace.
///
/// The comparison folds case on Windows because the filesystem does: there
/// `_Work` and `_work` are one directory, so a case-sensitive test would let
/// [`remove_slot_entries_except_work`] delete the very directory it exists to
/// keep, let [`accept_reusable_slot`] refuse a slot that holds nothing but a
/// valid job workspace, and let a package's top-level `_Work` merge itself into
/// the previous attempt's `_work`. Elsewhere the two names really are two
/// directories and only the exact one is the job workspace.
fn is_work_folder(name: &OsStr) -> bool {
    if cfg!(windows) {
        name.eq_ignore_ascii_case(DEFAULT_WORK_FOLDER)
    } else {
        name == OsStr::new(DEFAULT_WORK_FOLDER)
    }
}

/// Undo one package materialization, dispatching on the journalled workspace.
///
/// The ephemeral half is what this always did: the directory is the attempt's
/// alone, so it goes whole. The persistent half removes the copy and nothing
/// else, because the slot's `_work` predates this attempt and outlives it
/// (`02-target-architecture.md`, "Persistent repository").
fn remove_materialized_package(attempt: &RunnerAttempt) -> std::io::Result<()> {
    match attempt.workspace() {
        AttemptWorkspace::Ephemeral => fs::remove_dir_all(attempt.runtime_path()),
        AttemptWorkspace::PersistentSlot { .. } => {
            remove_slot_entries_except_work(attempt.runtime_path())
        }
    }
}

/// Every direct child of a slot except the retained job workspace.
///
/// A link-shaped entry is unlinked rather than followed, so removal cannot
/// reach outside the slot even though `accept_reusable_slot` already refused to
/// allocate into a slot holding one.
fn remove_slot_entries_except_work(slot: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(slot)? {
        let entry = entry?;
        if is_work_folder(&entry.file_name()) {
            continue;
        }
        let path = entry.path();
        let file_type = fs::symlink_metadata(&path)?.file_type();
        if file_type.is_symlink() {
            // A file symlink unlinks with `remove_file`; a directory symlink or
            // a Windows junction needs `remove_dir`. Neither follows the link.
            fs::remove_file(&path).or_else(|_| fs::remove_dir(&path))?;
        } else if file_type.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn replacement_operation(outcome: &AttemptOutcome) -> Option<&'static str> {
    match outcome {
        AttemptOutcome::Failed {
            reason: FailureReason::JitExpired,
        } => Some("jit_expired_replacement"),
        AttemptOutcome::Failed {
            reason: FailureReason::ProcessExitedUnexpectedly,
        } => Some("exit_before_acceptance_replacement"),
        _ => None,
    }
}

/// Lay the verified runner package out *around* whatever the slot retains.
///
/// `02-target-architecture.md`: "The verified runner package is copied into the
/// slot for the attempt", beside a `_work` that survives every attempt. Two
/// properties make that safe, and both are structural rather than documented:
///
/// * the walk is of the **source** tree, so a retained `_work` in the
///   destination is never opened, never descended into, and cannot be followed
///   wherever it might point;
/// * a top-level source entry named `_work` is refused rather than copied, so a
///   package that ever grew one could not merge itself into, or replace, the
///   job workspace of the attempt before it. The refusal is top-level only,
///   because the retained directory is a direct child of the slot; a `_work`
///   nested inside the package's own tree is an ordinary name.
fn copy_package_tree(source: &Path, destination: &Path) -> std::io::Result<()> {
    copy_package_entries(source, destination, true)
}

fn copy_package_entries(source: &Path, destination: &Path, top_level: bool) -> std::io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if top_level && is_work_folder(&entry.file_name()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "the runner package holds a top-level `{DEFAULT_WORK_FOLDER}`; copying \
                     it would overwrite the job workspace a persistent slot retains"
                ),
            ));
        }
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_package_entries(&entry.path(), &target, false)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Process operations are attempt-addressed so a recovered process and a child
/// started in this invocation are supervised through one port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStartFailure {
    pub reason: FailureReason,
    /// False once a child existed: the one-shot JIT value may have been
    /// consumed, so retrying it could start a duplicate.
    pub retryable: bool,
    /// Set only when cleanup could not prove the spawned process dead.  The
    /// caller must journal `starting` and retain capacity/supervision.
    pub live_pid: Option<u32>,
}

impl ProcessStartFailure {
    fn before_spawn(reason: FailureReason) -> Self {
        Self {
            reason,
            retryable: true,
            live_pid: None,
        }
    }

    fn after_spawn_stopped() -> Self {
        Self {
            reason: FailureReason::ProcessStartFailed,
            retryable: false,
            live_pid: None,
        }
    }

    fn after_spawn_live(pid: u32) -> Self {
        Self::after_spawn_live_with_reason(pid, FailureReason::ProcessStartFailed)
    }

    fn after_spawn_live_with_reason(pid: u32, reason: FailureReason) -> Self {
        Self {
            reason,
            retryable: false,
            live_pid: Some(pid),
        }
    }
}

pub trait ProcessSupervisor: fmt::Debug + Send + Sync {
    fn spawn(
        &self,
        attempt: &RunnerAttempt,
        config: &EncodedJitConfig,
    ) -> Result<u32, ProcessStartFailure>;
    fn is_alive(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason>;
    /// Durable identity observed for a process that spawned before the
    /// `starting` journal write survived.
    fn recovered_pid(&self, attempt: &RunnerAttempt) -> Result<Option<u32>, FailureReason>;
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
    #[cfg(test)]
    post_spawn_faults: Mutex<VecDeque<PostSpawnBoundary>>,
    #[cfg(test)]
    post_spawn_reaps: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    post_spawn_stop_failures: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    use_long_lived_test_listener: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostSpawnBoundary {
    HandoffDelete,
    IdentitySerialize,
    IdentityWrite,
    ChildMapInsert,
}

impl NativeProcesses {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn fail_post_spawn_at(&self, boundary: PostSpawnBoundary) {
        self.post_spawn_faults.lock().unwrap().push_back(boundary);
    }

    #[cfg(test)]
    fn faults_at(&self, boundary: PostSpawnBoundary) -> bool {
        let mut faults = self.post_spawn_faults.lock().unwrap();
        if faults.front() == Some(&boundary) {
            faults.pop_front();
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn fail_post_spawn_stops(&self, count: usize) {
        self.post_spawn_stop_failures
            .fetch_add(count, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn fail_next_post_spawn_stop(&self) {
        self.fail_post_spawn_stops(1);
    }

    #[cfg(test)]
    fn use_long_lived_test_listener(&self) {
        self.use_long_lived_test_listener
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn stop_spawned_child(&self, child: &mut ChildProcess) -> Result<(), FailureReason> {
        #[cfg(test)]
        if self
            .post_spawn_stop_failures
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |left| if left > 0 { Some(left - 1) } else { None },
            )
            .is_ok()
        {
            return Err(FailureReason::Other("injected runner stop failure".into()));
        }
        child
            .stop(Duration::from_secs(1))
            .map(|_| ())
            .map_err(|_| FailureReason::Other("spawned runner process could not be stopped".into()))
    }

    fn abort_spawned_child(
        &self,
        mut child: ChildProcess,
        attempt: &RunnerAttempt,
        remove_identity: bool,
    ) -> ProcessStartFailure {
        let mut reaped = self.stop_spawned_child(&mut child).is_ok();
        if reaped {
            if remove_identity {
                Self::remove_identity_files(attempt);
            }
        } else {
            // A failed stop is not a failed attempt yet.  Persist enough truth
            // for crash recovery, and retain the owned child when possible.
            let identity_durable =
                serde_json::to_vec(child.identity())
                    .ok()
                    .is_some_and(|identity| {
                        self.persist_identity(attempt, &identity).is_ok()
                            || self.persist_fallback_identity(attempt, &identity).is_ok()
                    });
            if !identity_durable {
                // Returning a live PID as though recovery were complete would
                // make the next boot trust a recyclable PID. Reaping is bounded;
                // if it cannot finish, the durable `starting` journal entry is
                // deliberately unresolved on restart and blocks new launches.
                for _ in 1..MAX_POST_SPAWN_STOP_ATTEMPTS {
                    if self.stop_spawned_child(&mut child).is_ok() {
                        reaped = true;
                        break;
                    }
                }
                if !reaped {
                    // The attempt journal will durably record `starting` and
                    // its PID. Recovery treats a missing full identity as
                    // unresolved and starts nothing, so bounded stop failure
                    // cannot turn into either a hang or a duplicate runner.
                    let pid = child.pid();
                    let marker = write_durable_file(
                        &Self::unresolved_process_path(attempt),
                        pid.to_string().as_bytes(),
                    );
                    self.children
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(attempt.id, child);
                    let reason = if marker.is_ok() {
                        FailureReason::Other(
                            "spawn cleanup exhausted its bounded stop attempts; the live process remains under durable unresolved supervision"
                                .into(),
                        )
                    } else {
                        FailureReason::Other(
                            "spawn cleanup exhausted its bounded stop attempts and the unresolved-process marker could not be journalled"
                                .into(),
                        )
                    };
                    return ProcessStartFailure::after_spawn_live_with_reason(pid, reason);
                }
            } else {
                let pid = child.pid();
                self.children
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(attempt.id, child);
                return ProcessStartFailure::after_spawn_live(pid);
            }
        }
        #[cfg(test)]
        if reaped {
            self.post_spawn_reaps
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        #[cfg(not(test))]
        let _ = reaped;
        ProcessStartFailure::after_spawn_stopped()
    }

    fn identity_path(attempt: &RunnerAttempt) -> PathBuf {
        attempt.runtime_path().join(IDENTITY_FILE)
    }

    fn fallback_identity_path(attempt: &RunnerAttempt) -> PathBuf {
        attempt.runtime_path().join(FALLBACK_IDENTITY_FILE)
    }

    fn unresolved_process_path(attempt: &RunnerAttempt) -> PathBuf {
        attempt.runtime_path().join(UNRESOLVED_PROCESS_FILE)
    }

    fn remove_identity_files(attempt: &RunnerAttempt) {
        let _ = fs::remove_file(Self::identity_path(attempt));
        let _ = fs::remove_file(Self::fallback_identity_path(attempt));
        let _ = fs::remove_file(Self::unresolved_process_path(attempt));
    }

    fn persist_identity(&self, attempt: &RunnerAttempt, bytes: &[u8]) -> std::io::Result<()> {
        self.persist_identity_at(&Self::identity_path(attempt), bytes)
    }

    fn persist_fallback_identity(
        &self,
        attempt: &RunnerAttempt,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        self.persist_identity_at(&Self::fallback_identity_path(attempt), bytes)
    }

    fn persist_identity_at(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        #[cfg(test)]
        if self.faults_at(PostSpawnBoundary::IdentityWrite) {
            return Err(std::io::Error::other("injected identity write failure"));
        }
        write_durable_file(path, bytes)
    }

    fn intent_path(attempt: &RunnerAttempt) -> PathBuf {
        attempt.runtime_path().join(TERMINATE_INTENT_FILE)
    }

    fn read_identity(attempt: &RunnerAttempt) -> Result<Option<ProcessIdentity>, FailureReason> {
        match Self::read_identity_at(&Self::identity_path(attempt))? {
            Some(identity) => Ok(Some(identity)),
            None => Self::read_identity_at(&Self::fallback_identity_path(attempt)),
        }
    }

    fn read_identity_at(path: &Path) -> Result<Option<ProcessIdentity>, FailureReason> {
        match fs::read(path) {
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
    ) -> Result<u32, ProcessStartFailure> {
        let handoff = RestrictiveHandoff::create(
            attempt.runtime_path(),
            SecretString::from(config.expose().to_owned()),
        )
        .map_err(|_| ProcessStartFailure::before_spawn(FailureReason::ProcessStartFailed))?;
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
            return Err(ProcessStartFailure::before_spawn(
                FailureReason::ProcessStartFailed,
            ));
        }
        #[cfg(test)]
        let spec = if self
            .use_long_lived_test_listener
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            SpawnSpec::new(program)
                .args([
                    "--ignored",
                    "--exact",
                    "lifecycle::tests::long_lived_native_listener_helper",
                    "--nocapture",
                ])
                .env(
                    "RUNNER_MANAGER_TEST_LISTENER_READY",
                    attempt.runtime_path().join(TEST_LISTENER_READY),
                )
                .working_dir(attempt.runtime_path())
        } else {
            runner_listener_spec(program, attempt.runtime_path())
        };
        #[cfg(not(test))]
        let spec = runner_listener_spec(program, attempt.runtime_path());
        let child = spec
            .spawn_runner_with_handoff(&handoff)
            .map_err(|_| ProcessStartFailure::before_spawn(FailureReason::ProcessStartFailed))?;
        // The payload is gone before any state saying "starting" is persisted.
        #[cfg(test)]
        if self.faults_at(PostSpawnBoundary::HandoffDelete) {
            drop(handoff);
            return Err(self.abort_spawned_child(child, attempt, false));
        }
        if handoff.delete().is_err() {
            return Err(self.abort_spawned_child(child, attempt, false));
        }
        #[cfg(test)]
        if self.faults_at(PostSpawnBoundary::IdentitySerialize) {
            return Err(self.abort_spawned_child(child, attempt, false));
        }
        let identity = match serde_json::to_vec(child.identity()) {
            Ok(identity) => identity,
            Err(_) => {
                return Err(self.abort_spawned_child(child, attempt, false));
            }
        };
        if self.persist_identity(attempt, &identity).is_err() {
            return Err(self.abort_spawned_child(child, attempt, true));
        }
        let pid = child.pid();
        #[cfg(test)]
        if self.faults_at(PostSpawnBoundary::ChildMapInsert) {
            return Err(self.abort_spawned_child(child, attempt, true));
        }
        let mut children = self
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        children.insert(attempt.id, child);
        Ok(pid)
    }

    fn is_alive(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
        let mut children = self
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(child) = children.get_mut(&attempt.id) {
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
            if attempt.process_id().is_some() || Self::unresolved_process_path(attempt).is_file() {
                return Err(FailureReason::Other(
                    "runner process identity is missing; refusing recovery until the process is resolved"
                        .into(),
                ));
            }
            return Ok(false);
        };
        match identity.recheck() {
            Ok(Adoption::Live) => Ok(true),
            Ok(Adoption::Gone | Adoption::PidRecycled { .. }) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    fn recovered_pid(&self, attempt: &RunnerAttempt) -> Result<Option<u32>, FailureReason> {
        Ok(Self::read_identity(attempt)?.map(|identity| identity.pid()))
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
        write_durable_file(&path, b"registration-timeout\n")
            .map_err(|_| FailureReason::Other("terminate intent could not be journalled".into()))
    }

    fn has_terminate_intent(&self, attempt: &RunnerAttempt) -> bool {
        Self::intent_path(attempt).is_file()
    }

    fn terminate(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason> {
        let mut children = self
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(child) = children.get_mut(&attempt.id) {
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
    app_paths: runner_manager_platform::paths::AppPaths,
    diagnostics_root: PathBuf,
    runner_group_id: u64,
    timeouts: RecoveryTimeouts,
    retry: RetryPolicy,
    cancel: CancelToken,
    ports: LifecyclePorts,
    recovery_complete: Mutex<bool>,
    versions: Mutex<BTreeMap<AttemptId, RunnerVersion>>,
    pending_replacements: Mutex<BTreeMap<AttemptId, ReplacementIntent>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileProgress {
    Reconciled,
    Deferred,
    Replacement {
        attempt: AttemptId,
        operation: &'static str,
    },
}

impl LifecycleLauncher {
    #[must_use]
    pub fn new(
        host_id: HostId,
        app_paths: runner_manager_platform::paths::AppPaths,
        diagnostics_root: impl Into<PathBuf>,
        runner_group_id: u64,
        timeouts: RecoveryTimeouts,
        retry: RetryPolicy,
        ports: LifecyclePorts,
    ) -> Self {
        Self {
            host_id,
            app_paths,
            diagnostics_root: diagnostics_root.into(),
            runner_group_id,
            timeouts,
            retry,
            cancel: CancelToken::new(),
            ports,
            recovery_complete: Mutex::new(false),
            versions: Mutex::new(BTreeMap::new()),
            pending_replacements: Mutex::new(BTreeMap::new()),
        }
    }

    /// Reconcile the entire journal before allowing a launch.  Unknown-policy
    /// attempts are left untouched rather than being acted on without an
    /// ownership proof.
    pub async fn recover_startup(
        &self,
        policies: &[ScalePolicy],
    ) -> Result<Vec<ReplacementIntent>, LifecycleError> {
        let by_id: BTreeMap<_, _> = policies.iter().map(|policy| (policy.id, policy)).collect();
        let attempts = self
            .ports
            .store
            .attempts()
            .map_err(|_| LifecycleError::Journal)?;
        let mut unresolved = false;
        for attempt in attempts {
            let Some(policy) = by_id.get(&attempt.policy_id) else {
                if !attempt.is_terminal() && attempt.state() != AttemptState::Cleaned {
                    unresolved = true;
                }
                continue;
            };
            authorize(self.host_id, policy, &attempt).map_err(|_| LifecycleError::Journal)?;
            match self.reconcile_one(policy, attempt).await? {
                ReconcileProgress::Deferred => unresolved = true,
                ReconcileProgress::Replacement { attempt, operation } => {
                    self.pending_replacements
                        .lock()
                        .map_err(|_| LifecycleError::Journal)?
                        .insert(
                            attempt,
                            ReplacementIntent {
                                policy: policy.id,
                                previous_attempt: attempt,
                                operation,
                            },
                        );
                }
                ReconcileProgress::Reconciled => {}
            }
        }
        if unresolved {
            return Err(LifecycleError::RecoveryIncomplete);
        }
        *self
            .recovery_complete
            .lock()
            .map_err(|_| LifecycleError::Journal)? = true;
        Ok(self
            .pending_replacements
            .lock()
            .map_err(|_| LifecycleError::Journal)?
            .values()
            .copied()
            .collect())
    }

    /// Supervise all attempts of one policy during an ordinary poll.
    pub async fn supervise(
        &self,
        policy: &ScalePolicy,
    ) -> Result<Vec<ReplacementIntent>, LifecycleError> {
        let mut replacements = Vec::new();
        self.pending_replacements
            .lock()
            .map_err(|_| LifecycleError::Journal)?
            .retain(|_, intent| {
                if intent.policy == policy.id {
                    replacements.push(*intent);
                    false
                } else {
                    true
                }
            });
        let attempts = self
            .ports
            .store
            .attempts_for_policy(policy.id)
            .map_err(|_| LifecycleError::Journal)?;
        for attempt in attempts {
            authorize(self.host_id, policy, &attempt).map_err(|_| LifecycleError::Journal)?;
            if let ReconcileProgress::Replacement { attempt, operation } =
                self.reconcile_one(policy, attempt).await?
            {
                replacements.push(ReplacementIntent {
                    policy: policy.id,
                    previous_attempt: attempt,
                    operation,
                });
            }
        }
        Ok(replacements)
    }

    async fn reconcile_one(
        &self,
        policy: &ScalePolicy,
        mut attempt: RunnerAttempt,
    ) -> Result<ReconcileProgress, LifecycleError> {
        if attempt.state() == AttemptState::Cleaned {
            return Ok(ReconcileProgress::Reconciled);
        }
        if attempt.is_terminal() {
            self.clean_attempt(&mut attempt)?;
            return Ok(ReconcileProgress::Reconciled);
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

        // If the agent died after GitHub accepted the registration but before
        // the non-secret runner-id sidecar landed, inventory closes the gap.
        // Persist it before making any state decision so a second crash moves
        // the boundary forward rather than repeating it.
        if let Some(runner_id) = github.runner_id
            && read_runner_id(attempt.runtime_path()).is_none()
        {
            write_runner_id(attempt.runtime_path(), runner_id)?;
            self.ports
                .events
                .emit(AttemptEvent::RemoteIdentityRecovered {
                    attempt: attempt.id,
                    runner_id,
                });
        }

        // The child identity is synced before `spawn` returns.  If the agent
        // crashed before the following `starting` journal write, recover that
        // exact PID and take the legal `jit_received -> starting` edge before
        // applying GitHub's authoritative idle/busy observation below.
        if attempt.state() == AttemptState::JitReceived
            && process_alive
            && let Some(pid) = self
                .ports
                .processes
                .recovered_pid(&attempt)
                .map_err(LifecycleError::Failed)?
        {
            attempt
                .started(pid, self.ports.clock.now())
                .map_err(|_| LifecycleError::Transition)?;
            self.record(&attempt)?;
        }

        // A one-shot child owned by this invocation exited successfully after
        // GitHub had already reported it busy, and its ephemeral registration
        // is now gone.  This concludes the *runner attempt*, never the workflow
        // outcome; GitHub remains authoritative for that outcome.
        if attempt.state() == AttemptState::Busy
            && !process_alive
            && github.status == GithubRunnerObservation::NotRegistered
            && self.ports.processes.completed_successfully(&attempt)
        {
            self.conclude(&mut attempt, AttemptOutcome::CompletedJob)?;
            self.clean_attempt(&mut attempt)?;
            return Ok(ReconcileProgress::Reconciled);
        }

        // This durable mark is more authoritative than a later observation
        // which cannot distinguish an agent kill from a crash.
        if self.ports.processes.has_terminate_intent(&attempt) && !process_alive {
            self.deregister_runner(policy, &attempt).await;
            self.conclude(
                &mut attempt,
                AttemptOutcome::failed(FailureReason::TerminatedAfterRegistrationTimeout),
            )?;
            self.clean_attempt(&mut attempt)?;
            return Ok(ReconcileProgress::Replacement {
                attempt: attempt.id,
                operation: "registration_timeout_replacement",
            });
        }

        // A remote registration with no surviving process has lost its
        // one-shot JIT secret.  Walking it to `starting` would require inventing
        // a PID; retrying the same registration would require inventing the
        // secret.  Record the configuration as expired and let the bounded
        // replacement path request a fresh one only if demand remains.
        if matches!(
            attempt.state(),
            AttemptState::Allocated | AttemptState::JitReceived
        ) && !process_alive
            && matches!(github.status, GithubRunnerObservation::Registered { .. })
        {
            if attempt.state() == AttemptState::Allocated {
                attempt
                    .jit_received(self.ports.clock.now())
                    .map_err(|_| LifecycleError::Transition)?;
                self.record(&attempt)?;
            }
            self.deregister_runner(policy, &attempt).await;
            self.conclude(
                &mut attempt,
                AttemptOutcome::failed(FailureReason::JitExpired),
            )?;
            self.clean_attempt(&mut attempt)?;
            return Ok(ReconcileProgress::Replacement {
                attempt: attempt.id,
                operation: "jit_expired_replacement",
            });
        }

        match recovery_decision(
            &attempt,
            RecoveryObservation {
                process_alive,
                github: github.status,
            },
            self.timeouts,
            self.ports.clock.as_ref(),
        ) {
            RecoveryDecision::Nothing | RecoveryDecision::Wait => Ok(ReconcileProgress::Reconciled),
            RecoveryDecision::Defer => Ok(ReconcileProgress::Deferred),
            RecoveryDecision::Adopt => {
                self.ports.events.emit(AttemptEvent::Adopted {
                    attempt: attempt.id,
                });
                Ok(ReconcileProgress::Reconciled)
            }
            RecoveryDecision::Clean => {
                self.clean_attempt(&mut attempt)?;
                Ok(ReconcileProgress::Reconciled)
            }
            RecoveryDecision::Observe(state) => {
                let runner_id = attempt
                    .github_runner_id()
                    .or(github.runner_id)
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
                self.record(&attempt)?;
                Ok(ReconcileProgress::Reconciled)
            }
            RecoveryDecision::Conclude(outcome) => {
                let replacement = replacement_operation(&outcome);
                // Only when GitHub still holds one. Every other conclusion here
                // was reached *because* the observation was `NotRegistered`, and
                // spending a DELETE to be told so again would put a request per
                // concluded attempt on a budget `rest.rs` prices to the request.
                if matches!(github.status, GithubRunnerObservation::Registered { .. }) {
                    self.deregister_runner(policy, &attempt).await;
                }
                self.conclude(&mut attempt, outcome)?;
                self.clean_attempt(&mut attempt)?;
                Ok(
                    replacement.map_or(ReconcileProgress::Reconciled, |operation| {
                        ReconcileProgress::Replacement {
                            attempt: attempt.id,
                            operation,
                        }
                    }),
                )
            }
            RecoveryDecision::Terminate(payload) => {
                // The mark is synced first, and what proves the process died is
                // the `is_alive` re-read below -- not the outcome recorded after
                // it. Which outcome that is depends on why the termination was
                // ordered, and only the payload knows: a `starting` runner that
                // never registered is a failure this agent then stopped, while
                // an `idle` one past its timeout is flow 2.7's surplus exit and
                // no failure at all. Hardcoding the first reason here labelled
                // the second as a registration timeout and asked the allocator
                // for a replacement to boot.
                let idle_exit = payload.is_idle_exit();
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
                    return Ok(ReconcileProgress::Deferred);
                }
                self.ports.events.emit(AttemptEvent::Terminated {
                    attempt: attempt.id,
                });
                // The registration-timeout path keeps deriving its own reason
                // rather than applying the payload: on the pass that reads the
                // journalled mark back the process is dead, and
                // `TerminatedAfterRegistrationTimeout` is the reason that stays
                // true of a dead process. See `RecoveryDecision::Terminate`.
                let outcome = if idle_exit {
                    AttemptOutcome::ExitedIdleWithoutWork
                } else {
                    AttemptOutcome::failed(FailureReason::TerminatedAfterRegistrationTimeout)
                };
                self.deregister_runner(policy, &attempt).await;
                self.conclude(&mut attempt, outcome)?;
                self.clean_attempt(&mut attempt)?;
                // A surplus runner is not replaced. It was stopped precisely
                // because the work it was started for went elsewhere; asking the
                // allocator for another one rebuilds it every idle timeout.
                if idle_exit {
                    Ok(ReconcileProgress::Reconciled)
                } else {
                    Ok(ReconcileProgress::Replacement {
                        attempt: attempt.id,
                        operation: "registration_timeout_replacement",
                    })
                }
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

    /// Remove the GitHub registration an attempt is about to leave behind.
    ///
    /// # Why this is not fallible, and does not block the conclusion
    ///
    /// GitHub retires an ephemeral runner itself once that runner *completes a
    /// job*, and for the ordinary path that is the whole story. The paths that
    /// reach here are the ones where it does not: a runner stopped before it
    /// was ever assigned work, a registration whose process died still holding
    /// it, a JIT configuration that expired. Nothing else deletes those, and
    /// before this existed nothing did — they accumulated in the target's
    /// runner settings, one row per attempt, for the life of the repository.
    ///
    /// It returns `()` rather than a `Result` because the alternative is worse
    /// in both directions. The attempt is over: its process is gone and its
    /// slot has to come back, so a failed delete may not abort the conclusion
    /// or the host leaks capacity every time GitHub is unreachable. And a
    /// registration that outlives this call is not lost — it is exactly the
    /// `Registered` + dead-process observation that
    /// [`AttemptOutcome::Orphaned`] already names, which a later pass can still
    /// see. So a failure is logged and stepped over, deliberately.
    async fn deregister_runner(&self, policy: &ScalePolicy, attempt: &RunnerAttempt) {
        let Some(runner_id) = attempt
            .github_runner_id()
            .or_else(|| read_runner_id(attempt.runtime_path()))
        else {
            return;
        };
        if self
            .ports
            .github
            .deregister(&policy.target, runner_id, &self.cancel)
            .await
        {
            self.ports.events.emit(AttemptEvent::Deregistered {
                attempt: attempt.id,
                runner_id,
            });
        } else {
            tracing::warn!(
                attempt = %attempt.id,
                runner_id,
                "the runner registration could not be removed from GitHub; it will show in the \
                 target's runner settings until GitHub retires it or a later pass removes it"
            );
        }
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
        #[cfg(test)]
        let cleanup_result = if matches!(
            std::env::var("RUNNER_MANAGER_TEST_MUTANT").as_deref(),
            Ok("skip_workspace_cleanup" | "reuse_job_workspace")
        ) {
            Ok(())
        } else {
            fs::remove_dir_all(attempt.runtime_path())
        };
        #[cfg(not(test))]
        let cleanup_result = fs::remove_dir_all(attempt.runtime_path());
        match cleanup_result {
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

    async fn materialize_with_retry(
        &self,
        policy: &ScalePolicy,
        attempt: &RunnerAttempt,
    ) -> Result<RunnerVersion, FailureReason> {
        let mut issued = 0_u32;
        loop {
            issued = issued.saturating_add(1);
            match self.ports.packages.materialize(attempt).await {
                Ok(version) => return Ok(version),
                Err(reason)
                    if package_failure_is_terminal(&reason)
                        || issued >= self.retry.max_attempts.max(1) =>
                {
                    return Err(reason);
                }
                Err(reason) => {
                    if !self.ports.demand.persists(policy.id).await {
                        return Err(reason);
                    }
                    let delay = self.retry.delay(issued);
                    self.ports.events.emit(AttemptEvent::Retry {
                        attempt: attempt.id,
                        operation: "package_materialization",
                        delay,
                    });
                    self.ports.delay.wait(delay).await;
                    if !self.ports.demand.persists(policy.id).await {
                        return Err(reason);
                    }
                }
            }
        }
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
                Err(error) => {
                    if issued >= self.retry.max_attempts.max(1)
                        || !self.ports.demand.persists(policy.id).await
                    {
                        return Err(LifecycleError::Failed(error.reason));
                    }
                    let delay = error
                        .retry_after
                        .unwrap_or_else(|| self.retry.delay(issued));
                    self.ports.events.emit(AttemptEvent::Retry {
                        attempt,
                        operation: "jit_request",
                        delay,
                    });
                    self.ports.delay.wait(delay).await;
                    if !self.ports.demand.persists(policy.id).await {
                        return Err(LifecycleError::Failed(error.reason));
                    }
                }
            }
        }
    }

    /// Where one attempt's files go, decided while the host allocation lock is
    /// held and before anything external happens.
    ///
    /// The branch is on the *repository's configured* workspace policy, so an
    /// organization policy and an ephemeral repository never reach slot
    /// selection at all: a persistent policy is unrepresentable for an
    /// organization target (D7, refused by `WorkspacePolicy::permitted_for` in
    /// both the constructor and the loader), and an ephemeral repository takes
    /// the disposable arm that existed before slots did.
    fn allocate_workspace(
        &self,
        policy: &ScalePolicy,
        id: AttemptId,
    ) -> Result<Placement, LifecycleError> {
        match policy.workspace_policy() {
            // Precedence (`02-target-architecture.md`): the repository's
            // persistent root is selected *before* the host root, which is why
            // this arm is first and why it never makes resolving the host
            // default a precondition of its own success.
            WorkspacePolicy::Persistent { root } => self.allocate_persistent_slot(policy, root),
            WorkspacePolicy::Ephemeral => self.allocate_disposable(id),
        }
    }

    /// `Host.runner_root_override`, read from the journal.
    ///
    /// Separated from [`Self::effective_host_root`] so that the two failures it
    /// folds together stay apart: an unreadable or missing host row is a journal
    /// problem and is always fatal, while an unresolvable *platform default* is
    /// only fatal to a placement that actually needs the host root.
    fn configured_host_root(&self) -> Result<Option<LocalAbsolutePath>, LifecycleError> {
        let host = self
            .ports
            .store
            .host(self.host_id)
            .map_err(|_| LifecycleError::Journal)?
            .ok_or_else(|| LifecycleError::Failed(FailureReason::Other("host not found".into())))?;
        Ok(host.runner_root_override.clone())
    }

    /// `Host.runner_root_override`, or the platform default standing in for it.
    fn effective_host_root(&self) -> Result<LocalAbsolutePath, LifecycleError> {
        match self.configured_host_root()? {
            Some(configured) => Ok(configured),
            None => default_runner_root(&self.app_paths).map_err(root_failure),
        }
    }

    /// D3's disposable placement: a unique child of the effective host root,
    /// removed whole on cleanup. `c1`'s behaviour, moved behind the branch.
    fn allocate_disposable(&self, id: AttemptId) -> Result<Placement, LifecycleError> {
        let effective_root = self.effective_host_root()?;
        RootPreflight::new(&self.app_paths)
            .check(&RootOwner::Host, &effective_root)
            .map_err(root_failure)?;
        let runtime = effective_root.as_path().join({
            #[cfg(test)]
            {
                if std::env::var("RUNNER_MANAGER_TEST_MUTANT").as_deref()
                    == Ok("reuse_job_workspace")
                {
                    "mutant-shared-workspace".to_owned()
                } else {
                    workspace_name(id)
                }
            }
            #[cfg(not(test))]
            {
                workspace_name(id)
            }
        });
        fs::create_dir_all(&runtime)
            .map_err(|_| LifecycleError::Failed(FailureReason::ProcessStartFailed))?;
        Ok(Placement {
            runtime,
            workspace: AttemptWorkspace::Ephemeral,
        })
    }

    /// D4/D5's persistent placement: the lowest free `sN` under the repository's
    /// configured root.
    ///
    /// Steps 1 to 6 of `02-target-architecture.md`, "Slot allocation", in order;
    /// step 7 is the journal write [`Self::record_allocation`] owns. All of them
    /// run under the host allocation lock, because [`Self::launch_attempt`] is
    /// reachable only through a `LaunchRequest` and that carries the guard.
    ///
    /// **The filesystem is never consulted to decide which slots are taken**
    /// (invariant 6). The leases come from the journal; the directory is
    /// inspected only to decide whether *this* slot is safe to reuse.
    fn allocate_persistent_slot(
        &self,
        policy: &ScalePolicy,
        root: &LocalAbsolutePath,
    ) -> Result<Placement, LifecycleError> {
        // 1-4. The lowest positive slot no uncleaned attempt holds, refused
        // above the policy ceiling.
        let ceiling = policy.max_capacity().ok_or_else(|| {
            LifecycleError::Failed(FailureReason::Other(
                "a persistent workspace needs the policy's max_capacity to bound its slots"
                    .to_string(),
            ))
        })?;
        let leases = self
            .ports
            .store
            .slot_leases_for_policy(policy.id)
            .map_err(|_| LifecycleError::Journal)?;
        let slot = lowest_free_slot(&leases, ceiling).ok_or_else(|| {
            LifecycleError::Failed(FailureReason::Other(format!(
                "every persistent slot s1 to s{ceiling} for {} is leased by an attempt that has \
                 not been cleaned, so no slot is free; raise the repository's max capacity, or \
                 finish cleaning a concluded attempt",
                policy.target
            )))
        })?;
        let workspace = AttemptWorkspace::persistent_slot(slot);
        let name = workspace
            .slot_directory_name()
            .expect("a persistent allocation names its slot directory");

        // The operational preflight, for the reasons the host root gets one: a
        // root that is remote, unwritable, or overlapping application data has
        // to fail before a directory is created rather than after. The host
        // root is registered only as something *not* to overlap; a host default
        // that cannot be resolved is a host-root problem and does not block a
        // repository that configured a root of its own.
        //
        // Only *that* failure is tolerated. An unreadable host row is a journal
        // failure and propagates, because silently continuing would drop the
        // overlap check entirely and accept a repository root that sits inside
        // the host root — the pair `RootPreflight` exists to refuse.
        let host_root = self
            .configured_host_root()?
            .or_else(|| default_runner_root(&self.app_paths).ok());
        let mut preflight = RootPreflight::new(&self.app_paths);
        if let Some(host_root) = host_root {
            preflight = preflight.against(RootOwner::Host, host_root);
        }
        let checked = preflight
            .check(&RootOwner::Repository(policy.target.to_string()), root)
            .map_err(root_failure)?;
        if let Some(leaf) = checked.leaf_to_create() {
            fs::create_dir(leaf).map_err(|source| {
                LifecycleError::Failed(FailureReason::Other(format!(
                    "the persistent workspace root {} could not be created: {source}",
                    leaf.display()
                )))
            })?;
        }

        // 5-6. `<root>/sN`, contained lexically by construction, then created or
        // validated, then contained canonically now that it resolves, and only
        // then accepted for reuse.
        let slot_path = runner_root::derive_child(root, &name).map_err(root_failure)?;
        create_or_validate_slot(slot_path.as_path())?;
        runner_root::verify_containment(root, &slot_path).map_err(root_failure)?;
        accept_reusable_slot(slot_path.as_path())?;
        Ok(Placement {
            runtime: slot_path.as_path().to_path_buf(),
            workspace,
        })
    }

    /// The first journal write of an attempt, where a duplicate slot lease is
    /// still possible and has to be reported as itself.
    ///
    /// [`Self::record`] flattens every store failure into
    /// [`LifecycleError::Journal`], which is right for a state transition and
    /// wrong here: the partial unique index
    /// `one_uncleaned_persistent_attempt_per_slot` is the final race fence
    /// (`04-security-recovery.md`, "two attempts use one slot concurrently"),
    /// and an operator who reaches it needs to read that rather than "attempt
    /// journal operation failed". Nothing was written, so the caller returns
    /// without concluding an attempt that is not in the journal.
    fn record_allocation(&self, attempt: &RunnerAttempt) -> Result<(), LifecycleError> {
        match self.ports.store.record_attempt(attempt) {
            Ok(()) => {
                self.ports.events.emit(AttemptEvent::State {
                    attempt: attempt.id,
                    state: attempt.state(),
                });
                Ok(())
            }
            Err(error @ StoreError::SlotAlreadyLeased { .. }) => Err(LifecycleError::Failed(
                FailureReason::Other(error.to_string()),
            )),
            Err(_) => Err(LifecycleError::Journal),
        }
    }

    async fn launch_attempt(
        &self,
        policy: &ScalePolicy,
        allocation_guard: &AllocationGuard,
    ) -> Result<RunnerAttempt, LifecycleError> {
        if !*self
            .recovery_complete
            .lock()
            .map_err(|_| LifecycleError::Journal)?
        {
            return Err(LifecycleError::RecoveryIncomplete);
        }
        let labels = policy
            .routing_labels()
            .ok_or(LifecycleError::Failed(FailureReason::JitRequestFailed))?;
        let id = AttemptId::new_random();
        let placement = self.allocate_workspace(policy, id)?;
        let mut attempt = RunnerAttempt::allocate_in(
            id,
            policy.id,
            placement.runtime,
            placement.workspace,
            self.ports.clock.now(),
        );
        // This is deliberately the first effect after directory allocation, and
        // for a persistent attempt it is also what makes the slot lease durable
        // before any package or GitHub effect
        // (`02-target-architecture.md`, "Slot allocation", step 7).
        self.record_allocation(&attempt)?;

        let version = match self.materialize_with_retry(policy, &attempt).await {
            Ok(version) => version,
            Err(reason) => return self.fail_launch(&mut attempt, reason),
        };
        self.prune_under_allocation_lock(allocation_guard, &version)?;
        self.versions
            .lock()
            .map_err(|_| LifecycleError::Journal)?
            .insert(id, version);

        let jit_request =
            JitRunnerRequest::for_policy(runner_name(id), self.runner_group_id, labels);
        let registration = match self.register_with_retry(policy, id, &jit_request).await {
            Ok(registration) => registration,
            Err(error) => return self.fail_launch(&mut attempt, error.reason()),
        };
        let runner_id = registration.runner().id;
        write_runner_id(attempt.runtime_path(), runner_id)?;
        attempt
            .jit_received(self.ports.clock.now())
            .map_err(|_| LifecycleError::Transition)?;
        self.record(&attempt)?;
        let config = registration.into_config();
        let mut issued = 0_u32;
        let pid = loop {
            issued = issued.saturating_add(1);
            match self.ports.processes.spawn(&attempt, &config) {
                Ok(pid) => break pid,
                Err(error) => {
                    if let Some(pid) = error.live_pid {
                        attempt
                            .started(pid, self.ports.clock.now())
                            .map_err(|_| LifecycleError::Transition)?;
                        self.record(&attempt)?;
                        return Err(LifecycleError::Failed(error.reason));
                    }
                    if !error.retryable
                        || issued >= self.retry.max_attempts.max(1)
                        || !self.ports.demand.persists(policy.id).await
                    {
                        return self.fail_launch(&mut attempt, error.reason);
                    }
                    let delay = self.retry.delay(issued);
                    self.ports.events.emit(AttemptEvent::Retry {
                        attempt: attempt.id,
                        operation: "process_start",
                        delay,
                    });
                    self.ports.delay.wait(delay).await;
                    if !self.ports.demand.persists(policy.id).await {
                        return self.fail_launch(&mut attempt, error.reason);
                    }
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
    fn prune_under_allocation_lock(
        &self,
        guard: &AllocationGuard,
        version: &RunnerVersion,
    ) -> Result<(), LifecycleError> {
        let attempts = self
            .ports
            .store
            .attempts()
            .map_err(|_| LifecycleError::Journal)?;
        self.ports
            .packages
            .prune_obsolete_guarded(
                PruneAuthority::from_launch_request(guard),
                version,
                &attempts,
            )
            .map_err(LifecycleError::Failed)
    }
}

#[async_trait]
impl RunnerLauncher for LifecycleLauncher {
    async fn supervise(
        &self,
        policy: &ScalePolicy,
    ) -> Result<Vec<ReplacementIntent>, LaunchFailure> {
        LifecycleLauncher::supervise(self, policy)
            .await
            .map_err(|error| LaunchFailure::new(error.reason()))
    }

    async fn attempts(&self) -> Result<Vec<RunnerAttempt>, LaunchFailure> {
        self.ports.store.attempts().map_err(|_| {
            LaunchFailure::new(FailureReason::Other(
                "attempt journal could not be read".into(),
            ))
        })
    }

    async fn launch(&self, request: LaunchRequest<'_>) -> Result<RunnerAttempt, LaunchFailure> {
        self.launch_attempt(request.policy, request.allocation_guard)
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

fn write_runner_id(runtime: &Path, runner_id: u64) -> Result<(), LifecycleError> {
    let target = runtime.join(RUNNER_ID_FILE);
    if let Some(existing) = read_runner_id(runtime) {
        return (existing == runner_id)
            .then_some(())
            .ok_or(LifecycleError::Journal);
    }
    let temporary = runtime.join(format!("{RUNNER_ID_FILE}.{}.tmp", uuid::Uuid::new_v4()));
    write_durable_file(&temporary, runner_id.to_string().as_bytes())
        .map_err(|_| LifecycleError::Journal)?;
    match fs::rename(&temporary, &target) {
        Ok(()) => sync_directory(runtime).map_err(|_| LifecycleError::Journal),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            (read_runner_id(runtime) == Some(runner_id))
                .then_some(())
                .ok_or(LifecycleError::Journal)
        }
        Err(_) => {
            let _ = fs::remove_file(&temporary);
            Err(LifecycleError::Journal)
        }
    }
}

fn write_durable_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file has no parent directory",
        )
    })?;
    sync_directory(parent)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_SHARE_ALL: u32 = 0x0000_0007;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    fs::OpenOptions::new()
        .access_mode(GENERIC_WRITE)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::reconcile::{AllocationLock, InProcessAllocationLock};
    use runner_manager_domain::model::{Elapsed, TargetScope};
    use runner_manager_domain::store::SqliteStore;
    use runner_manager_github::jit::JitRunner;
    use runner_manager_testkit::clock::FakeClock;
    use runner_manager_testkit::fixtures;

    /// A slot number, for the tests that name one.
    fn nz(slot: u16) -> NonZeroU16 {
        NonZeroU16::new(slot).expect("a positive slot")
    }

    const JIT: &str = "eyJzZWNyZXQiOiJnaHBfRE9fTk9UX0xFQUsifQ==";

    #[derive(Debug, Default)]
    struct FakeGithubLifecycle {
        registration_failures: Mutex<VecDeque<bool>>,
        observations: Mutex<VecDeque<LifecycleGithubObservation>>,
        registrations: AtomicUsize,
        remaining_runners: AtomicUsize,
        /// Every runner id `deregister` was asked to remove, in order. A count
        /// would not do: the assertions worth making are that the *right*
        /// registration was deleted and that it was deleted once.
        deregistrations: Mutex<Vec<u64>>,
        /// Set to make `deregister` answer `false`, standing for a GitHub that
        /// could not be reached at the moment the attempt concluded.
        deregistration_fails: AtomicBool,
        /// The journal to read *during* a registration, for the ordering
        /// assertion `02-target-architecture.md` makes: the slot lease is
        /// written "before package or GitHub effects". Reading it afterwards
        /// would pass even if the write happened second.
        journal: Mutex<Option<Arc<SqliteStore>>>,
        /// One entry per registration, in order.
        registration_facts: Mutex<Vec<RegistrationFact>>,
    }

    /// What one JIT registration saw of the world at the moment it was issued.
    ///
    /// `runner_name` is what ties the other two fields to *one* attempt: with
    /// two allocators racing, "some slot was journalled" is a much weaker claim
    /// than "the slot this very request belongs to was journalled", and only the
    /// name distinguishes them.
    #[derive(Debug, Clone)]
    struct RegistrationFact {
        /// The persistent slots the journal already held.
        leased_slots: Vec<u16>,
        /// The `work_folder` the request carried.
        work_folder: String,
        /// The runner name the request carried, i.e. [`runner_name`] of the
        /// registering attempt.
        runner_name: String,
    }

    impl FakeGithubLifecycle {
        fn fail(mut self, terminal: bool) -> Self {
            self.registration_failures
                .get_mut()
                .expect("unpoisoned")
                .push_back(terminal);
            self
        }

        fn watch_journal(&self, store: Arc<SqliteStore>) {
            *self.journal.lock().unwrap() = Some(store);
        }

        fn registration_facts(&self) -> Vec<RegistrationFact> {
            self.registration_facts.lock().unwrap().clone()
        }

        fn observe(&self, observation: GithubRunnerObservation) {
            let observation = match observation {
                GithubRunnerObservation::Unreachable => LifecycleGithubObservation::unreachable(),
                GithubRunnerObservation::NotRegistered => {
                    LifecycleGithubObservation::not_registered()
                }
                GithubRunnerObservation::Registered { busy } => {
                    LifecycleGithubObservation::registered(73, busy)
                }
            };
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
            if let Some(store) = self.journal.lock().unwrap().as_ref() {
                let slots = store
                    .attempts()
                    .expect("the journal is readable")
                    .iter()
                    .filter_map(|attempt| attempt.workspace().slot_number())
                    .collect();
                self.registration_facts
                    .lock()
                    .unwrap()
                    .push(RegistrationFact {
                        leased_slots: slots,
                        work_folder: request.work_folder().to_string(),
                        runner_name: request.name().to_string(),
                    });
            }
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
        ) -> LifecycleGithubObservation {
            let observation = self
                .observations
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(LifecycleGithubObservation::not_registered());
            if observation.status == GithubRunnerObservation::NotRegistered {
                self.remaining_runners.store(0, Ordering::SeqCst);
            }
            observation
        }

        async fn deregister(
            &self,
            _target: &ScaleTarget,
            runner_id: u64,
            _cancel: &CancelToken,
        ) -> bool {
            self.deregistrations.lock().unwrap().push(runner_id);
            if self.deregistration_fails.load(Ordering::SeqCst) {
                return false;
            }
            self.remaining_runners.store(0, Ordering::SeqCst);
            true
        }
    }

    #[derive(Debug)]
    struct FakePackages {
        version: RunnerVersion,
        leases: Mutex<BTreeSet<AttemptId>>,
        materializations: AtomicUsize,
        materialization_failures: AtomicUsize,
        releases: AtomicUsize,
        prunes: AtomicUsize,
        prune_currents: Mutex<Vec<RunnerVersion>>,
    }

    impl Default for FakePackages {
        fn default() -> Self {
            Self {
                version: RunnerVersion::parse("2.330.0").unwrap(),
                leases: Mutex::new(BTreeSet::new()),
                materializations: AtomicUsize::new(0),
                materialization_failures: AtomicUsize::new(0),
                releases: AtomicUsize::new(0),
                prunes: AtomicUsize::new(0),
                prune_currents: Mutex::new(Vec::new()),
            }
        }
    }

    impl FakePackages {
        fn fail_materializations(&self, count: usize) {
            self.materialization_failures.store(count, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl RuntimePackages for FakePackages {
        async fn materialize(
            &self,
            attempt: &RunnerAttempt,
        ) -> Result<RunnerVersion, FailureReason> {
            self.materializations.fetch_add(1, Ordering::SeqCst);
            if self
                .materialization_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    if left > 0 { Some(left - 1) } else { None }
                })
                .is_ok()
            {
                return Err(FailureReason::Other(
                    "runner package materialization failed transiently".into(),
                ));
            }
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

        fn prune_obsolete_guarded(
            &self,
            _authority: PruneAuthority<'_>,
            current: &RunnerVersion,
            _attempts: &[RunnerAttempt],
        ) -> Result<(), FailureReason> {
            self.prunes.fetch_add(1, Ordering::SeqCst);
            self.prune_currents.lock().unwrap().push(current.clone());
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeProcesses {
        alive: AtomicBool,
        completed_successfully: AtomicBool,
        spawns: AtomicUsize,
        spawn_failures: AtomicUsize,
        live_spawn_failure: AtomicBool,
        terminations: AtomicUsize,
        intent: AtomicBool,
        intent_failure: AtomicBool,
        actions: Mutex<Vec<&'static str>>,
        saw_secret: AtomicBool,
    }

    impl FakeProcesses {
        fn fail_spawns(&self, count: usize) {
            self.spawn_failures.store(count, Ordering::SeqCst);
        }

        fn fail_spawn_with_live_child(&self) {
            self.live_spawn_failure.store(true, Ordering::SeqCst);
        }

        fn set_alive(&self, alive: bool) {
            self.alive.store(alive, Ordering::SeqCst);
        }

        fn finish_successfully(&self) {
            self.completed_successfully.store(true, Ordering::SeqCst);
            self.alive.store(false, Ordering::SeqCst);
        }

        fn fail_intent(&self) {
            self.intent_failure.store(true, Ordering::SeqCst);
        }
    }

    impl ProcessSupervisor for FakeProcesses {
        fn spawn(
            &self,
            attempt: &RunnerAttempt,
            config: &EncodedJitConfig,
        ) -> Result<u32, ProcessStartFailure> {
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
            if self.live_spawn_failure.swap(false, Ordering::SeqCst) {
                self.alive.store(true, Ordering::SeqCst);
                return Err(ProcessStartFailure::after_spawn_live(4242));
            }
            if failing {
                return Err(ProcessStartFailure::before_spawn(
                    FailureReason::ProcessStartFailed,
                ));
            }
            self.alive.store(true, Ordering::SeqCst);
            Ok(4242)
        }

        fn is_alive(&self, _attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
            self.actions.lock().unwrap().push("observe_process");
            Ok(self.alive.load(Ordering::SeqCst))
        }

        fn recovered_pid(&self, _attempt: &RunnerAttempt) -> Result<Option<u32>, FailureReason> {
            Ok(self.alive.load(Ordering::SeqCst).then_some(4242))
        }

        fn completed_successfully(&self, _attempt: &RunnerAttempt) -> bool {
            self.completed_successfully.load(Ordering::SeqCst)
        }

        fn record_terminate_intent(&self, _attempt: &RunnerAttempt) -> Result<(), FailureReason> {
            self.actions.lock().unwrap().push("terminate_intent");
            if self.intent_failure.load(Ordering::SeqCst) {
                return Err(FailureReason::Other(
                    "terminate intent directory sync failed".into(),
                ));
            }
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
        allocation_lock: InProcessAllocationLock,
        /// The repository persistent root, once one is configured.
        workspace_root: Option<LocalAbsolutePath>,
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
            store.put_host(&host).unwrap();
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
                paths.clone(),
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
                allocation_lock: InProcessAllocationLock::new(),
                workspace_root: None,
            }
        }

        /// Put disposable attempts under a host root of this harness's own.
        ///
        /// Without it the launcher resolves the *platform* default, which on
        /// Windows is `%SystemDrive%\rman` — a real directory on the machine
        /// running the suite. Every test added by `c2` places its files inside
        /// its own temporary directory instead.
        fn with_host_runner_root(mut self) -> Self {
            let host_root = self.host_root();
            fs::create_dir_all(&host_root).unwrap();
            self.host.runner_root_override = Some(
                LocalAbsolutePath::new(host_root.to_str().expect("a UTF-8 temporary path"))
                    .expect("a local absolute host root"),
            );
            self.store.put_host(&self.host).unwrap();
            self
        }

        /// Opt this harness's repository into a persistent workspace (D4).
        fn with_persistent_workspace(mut self, capacity: u16) -> Self {
            self = self.with_host_runner_root();
            let root = self._root.path().join("persist");
            let root = LocalAbsolutePath::new(root.to_str().expect("a UTF-8 temporary path"))
                .expect("a local absolute workspace root");
            self.policy = fixtures::policy()
                .repository("octo/repo")
                .autoscale("home", capacity)
                .active()
                .build();
            self.policy
                .set_workspace_policy(
                    WorkspacePolicy::persistent(root.clone(), TargetScope::Repository)
                        .expect("a repository may be persistent"),
                )
                .expect("a repository may be persistent");
            self.workspace_root = Some(root);
            self
        }

        fn workspace_root(&self) -> &LocalAbsolutePath {
            self.workspace_root
                .as_ref()
                .expect("this harness configured a persistent workspace")
        }

        fn slot_path(&self, slot: u16) -> PathBuf {
            self.workspace_root().as_path().join(format!("s{slot}"))
        }

        fn host_root(&self) -> PathBuf {
            self._root.path().join("host-root")
        }

        fn attempt(&self, id: AttemptId) -> RunnerAttempt {
            self.store
                .attempt(id)
                .unwrap()
                .expect("the attempt is journalled")
        }

        /// Stand in for `c3`'s persistent cleanup, which this task does not own:
        /// the lease is released by the journal and everything but `_work` goes.
        fn cleanup_retaining_work(&self, id: AttemptId) {
            let mut attempt = self.attempt(id);
            attempt
                .conclude(
                    AttemptOutcome::failed(FailureReason::ProcessExitedUnexpectedly),
                    self.clock.now(),
                )
                .unwrap();
            attempt.clean(self.clock.now()).unwrap();
            self.store.record_attempt(&attempt).unwrap();
            remove_slot_entries_except_work(attempt.runtime_path()).unwrap();
        }

        async fn ready(&self) {
            self.launcher
                .recover_startup(std::slice::from_ref(&self.policy))
                .await
                .unwrap();
        }

        async fn launch(&self) -> RunnerAttempt {
            self.launch_result().await.unwrap()
        }

        async fn launch_result(&self) -> Result<RunnerAttempt, LaunchFailure> {
            let guard = self.allocation_lock.acquire().await.unwrap();
            self.launcher
                .launch(LaunchRequest {
                    host: &self.host,
                    policy: &self.policy,
                    allocation_guard: &guard,
                })
                .await
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
        assert!(gone.launch_result().await.is_err());
        assert_eq!(gone.github.registrations.load(Ordering::SeqCst), 1);
        assert!(gone.delay.0.lock().unwrap().is_empty());

        let forbidden = Harness::new(
            FakeGithubLifecycle::default().fail(true),
            Arc::new(PersistentDemand),
        );
        forbidden.ready().await;
        assert!(forbidden.launch_result().await.is_err());
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

    /// The layout has to leave room for what the runner writes underneath it.
    ///
    /// Windows refuses a path over `MAX_PATH`, and this product's own CI hit
    /// that: 264 characters against a limit of 260, failing three checkout
    /// retries with `Filename too long`. The two identifiers in the old layout
    /// cost 74 characters between them for no benefit -- an attempt id is
    /// unique on its own.
    #[test]
    fn a_workspace_leaves_room_for_the_deepest_path_a_checkout_writes() {
        const MAX_PATH: usize = 260;
        // The real root on the machine this was found on.
        let root = r"C:\Users\IvanD\AppData\Local\IvanMurzak\runner-manager\data\runtime";
        // What `actions/checkout` writes at its deepest: the work directory,
        // the repository named twice, and a pack keep-file with a 40-character
        // object name.
        let repo = "GitHub-Runner-Scaler-UI";
        let deepest = format!(
            r"_work\{repo}\{repo}\.git\objects\pack\pack-{}.keep",
            "0".repeat(40)
        );

        let name = workspace_name(AttemptId::new_random());
        assert_eq!(name.len(), WORKSPACE_NAME_LEN, "{name}");
        assert!(
            name.chars().all(|c| c.is_ascii_hexdigit()),
            "a directory name must not carry the identifier's dashes: {name}"
        );

        let full = format!(r"{root}\{name}\{deepest}");
        assert!(
            full.len() < MAX_PATH,
            "the deepest path a checkout writes must fit: {} characters, limit {MAX_PATH}",
            full.len()
        );

        // The discriminator: the layout this replaced does not fit, so a test
        // that passed for both would be proving nothing.
        let old = format!(
            r"{root}\{}\{}\{deepest}",
            PolicyId::new_random(),
            AttemptId::new_random()
        );
        assert!(
            old.len() > MAX_PATH,
            "the old layout is supposed to be the thing that did not fit: {} characters",
            old.len()
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
    async fn a_runner_that_never_gets_a_job_is_stopped_deregistered_and_not_replaced() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.ready().await;
        let attempt = harness.launch().await;

        // Registered and waiting, which is where it stays: the fake keeps
        // answering the same observation, exactly as GitHub does for a runner
        // nobody assigns work to.
        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: false });
        harness.launcher.supervise(&harness.policy).await.unwrap();
        assert_eq!(harness.only_attempt().state(), AttemptState::Idle);

        // One second inside the ten-second idle timeout nothing happens, which
        // is what keeps this from being a test that would pass on any clock.
        harness.clock.advance_secs(9);
        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: false });
        let none_yet = harness.launcher.supervise(&harness.policy).await.unwrap();
        assert_eq!(harness.only_attempt().state(), AttemptState::Idle);
        assert!(none_yet.is_empty());
        assert_eq!(harness.processes.terminations.load(Ordering::SeqCst), 0);

        // Past it, the agent ends the runner itself.
        harness.clock.advance_secs(1);
        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: false });
        let replacements = harness.launcher.supervise(&harness.policy).await.unwrap();

        let concluded = harness.store.attempt(attempt.id).unwrap().unwrap();
        assert_eq!(
            concluded.outcome(),
            Some(&AttemptOutcome::ExitedIdleWithoutWork),
            "a surplus runner did not fail; recording one as a failure sends an operator \
             hunting a fault that does not exist"
        );
        assert_eq!(concluded.state(), AttemptState::Cleaned);
        assert_eq!(harness.processes.terminations.load(Ordering::SeqCst), 1);
        assert!(!attempt.runtime_path().exists());

        // The registration goes with it. Without this the runner stays listed
        // in the target's runner settings after the process it named is gone.
        assert_eq!(
            *harness.github.deregistrations.lock().unwrap(),
            vec![73],
            "the attempt's own runner id, deleted exactly once"
        );

        // And nothing is started in its place: the work it was launched for went
        // elsewhere, so a replacement would rebuild it every idle timeout.
        assert!(
            replacements.is_empty(),
            "a surplus exit must not request a replacement"
        );
    }

    #[tokio::test]
    async fn a_registration_github_will_not_delete_still_concludes_the_attempt() {
        // The delete is best-effort by construction: the process is gone and the
        // slot has to come back. Holding the conclusion until GitHub cooperates
        // would leak a capacity slot on every unreachable moment.
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.ready().await;
        let attempt = harness.launch().await;
        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: false });
        harness.launcher.supervise(&harness.policy).await.unwrap();

        harness
            .github
            .deregistration_fails
            .store(true, Ordering::SeqCst);
        harness.clock.advance_secs(11);
        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: false });
        harness.launcher.supervise(&harness.policy).await.unwrap();

        assert_eq!(
            *harness.github.deregistrations.lock().unwrap(),
            vec![73],
            "the delete was attempted"
        );
        let concluded = harness.store.attempt(attempt.id).unwrap().unwrap();
        assert_eq!(
            concluded.outcome(),
            Some(&AttemptOutcome::ExitedIdleWithoutWork),
            "the attempt concluded anyway"
        );
        assert_eq!(concluded.state(), AttemptState::Cleaned);
        assert!(!attempt.runtime_path().exists());
    }

    #[tokio::test]
    async fn exit_before_acceptance_returns_replacement_intent_without_launching() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.ready().await;
        let first = harness.launch().await;
        harness.processes.set_alive(false);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        let replacements = harness.launcher.supervise(&harness.policy).await.unwrap();
        let failed = harness.store.attempt(first.id).unwrap().unwrap();
        assert!(matches!(
            failed.outcome(),
            Some(AttemptOutcome::Failed {
                reason: FailureReason::ProcessExitedUnexpectedly
            })
        ));
        assert!(!first.runtime_path().exists());

        assert_eq!(
            replacements,
            vec![ReplacementIntent {
                policy: harness.policy.id,
                previous_attempt: first.id,
                operation: "exit_before_acceptance_replacement",
            }]
        );
        assert_eq!(harness.store.attempts().unwrap().len(), 1);
        assert_eq!(harness.github.registrations.load(Ordering::SeqCst), 1);
        assert_eq!(harness.processes.spawns.load(Ordering::SeqCst), 1);
        assert!(harness.delay.0.lock().unwrap().is_empty());
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
            .app_paths
            .runtime_dir()
            .join(harness.policy.id.to_string())
            .join(id.to_string());
        fs::create_dir_all(&runtime).unwrap();
        let mut attempt =
            RunnerAttempt::allocate(id, harness.policy.id, &runtime, harness.clock.now());
        attempt.jit_received(harness.clock.now()).unwrap();
        harness.store.record_attempt(&attempt).unwrap();
        harness.clock.advance_secs(11);
        let replacements = harness
            .launcher
            .recover_startup(std::slice::from_ref(&harness.policy))
            .await
            .unwrap();
        assert_eq!(
            replacements,
            vec![ReplacementIntent {
                policy: harness.policy.id,
                previous_attempt: id,
                operation: "jit_expired_replacement",
            }]
        );

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
        assert!(harness.delay.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn expired_jit_returns_intent_but_never_launches_inside_lifecycle() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let id = AttemptId::new_random();
        let runtime = harness
            .launcher
            .app_paths
            .runtime_dir()
            .join("expired-with-demand");
        fs::create_dir_all(&runtime).unwrap();
        let mut attempt =
            RunnerAttempt::allocate(id, harness.policy.id, &runtime, harness.clock.now());
        attempt.jit_received(harness.clock.now()).unwrap();
        harness.store.record_attempt(&attempt).unwrap();
        harness.clock.advance_secs(11);
        let replacements = harness
            .launcher
            .recover_startup(std::slice::from_ref(&harness.policy))
            .await
            .unwrap();

        let attempts = harness.store.attempts().unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts
                .iter()
                .find(|attempt| attempt.id == id)
                .unwrap()
                .state(),
            AttemptState::Cleaned
        );
        assert_eq!(
            replacements,
            vec![ReplacementIntent {
                policy: harness.policy.id,
                previous_attempt: id,
                operation: "jit_expired_replacement",
            }]
        );
        assert_eq!(harness.github.registrations.load(Ordering::SeqCst), 0);
        assert_eq!(harness.processes.spawns.load(Ordering::SeqCst), 0);
        assert!(harness.delay.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn package_materialization_retries_are_bounded_and_demand_adjacent() {
        let persistent = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        persistent.packages.fail_materializations(2);
        persistent.ready().await;
        persistent.launch().await;
        assert_eq!(
            persistent.packages.materializations.load(Ordering::SeqCst),
            3
        );
        assert_eq!(
            *persistent.delay.0.lock().unwrap(),
            vec![Duration::from_millis(10), Duration::from_millis(20)]
        );

        let gone_before_wait = Harness::new(
            FakeGithubLifecycle::default(),
            Arc::new(FakeDemand::answering([false])),
        );
        gone_before_wait.packages.fail_materializations(3);
        gone_before_wait.ready().await;
        assert!(gone_before_wait.launch_result().await.is_err());
        assert_eq!(
            gone_before_wait
                .packages
                .materializations
                .load(Ordering::SeqCst),
            1
        );
        assert!(gone_before_wait.delay.0.lock().unwrap().is_empty());

        let gone_during_wait = Harness::new(
            FakeGithubLifecycle::default(),
            Arc::new(FakeDemand::answering([true, false])),
        );
        gone_during_wait.packages.fail_materializations(3);
        gone_during_wait.ready().await;
        assert!(gone_during_wait.launch_result().await.is_err());
        assert_eq!(
            gone_during_wait
                .packages
                .materializations
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            *gone_during_wait.delay.0.lock().unwrap(),
            vec![Duration::from_millis(10)]
        );
    }

    #[tokio::test]
    async fn replacement_is_intent_only_and_never_launches_inside_lifecycle() {
        let harness = Harness::new(
            FakeGithubLifecycle::default(),
            Arc::new(FakeDemand::answering([true, false])),
        );
        harness.ready().await;
        let first = harness.launch().await;
        harness.processes.set_alive(false);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        let replacements = harness.launcher.supervise(&harness.policy).await.unwrap();

        assert_eq!(harness.store.attempts().unwrap().len(), 1);
        assert_eq!(harness.github.registrations.load(Ordering::SeqCst), 1);
        assert_eq!(harness.processes.spawns.load(Ordering::SeqCst), 1);
        assert!(harness.delay.0.lock().unwrap().is_empty());
        assert_eq!(
            replacements,
            vec![ReplacementIntent {
                policy: harness.policy.id,
                previous_attempt: first.id,
                operation: "exit_before_acceptance_replacement",
            }]
        );
        assert_eq!(
            harness.store.attempt(first.id).unwrap().unwrap().state(),
            AttemptState::Cleaned
        );
    }

    #[tokio::test]
    async fn startup_adopts_a_live_process_and_refuses_launch_before_recovery() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let before = harness.launch_result().await;
        assert!(before.is_err());
        assert_eq!(harness.processes.spawns.load(Ordering::SeqCst), 0);

        let id = AttemptId::new_random();
        let runtime = harness.launcher.app_paths.runtime_dir().join("adopt");
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
        let replacements = harness
            .launcher
            .recover_startup(std::slice::from_ref(&harness.policy))
            .await
            .unwrap();
        assert!(replacements.is_empty());
        assert_eq!(harness.processes.spawns.load(Ordering::SeqCst), 0);
        assert!(
            harness
                .events
                .events()
                .contains(&AttemptEvent::Adopted { attempt: id })
        );
    }

    #[tokio::test]
    async fn spawn_before_starting_crash_recovers_pid_then_completes_and_cleans() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let id = AttemptId::new_random();
        let runtime = harness
            .launcher
            .app_paths
            .runtime_dir()
            .join("spawn-before-starting");
        fs::create_dir_all(&runtime).unwrap();
        let mut attempt =
            RunnerAttempt::allocate(id, harness.policy.id, &runtime, harness.clock.now());
        attempt.jit_received(harness.clock.now()).unwrap();
        harness.store.record_attempt(&attempt).unwrap();
        harness.processes.set_alive(true);
        harness
            .github
            .observe(GithubRunnerObservation::Registered { busy: true });

        let replacements = harness
            .launcher
            .recover_startup(std::slice::from_ref(&harness.policy))
            .await
            .unwrap();
        assert!(replacements.is_empty());
        let recovered = harness.store.attempt(id).unwrap().unwrap();
        assert_eq!(recovered.state(), AttemptState::Busy);
        assert_eq!(recovered.process_id(), Some(4242));
        assert_eq!(recovered.github_runner_id(), Some(73));
        let events = harness.events.events();
        let starting = events
            .iter()
            .position(|event| matches!(event, AttemptEvent::State { attempt, state: AttemptState::Starting } if *attempt == id))
            .unwrap();
        let busy = events
            .iter()
            .position(|event| matches!(event, AttemptEvent::State { attempt, state: AttemptState::Busy } if *attempt == id))
            .unwrap();
        assert!(starting < busy, "recovery skipped a legal edge: {events:?}");

        harness.processes.finish_successfully();
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        assert!(
            harness
                .launcher
                .supervise(&harness.policy)
                .await
                .unwrap()
                .is_empty()
        );
        let cleaned = harness.store.attempt(id).unwrap().unwrap();
        assert_eq!(cleaned.state(), AttemptState::Cleaned);
        assert_eq!(cleaned.outcome(), Some(&AttemptOutcome::CompletedJob));
        assert!(!runtime.exists());
    }

    #[tokio::test]
    async fn failed_post_spawn_stop_keeps_capacity_until_supervision_proves_death() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.processes.fail_spawn_with_live_child();
        harness.ready().await;
        assert!(harness.launch_result().await.is_err());

        let attempt = harness.only_attempt();
        assert_eq!(attempt.state(), AttemptState::Starting);
        assert_eq!(attempt.process_id(), Some(4242));
        assert!(attempt.outcome().is_none());
        assert!(attempt.state().counts_against_capacity());
        assert_eq!(harness.processes.spawns.load(Ordering::SeqCst), 1);
        assert!(harness.delay.0.lock().unwrap().is_empty());

        harness.processes.set_alive(false);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);
        let replacements = harness.launcher.supervise(&harness.policy).await.unwrap();
        assert_eq!(replacements.len(), 1);
        assert_eq!(
            harness.store.attempt(attempt.id).unwrap().unwrap().state(),
            AttemptState::Cleaned
        );
    }

    #[tokio::test]
    async fn remote_runner_identity_closes_both_sides_of_the_registration_crash_boundary() {
        for sidecar_already_present in [false, true] {
            let harness = Harness::new(
                FakeGithubLifecycle::default(),
                Arc::new(FakeDemand::answering([false])),
            );
            let id = AttemptId::new_random();
            let runtime =
                harness
                    .launcher
                    .app_paths
                    .runtime_dir()
                    .join(if sidecar_already_present {
                        "after-id-sidecar"
                    } else {
                        "before-id-sidecar"
                    });
            fs::create_dir_all(&runtime).unwrap();
            let mut attempt =
                RunnerAttempt::allocate(id, harness.policy.id, &runtime, harness.clock.now());
            if sidecar_already_present {
                write_runner_id(&runtime, 73).unwrap();
                attempt.jit_received(harness.clock.now()).unwrap();
            }
            harness.store.record_attempt(&attempt).unwrap();
            harness.processes.set_alive(true);
            harness
                .github
                .observe(GithubRunnerObservation::Registered { busy: false });
            harness
                .launcher
                .recover_startup(std::slice::from_ref(&harness.policy))
                .await
                .unwrap();

            assert_eq!(read_runner_id(&runtime), Some(73));
            assert!(
                harness
                    .store
                    .attempt(id)
                    .unwrap()
                    .unwrap()
                    .outcome()
                    .is_none()
            );
            let events = harness.events.events();
            let recovered = events.iter().position(|event| {
                matches!(
                    event,
                    AttemptEvent::RemoteIdentityRecovered {
                        attempt,
                        runner_id: 73
                    } if *attempt == id
                )
            });
            assert_eq!(recovered.is_some(), !sidecar_already_present);
            if let Some(recovered) = recovered {
                let adopted = events
                    .iter()
                    .position(|event| matches!(event, AttemptEvent::Adopted { attempt } if *attempt == id))
                    .unwrap();
                assert!(
                    recovered < adopted,
                    "identity was not durable before adoption: {events:?}"
                );
            }
            assert!(runtime.exists());
        }
    }

    #[tokio::test]
    async fn recovery_stays_closed_for_unknown_policy_and_unreachable_attempts() {
        let unknown = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let unknown_attempt = RunnerAttempt::allocate(
            AttemptId::new_random(),
            PolicyId::from_u128(0xfeed),
            unknown
                .launcher
                .app_paths
                .runtime_dir()
                .join("unknown-policy"),
            unknown.clock.now(),
        );
        unknown.store.record_attempt(&unknown_attempt).unwrap();
        let expired_id = AttemptId::new_random();
        let expired_runtime = unknown
            .launcher
            .app_paths
            .runtime_dir()
            .join("expired-beside-unknown");
        fs::create_dir_all(&expired_runtime).unwrap();
        let mut expired = RunnerAttempt::allocate(
            expired_id,
            unknown.policy.id,
            expired_runtime,
            unknown.clock.now(),
        );
        expired.jit_received(unknown.clock.now()).unwrap();
        unknown.store.record_attempt(&expired).unwrap();
        unknown.clock.advance_secs(11);
        assert!(matches!(
            unknown
                .launcher
                .recover_startup(std::slice::from_ref(&unknown.policy))
                .await,
            Err(LifecycleError::RecoveryIncomplete)
        ));
        assert!(unknown.launch_result().await.is_err());
        assert_eq!(unknown.processes.spawns.load(Ordering::SeqCst), 0);
        let recovered_policy = fixtures::policy()
            .id(PolicyId::from_u128(0xfeed))
            .repository("octo/repo")
            .autoscale("home", 2)
            .active()
            .build();
        let pending = unknown
            .launcher
            .recover_startup(&[unknown.policy.clone(), recovered_policy])
            .await
            .unwrap();
        assert_eq!(
            pending,
            vec![ReplacementIntent {
                policy: unknown.policy.id,
                previous_attempt: expired_id,
                operation: "jit_expired_replacement",
            }]
        );
        assert_eq!(unknown.processes.spawns.load(Ordering::SeqCst), 0);

        let unreachable = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let id = AttemptId::new_random();
        let runtime = unreachable
            .launcher
            .app_paths
            .runtime_dir()
            .join("unreachable");
        fs::create_dir_all(&runtime).unwrap();
        unreachable
            .store
            .record_attempt(&RunnerAttempt::allocate(
                id,
                unreachable.policy.id,
                runtime,
                unreachable.clock.now(),
            ))
            .unwrap();
        unreachable
            .github
            .observe(GithubRunnerObservation::Unreachable);
        assert!(matches!(
            unreachable
                .launcher
                .recover_startup(std::slice::from_ref(&unreachable.policy))
                .await,
            Err(LifecycleError::RecoveryIncomplete)
        ));
        assert!(unreachable.launch_result().await.is_err());
        assert_eq!(unreachable.processes.spawns.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_dead_busy_process_unknown_to_github_is_orphaned_and_cleaned() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let id = AttemptId::new_random();
        let runtime = harness.launcher.app_paths.runtime_dir().join("orphan");
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
        harness.ready().await;
        let id = AttemptId::new_random();
        let runtime = harness.launcher.app_paths.runtime_dir().join("timeout");
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
        let replacements = harness.launcher.supervise(&harness.policy).await.unwrap();
        assert_eq!(
            replacements,
            vec![ReplacementIntent {
                policy: harness.policy.id,
                previous_attempt: id,
                operation: "registration_timeout_replacement",
            }]
        );

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
    async fn timeout_crash_recovery_returns_the_same_replacement_intent() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let id = AttemptId::new_random();
        let runtime = harness
            .launcher
            .app_paths
            .runtime_dir()
            .join("timeout-after-crash");
        fs::create_dir_all(&runtime).unwrap();
        let mut attempt =
            RunnerAttempt::allocate(id, harness.policy.id, runtime, harness.clock.now());
        attempt.jit_received(harness.clock.now()).unwrap();
        attempt.started(4242, harness.clock.now()).unwrap();
        harness.store.record_attempt(&attempt).unwrap();
        harness.processes.intent.store(true, Ordering::SeqCst);
        harness.processes.set_alive(false);
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);

        let replacements = harness
            .launcher
            .recover_startup(std::slice::from_ref(&harness.policy))
            .await
            .unwrap();
        assert_eq!(
            replacements,
            vec![ReplacementIntent {
                policy: harness.policy.id,
                previous_attempt: id,
                operation: "registration_timeout_replacement",
            }]
        );
        let consumed = RunnerLauncher::supervise(&harness.launcher, &harness.policy)
            .await
            .unwrap();
        assert_eq!(consumed, replacements);
        assert!(
            RunnerLauncher::supervise(&harness.launcher, &harness.policy)
                .await
                .unwrap()
                .is_empty(),
            "startup replacement evidence must be consumed exactly once by e1"
        );
        assert!(matches!(
            harness.store.attempt(id).unwrap().unwrap().outcome(),
            Some(AttemptOutcome::Failed {
                reason: FailureReason::TerminatedAfterRegistrationTimeout
            })
        ));
    }

    #[tokio::test]
    async fn terminate_intent_sync_failure_prevents_signal_and_conclusion() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        let id = AttemptId::new_random();
        let runtime = harness
            .launcher
            .app_paths
            .runtime_dir()
            .join("timeout-sync-failure");
        fs::create_dir_all(&runtime).unwrap();
        let mut attempt =
            RunnerAttempt::allocate(id, harness.policy.id, &runtime, harness.clock.now());
        attempt.jit_received(harness.clock.now()).unwrap();
        attempt.started(4242, harness.clock.now()).unwrap();
        harness.store.record_attempt(&attempt).unwrap();
        harness.clock.advance_secs(11);
        harness.processes.set_alive(true);
        harness.processes.fail_intent();
        harness
            .github
            .observe(GithubRunnerObservation::NotRegistered);

        assert!(
            harness
                .launcher
                .recover_startup(std::slice::from_ref(&harness.policy))
                .await
                .is_err()
        );
        assert_eq!(harness.processes.terminations.load(Ordering::SeqCst), 0);
        assert!(harness.processes.alive.load(Ordering::SeqCst));
        assert_eq!(
            harness.store.attempt(id).unwrap().unwrap().state(),
            AttemptState::Starting
        );
        assert!(!harness.events.events().iter().any(|event| matches!(
            event,
            AttemptEvent::Terminated { attempt } | AttemptEvent::Concluded { attempt, .. }
                if *attempt == id
        )));
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
        let mut child = native_inspection_spec()
            .spawn_runner_with_handoff(&handoff)
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
        processes
            .record_terminate_intent(&failed)
            .expect("the intent file and its directory entry are durably synced");
        assert_eq!(
            fs::read(NativeProcesses::intent_path(&failed)).unwrap(),
            b"registration-timeout\n"
        );
    }

    #[test]
    fn post_spawn_boundaries_are_bounded_durable_and_never_retry_jit() {
        let root = tempfile::tempdir().unwrap();
        let policy = fixtures::policy()
            .repository("octo/repo")
            .autoscale("home", 1)
            .active()
            .build();
        let processes = NativeProcesses::new();
        processes.use_long_lived_test_listener();
        for (index, boundary) in [
            PostSpawnBoundary::HandoffDelete,
            PostSpawnBoundary::IdentitySerialize,
            PostSpawnBoundary::IdentityWrite,
            PostSpawnBoundary::ChildMapInsert,
        ]
        .into_iter()
        .enumerate()
        {
            let runtime = root.path().join(format!("post-spawn-{index}"));
            let bin = runtime.join("bin");
            fs::create_dir_all(&bin).unwrap();
            #[cfg(windows)]
            let listener = bin.join("Runner.Listener.exe");
            #[cfg(not(windows))]
            let listener = bin.join("Runner.Listener");
            fs::copy(std::env::current_exe().unwrap(), &listener).unwrap();
            let attempt = RunnerAttempt::allocate(
                AttemptId::new_random(),
                policy.id,
                &runtime,
                FakeClock::default().now(),
            );
            processes.fail_post_spawn_at(boundary);
            let failure = processes
                .spawn(&attempt, &EncodedJitConfig::new(JIT))
                .expect_err("fault must cross the post-spawn cleanup path");
            assert!(!failure.retryable, "{boundary:?} allowed duplicate retry");
            assert!(
                !processes.is_alive(&attempt).unwrap(),
                "{boundary:?} left a child"
            );
            assert!(!NativeProcesses::identity_path(&attempt).exists());
            assert_no_jit_file(&runtime);
        }
        assert_eq!(processes.post_spawn_reaps.load(Ordering::SeqCst), 4);

        let runtime = root.path().join("identity-and-stop-fail");
        let bin = runtime.join("bin");
        fs::create_dir_all(&bin).unwrap();
        #[cfg(windows)]
        let listener = bin.join("Runner.Listener.exe");
        #[cfg(not(windows))]
        let listener = bin.join("Runner.Listener");
        fs::copy(std::env::current_exe().unwrap(), &listener).unwrap();
        let attempt = RunnerAttempt::allocate(
            AttemptId::new_random(),
            policy.id,
            &runtime,
            FakeClock::default().now(),
        );
        // The first fault rejects the normal identity write; the second rejects
        // its retry after the first stop fails. The fallback sidecar must make
        // the live-child result durable without an unbounded reap loop.
        processes.fail_post_spawn_at(PostSpawnBoundary::IdentityWrite);
        processes.fail_post_spawn_at(PostSpawnBoundary::IdentityWrite);
        processes.fail_next_post_spawn_stop();
        let failure = processes
            .spawn(&attempt, &EncodedJitConfig::new(JIT))
            .expect_err("the identity boundary must fail closed");
        assert!(failure.live_pid.is_some());
        assert_long_lived_listener_ready(&processes, &attempt);
        assert!(processes.is_alive(&attempt).unwrap());
        assert!(!NativeProcesses::identity_path(&attempt).exists());
        assert!(NativeProcesses::fallback_identity_path(&attempt).is_file());
        assert_eq!(processes.post_spawn_reaps.load(Ordering::SeqCst), 4);
        processes.terminate(&attempt).unwrap();

        let runtime = root.path().join("persistent-stop-and-identity-failures");
        let bin = runtime.join("bin");
        fs::create_dir_all(&bin).unwrap();
        #[cfg(windows)]
        let listener = bin.join("Runner.Listener.exe");
        #[cfg(not(windows))]
        let listener = bin.join("Runner.Listener");
        fs::copy(std::env::current_exe().unwrap(), &listener).unwrap();
        let mut unresolved = RunnerAttempt::allocate(
            AttemptId::new_random(),
            policy.id,
            &runtime,
            FakeClock::default().now(),
        );
        for _ in 0..3 {
            processes.fail_post_spawn_at(PostSpawnBoundary::IdentityWrite);
        }
        processes.fail_post_spawn_stops(MAX_POST_SPAWN_STOP_ATTEMPTS);
        let failure = processes
            .spawn(&unresolved, &EncodedJitConfig::new(JIT))
            .expect_err("bounded cleanup must return even when every stop errors");
        let pid = failure
            .live_pid
            .expect("the owned child remains supervised in this invocation");
        assert!(matches!(failure.reason, FailureReason::Other(_)));
        assert_long_lived_listener_ready(&processes, &unresolved);
        unresolved.jit_received(FakeClock::default().now()).unwrap();
        unresolved.started(pid, FakeClock::default().now()).unwrap();
        let journal = SqliteStore::open_in_memory().unwrap();
        journal.record_attempt(&unresolved).unwrap();
        let recovered = journal.attempt(unresolved.id).unwrap().unwrap();
        assert_eq!(recovered.process_id(), Some(pid));
        assert_eq!(recovered.state(), AttemptState::Starting);
        assert!(processes.is_alive(&unresolved).unwrap());
        assert!(!NativeProcesses::identity_path(&unresolved).exists());
        assert!(!NativeProcesses::fallback_identity_path(&unresolved).exists());
        assert_eq!(
            fs::read_to_string(NativeProcesses::unresolved_process_path(&unresolved)).unwrap(),
            pid.to_string(),
            "bounded cleanup must leave durable unresolved-process evidence before returning"
        );
        assert!(
            NativeProcesses::new().is_alive(&recovered).is_err(),
            "restart must fail closed on the durable starting/PID journal rather than trust a bare PID"
        );
        processes.terminate(&unresolved).unwrap();

        let runtime = root.path().join("post-spawn-stop-failed");
        let bin = runtime.join("bin");
        fs::create_dir_all(&bin).unwrap();
        #[cfg(windows)]
        let listener = bin.join("Runner.Listener.exe");
        #[cfg(not(windows))]
        let listener = bin.join("Runner.Listener");
        fs::copy(std::env::current_exe().unwrap(), &listener).unwrap();
        let attempt = RunnerAttempt::allocate(
            AttemptId::new_random(),
            policy.id,
            &runtime,
            FakeClock::default().now(),
        );
        processes.fail_post_spawn_at(PostSpawnBoundary::ChildMapInsert);
        processes.fail_next_post_spawn_stop();
        let failure = processes
            .spawn(&attempt, &EncodedJitConfig::new(JIT))
            .expect_err("the injected stop failure must preserve supervision");
        let live_pid = failure
            .live_pid
            .expect("live PID is returned to the journal");
        assert!(!failure.retryable);
        assert_long_lived_listener_ready(&processes, &attempt);
        assert!(NativeProcesses::identity_path(&attempt).is_file());
        assert_eq!(
            NativeProcesses::read_identity(&attempt)
                .unwrap()
                .unwrap()
                .pid(),
            live_pid
        );
        assert_eq!(processes.post_spawn_reaps.load(Ordering::SeqCst), 4);
        processes.terminate(&attempt).unwrap();
    }

    #[test]
    #[ignore = "spawned only as the platform-stable native listener fixture"]
    fn long_lived_native_listener_helper() {
        let ready = std::env::var_os("RUNNER_MANAGER_TEST_LISTENER_READY")
            .map(PathBuf::from)
            .expect("the parent supplies the readiness path");
        fs::write(ready, b"ready\n").expect("the listener publishes readiness");
        std::thread::sleep(Duration::from_secs(30));
    }

    fn assert_long_lived_listener_ready(processes: &NativeProcesses, attempt: &RunnerAttempt) {
        let ready = attempt.runtime_path().join(TEST_LISTENER_READY);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if ready.is_file() {
                assert_eq!(fs::read(&ready).unwrap(), b"ready\n");
                return;
            }
            assert!(
                processes.is_alive(attempt).unwrap(),
                "the native listener exited before publishing readiness"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "the native listener stayed alive but never published readiness"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[tokio::test]
    async fn every_production_launch_prunes_under_the_same_allocation_guard() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand));
        harness.ready().await;
        assert_eq!(harness.packages.prunes.load(Ordering::SeqCst), 0);
        harness.launch().await;
        assert_eq!(harness.packages.prunes.load(Ordering::SeqCst), 1);
        assert_eq!(
            *harness.packages.prune_currents.lock().unwrap(),
            vec![harness.packages.version.clone()],
            "the leased current version is an exclusion, never the prune target"
        );
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

    #[test]
    fn production_listener_command_uses_the_supported_jit_contract() {
        let runtime = Path::new("runtime");
        let spec = runner_listener_spec(PathBuf::from("Runner.Listener"), runtime);
        let arguments: Vec<_> = spec
            .arguments()
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();

        assert_eq!(arguments, ["run"]);
        assert!(
            !arguments
                .iter()
                .any(|argument| argument == "--jit-config-file"),
            "the obsolete file option would be rejected by Runner.Listener 2.336.0"
        );
    }

    #[cfg(windows)]
    fn native_inspection_spec() -> SpawnSpec {
        SpawnSpec::new("powershell.exe").args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 30",
        ])
    }

    #[cfg(unix)]
    fn native_inspection_spec() -> SpawnSpec {
        SpawnSpec::new("/bin/sh").args(["-c", "sleep 30"])
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

    // -- c2: persistent slot allocation -------------------------------------

    #[tokio::test]
    async fn a_persistent_repository_leases_s1_and_journals_it_before_any_github_effect() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand))
            .with_persistent_workspace(2);
        harness.github.watch_journal(Arc::clone(&harness.store));
        harness.ready().await;

        let attempt = harness.launch().await;

        assert_eq!(
            attempt.workspace(),
            AttemptWorkspace::persistent_slot(nz(1)),
            "the lowest free slot is leased"
        );
        assert_eq!(attempt.runtime_path(), harness.slot_path(1));
        assert!(attempt.holds_slot_lease());
        // The exact runtime path is journalled, not re-derived later.
        assert_eq!(
            harness.attempt(attempt.id).runtime_path(),
            harness.slot_path(1)
        );

        // Step 7 of "Slot allocation": the lease exists before GitHub is asked
        // for anything, and the runner's work folder stays the relative `_work`
        // the slot root is laid out around.
        let facts = harness.github.registration_facts();
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0].leased_slots,
            vec![1],
            "the lease was journalled first"
        );
        assert_eq!(facts[0].work_folder, DEFAULT_WORK_FOLDER);
    }

    #[tokio::test]
    async fn a_terminal_but_uncleaned_attempt_keeps_its_slot_without_holding_capacity() {
        let harness = Harness::new(
            FakeGithubLifecycle::default().fail(true),
            Arc::new(PersistentDemand),
        )
        .with_persistent_workspace(2);
        harness.ready().await;

        // A terminal JIT refusal concludes the attempt without cleaning it.
        harness.launch_result().await.unwrap_err();
        let first = harness.store.attempts().unwrap().remove(0);
        assert_eq!(first.state(), AttemptState::Failed);
        assert!(
            !first.state().counts_against_capacity(),
            "a concluded attempt is invisible to host capacity"
        );
        assert!(
            first.holds_slot_lease(),
            "and still owns its directory, so its slot is not free"
        );

        let second = harness.launch().await;
        assert_eq!(second.workspace(), AttemptWorkspace::persistent_slot(nz(2)));
        assert_eq!(second.runtime_path(), harness.slot_path(2));
        assert_eq!(
            harness
                .store
                .slot_leases_for_policy(harness.policy.id)
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn two_sequential_allocations_at_capacity_one_reuse_s1_and_its_retained_work() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand))
            .with_persistent_workspace(1);
        harness.ready().await;

        let first = harness.launch().await;
        assert_eq!(first.runtime_path(), harness.slot_path(1));

        // What a job leaves behind, at the path the runner writes it to.
        let checkout = harness.slot_path(1).join(DEFAULT_WORK_FOLDER).join("repo");
        fs::create_dir_all(&checkout).unwrap();
        fs::write(checkout.join("checkout.txt"), b"from the first job").unwrap();

        harness.cleanup_retaining_work(first.id);

        let second = harness.launch().await;
        assert_ne!(second.id, first.id);
        assert_eq!(
            second.workspace(),
            AttemptWorkspace::persistent_slot(nz(1)),
            "a released slot is leased again rather than skipped"
        );
        assert_eq!(
            second.runtime_path(),
            first.runtime_path(),
            "the same slot is the same exact path"
        );
        assert_eq!(
            fs::read_to_string(checkout.join("checkout.txt")).unwrap(),
            "from the first job",
            "the retained job workspace survived the second allocation"
        );
        // The attempt's own runner material was recreated for this attempt.
        assert!(harness.slot_path(1).join("runner-package").exists());
    }

    #[tokio::test]
    async fn lowering_capacity_leaves_higher_slots_alone_and_raising_it_permits_them_again() {
        let mut harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand))
            .with_persistent_workspace(2);
        harness.ready().await;

        let first = harness.launch().await;
        let second = harness.launch().await;
        assert_eq!(second.runtime_path(), harness.slot_path(2));
        let kept = harness
            .slot_path(2)
            .join(DEFAULT_WORK_FOLDER)
            .join("kept.txt");
        fs::create_dir_all(kept.parent().unwrap()).unwrap();
        fs::write(&kept, b"s2 was here").unwrap();
        harness.cleanup_retaining_work(second.id);

        // The operator lowers the ceiling while s1 is still leased.
        harness.policy.set_max_capacity(nz(1)).unwrap();
        let refusal = harness.launch_result().await.unwrap_err().to_string();
        assert!(
            refusal.contains("s1 to s1"),
            "the refusal names the ceiling it reached: {refusal}"
        );
        assert!(
            harness.slot_path(2).exists() && kept.exists(),
            "lowering capacity deletes nothing; the higher slot is merely unusable"
        );

        // Raising it again makes the free higher slot available.
        harness.policy.set_max_capacity(nz(2)).unwrap();
        let third = harness.launch().await;
        assert_eq!(third.workspace(), AttemptWorkspace::persistent_slot(nz(2)));
        assert_eq!(third.runtime_path(), harness.slot_path(2));
        assert_eq!(fs::read_to_string(&kept).unwrap(), "s2 was here");
        assert!(first.holds_slot_lease(), "s1 was never disturbed");
    }

    #[tokio::test]
    async fn organization_and_ephemeral_policies_never_enter_slot_allocation() {
        for policy in [
            fixtures::policy()
                .organization("octo")
                .autoscale("home", 2)
                .active()
                .build(),
            fixtures::policy()
                .repository("octo/repo")
                .autoscale("home", 2)
                .active()
                .build(),
        ] {
            let mut harness =
                Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand))
                    .with_host_runner_root();
            assert_eq!(policy.workspace_policy(), &WorkspacePolicy::Ephemeral);
            harness.policy = policy;
            harness.ready().await;

            let attempt = harness.launch().await;
            assert_eq!(attempt.workspace(), AttemptWorkspace::Ephemeral);
            assert_eq!(attempt.workspace().slot_number(), None);
            assert!(!attempt.holds_slot_lease());
            assert_eq!(
                attempt.runtime_path().parent().unwrap(),
                harness.host_root(),
                "a disposable attempt is a child of the host root, never of a slot"
            );
            assert!(
                harness
                    .store
                    .slot_leases_for_policy(harness.policy.id)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn two_concurrent_allocations_never_share_a_slot() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand))
            .with_persistent_workspace(2);
        harness.github.watch_journal(Arc::clone(&harness.store));
        harness.ready().await;

        // Both allocators race for the same host allocation lock, which is what
        // orders slot *selection*; each one then journals its lease before it
        // asks GitHub for anything.
        let (first, second) = tokio::join!(harness.launch_result(), harness.launch_result());
        let first = first.unwrap();
        let second = second.unwrap();

        let slots: BTreeSet<u16> = [&first, &second]
            .iter()
            .map(|attempt| {
                attempt
                    .workspace()
                    .slot_number()
                    .expect("a persistent attempt leases a slot")
            })
            .collect();
        assert_eq!(slots, BTreeSet::from([1, 2]), "one slot each, never shared");
        assert_ne!(first.runtime_path(), second.runtime_path());
        assert_eq!(
            harness
                .store
                .slot_leases_for_policy(harness.policy.id)
                .unwrap()
                .len(),
            2
        );

        // Every registration saw *its own* lease already in the journal. Reading
        // the whole journal and asking only that it be non-empty would pass on
        // the other allocator's lease, which is precisely the ordering bug this
        // test exists to exclude.
        let facts = harness.github.registration_facts();
        assert_eq!(facts.len(), 2);
        for fact in facts {
            let attempt = [&first, &second]
                .into_iter()
                .find(|attempt| runner_name(attempt.id) == fact.runner_name)
                .expect("every registration belongs to one of the two attempts");
            let slot = attempt
                .workspace()
                .slot_number()
                .expect("a persistent attempt leases a slot");
            assert!(
                fact.leased_slots.contains(&slot),
                "a JIT request never precedes its own lease: s{slot} not in {:?}",
                fact.leased_slots
            );
            assert_eq!(fact.work_folder, DEFAULT_WORK_FOLDER);
        }
    }

    #[tokio::test]
    async fn the_database_is_the_final_fence_against_two_attempts_in_one_slot() {
        let harness = Harness::new(FakeGithubLifecycle::default(), Arc::new(PersistentDemand))
            .with_persistent_workspace(2);
        harness.ready().await;
        let first = harness.launch().await;

        // What a second allocator that lost the race would write: the lock
        // orders selection, and this index is what catches a writer the lock
        // could not see.
        let clash = RunnerAttempt::allocate_in(
            AttemptId::new_random(),
            harness.policy.id,
            first.runtime_path(),
            AttemptWorkspace::persistent_slot(nz(1)),
            harness.clock.now(),
        );
        assert!(matches!(
            harness.store.record_attempt(&clash).unwrap_err(),
            StoreError::SlotAlreadyLeased { slot: 1, .. }
        ));

        // And the launcher reports it as itself rather than as a generic
        // journal failure, so the operator reads what actually happened.
        let error = harness.launcher.record_allocation(&clash).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("slot s1"), "{rendered}");
        assert!(rendered.contains("nothing was written"), "{rendered}");
        assert_eq!(
            harness.store.attempts().unwrap().len(),
            1,
            "the losing allocator journalled nothing"
        );
    }

    #[test]
    fn slot_selection_fills_the_lowest_gap_and_stops_at_the_ceiling() {
        let leased = |slots: &[u16]| -> Vec<RunnerAttempt> {
            slots
                .iter()
                .map(|slot| {
                    RunnerAttempt::allocate_in(
                        AttemptId::new_random(),
                        fixtures::POLICY_ID,
                        format!("/srv/rman/acme/s{slot}"),
                        AttemptWorkspace::persistent_slot(nz(*slot)),
                        fixtures::created_at(),
                    )
                })
                .collect()
        };

        assert_eq!(lowest_free_slot(&[], nz(1)), Some(nz(1)));
        assert_eq!(lowest_free_slot(&leased(&[1]), nz(4)), Some(nz(2)));
        // The gap a released middle slot leaves is filled before the tail.
        assert_eq!(lowest_free_slot(&leased(&[1, 3]), nz(4)), Some(nz(2)));
        // The ceiling is a refusal, never a reason to allocate past it.
        assert_eq!(lowest_free_slot(&leased(&[1]), nz(1)), None);
        assert_eq!(lowest_free_slot(&leased(&[1, 2]), nz(2)), None);
        // An ephemeral attempt holds no slot and cannot block one.
        let ephemeral = vec![RunnerAttempt::allocate(
            AttemptId::new_random(),
            fixtures::POLICY_ID,
            "/srv/rman/host/abc",
            fixtures::created_at(),
        )];
        assert_eq!(lowest_free_slot(&ephemeral, nz(1)), Some(nz(1)));
    }

    #[test]
    fn a_slot_is_reusable_only_when_it_is_empty_or_holds_one_real_work_directory() {
        let root = tempfile::tempdir().unwrap();
        let slot = root.path().join("s1");
        fs::create_dir(&slot).unwrap();
        accept_reusable_slot(&slot).expect("an empty slot is reusable");

        fs::create_dir(slot.join(DEFAULT_WORK_FOLDER)).unwrap();
        accept_reusable_slot(&slot).expect("a retained job workspace is reusable");

        // Runner material a previous attempt left behind is refused rather than
        // reused or removed: deciding those bytes are safe is cleanup's job.
        fs::create_dir(slot.join("bin")).unwrap();
        fs::write(slot.join(".github-runner-id"), b"73").unwrap();
        let refusal = accept_reusable_slot(&slot).unwrap_err().to_string();
        assert!(refusal.contains("bin"), "{refusal}");
        assert!(refusal.contains(".github-runner-id"), "{refusal}");

        // A `_work` that is not a real directory is not a job workspace.
        let file_work = root.path().join("s2");
        fs::create_dir(&file_work).unwrap();
        fs::write(file_work.join(DEFAULT_WORK_FOLDER), b"not a directory").unwrap();
        assert!(accept_reusable_slot(&file_work).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_shaped_work_directory_is_refused_rather_than_followed() {
        // Windows needs a privilege to create either kind of link, so the
        // link-shaped cases are asserted here; the rule itself is
        // platform-independent because it is `symlink_metadata`'s answer.
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();

        let slot = root.path().join("s1");
        fs::create_dir(&slot).unwrap();
        std::os::unix::fs::symlink(&elsewhere, slot.join(DEFAULT_WORK_FOLDER)).unwrap();
        assert!(accept_reusable_slot(&slot).is_err());

        let linked_slot = root.path().join("s2");
        std::os::unix::fs::symlink(&elsewhere, &linked_slot).unwrap();
        assert!(create_or_validate_slot(&linked_slot).is_err());
    }

    #[test]
    fn a_slot_standing_where_a_file_is_refuses_rather_than_replacing_it() {
        let root = tempfile::tempdir().unwrap();
        let occupied = root.path().join("s1");
        fs::write(&occupied, b"an operator's file").unwrap();
        let refusal = create_or_validate_slot(&occupied).unwrap_err().to_string();
        assert!(refusal.contains("is not a directory"), "{refusal}");
        assert_eq!(fs::read_to_string(&occupied).unwrap(), "an operator's file");

        let fresh = root.path().join("s2");
        create_or_validate_slot(&fresh).expect("a missing slot is created");
        assert!(fresh.is_dir());
        create_or_validate_slot(&fresh).expect("an existing directory is accepted");
    }

    #[test]
    fn the_retained_work_directory_is_matched_the_way_the_filesystem_matches_it() {
        assert!(is_work_folder(OsStr::new(DEFAULT_WORK_FOLDER)));
        assert!(!is_work_folder(OsStr::new("_work2")));
        // A Windows filesystem is case-insensitive, so `_Work` *is* the retained
        // job workspace there and must never be removed as a leftover; on a
        // case-sensitive filesystem it is a different directory entirely.
        assert_eq!(is_work_folder(OsStr::new("_Work")), cfg!(windows));
    }

    #[test]
    fn package_materialization_never_overwrites_or_follows_a_retained_work_directory() {
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("package");
        fs::create_dir_all(package.join("bin")).unwrap();
        fs::write(package.join("bin").join("Runner.Listener"), b"binary").unwrap();
        // A nested `_work` inside the package's own tree is an ordinary name.
        fs::create_dir_all(package.join("externals").join(DEFAULT_WORK_FOLDER)).unwrap();

        let slot = root.path().join("s1");
        let retained = slot.join(DEFAULT_WORK_FOLDER).join("repo");
        fs::create_dir_all(&retained).unwrap();
        fs::write(retained.join("checkout.txt"), b"from the first job").unwrap();

        copy_package_tree(&package, &slot).expect("the package lays out around `_work`");
        assert!(slot.join("bin").join("Runner.Listener").exists());
        assert!(
            slot.join("externals").join(DEFAULT_WORK_FOLDER).is_dir(),
            "the guard is top-level only"
        );
        assert_eq!(
            fs::read_to_string(retained.join("checkout.txt")).unwrap(),
            "from the first job"
        );

        // A package that ever grew a top-level `_work` is refused, not merged.
        fs::create_dir(package.join(DEFAULT_WORK_FOLDER)).unwrap();
        let error = copy_package_tree(&package, &slot).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            fs::read_to_string(retained.join("checkout.txt")).unwrap(),
            "from the first job"
        );
    }

    #[test]
    fn rolling_back_a_materialization_keeps_a_slot_but_removes_a_disposable_directory() {
        let root = tempfile::tempdir().unwrap();

        let slot = root.path().join("s1");
        let retained = slot.join(DEFAULT_WORK_FOLDER);
        fs::create_dir_all(retained.join("repo")).unwrap();
        fs::write(retained.join("repo").join("checkout.txt"), b"kept").unwrap();
        fs::create_dir_all(slot.join("bin")).unwrap();
        fs::write(slot.join(".github-runner-id"), b"73").unwrap();
        let persistent = RunnerAttempt::allocate_in(
            AttemptId::new_random(),
            fixtures::POLICY_ID,
            &slot,
            AttemptWorkspace::persistent_slot(nz(1)),
            fixtures::created_at(),
        );

        remove_materialized_package(&persistent).unwrap();
        assert!(slot.is_dir(), "the slot itself is not removed");
        assert!(!slot.join("bin").exists());
        assert!(!slot.join(".github-runner-id").exists());
        assert_eq!(
            fs::read_to_string(retained.join("repo").join("checkout.txt")).unwrap(),
            "kept"
        );

        let disposable_path = root.path().join("abcdef012345");
        fs::create_dir_all(disposable_path.join(DEFAULT_WORK_FOLDER)).unwrap();
        let disposable = RunnerAttempt::allocate(
            AttemptId::new_random(),
            fixtures::POLICY_ID,
            &disposable_path,
            fixtures::created_at(),
        );
        remove_materialized_package(&disposable).unwrap();
        assert!(
            !disposable_path.exists(),
            "a disposable directory is still removed whole"
        );
    }
}
