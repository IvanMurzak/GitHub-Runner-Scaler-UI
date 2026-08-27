// owner: f3-cli-daemon-service

//! The foreground agent and its graceful drain boundary.

use std::collections::BTreeSet;
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use runner_manager_agent::lifecycle::{
    CachedRuntimePackages, LifecycleGithub, LifecycleGithubObservation, LifecycleLauncher,
    LifecyclePorts, NativeProcesses, NoAttemptEvents, PersistentDemand, RetryPolicy,
    TokioRetryDelay,
};
use runner_manager_agent::package::{
    CachePorts, ExponentialBackoff, GatewayCatalog, HttpFetcher, PackageCache,
};
use runner_manager_agent::reconcile::{
    FileAllocationLock, GatewayDemand, RandomJitter, ReconcileReport, Reconciler, ReconcilerPorts,
    RepositoryDirectory, TeeEvents, TracingEvents,
};
use runner_manager_domain::attempt::{FailureReason, active_count_for};
use runner_manager_domain::model::{AttemptId, Clock, Org, OwnerRepo, ScaleTarget};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::Store;
use runner_manager_github::demand::RestDemand;
use runner_manager_github::jit::{JitError, JitGateway, JitRunnerRequest, RestJit};
use runner_manager_github::rest::{CancelToken, InventoryError, InventoryGateway, RestInventory};
use runner_manager_github::{AppRegistration, AuthenticatedClient, GithubError, UserAccessToken};
use runner_manager_platform::lock::{HostLock, LockError, LockKind};
use runner_manager_platform::secrets::SecretStore as _;
use runner_manager_platform::service::{InstallRecord, record_github_contact};

use super::{CliError, Context, DaemonCommand, Failure, write_failed};

pub fn dispatch(
    context: &Context,
    command: &DaemonCommand,
    out: &mut dyn Write,
    service_shutdown: Option<runner_manager_platform::service::ServiceShutdown>,
) -> Result<(), CliError> {
    match command {
        DaemonCommand::Run(_) => {
            let runtime = super::runtime()?;
            runtime.block_on(run(context, out, service_shutdown))
        }
    }
}

async fn run(
    context: &Context,
    out: &mut dyn Write,
    service_shutdown: Option<runner_manager_platform::service::ServiceShutdown>,
) -> Result<(), CliError> {
    let _instance = acquire_instance(context)?;
    let store = Arc::new(context.store()?);
    let host = super::host::local_host_or_create(context, store.as_ref())?;
    let targets = active_autoscale_targets(store.policies().map_err(local_store_failure)?);
    let failed = write_failed("the daemon state");

    writeln!(out, "daemon running (pid {})", std::process::id()).map_err(failed)?;

    // A host with no policies owns no GitHub work. It still holds the lock and
    // behaves as a real daemon, but it neither demands a credential nor opens a
    // network connection while waiting to be configured or stopped.
    if targets.is_empty() {
        wait_for_shutdown(service_shutdown)
            .await
            .map_err(signal_failure)?;
        writeln!(out, "daemon stopped; no runner was terminated").map_err(failed)?;
        return Ok(());
    }

    let mode = host.service_start_mode;
    let secrets = context.secret_store(mode)?;
    let secret = secrets
        .load()
        .map_err(|source| {
            CliError::with_remedy(
                Failure::SecretStore,
                format!("cannot read the stored GitHub credential: {source}"),
                "runner-manager auth login",
            )
        })?
        .ok_or_else(|| {
            CliError::with_remedy(
                Failure::NotAuthenticated,
                "no GitHub credential is stored for this daemon's start mode",
                "runner-manager auth login",
            )
        })?;
    let client = Arc::new(
        AuthenticatedClient::new(
            context.endpoints().clone(),
            UserAccessToken::from_stored(secret),
            context.clock(),
        )
        .map_err(github_failure)?,
    );
    let app = context.app_registration()?;
    let clock = context.clock();
    let inventory = Arc::new(RestInventory::new(Arc::clone(&client), Arc::clone(&clock)));
    let jit = Arc::new(RestJit::new(Arc::clone(&client)));
    let lifecycle_github = Arc::new(GithubLifecycle {
        jit,
        inventory: Arc::clone(&inventory),
        clock: Arc::clone(&clock),
    });
    let directory = Arc::new(GithubDirectory {
        client: Arc::clone(&client),
        app,
    });

    let paths = Arc::new(context.paths().clone());
    let events: Arc<dyn runner_manager_agent::reconcile::EventSink> = Arc::new(TeeEvents(
        Arc::new(TracingEvents),
        Arc::new(runner_manager_agent::reconcile::EventLog::new()),
    ));
    let shared_lock = Arc::new(FileAllocationLock::new(paths));
    let mut managed_targets = Vec::with_capacity(targets.len());
    for policies in targets {
        let package_target = policies[0].target.clone();
        let catalog = Arc::new(GatewayCatalog::new(
            RestInventory::new(Arc::clone(&client), Arc::clone(&clock)),
            package_target.clone(),
        ));
        let cache = Arc::new(PackageCache::new(
            context.paths(),
            host.os,
            host.architecture,
            CachePorts {
                catalog,
                fetcher: Arc::new(HttpFetcher::default()),
                backoff: Arc::new(ExponentialBackoff::default()),
                clock: Arc::clone(&clock),
            },
        ));
        let lifecycle_store = Arc::new(TargetRecoveryStore::new(
            Arc::clone(&store) as Arc<dyn Store>,
            &policies,
        ));
        let launcher = Arc::new(LifecycleLauncher::new(
            host.id,
            context.paths().runtime_dir(),
            context.paths().logs_dir(),
            1,
            runner_manager_domain::attempt::RecoveryTimeouts::provisional(),
            RetryPolicy::bounded(3, Duration::from_secs(2), Duration::from_secs(30)),
            LifecyclePorts {
                store: Arc::clone(&lifecycle_store) as Arc<dyn Store>,
                github: Arc::clone(&lifecycle_github) as Arc<dyn LifecycleGithub>,
                packages: Arc::new(CachedRuntimePackages::new(cache)),
                processes: Arc::new(NativeProcesses::new()),
                clock: Arc::clone(&clock),
                demand: Arc::new(PersistentDemand),
                delay: Arc::new(TokioRetryDelay),
                events: Arc::new(NoAttemptEvents),
                reconcile_events: Arc::clone(&events),
            },
        ));
        launcher
            .recover_startup(&policies)
            .await
            .map_err(|source| {
                CliError::new(
                    Failure::LocalState,
                    format!(
                        "startup recovery for {} did not complete: {source}",
                        package_target
                    ),
                )
            })?;
        lifecycle_store.finish_recovery();
        let cancel = CancelToken::new();
        let demand = Arc::new(GatewayDemand::new(
            RestDemand::new(Arc::clone(&client), Arc::clone(&clock)),
            cancel.clone(),
        ));
        managed_targets.push(ManagedTarget {
            policies,
            store: Arc::clone(&store) as Arc<dyn Store>,
            reconciler: Reconciler::new(
                host.clone(),
                ReconcilerPorts {
                    demand,
                    launcher,
                    lock: Arc::clone(&shared_lock) as Arc<_>,
                    directory: Arc::clone(&directory) as Arc<_>,
                    clock: Arc::clone(&clock),
                    jitter: Arc::new(RandomJitter),
                    events: Arc::clone(&events),
                },
            ),
            cancel,
        });
    }

    let (shutdown, _) = tokio::sync::watch::channel(false);
    let (upgrade, _) = tokio::sync::watch::channel(false);
    let mut loops = tokio::task::JoinSet::new();
    let contacts: Arc<dyn ContactRecorder> = Arc::new(FileContactRecorder {
        paths: context.paths().clone(),
        clock: Arc::clone(&clock),
        write: Mutex::new(()),
    });
    for target in managed_targets {
        loops.spawn(run_target_loop(
            target,
            shutdown.subscribe(),
            upgrade.subscribe(),
            Arc::clone(&contacts),
        ));
    }

    // The *source*, not `current_exe`. A service registered by `service
    // install` runs a copy this product owns, precisely so that the package
    // manager's own file stays replaceable while the service runs -- so the
    // file that changes on an upgrade is the source, and the copy never
    // changes on its own. `None` for a daemon started by hand, or for a
    // registration made before copies existed, and then nothing is watched.
    let own_binary = InstallRecord::read(context.paths())
        .ok()
        .flatten()
        .and_then(|record| record.source_binary);
    let mut upgraded_to = None;

    let early = tokio::select! {
        signal = wait_for_shutdown(service_shutdown) => {
            signal.map_err(signal_failure)?;
            None
        }
        version = async {
            match own_binary.clone() {
                Some(path) => wait_for_upgrade(path).await,
                // Nothing to watch, so never resolve; the other arms decide.
                None => std::future::pending().await,
            }
        } => {
            writeln!(
                out,
                "a newer runner-manager ({version}) was installed; finishing every running                  job before handing over"
            )
            .map_err(failed)?;
            tracing::info!(
                version = %version,
                "a newer binary was installed; draining before restart"
            );
            upgraded_to = Some(version);
            None
        }
        result = loops.join_next() => result,
    };
    if upgraded_to.is_some() {
        let _ = upgrade.send(true);
        // Not `shutdown`: that one is bounded, and an upgrade must outlast any
        // job rather than any deadline.
        while let Some(result) = loops.join_next().await {
            result.map_err(|source| {
                CliError::new(
                    Failure::LocalState,
                    format!("a daemon target loop failed: {source}"),
                )
            })??;
        }
        let version = upgraded_to.unwrap_or_default();
        // The copy is replaced here, by the daemon, because nothing else can:
        // a package manager updates the source and never touches this path.
        // The old file is renamed rather than deleted -- Windows refuses to
        // unlink an executable that is running, which this one still is, but
        // allows it to be renamed out of the way.
        if let Some(source) = own_binary.as_deref()
            && let Err(error) = replace_own_binary(source)
        {
            tracing::warn!(
                %error,
                "the new binary could not be put in place; the service manager will restart the                  version already there"
            );
            writeln!(out, "warning: {error}").map_err(failed)?;
        }
        writeln!(
            out,
            "every runner finished; stopping so {version} can take over"
        )
        .map_err(failed)?;
        return Err(CliError::with_remedy(
            Failure::UpgradePending,
            format!(
                "a newer runner-manager ({version}) is installed and every runner this daemon                  held has finished; stopping so the service manager starts the new one"
            ),
            "runner-manager service status",
        ));
    }
    let _ = shutdown.send(true);
    if let Some(result) = early {
        let outcome = result.map_err(|source| {
            CliError::new(
                Failure::LocalState,
                format!("a daemon target loop failed: {source}"),
            )
        })?;
        outcome?;
        return Err(CliError::new(
            Failure::LocalState,
            "a daemon target loop stopped before shutdown",
        ));
    }
    while let Some(result) = loops.join_next().await {
        result.map_err(|source| {
            CliError::new(
                Failure::LocalState,
                format!("a daemon target loop failed: {source}"),
            )
        })??;
    }
    writeln!(out, "daemon stopped; no busy runner was terminated").map_err(failed)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Upgrade detection
// ---------------------------------------------------------------------------

/// How often the daemon looks at its own binary.
///
/// Deliberately unrelated to the poll interval: this is two `stat` calls
/// against a local path and costs nothing GitHub can see, so it is not on the
/// REST budget and does not need to be.
const UPGRADE_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// What a file looked like, in the two fields that change when it is replaced.
///
/// Not a hash. Reading 13 MB every thirty seconds to notice a change that a
/// `stat` already reports would be paying a lot for a stronger answer than the
/// question needs — and the answer is confirmed by executing the binary anyway
/// (see [`upgraded_version`]), which is a stronger check than any digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BinaryStamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
}

impl BinaryStamp {
    fn of(path: &std::path::Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        Some(Self {
            len: meta.len(),
            modified: meta.modified().ok(),
        })
    }
}

/// The version a replaced binary reports, when it is genuinely a different one.
///
/// # Why the file is executed rather than trusted
///
/// A changed `stat` says the bytes moved, not that they are complete. A package
/// manager writing 13 MB is momentarily a file of the right name and the wrong
/// length, and restarting into that leaves the machine in a restart loop with
/// no daemon — the failure this whole feature exists to avoid, caused by the
/// feature itself.
///
/// Running `--version` settles both halves at once: it exits non-zero or not at
/// all if the file is partial, and it prints the version if it is not. That is
/// also the only way to learn the *new* version, since this process can only
/// ever report the one it was compiled as.
///
/// `None` means "nothing to do": unreadable, unrunnable, or the same version
/// this daemon already is. A same-version rewrite — a reinstall of what is
/// already there — is deliberately not an upgrade, because restarting for it
/// would interrupt runners to change nothing.
fn upgraded_version(path: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let reported = String::from_utf8(output.stdout).ok()?;
    // `--version` prints `runner-manager X.Y.Z`; the last token is the version.
    let reported = reported.split_whitespace().last()?.to_string();
    (reported != env!("CARGO_PKG_VERSION")).then_some(reported)
}

/// Resolves when a different, runnable version has replaced this daemon's own
/// binary. Never resolves otherwise.
async fn wait_for_upgrade(path: std::path::PathBuf) -> String {
    // The stamp this daemon started from. A binary replaced *before* the first
    // look is still caught, because the version comparison below is against
    // what this process was compiled as rather than against the file.
    let mut known = BinaryStamp::of(&path);
    loop {
        tokio::time::sleep(UPGRADE_CHECK_INTERVAL).await;
        let current = BinaryStamp::of(&path);
        if current == known {
            continue;
        }
        // Record the new stamp before validating, so a partial write is not
        // re-examined every thirty seconds until it happens to finish.
        known = current;
        if current.is_none() {
            continue;
        }
        if let Some(version) = upgraded_version(&path) {
            return version;
        }
    }
}

/// Puts the source binary in place of the one this process is running.
///
/// The running file is renamed aside rather than deleted: Windows refuses to
/// unlink an executable that is running -- which this one is, right now -- and
/// permits renaming it. The leftover is removed by the next install or upgrade,
/// whichever comes first, and is harmless until then because nothing names it.
fn replace_own_binary(source: &std::path::Path) -> Result<(), String> {
    let own = std::env::current_exe().map_err(|error| format!("own path unknown: {error}"))?;
    let aside = own.with_extension("old");
    let _ = std::fs::remove_file(&aside);
    std::fs::rename(&own, &aside)
        .map_err(|error| format!("the running binary could not be moved aside: {error}"))?;
    if let Err(error) = std::fs::copy(source, &own) {
        // Put back what was working. A daemon that restarts into nothing is a
        // machine with no runner manager at all.
        let _ = std::fs::rename(&aside, &own);
        return Err(format!(
            "the new binary could not be copied into place: {error}"
        ));
    }
    Ok(())
}

async fn wait_for_shutdown(
    service_shutdown: Option<runner_manager_platform::service::ServiceShutdown>,
) -> std::io::Result<()> {
    match service_shutdown {
        Some(shutdown) => {
            shutdown.wait().await;
            Ok(())
        }
        None => shutdown_signal().await,
    }
}

/// Gives one lifecycle launcher a target-scoped journal only while it performs
/// startup recovery. Ordinary reconciliation sees the complete host attempt
/// set again, which preserves the host-wide capacity invariant.
#[derive(Debug)]
struct TargetRecoveryStore {
    inner: Arc<dyn Store>,
    policies: BTreeSet<runner_manager_domain::model::PolicyId>,
    recovering: AtomicBool,
}

impl TargetRecoveryStore {
    fn new(inner: Arc<dyn Store>, policies: &[ScalePolicy]) -> Self {
        Self {
            inner,
            policies: policies.iter().map(|policy| policy.id).collect(),
            recovering: AtomicBool::new(true),
        }
    }

    fn finish_recovery(&self) {
        self.recovering.store(false, Ordering::Release);
    }
}

impl Store for TargetRecoveryStore {
    fn put_host(
        &self,
        host: &runner_manager_domain::model::Host,
    ) -> Result<(), runner_manager_domain::store::StoreError> {
        self.inner.put_host(host)
    }

    fn host(
        &self,
        id: runner_manager_domain::model::HostId,
    ) -> Result<Option<runner_manager_domain::model::Host>, runner_manager_domain::store::StoreError>
    {
        self.inner.host(id)
    }

    fn hosts(
        &self,
    ) -> Result<Vec<runner_manager_domain::model::Host>, runner_manager_domain::store::StoreError>
    {
        self.inner.hosts()
    }

    fn insert_policy(
        &self,
        policy: &ScalePolicy,
    ) -> Result<(), runner_manager_domain::store::StoreError> {
        self.inner.insert_policy(policy)
    }

    fn update_policy(
        &self,
        policy: &ScalePolicy,
        expected_revision: u64,
    ) -> Result<(), runner_manager_domain::store::StoreError> {
        self.inner.update_policy(policy, expected_revision)
    }

    fn update_policy_confirming_active_count(
        &self,
        policy: &ScalePolicy,
        expected_revision: u64,
        expected_active: u16,
    ) -> Result<(), runner_manager_domain::store::StoreError> {
        self.inner
            .update_policy_confirming_active_count(policy, expected_revision, expected_active)
    }

    fn remove_policy(
        &self,
        id: runner_manager_domain::model::PolicyId,
        expected_revision: u64,
    ) -> Result<(), runner_manager_domain::store::StoreError> {
        self.inner.remove_policy(id, expected_revision)
    }

    fn policy(
        &self,
        id: runner_manager_domain::model::PolicyId,
    ) -> Result<Option<ScalePolicy>, runner_manager_domain::store::StoreError> {
        self.inner.policy(id)
    }

    fn policies(&self) -> Result<Vec<ScalePolicy>, runner_manager_domain::store::StoreError> {
        self.inner.policies()
    }

    fn record_attempt(
        &self,
        attempt: &runner_manager_domain::attempt::RunnerAttempt,
    ) -> Result<(), runner_manager_domain::store::StoreError> {
        self.inner.record_attempt(attempt)
    }

    fn attempt(
        &self,
        id: AttemptId,
    ) -> Result<
        Option<runner_manager_domain::attempt::RunnerAttempt>,
        runner_manager_domain::store::StoreError,
    > {
        self.inner.attempt(id)
    }

    fn attempts(
        &self,
    ) -> Result<
        Vec<runner_manager_domain::attempt::RunnerAttempt>,
        runner_manager_domain::store::StoreError,
    > {
        let mut attempts = self.inner.attempts()?;
        if self.recovering.load(Ordering::Acquire) {
            attempts.retain(|attempt| self.policies.contains(&attempt.policy_id));
        }
        Ok(attempts)
    }

    fn attempts_for_policy(
        &self,
        policy_id: runner_manager_domain::model::PolicyId,
    ) -> Result<
        Vec<runner_manager_domain::attempt::RunnerAttempt>,
        runner_manager_domain::store::StoreError,
    > {
        self.inner.attempts_for_policy(policy_id)
    }

    fn remove_attempt(
        &self,
        id: AttemptId,
    ) -> Result<bool, runner_manager_domain::store::StoreError> {
        self.inner.remove_attempt(id)
    }
}

fn active_autoscale_targets(mut policies: Vec<ScalePolicy>) -> Vec<Vec<ScalePolicy>> {
    policies.retain(ScalePolicy::may_start_runners);
    policies.sort_by(|left, right| left.target.to_string().cmp(&right.target.to_string()));
    let mut targets: Vec<Vec<ScalePolicy>> = Vec::new();
    for policy in policies {
        match targets.last_mut() {
            Some(group) if group[0].target == policy.target => group.push(policy),
            _ => targets.push(vec![policy]),
        }
    }
    targets
}

trait TargetReconciler: Send + 'static {
    fn policies(&self) -> &[ScalePolicy];
    fn begin_drain(&mut self);
    fn reconcile(&mut self) -> Pin<Box<dyn Future<Output = ReconcileReport> + Send + '_>>;
    fn active_owned(&self, report: &ReconcileReport) -> Option<u16> {
        active_owned(report, self.policies())
    }

    /// Runners this host still holds for this target, counted from the **local
    /// journal** rather than from GitHub.
    ///
    /// # Why a second count exists beside [`Self::active_owned`]
    ///
    /// They answer different questions and fail differently, and an upgrade
    /// needs the one that cannot fail. `active_owned` reads the reconcile
    /// report, and a target GitHub could not be polled contributes no
    /// allocation to it — so its answer is `None`, meaning "unknown", for as
    /// long as the credential or the network is bad.
    ///
    /// Waiting for `Some(0)` from that is what made shutdown hang forever, and
    /// an upgrade drain that waits without a deadline would inherit exactly
    /// that: a revoked token would mean the upgrade never happens, on the one
    /// machine whose daemon most needs replacing.
    ///
    /// Whether *this host* has a runner process alive is a local fact. The
    /// journal holds it, `d1` keeps it true across a crash, and no network is
    /// involved. So the upgrade drain waits on this instead, and can then
    /// afford to wait as long as a job takes.
    fn local_active(&self) -> Option<u16>;
}

struct ManagedTarget {
    policies: Vec<ScalePolicy>,
    reconciler: Reconciler,
    cancel: CancelToken,
    store: Arc<dyn Store>,
}

impl TargetReconciler for ManagedTarget {
    fn policies(&self) -> &[ScalePolicy] {
        &self.policies
    }

    fn begin_drain(&mut self) {
        self.cancel.cancel();
        begin_drain(&mut self.policies);
    }

    fn reconcile(&mut self) -> Pin<Box<dyn Future<Output = ReconcileReport> + Send + '_>> {
        Box::pin(self.reconciler.reconcile(&self.policies))
    }

    fn local_active(&self) -> Option<u16> {
        let mut total = 0_u16;
        for policy in &self.policies {
            // A journal this pass could not read is `None`, not zero: reporting
            // an unreadable set as empty would let the upgrade stop a daemon
            // that is in the middle of somebody's job.
            let attempts = self.store.attempts_for_policy(policy.id).ok()?;
            total = total.saturating_add(active_count_for(policy.id, attempts.iter()));
        }
        Some(total)
    }
}

trait ContactRecorder: Send + Sync + 'static {
    fn record(&self) -> Result<(), CliError>;
}

struct FileContactRecorder {
    paths: runner_manager_platform::paths::AppPaths,
    clock: Arc<dyn Clock>,
    write: Mutex<()>,
}

impl ContactRecorder for FileContactRecorder {
    fn record(&self) -> Result<(), CliError> {
        let _write = self.write.lock().map_err(|_| {
            CliError::new(
                Failure::LocalState,
                "cannot lock the last successful GitHub contact record",
            )
        })?;
        record_github_contact(&self.paths, self.clock.now()).map_err(|source| {
            CliError::new(
                Failure::LocalState,
                format!("cannot record the last successful GitHub contact: {source}"),
            )
        })
    }
}

/// How long a drain may run before the daemon stops regardless.
///
/// # Why a drain needs a deadline at all
///
/// The graceful path below ends when the target reports no owned runners left.
/// That reading is an `Option`, and the `None` is not a zero: a target GitHub
/// could not be read contributes no allocation to the report at all
/// (`reconcile.rs`, the `PollOutcome::Failed` arm), so `active_owned` answers
/// `None` and the equality against `Some(0)` is false however long the drain
/// runs. Without a second exit, a daemon whose credential GitHub has rejected
/// drains **forever** — and since that is precisely the state a daemon sits in
/// after a token is revoked, the practical effect was a service that could not
/// be stopped or restarted at all, only killed. It was found that way: seven
/// minutes of `STOP_PENDING`, still polling, on the machine this was reported
/// from.
///
/// # Why stopping anyway is safe
///
/// Nothing is lost by stopping with runners still up. A runner this host owns
/// survives in the journal, and startup recovery is the thing that reconciles
/// it on the next run — adopting one still doing its job, concluding one that
/// is gone. That path is not a fallback added for this; it is how the daemon
/// already starts after any crash or reboot, which is the same situation.
///
/// Sixty seconds is chosen to be longer than a normal poll cycle, so an
/// ordinary drain still ends the graceful way, and short enough that the
/// service manager's own stop timeout does not expire first.
const DRAIN_DEADLINE: Duration = Duration::from_secs(60);

/// Why a target loop is draining, which is the whole of what separates the two
/// drains.
///
/// A **shutdown** is an operator or a machine waiting: it is bounded, and past
/// its deadline the daemon stops with runners still up, because startup
/// recovery will adopt them on the next run.
///
/// An **upgrade** has nobody waiting. Its whole purpose is to replace the
/// binary without interrupting work, so a deadline would defeat it — the one
/// thing it must not do is cut a job short to be timely. It waits on the local
/// journal instead of on GitHub precisely so that waiting forever is safe; see
/// [`TargetReconciler::local_active`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainKind {
    Shutdown,
    Upgrade,
}

async fn run_target_loop<T: TargetReconciler>(
    mut target: T,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut upgrade: tokio::sync::watch::Receiver<bool>,
    contacts: Arc<dyn ContactRecorder>,
) -> Result<(), CliError> {
    let mut draining = shutdown_kind(&shutdown, &upgrade);
    let mut drain_deadline = match draining {
        Some(DrainKind::Shutdown) => Some(tokio::time::Instant::now() + DRAIN_DEADLINE),
        _ => None,
    };
    if draining.is_some() {
        target.begin_drain();
    }
    loop {
        if drain_deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            // Whatever is still running is startup recovery's to adopt.
            return Ok(());
        }
        let report = target.reconcile().await;
        if draining.is_none() && report.failure.is_none() {
            contacts.record()?;
        }
        match draining {
            Some(DrainKind::Shutdown) if target.active_owned(&report) == Some(0) => {
                return Ok(());
            }
            // GitHub is not consulted: an upgrade must complete even when the
            // credential is the reason the operator is upgrading.
            Some(DrainKind::Upgrade) if target.local_active() == Some(0) => {
                return Ok(());
            }
            _ => {}
        }
        // Capped by the deadline, so a long back-off delay cannot outlast it. A
        // drain that has run out of time sleeps zero and exits at the top.
        let delay = drain_deadline.map_or(report.next_poll.delay, |deadline| {
            report
                .next_poll
                .delay
                .min(deadline.saturating_duration_since(tokio::time::Instant::now()))
        });
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            changed = shutdown.changed(), if draining != Some(DrainKind::Shutdown) => {
                if changed.is_err() || *shutdown.borrow() {
                    // A shutdown arriving mid-upgrade supersedes it, deadline
                    // and all: the machine is going down either way, and the
                    // upgrade's patience is no longer anybody's benefit.
                    target.begin_drain();
                    draining = Some(DrainKind::Shutdown);
                    drain_deadline = Some(tokio::time::Instant::now() + DRAIN_DEADLINE);
                }
            }
            changed = upgrade.changed(), if draining.is_none() => {
                if changed.is_err() || *upgrade.borrow() {
                    target.begin_drain();
                    draining = Some(DrainKind::Upgrade);
                }
            }
        }
    }
}

/// The drain a loop is already in when it starts, if any. Shutdown wins.
fn shutdown_kind(
    shutdown: &tokio::sync::watch::Receiver<bool>,
    upgrade: &tokio::sync::watch::Receiver<bool>,
) -> Option<DrainKind> {
    if *shutdown.borrow() {
        Some(DrainKind::Shutdown)
    } else if *upgrade.borrow() {
        Some(DrainKind::Upgrade)
    } else {
        None
    }
}

fn active_owned(report: &ReconcileReport, policies: &[ScalePolicy]) -> Option<u16> {
    policies.iter().try_fold(0_u16, |total, policy| {
        report
            .allocations
            .iter()
            .find(|allocation| allocation.policy_id == policy.id)
            .map(|allocation| total.saturating_add(allocation.active_owned))
    })
}

fn begin_drain(policies: &mut [runner_manager_domain::policy::ScalePolicy]) {
    for policy in policies {
        if policy.can_request_disable() {
            let _ = policy.request_disable();
        }
    }
}

fn acquire_instance(context: &Context) -> Result<HostLock, CliError> {
    HostLock::try_acquire(context.paths(), LockKind::SingleInstance).map_err(
        |source| match source {
            held @ LockError::Held { .. } => CliError::with_remedy(
                Failure::Conflict,
                format!("another daemon already owns this host: {held}"),
                "runner-manager service status",
            ),
            other => CliError::new(
                Failure::LocalState,
                format!("cannot acquire the daemon's single-instance lock: {other}"),
            ),
        },
    )
}

fn local_store_failure(source: runner_manager_domain::store::StoreError) -> CliError {
    CliError::new(
        Failure::LocalState,
        format!("cannot read the daemon's local database: {source}"),
    )
}

fn github_failure(source: GithubError) -> CliError {
    CliError::with_remedy(
        Failure::GithubUnavailable,
        source.to_string(),
        "runner-manager auth status",
    )
}

fn signal_failure(source: std::io::Error) -> CliError {
    CliError::new(
        Failure::UnsupportedHost,
        format!("cannot listen for the daemon shutdown signal: {source}"),
    )
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[derive(Debug)]
struct GithubLifecycle {
    jit: Arc<RestJit>,
    inventory: Arc<RestInventory>,
    clock: Arc<dyn Clock>,
}

impl LifecycleGithub for GithubLifecycle {
    fn register<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        target: &'life1 ScaleTarget,
        request: &'life2 JitRunnerRequest,
        cancel: &'life3 CancelToken,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        runner_manager_github::jit::JitRegistration,
                        runner_manager_agent::lifecycle::JitRequestFailure,
                    >,
                > + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.jit
                .generate_jit_config(target, request, cancel)
                .await
                .map_err(|error| runner_manager_agent::lifecycle::JitRequestFailure {
                    terminal: error.is_terminal(),
                    retry_after: error.rate_limited().map(|limit| limit.delay_from(self.clock.now())),
                    reason: if matches!(error, JitError::Forbidden { .. }) {
                        FailureReason::Other("GitHub refused JIT registration; check the App runner permission and runner-group access".into())
                    } else {
                        FailureReason::JitRequestFailed
                    },
                })
        })
    }

    fn observe<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        target: &'life1 ScaleTarget,
        attempt: AttemptId,
        cancel: &'life2 CancelToken,
    ) -> Pin<Box<dyn Future<Output = LifecycleGithubObservation> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let name = format!("runner-manager-{attempt}");
            match self.inventory.list_runners(target, cancel).await {
                Ok(inventory) => inventory
                    .runners()
                    .iter()
                    .find(|runner| runner.name == name)
                    .map_or(LifecycleGithubObservation::not_registered(), |runner| {
                        LifecycleGithubObservation::registered(runner.id, runner.busy)
                    }),
                Err(_) => LifecycleGithubObservation::unreachable(),
            }
        })
    }

    fn deregister<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        target: &'life1 ScaleTarget,
        runner_id: u64,
        cancel: &'life2 CancelToken,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.inventory
                .remove_runner(target, runner_id, cancel)
                .await
                .is_ok()
        })
    }
}

#[derive(Debug)]
struct GithubDirectory {
    client: Arc<AuthenticatedClient>,
    app: AppRegistration,
}

impl RepositoryDirectory for GithubDirectory {
    fn repositories<'life0, 'life1, 'async_trait>(
        &'life0 self,
        org: &'life1 Org,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<OwnerRepo>, InventoryError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let discovery = self
                .client
                .discover_installations(&self.app)
                .await
                .map_err(InventoryError::from)?;
            Ok(discovery
                .targets()
                .map(|targets| {
                    targets
                        .repositories()
                        .into_iter()
                        .filter(|repository| repository.owner().eq_ignore_ascii_case(org.as_str()))
                        .collect()
                })
                .unwrap_or_default())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use runner_manager_agent::lifecycle::{JitRequestFailure, PruneAuthority, RuntimePackages};
    use runner_manager_agent::package::RunnerVersion;
    use runner_manager_domain::attempt::RunnerAttempt;
    use runner_manager_domain::model::PolicyId;
    use runner_manager_domain::store::SqliteStore;
    use runner_manager_github::jit::JitRegistration;
    use runner_manager_github::rest::RefreshState;
    use runner_manager_testkit::clock::FakeClock;
    use runner_manager_testkit::fixtures;

    #[derive(Debug)]
    struct RecoveryGithub {
        expected: ScaleTarget,
    }

    impl LifecycleGithub for RecoveryGithub {
        fn register<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            _target: &'life1 ScaleTarget,
            _request: &'life2 JitRunnerRequest,
            _cancel: &'life3 CancelToken,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<JitRegistration, JitRequestFailure>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { panic!("startup recovery must not register a runner") })
        }

        fn observe<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            target: &'life1 ScaleTarget,
            _attempt: AttemptId,
            _cancel: &'life2 CancelToken,
        ) -> Pin<Box<dyn Future<Output = LifecycleGithubObservation> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            assert_eq!(
                target, &self.expected,
                "a target launcher observed another target's startup attempt"
            );
            Box::pin(std::future::ready(LifecycleGithubObservation::registered(
                73, false,
            )))
        }

        fn deregister<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            target: &'life1 ScaleTarget,
            _runner_id: u64,
            _cancel: &'life2 CancelToken,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            assert_eq!(
                target, &self.expected,
                "a target launcher deregistered another target's runner"
            );
            Box::pin(std::future::ready(true))
        }
    }

    #[derive(Debug)]
    struct UnusedPackages;

    impl RuntimePackages for UnusedPackages {
        fn materialize<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _attempt: &'life1 RunnerAttempt,
        ) -> Pin<Box<dyn Future<Output = Result<RunnerVersion, FailureReason>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { panic!("startup recovery must not materialize a package") })
        }

        fn release(&self, _attempt: AttemptId) -> Result<(), FailureReason> {
            Ok(())
        }

        fn prune_obsolete_guarded(
            &self,
            _authority: PruneAuthority<'_>,
            _current: &RunnerVersion,
            _attempts: &[RunnerAttempt],
        ) -> Result<(), FailureReason> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FakeTarget {
        policy: ScalePolicy,
        reports: VecDeque<ReconcileReport>,
        calls: Arc<AtomicUsize>,
        active: u16,
        draining: bool,
        busy_was_terminated: Arc<AtomicUsize>,
        /// Models a target GitHub could not be read: `reconcile` contributes no
        /// allocation for it, so `active_owned` can only answer "unknown".
        unreadable: bool,
    }

    impl FakeTarget {
        fn repeating(policy: ScalePolicy, report: ReconcileReport) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    policy,
                    reports: VecDeque::from([report]),
                    calls: Arc::clone(&calls),
                    active: 0,
                    draining: false,
                    busy_was_terminated: Arc::new(AtomicUsize::new(0)),
                    unreadable: false,
                },
                calls,
            )
        }

        fn busy_then_finished(policy: ScalePolicy) -> Self {
            Self {
                policy,
                reports: VecDeque::new(),
                calls: Arc::new(AtomicUsize::new(0)),
                active: 1,
                draining: false,
                busy_was_terminated: Arc::new(AtomicUsize::new(0)),
                unreadable: false,
            }
        }

        /// A target that never reports a runner count, because GitHub never
        /// answers for it.
        fn never_readable(policy: ScalePolicy) -> Self {
            Self {
                policy,
                reports: VecDeque::new(),
                calls: Arc::new(AtomicUsize::new(0)),
                active: 1,
                draining: false,
                busy_was_terminated: Arc::new(AtomicUsize::new(0)),
                unreadable: true,
            }
        }
    }

    impl TargetReconciler for FakeTarget {
        fn policies(&self) -> &[ScalePolicy] {
            std::slice::from_ref(&self.policy)
        }

        fn begin_drain(&mut self) {
            self.draining = true;
            begin_drain(std::slice::from_mut(&mut self.policy));
        }

        fn reconcile(&mut self) -> Pin<Box<dyn Future<Output = ReconcileReport> + Send + '_>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.draining && self.active > 0 {
                // The first drain pass supervises the busy child without any
                // termination action. The next pass observes its ordinary
                // completion and permits daemon exit.
                if self.calls.load(Ordering::SeqCst) >= 3 {
                    self.active = 0;
                }
            }
            let report = self.reports.front().cloned().unwrap_or_else(|| {
                let mut report = ReconcileReport::default();
                report.next_poll.delay = Duration::from_secs(1);
                report
            });
            Box::pin(std::future::ready(report))
        }

        fn active_owned(&self, _report: &ReconcileReport) -> Option<u16> {
            if self.unreadable {
                return None;
            }
            Some(self.active)
        }

        /// Deliberately answers even when `unreadable`: that is the whole point
        /// of the local count, and a fake that hid it could not show the
        /// difference the upgrade drain depends on.
        fn local_active(&self) -> Option<u16> {
            Some(self.active)
        }
    }

    /// An upgrade signal that never fires, for the tests that are about
    /// shutdown.
    fn never_upgraded() -> tokio::sync::watch::Receiver<bool> {
        let (sender, receiver) = tokio::sync::watch::channel(false);
        // Kept alive for the receiver's lifetime; a dropped sender would make
        // `changed()` resolve immediately and read as an upgrade.
        Box::leak(Box::new(sender));
        receiver
    }

    #[tokio::test(start_paused = true)]
    async fn an_upgrade_waits_for_a_running_job_however_long_it_takes() {
        // The promise this feature makes: a new binary never interrupts work.
        // `busy_then_finished` holds one runner for the first two passes.
        let target = FakeTarget::busy_then_finished(
            fixtures::policy()
                .repository("acme/repo")
                .autoscale("home", 1)
                .active()
                .build(),
        );
        let terminations = Arc::clone(&target.busy_was_terminated);
        let contacts = Arc::new(CountingContacts::default());
        let (stop, _) = tokio::sync::watch::channel(false);
        let (upgrade, _) = tokio::sync::watch::channel(false);
        let daemon = tokio::spawn(run_target_loop(
            target,
            stop.subscribe(),
            upgrade.subscribe(),
            contacts as Arc<dyn ContactRecorder>,
        ));

        tokio::task::yield_now().await;
        upgrade.send(true).unwrap();

        // Far past the shutdown deadline, which must not apply here: an upgrade
        // that gave up after a minute would cut the job it exists to protect.
        for _ in 0..DRAIN_DEADLINE.as_secs() {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        // The fake releases its runner on the third pass, and only then does
        // the loop end.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        tokio::time::timeout(Duration::from_secs(1), daemon)
            .await
            .expect("the upgrade drain ends once the job is done")
            .unwrap()
            .unwrap();
        assert_eq!(
            terminations.load(Ordering::SeqCst),
            0,
            "an upgrade must never terminate a running job"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_upgrade_completes_even_when_github_cannot_be_read() {
        // The reason the upgrade drain counts locally. `never_readable` answers
        // `None` from `active_owned` forever -- the revoked-credential state --
        // while its local count still falls to zero. Waiting on the former
        // would mean the machine that most needs a new binary never gets one.
        let mut target = FakeTarget::never_readable(
            fixtures::policy()
                .repository("acme/repo")
                .autoscale("home", 1)
                .active()
                .build(),
        );
        target.active = 0;
        let contacts = Arc::new(CountingContacts::default());
        let (stop, _) = tokio::sync::watch::channel(false);
        let (upgrade, _) = tokio::sync::watch::channel(false);
        let daemon = tokio::spawn(run_target_loop(
            target,
            stop.subscribe(),
            upgrade.subscribe(),
            contacts as Arc<dyn ContactRecorder>,
        ));

        tokio::task::yield_now().await;
        upgrade.send(true).unwrap();
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        tokio::time::timeout(Duration::from_secs(1), daemon)
            .await
            .expect("an unreadable target must not block an upgrade")
            .unwrap()
            .unwrap();
    }

    /// A rewrite of the *same* version is not an upgrade: restarting for it
    /// would interrupt runners to change nothing.
    #[test]
    fn the_running_version_is_not_an_upgrade_of_itself() {
        let own = std::env::current_exe().expect("the test binary's own path");
        assert!(
            BinaryStamp::of(&own).is_some(),
            "a running binary must be stat-able"
        );
        assert!(
            BinaryStamp::of(std::path::Path::new("no-such-binary")).is_none(),
            "a missing file has no stamp, and is not mistaken for a new one"
        );
        assert!(
            upgraded_version(std::path::Path::new("no-such-binary")).is_none(),
            "a path that cannot be executed is never reported as an upgrade"
        );
    }

    #[derive(Default)]
    struct CountingContacts(AtomicUsize);

    impl ContactRecorder for CountingContacts {
        fn record(&self) -> Result<(), CliError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn a_second_daemon_names_the_holder_and_uses_the_conflict_exit_class() {
        let temporary = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(temporary.path()), &mut Vec::new()).unwrap();
        let held = acquire_instance(&context).expect("first daemon acquires the lock");
        let error = acquire_instance(&context).expect_err("second daemon must be refused");
        assert_eq!(error.class(), Failure::Conflict);
        assert!(error.message().contains(&std::process::id().to_string()));
        drop(held);
        acquire_instance(&context).expect("dropping the daemon releases the lock");
    }

    #[test]
    fn only_active_autoscale_policies_are_loaded_in_stable_target_order() {
        let active_z = fixtures::policy()
            .repository("zeta/repo")
            .autoscale("home", 1)
            .active()
            .build();
        let active_a = fixtures::policy()
            .repository("alpha/repo")
            .autoscale("home", 1)
            .active()
            .build();
        let pending = fixtures::policy()
            .repository("pending/repo")
            .autoscale("home", 1)
            .build();
        let monitor = fixtures::policy()
            .repository("monitor/repo")
            .monitor_only()
            .active()
            .build();
        let mut draining = fixtures::policy()
            .repository("draining/repo")
            .autoscale("home", 1)
            .active()
            .build();
        draining.request_disable().unwrap();
        let mut disabled = draining.clone();
        disabled.drain_completed(0).unwrap();

        let active_a_second = fixtures::policy()
            .repository("alpha/repo")
            .autoscale("home", 1)
            .active()
            .build();
        let selected = active_autoscale_targets(vec![
            active_z,
            pending,
            disabled,
            monitor,
            active_a,
            draining,
            active_a_second,
        ]);
        let targets: Vec<_> = selected
            .iter()
            .map(|policies| policies[0].target.to_string())
            .collect();
        assert_eq!(targets, ["alpha/repo", "zeta/repo"]);
        assert_eq!(selected[0].len(), 2, "same-target policies share one loop");
        assert!(
            selected
                .iter()
                .flatten()
                .all(ScalePolicy::may_start_runners)
        );
    }

    #[tokio::test]
    async fn startup_recovery_keeps_each_targets_replacement_intent_in_its_launcher() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let policy_a = fixtures::policy()
            .id(PolicyId::from_u128(1))
            .repository("acme/alpha")
            .autoscale("home", 1)
            .active()
            .build();
        let policy_b = fixtures::policy()
            .id(PolicyId::from_u128(2))
            .repository("acme/beta")
            .autoscale("home", 1)
            .active()
            .build();
        store.insert_policy(&policy_a).unwrap();
        store.insert_policy(&policy_b).unwrap();

        let attempt_for = |id: u128, policy: &ScalePolicy, directory: &str| {
            let runtime = temporary.path().join(directory);
            std::fs::create_dir_all(&runtime).unwrap();
            fixtures::attempt()
                .id(AttemptId::from_u128(id))
                .policy_id(policy.id)
                .runtime_path(runtime.to_string_lossy())
                .build()
        };
        let attempt_a = attempt_for(11, &policy_a, "alpha");
        let attempt_b = attempt_for(22, &policy_b, "beta");
        store.record_attempt(&attempt_a).unwrap();
        store.record_attempt(&attempt_b).unwrap();

        let build_launcher = |policy: &ScalePolicy| {
            let scoped = Arc::new(TargetRecoveryStore::new(
                Arc::clone(&store) as Arc<dyn Store>,
                std::slice::from_ref(policy),
            ));
            let launcher = LifecycleLauncher::new(
                policy.to_persisted().host_id,
                temporary.path().join("runtime"),
                temporary.path().join("logs"),
                1,
                runner_manager_domain::attempt::RecoveryTimeouts::provisional(),
                RetryPolicy::bounded(1, Duration::from_millis(1), Duration::from_millis(1)),
                LifecyclePorts {
                    store: Arc::clone(&scoped) as Arc<dyn Store>,
                    github: Arc::new(RecoveryGithub {
                        expected: policy.target.clone(),
                    }),
                    packages: Arc::new(UnusedPackages),
                    processes: Arc::new(NativeProcesses::new()),
                    clock: Arc::new(FakeClock::default()),
                    demand: Arc::new(PersistentDemand),
                    delay: Arc::new(TokioRetryDelay),
                    events: Arc::new(NoAttemptEvents),
                    reconcile_events: Arc::new(runner_manager_agent::reconcile::EventLog::new()),
                },
            );
            (launcher, scoped)
        };
        let (launcher_a, scoped_a) = build_launcher(&policy_a);
        let (launcher_b, scoped_b) = build_launcher(&policy_b);

        let placed_a = launcher_a
            .recover_startup(std::slice::from_ref(&policy_a))
            .await
            .unwrap();
        scoped_a.finish_recovery();
        let placed_b = launcher_b
            .recover_startup(std::slice::from_ref(&policy_b))
            .await
            .unwrap();
        scoped_b.finish_recovery();
        assert_eq!(placed_a.len(), 1);
        assert_eq!(placed_a[0].policy, policy_a.id);
        assert_eq!(placed_a[0].previous_attempt, attempt_a.id);
        assert_eq!(placed_b.len(), 1);
        assert_eq!(placed_b[0].policy, policy_b.id);
        assert_eq!(placed_b[0].previous_attempt, attempt_b.id);

        let consumed_a = launcher_a.supervise(&policy_a).await.unwrap();
        let consumed_b = launcher_b.supervise(&policy_b).await.unwrap();
        assert_eq!(consumed_a, placed_a);
        assert_eq!(consumed_b, placed_b);
        assert!(launcher_a.supervise(&policy_a).await.unwrap().is_empty());
        assert!(launcher_b.supervise(&policy_b).await.unwrap().is_empty());
        assert_eq!(scoped_a.attempts().unwrap().len(), 2);
        assert_eq!(scoped_b.attempts().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_offline_target_neither_suppresses_contacts_nor_backs_off_a_healthy_target() {
        let policy = |repository| {
            fixtures::policy()
                .repository(repository)
                .autoscale("home", 1)
                .active()
                .build()
        };
        let healthy_report = ReconcileReport {
            next_poll: runner_manager_agent::reconcile::NextPoll {
                delay: Duration::from_secs(1),
                ..Default::default()
            },
            ..Default::default()
        };
        let offline_report = ReconcileReport {
            failure: Some(RefreshState::Offline),
            next_poll: runner_manager_agent::reconcile::NextPoll {
                delay: Duration::from_secs(60),
                ..Default::default()
            },
            ..Default::default()
        };
        let (healthy, healthy_calls) =
            FakeTarget::repeating(policy("acme/healthy"), healthy_report);
        let (offline, offline_calls) =
            FakeTarget::repeating(policy("acme/offline"), offline_report);
        let contacts = Arc::new(CountingContacts::default());
        let (stop, _) = tokio::sync::watch::channel(false);
        let healthy_loop = tokio::spawn(run_target_loop(
            healthy,
            stop.subscribe(),
            never_upgraded(),
            Arc::clone(&contacts) as Arc<dyn ContactRecorder>,
        ));
        let offline_loop = tokio::spawn(run_target_loop(
            offline,
            stop.subscribe(),
            never_upgraded(),
            Arc::clone(&contacts) as Arc<dyn ContactRecorder>,
        ));

        tokio::task::yield_now().await;
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        assert!(healthy_calls.load(Ordering::SeqCst) >= 3);
        assert_eq!(offline_calls.load(Ordering::SeqCst), 1);
        assert!(contacts.0.load(Ordering::SeqCst) >= 3);

        stop.send(true).unwrap();
        tokio::time::advance(Duration::from_secs(60)).await;
        healthy_loop.await.unwrap().unwrap();
        offline_loop.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_drain_whose_target_never_reports_a_count_still_ends() {
        // The state a revoked credential puts every target into: `reconcile`
        // contributes no allocation, so `active_owned` answers `None` and the
        // graceful exit's `== Some(0)` is false on every pass, forever. Before
        // the deadline this loop never returned, and the service could only be
        // killed.
        let target = FakeTarget::never_readable(
            fixtures::policy()
                .repository("acme/repo")
                .autoscale("home", 1)
                .active()
                .build(),
        );
        let calls = Arc::clone(&target.calls);
        let terminations = Arc::clone(&target.busy_was_terminated);
        let contacts = Arc::new(CountingContacts::default());
        let (stop, _) = tokio::sync::watch::channel(false);
        let daemon = tokio::spawn(run_target_loop(
            target,
            stop.subscribe(),
            never_upgraded(),
            contacts as Arc<dyn ContactRecorder>,
        ));

        tokio::task::yield_now().await;
        stop.send(true).unwrap();

        // Well inside the deadline the daemon is still draining, which is what
        // keeps this from passing on a loop that simply exits at once.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        assert!(
            !daemon.is_finished(),
            "the drain gave up before its deadline"
        );

        // Past it, it stops anyway.
        for _ in 0..DRAIN_DEADLINE.as_secs() {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        tokio::time::timeout(Duration::from_secs(1), daemon)
            .await
            .expect("an unreadable target must not hold the daemon open forever")
            .unwrap()
            .unwrap();
        assert!(calls.load(Ordering::SeqCst) >= 2, "the drain never polled");
        assert_eq!(
            terminations.load(Ordering::SeqCst),
            0,
            "the deadline must not terminate a runner; startup recovery adopts it"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_loop_supervises_a_busy_child_to_completion_without_terminating_it() {
        let target = FakeTarget::busy_then_finished(
            fixtures::policy()
                .repository("acme/repo")
                .autoscale("home", 1)
                .active()
                .build(),
        );
        let calls = Arc::clone(&target.calls);
        let terminations = Arc::clone(&target.busy_was_terminated);
        let contacts = Arc::new(CountingContacts::default());
        let (stop, _) = tokio::sync::watch::channel(false);
        let daemon = tokio::spawn(run_target_loop(
            target,
            stop.subscribe(),
            never_upgraded(),
            contacts as Arc<dyn ContactRecorder>,
        ));

        tokio::task::yield_now().await;
        stop.send(true).unwrap();
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        tokio::time::timeout(Duration::from_secs(1), daemon)
            .await
            .expect("the daemon exits after supervised completion")
            .unwrap()
            .unwrap();
        assert!(
            calls.load(Ordering::SeqCst) >= 3,
            "shutdown skipped supervision"
        );
        assert_eq!(
            terminations.load(Ordering::SeqCst),
            0,
            "busy child was terminated"
        );
    }
}
