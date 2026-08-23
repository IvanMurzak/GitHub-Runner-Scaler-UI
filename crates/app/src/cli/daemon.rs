// owner: f3-cli-daemon-service

//! The foreground agent and its graceful drain boundary.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
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
use runner_manager_domain::attempt::FailureReason;
use runner_manager_domain::model::{AttemptId, Clock, Org, OwnerRepo, ScaleTarget};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::Store;
use runner_manager_github::demand::RestDemand;
use runner_manager_github::jit::{JitError, JitGateway, JitRunnerRequest, RestJit};
use runner_manager_github::rest::{CancelToken, InventoryError, InventoryGateway, RestInventory};
use runner_manager_github::{AppRegistration, AuthenticatedClient, GithubError, UserAccessToken};
use runner_manager_platform::lock::{HostLock, LockError, LockKind};
use runner_manager_platform::secrets::SecretStore as _;
use runner_manager_platform::service::record_github_contact;

use super::{CliError, Context, DaemonCommand, Failure, write_failed};

pub fn dispatch(
    context: &Context,
    command: &DaemonCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        DaemonCommand::Run(_) => {
            let runtime = super::runtime()?;
            runtime.block_on(run(context, out))
        }
    }
}

async fn run(context: &Context, out: &mut dyn Write) -> Result<(), CliError> {
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
        shutdown_signal().await.map_err(signal_failure)?;
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
    let recovery_policies: Vec<_> = targets.iter().flatten().cloned().collect();
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
        let launcher = Arc::new(LifecycleLauncher::new(
            host.id,
            context.paths().runtime_dir(),
            context.paths().logs_dir(),
            1,
            runner_manager_domain::attempt::RecoveryTimeouts::provisional(),
            RetryPolicy::bounded(3, Duration::from_secs(2), Duration::from_secs(30)),
            LifecyclePorts {
                store: Arc::clone(&store) as Arc<dyn Store>,
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
            // Startup recovery is journal-wide. Each target owns its launcher
            // for package acquisition, but unknown live policies make recovery
            // fail closed, so every launcher proves the same active policy set.
            .recover_startup(&recovery_policies)
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
        let cancel = CancelToken::new();
        let demand = Arc::new(GatewayDemand::new(
            RestDemand::new(Arc::clone(&client), Arc::clone(&clock)),
            cancel.clone(),
        ));
        managed_targets.push(ManagedTarget {
            policies,
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
            Arc::clone(&contacts),
        ));
    }

    let early = tokio::select! {
        signal = shutdown_signal() => {
            signal.map_err(signal_failure)?;
            None
        }
        result = loops.join_next() => result,
    };
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
}

struct ManagedTarget {
    policies: Vec<ScalePolicy>,
    reconciler: Reconciler,
    cancel: CancelToken,
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

async fn run_target_loop<T: TargetReconciler>(
    mut target: T,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    contacts: Arc<dyn ContactRecorder>,
) -> Result<(), CliError> {
    let mut draining = *shutdown.borrow();
    if draining {
        target.begin_drain();
    }
    loop {
        let report = target.reconcile().await;
        if !draining && report.failure.is_none() {
            contacts.record()?;
        }
        if draining && target.active_owned(&report) == Some(0) {
            return Ok(());
        }
        tokio::select! {
            () = tokio::time::sleep(report.next_poll.delay) => {}
            changed = shutdown.changed(), if !draining => {
                if changed.is_err() || *shutdown.borrow() {
                    target.begin_drain();
                    draining = true;
                }
            }
        }
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

    use runner_manager_github::rest::RefreshState;
    use runner_manager_testkit::fixtures;

    #[derive(Debug)]
    struct FakeTarget {
        policy: ScalePolicy,
        reports: VecDeque<ReconcileReport>,
        calls: Arc<AtomicUsize>,
        active: u16,
        draining: bool,
        busy_was_terminated: Arc<AtomicUsize>,
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
            Some(self.active)
        }
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
            Arc::clone(&contacts) as Arc<dyn ContactRecorder>,
        ));
        let offline_loop = tokio::spawn(run_target_loop(
            offline,
            stop.subscribe(),
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
