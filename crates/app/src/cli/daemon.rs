// owner: f3-cli-daemon-service

//! The foreground agent and its graceful drain boundary.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
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
    FileAllocationLock, GatewayDemand, RandomJitter, Reconciler, ReconcilerPorts,
    RepositoryDirectory, TeeEvents, TracingEvents,
};
use runner_manager_domain::attempt::FailureReason;
use runner_manager_domain::model::{AttemptId, Clock, Org, OwnerRepo, ScaleTarget};
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
    let policies = store.policies().map_err(local_store_failure)?;
    let failed = write_failed("the daemon state");

    writeln!(out, "daemon running (pid {})", std::process::id()).map_err(failed)?;

    // A host with no policies owns no GitHub work. It still holds the lock and
    // behaves as a real daemon, but it neither demands a credential nor opens a
    // network connection while waiting to be configured or stopped.
    if policies.is_empty() {
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

    let package_target = policies[0].target.clone();
    let catalog = Arc::new(GatewayCatalog::new(
        RestInventory::new(Arc::clone(&client), Arc::clone(&clock)),
        package_target,
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
    let paths = Arc::new(context.paths().clone());
    let events: Arc<dyn runner_manager_agent::reconcile::EventSink> = Arc::new(TeeEvents(
        Arc::new(TracingEvents),
        Arc::new(runner_manager_agent::reconcile::EventLog::new()),
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
            github: lifecycle_github,
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
                format!("startup recovery did not complete: {source}"),
            )
        })?;

    let demand_cancel = CancelToken::new();
    let demand = Arc::new(GatewayDemand::new(
        RestDemand::new(client, Arc::clone(&clock)),
        demand_cancel.clone(),
    ));
    let mut reconciler = Reconciler::new(
        host,
        ReconcilerPorts {
            demand,
            launcher,
            lock: Arc::new(FileAllocationLock::new(paths)),
            directory,
            clock: Arc::clone(&clock),
            jitter: Arc::new(RandomJitter),
            events,
        },
    );

    let mut stopping = Box::pin(shutdown_signal());
    let mut draining = false;
    let mut drain_policies = policies.clone();
    loop {
        let active = store
            .attempts()
            .map_err(local_store_failure)?
            .into_iter()
            .filter(|attempt| attempt.counts_against_capacity())
            .count();
        if draining && active == 0 {
            // One last pass removes terminal runtime directories.
            let _ = reconciler.reconcile(&drain_policies).await;
            writeln!(out, "daemon stopped; no busy runner was terminated").map_err(failed)?;
            return Ok(());
        }

        let selected = if draining { &drain_policies } else { &policies };
        let report = if draining {
            reconciler.reconcile(selected).await
        } else {
            tokio::select! {
                signal = &mut stopping => {
                    signal.map_err(signal_failure)?;
                    demand_cancel.cancel();
                    begin_drain(&mut drain_policies);
                    draining = true;
                    continue;
                }
                report = reconciler.reconcile(selected) => report,
            }
        };
        if !draining && !selected.is_empty() && report.failure.is_none() {
            record_github_contact(context.paths(), clock.now()).map_err(|source| {
                CliError::new(
                    Failure::LocalState,
                    format!("cannot record the last successful GitHub contact: {source}"),
                )
            })?;
        }

        if draining {
            tokio::time::sleep(report.next_poll.delay).await;
        } else {
            tokio::select! {
                signal = &mut stopping => {
                    signal.map_err(signal_failure)?;
                    demand_cancel.cancel();
                    begin_drain(&mut drain_policies);
                    draining = true;
                }
                () = tokio::time::sleep(report.next_poll.delay) => {}
            }
        }
    }
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
    use runner_manager_testkit::fixtures;

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
    fn shutdown_drain_stops_new_launches_without_having_process_termination_capability() {
        let mut policies = [fixtures::policy()
            .repository("acme/repo")
            .autoscale("home", 1)
            .active()
            .build()];
        assert!(policies[0].may_start_runners());

        begin_drain(&mut policies);

        assert!(!policies[0].may_start_runners());
        assert_eq!(
            policies[0].state(),
            runner_manager_domain::policy::PolicyState::Draining
        );
        // `begin_drain` accepts only policy records. It has no launcher,
        // process supervisor, attempt, or PID with which it could terminate a
        // busy runner; ordinary reconciliation supervises it to completion.
    }
}
