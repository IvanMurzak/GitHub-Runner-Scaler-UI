//! The reconciliation sweep (stage 2): the coordinator polls GitHub's queue
//! for its hosts, so they can stop polling it themselves.
//!
//! Webhooks can be lost, delayed, or arrive while no host was connected. Every
//! [`SweepConfig::interval`] the coordinator lists the queued jobs of every
//! repository a connected host serves, through its own GitHub App, and wakes
//! the hosts for any queued job that no wake was sent for within the last
//! interval. A host whose target is covered (see [`Coverage`]) then polls
//! GitHub only at its long safety interval.
//!
//! # Cost
//!
//! The listings are `runner-manager-github`'s [`RestDemand`] reads: two
//! conditional run listings per repository, plus one job listing per active
//! run, each answered `304` (free against the hourly quota) while nothing
//! changes. One reader per installation, so each installation's rate-limit
//! bucket and quiet period are its own; a rate-limited installation is left
//! alone for the rest of the sweep, and its reader withholds every request
//! until GitHub's wait is over.
//!
//! [`RestDemand`]: runner_manager_github::demand::RestDemand

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use runner_manager_domain::coordinator_protocol::{TargetRef, WakeReason};
use runner_manager_domain::model::{Label, OwnerRepo};
use runner_manager_github::demand::DemandGateway;
use runner_manager_github::rest::{ActivityScope, CancelToken, InventoryError};

use crate::github_app::{AppError, GithubApp};
use crate::placement::{Placement, SweptQueue};
use crate::registry::{Coverage, Inventory, Registry, is_pool_job};
use crate::stats::JobIdentity;

/// The shortest sweep interval accepted.
pub const MIN_INTERVAL: Duration = Duration::from_secs(30);

/// How often the installations and their repositories are listed again.
pub const INVENTORY_EVERY: Duration = Duration::from_secs(10 * 60);

/// The least time between two inventories asked for by events (a host
/// advertising a target not covered, a webhook for a repository not known).
pub const INVENTORY_DEBOUNCE: Duration = Duration::from_secs(30);

/// The delivery id a sweep's wakes carry.
pub const SWEEP_DELIVERY: &str = "reconcile";

/// One installation, as the sweep reads it.
pub struct Reachable {
    pub id: u64,
    pub account: String,
    /// The installation covers every repository of `account`.
    pub all_repositories: bool,
    pub repositories: Vec<OwnerRepo>,
    pub demand: Arc<dyn DemandGateway>,
}

/// Where the sweep's installations come from: the GitHub App, or a test's
/// fixed list.
#[async_trait::async_trait]
pub trait Reach: Send + Sync {
    /// Brings the installations up to date: tokens always, the inventory
    /// when `inventory` is set.
    ///
    /// # Errors
    /// The App's; the sweep then works with what it had.
    async fn refresh(&mut self, inventory: bool) -> Result<(), AppError>;
    fn installations(&self) -> Vec<Reachable>;
    /// The installation's credential stopped working.
    fn forget(&mut self, id: u64);
}

#[async_trait::async_trait]
impl Reach for GithubApp {
    async fn refresh(&mut self, inventory: bool) -> Result<(), AppError> {
        if inventory {
            self.refresh_inventory().await
        } else {
            self.refresh_tokens().await
        }
    }

    fn installations(&self) -> Vec<Reachable> {
        self.installations()
            .values()
            .map(|installation| Reachable {
                id: installation.id,
                account: installation.account.clone(),
                all_repositories: installation.all_repositories,
                repositories: installation.repositories.clone(),
                demand: installation.demand(),
            })
            .collect()
    }

    fn forget(&mut self, id: u64) {
        GithubApp::forget(self, id);
    }
}

/// What one sweep did, for its log line and for tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Repositories whose queue was read.
    pub repositories: u32,
    /// Queued jobs seen.
    pub queued: u32,
    /// Of those, jobs a wake was already sent for within the interval.
    pub already_woken: u32,
    /// Wakes sent (one per host per job).
    pub wakes: u32,
    /// Installations left alone for the rest of the sweep: rate limited.
    pub rate_limited: u32,
    /// Repositories that could not be read for another reason.
    pub failed: u32,
}

/// The sweep and its state.
pub struct Sweeper {
    interval: Duration,
    reach: Box<dyn Reach>,
    registry: Arc<Registry>,
    inventory_at: Option<Instant>,
    /// When the inventory was last asked for, whether or not it answered.
    inventory_tried_at: Option<tokio::time::Instant>,
    /// Stage 3: told how many pool jobs each repository read has queued.
    placement: Option<Arc<Placement>>,
}

impl Sweeper {
    /// Sweeps every `interval`; wakes go through `registry`, whose wake log
    /// the webhook shares.
    #[must_use]
    pub fn new(interval: Duration, reach: Box<dyn Reach>, registry: Arc<Registry>) -> Self {
        Self {
            interval,
            reach,
            registry,
            inventory_at: None,
            inventory_tried_at: None,
            placement: None,
        }
    }

    /// Also counts every read repository's queued pool jobs for `placement`,
    /// which places a launch for any no lease covers yet.
    #[must_use]
    pub fn with_placement(mut self, placement: Arc<Placement>) -> Self {
        self.placement = Some(placement);
        self
    }

    /// Sweeps every interval, and at once (at most every
    /// [`INVENTORY_DEBOUNCE`]) with a fresh inventory when the registry says
    /// the one it has may be out of date. Forever.
    pub async fn run(mut self) {
        let registry = Arc::clone(&self.registry);
        let mut ticks = tokio::time::interval(self.interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticks.tick() => {}
                () = registry.inventory_wanted() => {
                    if let Some(tried) = self.inventory_tried_at {
                        tokio::time::sleep_until(tried + INVENTORY_DEBOUNCE).await;
                    }
                    self.inventory_at = None;
                }
            }
            let report = self.sweep_once().await;
            tracing::info!(
                repositories = report.repositories,
                queued = report.queued,
                already_woken = report.already_woken,
                wakes = report.wakes,
                rate_limited = report.rate_limited,
                failed = report.failed,
                "reconciliation sweep"
            );
        }
    }

    /// One sweep: refresh the App's view, read every served repository's
    /// queue, wake for what no wake was sent for, and publish as covered only
    /// what the sweep could read.
    pub async fn sweep_once(&mut self) -> SweepReport {
        let now = Instant::now();
        let inventory = self
            .inventory_at
            .is_none_or(|at| now.saturating_duration_since(at) >= INVENTORY_EVERY);
        match self.reach.refresh(inventory).await {
            Ok(()) if inventory => self.inventory_at = Some(now),
            Ok(()) => {}
            Err(error) => {
                tracing::warn!(%error, "the GitHub App could not be refreshed; sweeping with what is known");
            }
        }
        if inventory {
            self.inventory_tried_at = Some(tokio::time::Instant::now());
        }
        let mut installations = self.reach.installations();
        self.registry.set_inventory(Inventory {
            repositories: installations
                .iter()
                .flat_map(|installation| &installation.repositories)
                .map(|repository| repository.to_string().to_ascii_lowercase())
                .collect(),
            accounts: installations
                .iter()
                .map(|installation| installation.account.to_ascii_lowercase())
                .collect(),
        });
        let advertised = self.registry.advertised();
        let mut report = SweepReport::default();
        // What this sweep could not read is not covered: a host relies on the
        // sweep only where the sweep actually reads its queue (a missing
        // Actions permission, a rate limit, a refused token).
        let mut unread = BTreeSet::new();
        let mut failed = BTreeSet::new();
        for installation in &installations {
            let repositories = served(installation, &advertised);
            for repository in repositories {
                match self.read(installation, &repository, &mut report).await {
                    Ok(()) => {}
                    Err(InventoryError::RateLimited(_)) => {
                        report.rate_limited += 1;
                        unread.insert(installation.id);
                        break;
                    }
                    Err(InventoryError::Github(error)) if error.is_authentication() => {
                        tracing::warn!(
                            installation = installation.id,
                            "an installation's token was refused; it is minted again at the next \
                             inventory"
                        );
                        self.reach.forget(installation.id);
                        self.inventory_at = None;
                        report.failed += 1;
                        unread.insert(installation.id);
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(
                            installation = installation.id,
                            %error,
                            "a repository's queue could not be read"
                        );
                        report.failed += 1;
                        failed.insert(repository);
                    }
                }
            }
        }
        installations.retain(|installation| !unread.contains(&installation.id));
        for installation in &mut installations {
            let before = installation.repositories.len();
            installation
                .repositories
                .retain(|repository| !failed.contains(repository));
            // An account is covered whole only when every repository of it
            // the hosts serve was read.
            if installation.repositories.len() != before {
                installation.all_repositories = false;
            }
        }
        self.registry
            .set_coverage(coverage(&installations, self.interval));
        report
    }

    async fn read(
        &self,
        installation: &Reachable,
        repository: &OwnerRepo,
        report: &mut SweepReport,
    ) -> Result<(), InventoryError> {
        let read_at = Instant::now();
        let demand = installation
            .demand
            .queued_demand(
                &ActivityScope::repository(repository.clone()),
                &CancelToken::new(),
            )
            .await?;
        report.repositories += 1;
        let name = repository.to_string();
        let mut pool: HashMap<BTreeSet<Label>, SweptQueue> = HashMap::new();
        for (job, identity) in demand.identified_jobs_for(repository) {
            let Ok(required) = job.required_labels() else {
                continue;
            };
            report.queued += 1;
            if is_pool_job(&required) {
                let queue = pool.entry(required.iter().cloned().collect()).or_default();
                match identity.and_then(|identity| Some((identity.id?, identity))) {
                    Some((id, identity)) => queue.jobs.push((
                        id,
                        JobIdentity::new(&name, identity.name.as_deref())
                            .map(|identity| identity.key()),
                    )),
                    None => queue.unnamed += 1,
                }
            }
            if self
                .registry
                .wakes()
                .recent(&name, &required, self.interval, Instant::now())
            {
                report.already_woken += 1;
                continue;
            }
            let woken =
                self.registry
                    .wake_for(&name, &required, WakeReason::Reconcile, SWEEP_DELIVERY);
            report.wakes += u32::try_from(woken).unwrap_or(u32::MAX);
        }
        if let Some(placement) = &self.placement {
            let floor = demand.is_truncated(repository);
            for key in placement.swept(&name, &pool, read_at, floor) {
                placement.spawn_rebalance(key, Duration::ZERO);
            }
        }
        Ok(())
    }
}

/// What `installations` cover, swept every `interval`.
#[must_use]
pub fn coverage(installations: &[Reachable], interval: Duration) -> Coverage {
    Coverage {
        interval: Some(interval),
        repositories: installations
            .iter()
            .flat_map(|installation| &installation.repositories)
            .map(|repository| repository.to_string().to_ascii_lowercase())
            .collect(),
        accounts: installations
            .iter()
            .filter(|installation| installation.all_repositories)
            .map(|installation| installation.account.to_ascii_lowercase())
            .collect(),
    }
}

/// The repositories of `installation` some advertised target serves.
fn served(installation: &Reachable, advertised: &[TargetRef]) -> BTreeSet<OwnerRepo> {
    installation
        .repositories
        .iter()
        .filter(|repository| {
            let name = repository.to_string();
            advertised.iter().any(|target| target.covers(&name))
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use runner_manager_domain::coordinator_protocol::{
        Hello, HelloAck, PROTOCOL_VERSION, Profile, ServerMessage, Target, TargetScope, Wake,
    };
    use runner_manager_domain::model::Label;
    use runner_manager_domain::policy::RunsOn;
    use runner_manager_testkit::github::FakeGithub;
    use tokio::sync::mpsc;

    use super::*;
    use crate::registry::Outbound;

    /// Installation id, account, all repositories?, repositories, reader.
    type Installation = (u64, &'static str, bool, Vec<&'static str>, Arc<FakeGithub>);

    struct Fixed(Vec<Installation>);

    #[async_trait::async_trait]
    impl Reach for Fixed {
        async fn refresh(&mut self, _inventory: bool) -> Result<(), AppError> {
            Ok(())
        }

        fn installations(&self) -> Vec<Reachable> {
            self.0
                .iter()
                .map(|(id, account, all, repositories, fake)| Reachable {
                    id: *id,
                    account: (*account).to_string(),
                    all_repositories: *all,
                    repositories: repositories
                        .iter()
                        .map(|name| OwnerRepo::parse(name).expect("repo"))
                        .collect(),
                    demand: Arc::clone(fake) as Arc<dyn DemandGateway>,
                })
                .collect()
        }

        fn forget(&mut self, _id: u64) {}
    }

    fn job(labels: &[&str]) -> RunsOn {
        runner_manager_testkit::fixtures::queued_job(labels)
    }

    /// A reach whose inventory requests are counted, serving `reachable`.
    #[derive(Clone, Default)]
    struct Counting {
        inventories: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Reach for Counting {
        async fn refresh(&mut self, inventory: bool) -> Result<(), AppError> {
            if inventory {
                self.inventories
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        }

        fn installations(&self) -> Vec<Reachable> {
            Vec::new()
        }

        fn forget(&mut self, _id: u64) {}
    }

    /// A target nothing covers yet refreshes the inventory at once, not at
    /// the next 10-minute inventory; a burst is at most one per 30 seconds.
    #[tokio::test(start_paused = true)]
    async fn an_uncovered_target_refreshes_the_inventory_at_once_debounced() {
        let reach = Counting::default();
        let inventories = Arc::clone(&reach.inventories);
        let count = move || inventories.load(std::sync::atomic::Ordering::SeqCst);
        let registry = Arc::new(Registry::default());
        let sweeper = Sweeper::new(
            Duration::from_secs(3600),
            Box::new(reach),
            Arc::clone(&registry),
        );
        let sweep = tokio::spawn(sweeper.run());
        let settle = || async {
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
        };
        settle().await;
        assert_eq!(count(), 1, "the first sweep reads the inventory");

        // Within the debounce: held until 30 seconds after the last one.
        tokio::time::advance(Duration::from_secs(10)).await;
        let _rx = host(&registry, "h", TargetScope::Repo, "octo/new");
        settle().await;
        assert_eq!(count(), 1);
        tokio::time::advance(Duration::from_secs(19)).await;
        settle().await;
        assert_eq!(count(), 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(count(), 2, "read again 30 seconds after the last");

        // A webhook for a repository a host serves and the sweep does not
        // know asks again; one nobody serves does not.
        registry.repository_seen("octo/other");
        tokio::time::advance(Duration::from_secs(31)).await;
        settle().await;
        assert_eq!(count(), 2, "nobody serves it");
        registry.repository_seen("Octo/New");
        settle().await;
        assert_eq!(count(), 3);
        sweep.abort();

        // Listed but not covered (a repository the sweep cannot read): a
        // fresh inventory would change nothing, so none is asked for.
        registry.set_inventory(Inventory {
            repositories: BTreeSet::from(["octo/new".to_string()]),
            accounts: BTreeSet::new(),
        });
        registry.repository_seen("octo/new");
        let _again = host(&registry, "h2", TargetScope::Repo, "octo/new");
        assert!(
            tokio::time::timeout(Duration::from_secs(1), registry.inventory_wanted())
                .await
                .is_err()
        );
    }

    /// The sweep's job listing names its jobs, so a job only the sweep saw is
    /// weighed by its own statistics key.
    #[tokio::test]
    async fn the_sweep_carries_each_jobs_identity_to_placement() {
        use runner_manager_github::demand::{QueuedDemand, QueuedJobIdentity};

        #[derive(Debug)]
        struct Named(QueuedDemand);

        #[async_trait::async_trait]
        impl DemandGateway for Named {
            async fn queued_demand(
                &self,
                _scope: &ActivityScope,
                _cancel: &CancelToken,
            ) -> Result<QueuedDemand, InventoryError> {
                Ok(self.0.clone())
            }

            fn now(&self) -> runner_manager_domain::model::Timestamp {
                chrono::Utc::now()
            }
        }

        struct One(Arc<Named>);

        #[async_trait::async_trait]
        impl Reach for One {
            async fn refresh(&mut self, _inventory: bool) -> Result<(), AppError> {
                Ok(())
            }

            fn installations(&self) -> Vec<Reachable> {
                vec![Reachable {
                    id: 1,
                    account: "octo".into(),
                    all_repositories: false,
                    repositories: vec![OwnerRepo::parse("octo/app").expect("repo")],
                    demand: Arc::clone(&self.0) as Arc<dyn DemandGateway>,
                }]
            }

            fn forget(&mut self, _id: u64) {}
        }

        // As GitHub lists them for a workflow with a `run-name`: the same key
        // a webhook makes for this job, whatever the run's title.
        let repository = OwnerRepo::parse("octo/app").expect("repo");
        let demand = QueuedDemand::of(
            repository.clone(),
            [job(&["rm-pool-linux"]), job(&["rm-pool-linux"])],
        )
        .with_identities(
            repository,
            vec![
                QueuedJobIdentity {
                    id: Some(11),
                    name: Some("light".into()),
                },
                QueuedJobIdentity {
                    id: Some(12),
                    name: None,
                },
            ],
        );
        let registry = Arc::new(Registry::default());
        let _rx = host(&registry, "h", TargetScope::Repo, "octo/app");
        let placement = Arc::new(Placement::new(Arc::clone(&registry)));
        let mut sweeper = Sweeper::new(
            Duration::from_secs(120),
            Box::new(One(Arc::new(Named(demand)))),
            Arc::clone(&registry),
        )
        .with_placement(Arc::clone(&placement));
        sweeper.sweep_once().await;
        let key = crate::placement::JobKey::new(
            "octo/app",
            &[Label::new("rm-pool-linux").expect("label")],
        );
        assert_eq!(placement.counts(&key).0, 2);
        assert_eq!(
            placement.queued_job_keys(&key),
            (vec!["octo/app/light".to_string()], true),
            "named from the listing; the other has no job name, so no key"
        );
    }

    fn host(
        registry: &Registry,
        id: &str,
        scope: TargetScope,
        name: &str,
    ) -> mpsc::Receiver<Outbound> {
        let (tx, rx) = mpsc::channel(32);
        let connection = registry.register(id, PROTOCOL_VERSION, tx);
        registry.set_hello(
            id,
            connection,
            Hello {
                protocol_version: PROTOCOL_VERSION,
                host_id: id.into(),
                os: "linux".into(),
                arch: "x64".into(),
                cores: 4,
                ram_bytes: None,
                disk_free_bytes: None,
                targets: vec![Target {
                    scope,
                    name: name.into(),
                    profiles: vec![Profile {
                        name: "default".into(),
                        labels: vec!["self-hosted".into(), "linux".into()],
                        enabled: true,
                        warm: false,
                    }],
                }],
            },
        );
        rx
    }

    fn drain(rx: &mut mpsc::Receiver<Outbound>) -> (Vec<Wake>, Vec<HelloAck>) {
        let (mut wakes, mut acks) = (Vec::new(), Vec::new());
        while let Ok(Outbound::Send(message)) = rx.try_recv() {
            match message {
                ServerMessage::Wake(wake) => wakes.push(wake),
                ServerMessage::HelloAck(ack) => acks.push(ack),
                _ => {}
            }
        }
        (wakes, acks)
    }

    #[tokio::test]
    async fn the_sweep_wakes_only_for_jobs_no_wake_was_sent_for() {
        let fake = Arc::new(
            FakeGithub::new()
                .with_queued_jobs(
                    OwnerRepo::parse("octo/app").expect("repo"),
                    [job(&["self-hosted", "linux"]), job(&["windows"])],
                )
                .with_queued_jobs(
                    OwnerRepo::parse("octo/lib").expect("repo"),
                    [job(&["self-hosted", "linux"])],
                ),
        );
        let registry = Arc::new(Registry::default());
        let mut repo_host = host(&registry, "repo-host", TargetScope::Repo, "octo/app");
        let mut org_host = host(&registry, "org-host", TargetScope::Org, "octo");
        // The webhook already woke the hosts for octo/app's linux job.
        let linux = required(&["self-hosted", "linux"]);
        registry.wakes().record("Octo/App", &linux, Instant::now());

        let mut sweeper = Sweeper::new(
            Duration::from_secs(120),
            Box::new(Fixed(vec![(
                1,
                "octo",
                true,
                vec!["octo/app", "octo/lib", "octo/unserved-by-nobody"],
                Arc::clone(&fake),
            )])),
            Arc::clone(&registry),
        );
        let report = sweeper.sweep_once().await;
        assert_eq!(report.repositories, 3, "the org host serves all three");
        assert_eq!(
            report.queued, 3,
            "the windows job is matched by nobody but counted"
        );
        assert_eq!(report.already_woken, 1);
        // octo/lib's job wakes the org host only; the windows job nobody.
        assert_eq!(report.wakes, 1);

        let (repo_wakes, repo_acks) = drain(&mut repo_host);
        assert!(repo_wakes.is_empty(), "octo/app's job was already woken");
        assert_eq!(repo_acks.last().map(|ack| ack.covered.len()), Some(1));
        let (org_wakes, org_acks) = drain(&mut org_host);
        assert_eq!(org_wakes.len(), 1);
        assert_eq!(org_wakes[0].repository, "octo/lib");
        assert_eq!(org_wakes[0].reason, WakeReason::Reconcile);
        assert_eq!(
            org_acks.last().and_then(|ack| ack.reconcile_interval_secs),
            Some(120)
        );

        // Within the interval, the next sweep sends nothing new.
        let again = sweeper.sweep_once().await;
        assert_eq!(again.wakes, 0);
        assert_eq!(again.already_woken, 2);
    }

    #[test]
    fn a_selected_repositories_installation_covers_its_repositories_not_the_organization() {
        let fake = Arc::new(FakeGithub::new());
        let reach = Fixed(vec![(1, "octo", false, vec!["octo/app"], fake)]);
        let coverage = coverage(&reach.installations(), Duration::from_secs(120));
        let target = |scope, name: &str| TargetRef {
            scope,
            name: name.into(),
        };
        assert!(coverage.covers(&target(TargetScope::Repo, "OCTO/app")));
        assert!(!coverage.covers(&target(TargetScope::Repo, "octo/other")));
        assert!(!coverage.covers(&target(TargetScope::Org, "octo")));
    }

    #[test]
    fn the_wake_log_forgets_after_the_interval() {
        let log = crate::registry::WakeLog::default();
        let start = Instant::now();
        let linux = required(&["linux"]);
        log.record("a/b", &linux, start);
        assert!(log.recent("A/B", &linux, Duration::from_secs(60), start));
        assert!(!log.recent(
            "a/b",
            &required(&["windows"]),
            Duration::from_secs(60),
            start
        ));
        assert!(!log.recent(
            "a/b",
            &linux,
            Duration::from_secs(60),
            start + Duration::from_secs(61)
        ));
    }

    fn required(labels: &[&str]) -> Vec<Label> {
        job(labels).required_labels().expect("resolvable")
    }
}
