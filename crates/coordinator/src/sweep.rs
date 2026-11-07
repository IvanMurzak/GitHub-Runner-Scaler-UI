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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use runner_manager_coordinator_protocol::{TargetRef, TargetScope, WakeReason};
use runner_manager_domain::model::{Label, OwnerRepo};
use runner_manager_github::demand::DemandGateway;
use runner_manager_github::rest::{ActivityScope, CancelToken, InventoryError};

use crate::github_app::{AppError, GithubApp};
use crate::registry::{Coverage, Registry};

/// The default sweep interval.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(120);

/// The shortest sweep interval accepted.
pub const MIN_INTERVAL: Duration = Duration::from_secs(30);

/// How often the installations and their repositories are listed again.
pub const INVENTORY_EVERY: Duration = Duration::from_secs(10 * 60);

/// The delivery id a sweep's wakes carry.
pub const SWEEP_DELIVERY: &str = "reconcile";

/// When a wake was last sent for a repository and a set of required labels,
/// by the webhook or by the sweep.
///
/// A job is identified by what decides which hosts it wakes: its repository
/// and its required labels. Two queued jobs with the same labels in the same
/// repository wake the same hosts, and one poll answers both.
#[derive(Debug, Default)]
pub struct WakeLog {
    sent: Mutex<HashMap<(String, BTreeSet<Label>), Instant>>,
}

/// Wake log entries kept at most this long.
const WAKE_MEMORY: Duration = Duration::from_secs(60 * 60);

impl WakeLog {
    fn key(repository: &str, required: &[Label]) -> (String, BTreeSet<Label>) {
        (
            repository.to_ascii_lowercase(),
            required.iter().cloned().collect(),
        )
    }

    /// Records a wake sent now.
    pub fn record(&self, repository: &str, required: &[Label], now: Instant) {
        let mut sent = self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sent.retain(|_, at| now.saturating_duration_since(*at) < WAKE_MEMORY);
        sent.insert(Self::key(repository, required), now);
    }

    /// Whether a wake was sent within `within` of `now`.
    #[must_use]
    pub fn recent(
        &self,
        repository: &str,
        required: &[Label],
        within: Duration,
        now: Instant,
    ) -> bool {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&Self::key(repository, required))
            .is_some_and(|at| now.saturating_duration_since(*at) < within)
    }
}

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

/// The sweep's settings.
#[derive(Debug, Clone, Copy)]
pub struct SweepConfig {
    pub interval: Duration,
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
    config: SweepConfig,
    reach: Box<dyn Reach>,
    registry: Arc<Registry>,
    wakes: Arc<WakeLog>,
    inventory_at: Option<Instant>,
}

impl Sweeper {
    #[must_use]
    pub fn new(
        config: SweepConfig,
        reach: Box<dyn Reach>,
        registry: Arc<Registry>,
        wakes: Arc<WakeLog>,
    ) -> Self {
        Self {
            config,
            reach,
            registry,
            wakes,
            inventory_at: None,
        }
    }

    /// Sweeps every interval, forever.
    pub async fn run(mut self) {
        let mut ticks = tokio::time::interval(self.config.interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
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

    /// One sweep: refresh the App's view, publish coverage, read every
    /// served repository's queue and wake for what no wake was sent for.
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
        let installations = self.reach.installations();
        self.registry
            .set_coverage(coverage(&installations, self.config.interval));

        let advertised = self.registry.advertised();
        let mut report = SweepReport::default();
        for installation in &installations {
            let repositories = served(installation, &advertised);
            for repository in repositories {
                match self.read(installation, &repository, &mut report).await {
                    Ok(()) => {}
                    Err(InventoryError::RateLimited(_)) => {
                        report.rate_limited += 1;
                        break;
                    }
                    Err(InventoryError::Github(error))
                        if error.is_authentication() || error.is_lockout() =>
                    {
                        tracing::warn!(
                            installation = installation.id,
                            "an installation's token was refused; it is minted again at the next \
                             inventory"
                        );
                        self.reach.forget(installation.id);
                        self.inventory_at = None;
                        report.failed += 1;
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(
                            installation = installation.id,
                            %error,
                            "a repository's queue could not be read"
                        );
                        report.failed += 1;
                    }
                }
            }
        }
        report
    }

    async fn read(
        &self,
        installation: &Reachable,
        repository: &OwnerRepo,
        report: &mut SweepReport,
    ) -> Result<(), InventoryError> {
        let demand = installation
            .demand
            .queued_demand(
                &ActivityScope::repository(repository.clone()),
                &CancelToken::new(),
            )
            .await?;
        report.repositories += 1;
        let name = repository.to_string();
        for job in demand.jobs_for(repository) {
            let Ok(required) = job.required_labels() else {
                continue;
            };
            report.queued += 1;
            let now = Instant::now();
            if self
                .wakes
                .recent(&name, &required, self.config.interval, now)
            {
                report.already_woken += 1;
                continue;
            }
            let woken =
                self.registry
                    .wake_for(&name, &required, WakeReason::Reconcile, SWEEP_DELIVERY);
            if woken > 0 {
                self.wakes.record(&name, &required, now);
                report.wakes += u32::try_from(woken).unwrap_or(u32::MAX);
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
fn served(installation: &Reachable, advertised: &[TargetRef]) -> Vec<OwnerRepo> {
    let mut repositories: BTreeMap<String, OwnerRepo> = BTreeMap::new();
    for repository in &installation.repositories {
        let name = repository.to_string();
        if advertised.iter().any(|target| match target.scope {
            TargetScope::Repo => target.covers(&name),
            TargetScope::Org => target.name.eq_ignore_ascii_case(&installation.account),
        }) {
            repositories.insert(name.to_ascii_lowercase(), repository.clone());
        }
    }
    repositories.into_values().collect()
}

#[cfg(test)]
mod tests {
    use runner_manager_coordinator_protocol::{
        Hello, HelloAck, PROTOCOL_VERSION, Profile, ServerMessage, Target, Wake,
    };
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
        RunsOn::from_job_labels(labels.iter().map(ToString::to_string))
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
        let wakes = Arc::new(WakeLog::default());
        // The webhook already woke the hosts for octo/app's linux job.
        let linux = required(&["self-hosted", "linux"]);
        wakes.record("Octo/App", &linux, Instant::now());

        let mut sweeper = Sweeper::new(
            SweepConfig {
                interval: Duration::from_secs(120),
            },
            Box::new(Fixed(vec![(
                1,
                "octo",
                true,
                vec!["octo/app", "octo/lib", "octo/unserved-by-nobody"],
                Arc::clone(&fake),
            )])),
            Arc::clone(&registry),
            Arc::clone(&wakes),
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
        let log = WakeLog::default();
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
