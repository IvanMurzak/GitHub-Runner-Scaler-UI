//! Does placement balance load across several hosts? A deterministic simulation.
//!
//! Live load experiments can use one host per pool at most, so choosing between
//! hosts is measured here: the **real** [`Placement`] and [`Statistics`], fed the
//! messages and webhooks `server.rs` feeds them and in the same order, on tokio's
//! paused clock. Only the hosts and GitHub are fake.
//!
//! A host has memory, slots and a speed. It sends a heartbeat every 15 s and right
//! after an attempt ends, brings a runner up in 15 s, and frees a slot 5 s after a
//! job ends. A job's memory ramps up to its peak. A runner takes any queued job of
//! its queue, as GitHub hands them out: usually the oldest.
//!
//! Each scenario repeats its workload over rounds, statistics accumulating from
//! empty, under three policies: round-robin (the only code here that decides
//! anything), placement without statistics, and placement with them.
//!
//! What this cannot show, compared with real hosts: CPU contention (a job's speed
//! does not depend on what else runs), swap and out-of-memory kills (memory above
//! a host's RAM is measured, and the job carries on), disk and network, GitHub's
//! actual choice of job, and lost or reordered webhooks beyond a seeded delay.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    reason = "a simulation's figures are small, and its one loop reads best whole"
)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use runner_manager_coordinator::placement::{CLAIM_GRACE, JobKey, Placement, TICK};
use runner_manager_coordinator::registry::{Coverage, OUTBOUND_QUEUE, Outbound, Registry};
use runner_manager_coordinator::stats::{
    JobIdentity, JobTimes, Statistics, StatsConfig, percentile,
};
use runner_manager_coordinator::store::{JobSample, Store};
use runner_manager_coordinator::webhook::required_labels;
use runner_manager_domain::coordinator_protocol::{
    AttemptFinished, AttemptOutcomeKind, AttemptStarted, AttemptUsage, Heartbeat, Hello, LaunchAck,
    PROTOCOL_VERSION, Profile, RefusalReason, ServerMessage, Target, TargetRef, TargetScope,
};
use runner_manager_domain::model::Label;
use tokio::sync::mpsc;
use tokio::time::{Instant, advance};

const GIB: u64 = 1 << 30;

const HEARTBEAT_MS: u64 = 15_000;
const BRING_UP_MS: u64 = 15_000;
const SLOT_RELEASE_MS: u64 = 5_000;
const IDLE_TIMEOUT_MS: u64 = 120_000;
/// `attempt_started` is this far behind a runner taking a job; its `in_progress`
/// webhook lands on either side of it.
const ATTEMPT_STARTED_MS: u64 = 1_000;
const WEBHOOK_MS: (u64, u64) = (200, 2_000);
/// How long GitHub takes to fail a job whose runner vanished.
const LOST_RUNNER_MS: u64 = 600_000;
/// Between rounds: every lease and reservation of the last one has lapsed.
const ROUND_GAP_MS: u64 = 30 * 60_000;
const ROUND_DEADLINE_MS: u64 = 8 * 60 * 60_000;
/// A job waiting this long, or never run, is starved.
const STARVED_MS: u64 = 30 * 60_000;
/// How much of a job's run its memory takes to reach its peak, and at most how
/// long: a build's peak comes minutes in.
const RAMP_SHARE: f64 = 0.6;
const RAMP_MAX_MS: f64 = 240_000.0;
/// How much of a job's time a warm checkout leaves.
const WARM_FACTOR: f64 = 0.6;
/// Of the queued jobs GitHub hands a runner: this often the oldest, else any.
const OLDEST_PERCENT: u64 = 70;

const LINUX: &str = "rm-pool-linux";
const WINDOWS: &str = "rm-pool-windows";
const MACOS: &str = "rm-pool-macos";

/// A small PCG-free generator: all this needs is a seeded, stable stream.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        let mut rng = Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        rng.next();
        rng.next();
        rng
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn range(&mut self, low: u64, high: u64) -> u64 {
        low + self.next() % (high - low + 1)
    }

    /// `value`, off by at most `percent` either way.
    fn jitter(&mut self, value: f64, percent: u64) -> f64 {
        value * (100 - percent + self.range(0, 2 * percent)) as f64 / 100.0
    }
}

#[derive(Debug, Clone)]
struct HostSpec {
    id: &'static str,
    ram: u64,
    /// What the OS and the daemon use.
    os_ram: u64,
    slots: u32,
    /// 2.0 runs a job in half its time.
    speed: f64,
    pool: &'static str,
    /// Repositories this host keeps a persistent workspace for.
    warm: &'static [&'static str],
}

const fn host(id: &'static str, gib: u64, slots: u32, speed: f64, pool: &'static str) -> HostSpec {
    HostSpec {
        id,
        ram: gib * GIB,
        os_ram: GIB + gib * GIB / 32,
        slots,
        speed,
        pool,
        warm: &[],
    }
}

/// Three Linux hosts of one pool: big, middling, small and slow.
fn linux_trio() -> Vec<HostSpec> {
    vec![
        host("big-64", 64, 8, 1.0, LINUX),
        host("mid-23", 23, 4, 1.0, LINUX),
        host("slow-8", 8, 2, 0.5, LINUX),
    ]
}

#[derive(Debug, Clone)]
struct JobSpec {
    at_ms: u64,
    repo: &'static str,
    name: &'static str,
    pool: &'static str,
    secs: f64,
    peak: u64,
}

fn job(at_s: u64, repo: &'static str, name: &'static str, secs: u64, gib: f64) -> JobSpec {
    JobSpec {
        at_ms: at_s * 1000,
        repo,
        name,
        pool: LINUX,
        secs: secs as f64,
        peak: (gib * GIB as f64) as u64,
    }
}

struct Scenario {
    name: &'static str,
    hosts: Vec<HostSpec>,
    rounds: usize,
    jobs: fn(usize) -> Vec<JobSpec>,
    /// This host vanishes this long into every round.
    vanishes: Option<(&'static str, u64)>,
    /// Samples the statistics start with: repository, job, GiB, how many.
    history: &'static [(&'static str, &'static str, u64, usize)],
}

/// Heavy jobs only the big host holds, and light ones, all in one queue: a runner
/// takes any of them, so the queue's demand is its heaviest.
fn mixed_one_queue(_round: usize) -> Vec<JobSpec> {
    let mut jobs = Vec::new();
    for at in 0..3 {
        jobs.push(job(at * 20, "octo/app", "build-heavy", 900, 28.0));
    }
    for at in 0..9 {
        jobs.push(job(5 + at * 5, "octo/app", "unit", 240, 2.0));
    }
    for at in 0..6 {
        jobs.push(job(7 + at * 5, "octo/app", "lint", 90, 0.5));
    }
    jobs
}

/// The same jobs, the heavy ones in a queue of their own.
fn mixed_two_queues(round: usize) -> Vec<JobSpec> {
    let mut jobs = mixed_one_queue(round);
    for job in &mut jobs {
        if job.name == "build-heavy" {
            job.repo = "octo/engine";
        }
    }
    jobs
}

/// Forty-five jobs at once, against fourteen slots.
fn burst(_round: usize) -> Vec<JobSpec> {
    (0..45)
        .map(|index| {
            let at = index / 2;
            match index % 3 {
                0 => job(at, "octo/app", "small", 180, 1.0),
                1 => job(at, "octo/app", "medium", 300, 3.0),
                _ => job(at, "octo/app", "large", 480, 6.0),
            }
        })
        .collect()
}

/// One job at a time, so memory never decides: the host it should learn to prefer
/// is the smaller one.
fn one_at_a_time(_round: usize) -> Vec<JobSpec> {
    (0..5)
        .map(|index| job(index * 660, "octo/app", "compile", 360, 4.0))
        .collect()
}

/// Three repositories, two jobs each; two hosts keep one of them warm.
fn several_repositories(_round: usize) -> Vec<JobSpec> {
    let mut jobs = Vec::new();
    for (index, repo) in ["octo/a", "octo/b", "octo/c"].into_iter().enumerate() {
        let index = index as u64;
        for step in 0..3u64 {
            let at = step * 300 + index * 20;
            jobs.push(job(at, repo, "build", 240, 2.0));
            jobs.push(job(at + 10, repo, "check", 120, 1.0));
        }
    }
    jobs
}

const GROWS_AT_ROUND: usize = 3;

/// A job with a long light history, run once a round, that turns heavy. The
/// fillers leave the big host little: by its history it fits elsewhere.
fn grows_heavier(round: usize) -> Vec<JobSpec> {
    let peak = if round >= GROWS_AT_ROUND { 30.0 } else { 6.0 };
    let mut jobs: Vec<JobSpec> = (0..4)
        .map(|index| job(index * 5, "octo/app", "filler", 480, 18.0))
        .collect();
    jobs.push(job(60, "octo/app", "grower", 480, peak));
    jobs
}

fn steady_stream(_round: usize) -> Vec<JobSpec> {
    (0..24)
        .map(|index| job(index * 10, "octo/app", "build", 300, 3.0))
        .collect()
}

/// The owner's fleet: Linux and WSL, one Windows host, and two Macs, one of them
/// small with a single slot.
fn owner_fleet(_round: usize) -> Vec<JobSpec> {
    let mut jobs = Vec::new();
    let mut add = |pool, name, count: u64, secs, gib| {
        for index in 0..count {
            let mut one = job(index * 10, "octo/game", name, secs, gib);
            one.pool = pool;
            jobs.push(one);
        }
    };
    add(LINUX, "linux-build", 2, 600, 12.0);
    add(LINUX, "linux-test", 6, 240, 3.0);
    add(WINDOWS, "windows-build", 2, 900, 20.0);
    add(WINDOWS, "windows-test", 4, 300, 4.0);
    add(MACOS, "mac-build", 2, 600, 14.0);
    add(MACOS, "mac-test", 4, 240, 3.0);
    jobs
}

fn scenarios() -> Vec<Scenario> {
    let warm_mid = HostSpec {
        warm: &["octo/a"],
        ..host("mid-23", 23, 4, 1.0, LINUX)
    };
    let warm_slow = HostSpec {
        warm: &["octo/b"],
        ..host("slow-8", 8, 2, 0.4, LINUX)
    };
    vec![
        Scenario {
            name: "1a mixed, one queue",
            hosts: linux_trio(),
            rounds: 6,
            jobs: mixed_one_queue,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "1b mixed, two queues",
            hosts: linux_trio(),
            rounds: 6,
            jobs: mixed_two_queues,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "2 burst over capacity",
            hosts: linux_trio(),
            rounds: 4,
            jobs: burst,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "3 faster on one host",
            hosts: vec![
                host("slow-64", 64, 8, 0.6, LINUX),
                host("fast-23", 23, 4, 1.5, LINUX),
            ],
            rounds: 4,
            jobs: one_at_a_time,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "4 repositories, warm",
            hosts: vec![host("big-64", 64, 8, 1.0, LINUX), warm_mid, warm_slow],
            rounds: 5,
            jobs: several_repositories,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "5 grows heavier",
            hosts: linux_trio(),
            rounds: 8,
            jobs: grows_heavier,
            vanishes: None,
            history: &[("octo/app", "grower", 6, 30), ("octo/app", "filler", 18, 30)],
        },
        Scenario {
            name: "6 host vanishes",
            hosts: linux_trio(),
            rounds: 4,
            jobs: steady_stream,
            vanishes: Some(("big-64", 120_000)),
            history: &[],
        },
        Scenario {
            name: "7 owner fleet",
            hosts: vec![
                host("linux-64", 64, 8, 1.0, LINUX),
                host("wsl-23", 23, 4, 0.9, LINUX),
                host("windows-64", 64, 8, 1.0, WINDOWS),
                host("mac-m6-24", 24, 4, 1.4, MACOS),
                host("mac-m1-8", 8, 1, 0.7, MACOS),
            ],
            rounds: 6,
            jobs: owner_fleet,
            vanishes: None,
            history: &[],
        },
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Policy {
    RoundRobin,
    NoStatistics,
    Weighted,
}

impl Policy {
    const fn label(self) -> &'static str {
        match self {
            Self::RoundRobin => "round-robin",
            Self::NoStatistics => "no statistics",
            Self::Weighted => "statistics",
        }
    }
}

/// What one round measured.
#[derive(Debug, Clone, Default, PartialEq)]
struct Metrics {
    makespan_s: u64,
    wait_p50_s: u64,
    wait_p95_s: u64,
    wait_max_s: u64,
    mean_run_s: u64,
    /// Seconds any host spent above its memory, and the GiB·seconds above it.
    over_s: u64,
    over_gib_s: u64,
    over_peak_gib: u64,
    /// Jobs started on a host that cannot hold them.
    misfits: u32,
    /// Of those, jobs of a key that had already finished once.
    misfits_measured: u32,
    /// Busiest host's slot use less the idlest's, in percentage points.
    spread_pct: u64,
    starved: u32,
    lost: u32,
}

#[derive(Debug)]
struct Job {
    id: u64,
    spec: JobSpec,
    secs: f64,
    peak: u64,
    key: JobKey,
    required: Vec<Label>,
    queued_at: u64,
    started_at: Option<u64>,
    run_ms: u64,
    host: usize,
    runner: usize,
    done: bool,
    lost: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerState {
    Booting,
    Idle,
    Running,
    /// Its job ended; the slot is not free yet.
    Exiting,
    Gone,
}

#[derive(Debug)]
struct Runner {
    name: String,
    host: usize,
    key: JobKey,
    lease: Option<String>,
    /// Its lease's job was taken: no longer among the host's open launches.
    claimed: bool,
    state: RunnerState,
}

struct Host {
    spec: HostSpec,
    connection: u64,
    connected: bool,
    rx: mpsc::Receiver<Outbound>,
    busy_ms: u64,
}

#[derive(Debug, Clone)]
enum Event {
    Queued(usize),
    Online(usize),
    IdleExit(usize),
    InProgressWebhook(usize),
    AttemptStarted(usize),
    JobDone(usize),
    CompletedWebhook(usize),
    SlotRelease(usize),
    Heartbeat(usize),
    Tick,
    Rebalance(JobKey),
    RetryAll,
    Vanish(usize),
}

struct Sim {
    seed: u64,
    registry: Arc<Registry>,
    placement: Option<Arc<Placement>>,
    stats: Option<Arc<Statistics>>,
    hosts: Vec<Host>,
    repos: Vec<&'static str>,
    epoch: Instant,
    round_start: u64,
    events: BTreeMap<(u64, u64), Event>,
    seq: u64,
    rng: Rng,
    jobs: Vec<Job>,
    runners: Vec<Runner>,
    /// GitHub's queues: what a runner of each can take.
    github: BTreeMap<JobKey, BTreeSet<usize>>,
    next_job_id: u64,
    next_runner: u64,
    next_host: usize,
    /// Job keys that finished at least once.
    seen: HashSet<(String, String)>,
    over_ms: u64,
    over_gib_ms: f64,
    over_peak: u64,
}

fn required_of(pool: &str) -> Vec<Label> {
    required_labels(&[pool.to_string()]).expect("a pool label")
}

fn wall(ms: u64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).expect("a date")
        + TimeDelta::milliseconds(ms as i64)
}

fn virtual_now() -> std::time::Instant {
    Instant::now().into_std()
}

impl Sim {
    fn new(scenario: &Scenario, policy: Policy, seed: u64) -> Self {
        let registry = Arc::new(Registry::default());
        let mut repos: BTreeSet<&'static str> = BTreeSet::new();
        for round in 1..=scenario.rounds {
            repos.extend((scenario.jobs)(round).into_iter().map(|job| job.repo));
        }
        registry.set_coverage(Coverage {
            interval: Some(Duration::from_secs(120)),
            repositories: repos.iter().map(ToString::to_string).collect(),
            accounts: BTreeSet::new(),
        });
        let stats = (policy == Policy::Weighted).then(|| {
            let mut store = Store::open_in_memory().expect("store");
            for (repo, name, gib, count) in scenario.history {
                let config = StatsConfig::default();
                for index in 0..*count {
                    let identity = JobIdentity::new(repo, Some(name)).expect("named");
                    let sample = JobSample {
                        job_key: identity.key(),
                        repository: identity.repository,
                        host_id: scenario.hosts[index % scenario.hosts.len()].id.to_string(),
                        finished_at: Utc::now(),
                        duration_secs: Some(480),
                        queue_wait_secs: Some(15),
                        peak_rss_bytes: Some(gib * GIB),
                        cpu_avg_millicores: Some(1000),
                        cpu_peak_millicores: Some(2000),
                    };
                    let oldest = Utc::now() - TimeDelta::days(1);
                    store
                        .record_sample(&sample, config.samples_per_job, oldest)
                        .expect("a sample");
                }
            }
            Arc::new(Statistics::load(
                Arc::new(Mutex::new(store)),
                StatsConfig::default(),
            ))
        });
        let placement = (policy != Policy::RoundRobin).then(|| {
            let placement = Placement::new(Arc::clone(&registry));
            Arc::new(match &stats {
                Some(stats) => placement.with_statistics(Arc::clone(stats)),
                None => placement,
            })
        });
        let mut sim = Self {
            seed,
            registry,
            placement,
            stats,
            hosts: Vec::new(),
            repos: repos.into_iter().collect(),
            epoch: Instant::now(),
            round_start: 0,
            events: BTreeMap::new(),
            seq: 0,
            rng: Rng::new(seed),
            jobs: Vec::new(),
            runners: Vec::new(),
            github: BTreeMap::new(),
            next_job_id: 1,
            next_runner: 1,
            next_host: 0,
            seen: HashSet::new(),
            over_ms: 0,
            over_gib_ms: 0.0,
            over_peak: 0,
        };
        for spec in &scenario.hosts {
            let (_, rx) = mpsc::channel(1);
            sim.hosts.push(Host {
                spec: spec.clone(),
                connection: 0,
                connected: false,
                rx,
                busy_ms: 0,
            });
        }
        sim
    }

    fn now(&self) -> u64 {
        Instant::now().duration_since(self.epoch).as_millis() as u64
    }

    fn at(&mut self, t: u64, event: Event) {
        self.seq += 1;
        self.events.insert((t, self.seq), event);
    }

    fn after(&mut self, delay: u64, event: Event) {
        let t = self.now() + delay;
        self.at(t, event);
    }

    fn webhook_delay(&mut self) -> u64 {
        self.rng.range(WEBHOOK_MS.0, WEBHOOK_MS.1)
    }

    /// What `server.rs` does as a host connects: its old link's leases close.
    fn connect(&mut self, index: usize) {
        let (tx, rx) = mpsc::channel(OUTBOUND_QUEUE);
        let spec = self.hosts[index].spec.clone();
        let connection = self.registry.register(spec.id, PROTOCOL_VERSION, tx);
        if let Some(placement) = &self.placement {
            placement.host_gone(spec.id);
        }
        self.registry.set_hello(
            spec.id,
            connection,
            Hello {
                protocol_version: PROTOCOL_VERSION,
                host_id: spec.id.into(),
                os: "linux".into(),
                arch: "x64".into(),
                cores: 16,
                ram_bytes: Some(spec.ram),
                disk_free_bytes: None,
                targets: self
                    .repos
                    .iter()
                    .map(|repo| Target {
                        scope: TargetScope::Repo,
                        name: (*repo).to_string(),
                        profiles: vec![Profile {
                            name: "pool".into(),
                            labels: vec![spec.pool.to_string()],
                            enabled: true,
                            warm: spec.warm.contains(repo),
                        }],
                    })
                    .collect(),
            },
        );
        let host = &mut self.hosts[index];
        host.rx = rx;
        host.connection = connection;
        host.connected = true;
    }

    fn slots_used(&self, host: usize) -> u32 {
        self.runners
            .iter()
            .filter(|runner| runner.host == host && runner.state != RunnerState::Gone)
            .count() as u32
    }

    fn rss(&self, job: &Job, now: u64) -> u64 {
        let Some(started) = job.started_at else {
            return 0;
        };
        if job.done {
            return 0;
        }
        let ramp = (job.run_ms as f64 * RAMP_SHARE).clamp(1.0, RAMP_MAX_MS);
        let share = ((now - started) as f64 / ramp).min(1.0);
        (job.peak as f64 * share) as u64
    }

    fn used_ram(&self, host: usize, now: u64) -> u64 {
        self.hosts[host].spec.os_ram
            + self
                .jobs
                .iter()
                .filter(|job| job.started_at.is_some() && job.host == host)
                .map(|job| self.rss(job, now))
                .sum::<u64>()
    }

    fn heartbeat_of(&self, host: usize) -> Heartbeat {
        let spec = &self.hosts[host].spec;
        let free = spec.slots.saturating_sub(self.slots_used(host));
        Heartbeat {
            free_slots: free,
            busy_slots: self
                .runners
                .iter()
                .filter(|runner| {
                    runner.host == host
                        && matches!(
                            runner.state,
                            RunnerState::Idle | RunnerState::Running | RunnerState::Exiting
                        )
                })
                .count() as u32,
            cpu_load_percent: None,
            free_ram_bytes: Some(spec.ram.saturating_sub(self.used_ram(host, self.now()))),
            unfit: false,
            draining: false,
            open_leases: Some(
                self.runners
                    .iter()
                    .filter(|runner| {
                        runner.host == host && runner.state != RunnerState::Gone && !runner.claimed
                    })
                    .filter_map(|runner| runner.lease.clone())
                    .collect(),
            ),
        }
    }

    /// A heartbeat, as `server.rs` takes one.
    fn send_heartbeat(&mut self, host: usize) {
        if !self.hosts[host].connected {
            return;
        }
        let mut heartbeat = self.heartbeat_of(host);
        let spec_id = self.hosts[host].spec.id;
        let dropped = match (&self.placement, heartbeat.open_leases.take()) {
            (Some(placement), Some(held)) => placement.reconcile_leases(spec_id, &held),
            _ => 0,
        };
        let freed = self
            .registry
            .set_heartbeat(spec_id, self.hosts[host].connection, heartbeat);
        if freed || dropped > 0 {
            self.after(0, Event::RetryAll);
        }
    }

    fn start_runner(&mut self, host: usize, lease: Option<String>, key: JobKey) {
        let name = format!("runner-manager-sim-{}", self.next_runner);
        self.next_runner += 1;
        self.runners.push(Runner {
            name,
            host,
            key,
            lease,
            claimed: false,
            state: RunnerState::Booting,
        });
        self.after(BRING_UP_MS, Event::Online(self.runners.len() - 1));
    }

    /// Everything the coordinator sent the hosts: launches answered, cancels
    /// honoured.
    fn drain_hosts(&mut self) {
        for index in 0..self.hosts.len() {
            while let Ok(message) = self.hosts[index].rx.try_recv() {
                match message {
                    Outbound::Send(ServerMessage::Launch(launch)) => {
                        let spec = self.hosts[index].spec.clone();
                        let answer = if self.slots_used(index) < spec.slots {
                            let key = JobKey::new(&launch.target.name, &required_of(spec.pool));
                            self.start_runner(index, Some(launch.lease_id.clone()), key);
                            LaunchAck::accepted(launch.lease_id)
                        } else {
                            LaunchAck::refused(launch.lease_id, RefusalReason::HostCapacity)
                        };
                        if let Some(placement) = &self.placement {
                            placement.acknowledged(spec.id, answer);
                        }
                    }
                    Outbound::Send(ServerMessage::CancelLaunch(cancel)) => {
                        for runner in &mut self.runners {
                            if runner.host == index
                                && runner.lease.as_deref() == Some(&cancel.lease_id)
                            {
                                match runner.state {
                                    RunnerState::Booting => runner.state = RunnerState::Gone,
                                    RunnerState::Idle => runner.lease = None,
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// [`Placement::rebalance`] with the hosts answering. Each launch takes 1 ms,
    /// so no two leases share a moment and "the newest" means one lease.
    async fn rebalance(&mut self, key: &JobKey) {
        let Some(placement) = self.placement.clone() else {
            return self.round_robin();
        };
        let rebalance = placement.rebalance(key);
        tokio::pin!(rebalance);
        loop {
            tokio::select! {
                biased;
                _ = &mut rebalance => break,
                () = tokio::task::yield_now() => {
                    self.drain_hosts();
                    advance(Duration::from_millis(1)).await;
                }
            }
        }
        self.drain_hosts();
    }

    /// [`Placement::retry_all`], with its order over queues seeded: in service it
    /// is a hash map's.
    async fn retry_all(&mut self) {
        let Some(placement) = self.placement.clone() else {
            return self.round_robin();
        };
        let mut keys = placement.expire(virtual_now());
        keys.sort();
        for index in (1..keys.len()).rev() {
            let other = self.rng.range(0, index as u64) as usize;
            keys.swap(index, other);
        }
        for key in keys {
            self.rebalance(&key).await;
        }
    }

    /// The baseline: every queue short of runners gets the next host in turn that
    /// has a free slot and serves its pool. Generous: it knows every host's slots
    /// exactly, not as of a heartbeat.
    fn round_robin(&mut self) {
        let keys: Vec<JobKey> = self.github.keys().cloned().collect();
        for key in keys {
            let queued = self.github.get(&key).map_or(0, BTreeSet::len);
            let coming = self
                .runners
                .iter()
                .filter(|runner| {
                    runner.key == key
                        && !runner.claimed
                        && matches!(runner.state, RunnerState::Booting | RunnerState::Idle)
                })
                .count();
            for _ in coming..queued {
                let count = self.hosts.len();
                let free = (0..count)
                    .map(|step| (self.next_host + step) % count)
                    .find(|&index| {
                        let host = &self.hosts[index];
                        host.connected
                            && key.labels.contains(
                                &Label::new(host.spec.pool).expect("a pool label"),
                            )
                            && self.slots_used(index) < host.spec.slots
                    });
                let Some(index) = free else { break };
                self.next_host = index + 1;
                self.start_runner(index, None, key.clone());
            }
        }
    }

    /// A runner is free: GitHub hands it a queued job of its queue, if any.
    fn hand_out(&mut self, runner_index: usize) -> bool {
        let key = self.runners[runner_index].key.clone();
        let Some(queue) = self.github.get_mut(&key) else {
            return false;
        };
        let oldest = self.rng.range(0, 99) < OLDEST_PERCENT;
        let position = if oldest {
            0
        } else {
            self.rng.range(0, queue.len() as u64 - 1) as usize
        };
        let Some(&job_index) = queue.iter().nth(position) else {
            return false;
        };
        queue.remove(&job_index);
        if queue.is_empty() {
            self.github.remove(&key);
        }
        let now = self.now();
        let host_index = self.runners[runner_index].host;
        let spec = self.hosts[host_index].spec.clone();
        let job = &mut self.jobs[job_index];
        let warm = if spec.warm.contains(&job.spec.repo) {
            WARM_FACTOR
        } else {
            1.0
        };
        job.run_ms = (job.secs * 1000.0 * warm / spec.speed) as u64;
        job.started_at = Some(now);
        job.host = host_index;
        job.runner = runner_index;
        let run_ms = job.run_ms;
        self.runners[runner_index].state = RunnerState::Running;
        self.runners[runner_index].claimed = true;
        self.hosts[host_index].busy_ms += run_ms;
        let in_progress = self.webhook_delay();
        self.after(in_progress, Event::InProgressWebhook(job_index));
        self.after(ATTEMPT_STARTED_MS, Event::AttemptStarted(runner_index));
        self.after(run_ms, Event::JobDone(job_index));
        true
    }

    fn identity_of(job: &Job) -> JobIdentity {
        JobIdentity::new(job.spec.repo, Some(job.spec.name)).expect("named")
    }

    async fn handle(&mut self, event: Event) {
        match event {
            Event::Tick => {
                let now = self.now();
                for index in 0..self.hosts.len() {
                    if !self.hosts[index].connected {
                        continue;
                    }
                    let used = self.used_ram(index, now);
                    let ram = self.hosts[index].spec.ram;
                    if used > ram {
                        let tick = TICK.as_millis() as u64;
                        self.over_ms += tick;
                        self.over_gib_ms += (used - ram) as f64 / GIB as f64 * tick as f64;
                        self.over_peak = self.over_peak.max(used - ram);
                    }
                }
                if let Some(stats) = &self.stats {
                    stats.flush();
                }
                self.retry_all().await;
                self.after(TICK.as_millis() as u64, Event::Tick);
            }
            Event::Heartbeat(host) => {
                self.send_heartbeat(host);
                self.after(HEARTBEAT_MS, Event::Heartbeat(host));
            }
            Event::Queued(index) => {
                let now = self.now();
                let job = &mut self.jobs[index];
                job.queued_at = now;
                let key = job.key.clone();
                let (repo, required, id, identity) = (
                    job.spec.repo,
                    job.required.clone(),
                    job.id,
                    Self::identity_of(job),
                );
                self.github.entry(key.clone()).or_default().insert(index);
                if let Some(placement) = &self.placement {
                    placement.queued_job(repo, &required, id, Some(identity.key()));
                }
                // A runner already waiting takes it at once.
                let idle = self.runners.iter().position(|runner| {
                    runner.key == key && runner.state == RunnerState::Idle
                });
                if let Some(idle) = idle {
                    self.hand_out(idle);
                }
                self.rebalance(&key).await;
            }
            Event::Online(index) => {
                if self.runners[index].state != RunnerState::Booting {
                    return;
                }
                self.runners[index].state = RunnerState::Idle;
                if !self.hand_out(index) {
                    self.after(IDLE_TIMEOUT_MS, Event::IdleExit(index));
                }
            }
            Event::IdleExit(index) => {
                if self.runners[index].state != RunnerState::Idle {
                    return;
                }
                let host = self.runners[index].host;
                let name = self.runners[index].name.clone();
                self.report_finished(host, None, name, AttemptOutcomeKind::IdleExit, None);
                if self.runners[index].lease.is_some() {
                    // The host keeps a launch whose runner exited idle.
                    self.runners[index].state = RunnerState::Booting;
                    self.after(BRING_UP_MS, Event::Online(index));
                } else {
                    self.runners[index].state = RunnerState::Exiting;
                    self.after(SLOT_RELEASE_MS, Event::SlotRelease(index));
                }
            }
            Event::InProgressWebhook(index) => {
                let job = &self.jobs[index];
                let runner = self.runners[job.runner].name.clone();
                let key = job.key.clone();
                let identity = Self::identity_of(job);
                let times = JobTimes {
                    created_at: Some(wall(job.queued_at)),
                    started_at: job.started_at.map(wall),
                    completed_at: None,
                };
                let (repo, required, id) = (job.spec.repo, job.required.clone(), job.id);
                if let Some(placement) = &self.placement {
                    placement.dequeued_by(repo, &required, id, Some(&runner));
                    self.after(CLAIM_GRACE.as_millis() as u64, Event::Rebalance(key));
                }
                if let Some(stats) = &self.stats {
                    stats.job_identified(&runner, identity, times);
                }
            }
            Event::AttemptStarted(index) => {
                let runner = &self.runners[index];
                let host = &self.hosts[runner.host];
                if !host.connected {
                    return;
                }
                if let Some(placement) = &self.placement {
                    placement.attempt_started(
                        host.spec.id,
                        &AttemptStarted {
                            lease_id: runner.lease.clone(),
                            runner_name: runner.name.clone(),
                            target: TargetRef {
                                scope: TargetScope::Repo,
                                name: runner.key.repository.clone(),
                            },
                            profile: "pool".into(),
                        },
                    );
                }
            }
            Event::JobDone(index) => {
                if self.jobs[index].done {
                    return;
                }
                self.jobs[index].done = true;
                let delay = self.webhook_delay();
                self.after(delay, Event::CompletedWebhook(index));
                let runner = self.jobs[index].runner;
                self.runners[runner].state = RunnerState::Exiting;
                self.after(SLOT_RELEASE_MS, Event::SlotRelease(runner));
            }
            Event::CompletedWebhook(index) => {
                let job = &self.jobs[index];
                let runner = self.runners[job.runner].name.clone();
                let key = job.key.clone();
                let identity = Self::identity_of(job);
                let started = job.started_at.expect("started");
                let times = JobTimes {
                    created_at: Some(wall(job.queued_at)),
                    started_at: Some(wall(started)),
                    completed_at: Some(wall(started + job.run_ms)),
                };
                let (repo, required, id) = (job.spec.repo, job.required.clone(), job.id);
                if let Some(placement) = &self.placement {
                    placement.dequeued_by(repo, &required, id, None);
                    self.after(CLAIM_GRACE.as_millis() as u64, Event::Rebalance(key));
                }
                if let Some(stats) = &self.stats {
                    stats.job_identified(&runner, identity, times);
                }
            }
            Event::SlotRelease(index) => {
                let runner = &self.runners[index];
                let host = runner.host;
                let lease = runner.lease.clone();
                let name = runner.name.clone();
                self.runners[index].state = RunnerState::Gone;
                if !self.hosts[host].connected {
                    return;
                }
                let finished = self.jobs.iter().find(|job| {
                    job.started_at.is_some() && job.runner == index && job.host == host
                });
                let usage = finished.map(|job| AttemptUsage {
                    peak_rss_bytes: job.peak,
                    cpu_avg_millicores: 1000,
                    cpu_peak_millicores: 2000,
                    samples: 10,
                });
                let outcome = finished.map_or(AttemptOutcomeKind::IdleExit, |_| {
                    AttemptOutcomeKind::CompletedJob
                });
                if let Some(job) = finished {
                    self.seen.insert((job.spec.repo.into(), job.spec.name.into()));
                }
                self.report_finished(host, lease, name, outcome, usage);
                self.after(0, Event::RetryAll);
                self.send_heartbeat(host);
            }
            Event::Rebalance(key) => {
                if self.placement.is_some() {
                    self.rebalance(&key).await;
                }
            }
            Event::RetryAll => self.retry_all().await,
            Event::Vanish(host) => {
                let now = self.now();
                let spec_id = self.hosts[host].spec.id;
                let connection = self.hosts[host].connection;
                self.hosts[host].connected = false;
                self.registry.unregister(spec_id, connection);
                if let Some(placement) = &self.placement {
                    placement.host_gone(spec_id);
                }
                for index in 0..self.runners.len() {
                    if self.runners[index].host != host {
                        continue;
                    }
                    self.runners[index].state = RunnerState::Gone;
                }
                for index in 0..self.jobs.len() {
                    let job = &mut self.jobs[index];
                    if job.host == host && job.started_at.is_some() && !job.done {
                        job.done = true;
                        job.lost = true;
                        // What it ran until it was lost is all it used.
                        job.run_ms = now - job.started_at.expect("started");
                        self.at(now + LOST_RUNNER_MS, Event::CompletedWebhook(index));
                    }
                }
                self.after(0, Event::RetryAll);
            }
        }
    }

    fn report_finished(
        &self,
        host: usize,
        lease_id: Option<String>,
        runner_name: String,
        outcome: AttemptOutcomeKind,
        usage: Option<AttemptUsage>,
    ) {
        let id = self.hosts[host].spec.id;
        let finished = AttemptFinished {
            lease_id,
            runner_name,
            outcome,
            duration_secs: Some(60),
            usage,
        };
        if let Some(placement) = &self.placement {
            placement.attempt_finished(id, &finished);
        }
        if let Some(stats) = &self.stats {
            stats.attempt_finished(id, &finished, self.registry.ram_bytes(id));
        }
    }

    fn round_finished(&self) -> bool {
        self.jobs.iter().all(|job| job.done)
            && self
                .runners
                .iter()
                .all(|runner| runner.state == RunnerState::Gone)
    }

    /// Runs one round from idle hosts and returns what it measured.
    async fn round(&mut self, scenario: &Scenario, round: usize) -> Metrics {
        advance(Duration::from_millis(ROUND_GAP_MS)).await;
        self.round_start = self.now();
        self.events.clear();
        self.jobs.clear();
        self.runners.clear();
        self.github.clear();
        self.over_ms = 0;
        self.over_gib_ms = 0.0;
        self.over_peak = 0;
        for index in 0..self.hosts.len() {
            self.hosts[index].busy_ms = 0;
            if !self.hosts[index].connected {
                self.connect(index);
            }
            self.send_heartbeat(index);
            let phase = 1_000 + 3_000 * index as u64;
            self.after(phase, Event::Heartbeat(index));
        }
        self.drain_hosts();
        self.retry_all().await;
        self.drain_hosts();
        self.after(TICK.as_millis() as u64, Event::Tick);
        let start = self.now();
        let specs = (scenario.jobs)(round);
        for (index, spec) in specs.into_iter().enumerate() {
            let mut draw = Rng::new(
                self.seed
                    ^ (round as u64).wrapping_mul(0x1000_0000_01b3)
                    ^ (index as u64 + 1).wrapping_mul(0x0100_0193_0000_0001),
            );
            let secs = draw.jitter(spec.secs, 5);
            let peak = draw.jitter(spec.peak as f64, 3) as u64;
            let required = required_of(spec.pool);
            let key = JobKey::new(spec.repo, &required);
            self.at(start + spec.at_ms, Event::Queued(index));
            self.jobs.push(Job {
                id: self.next_job_id,
                spec,
                secs,
                peak,
                key,
                required,
                queued_at: 0,
                started_at: None,
                run_ms: 0,
                host: 0,
                runner: 0,
                done: false,
                lost: false,
            });
            self.next_job_id += 1;
        }
        if let Some((id, at)) = scenario.vanishes {
            let host = self
                .hosts
                .iter()
                .position(|host| host.spec.id == id)
                .expect("a known host");
            self.at(start + at, Event::Vanish(host));
        }
        let deadline = start + ROUND_DEADLINE_MS;
        while let Some(((at, _), event)) = self.events.pop_first() {
            let now = self.now();
            if at > now {
                advance(Duration::from_millis(at - now)).await;
            }
            if self.round_finished() || at > deadline {
                break;
            }
            self.drain_hosts();
            self.handle(event).await;
            self.drain_hosts();
            advance(Duration::from_millis(1)).await;
        }
        self.finish_round(start)
    }

    fn finish_round(&mut self, start: u64) -> Metrics {
        let now = self.now();
        // Whatever never ran is forgotten, so it does not haunt the next round.
        let leftovers: Vec<usize> = self.github.values().flatten().copied().collect();
        for index in &leftovers {
            let job = &self.jobs[*index];
            if let Some(placement) = &self.placement {
                placement.dequeued(job.spec.repo, &job.required, job.id);
            }
        }
        let ran: Vec<&Job> = self
            .jobs
            .iter()
            .filter(|job| job.started_at.is_some() && !job.lost)
            .collect();
        let waits: Vec<u64> = self
            .jobs
            .iter()
            .filter_map(|job| job.started_at.map(|at| at - job.queued_at))
            .collect();
        let makespan = ran
            .iter()
            .map(|job| job.started_at.expect("started") + job.run_ms)
            .max()
            .unwrap_or(now)
            - start;
        let seconds = |ms: Option<u64>| ms.unwrap_or(0) / 1000;
        let mut misfits = 0;
        let mut misfits_measured = 0;
        for job in self.jobs.iter().filter(|job| job.started_at.is_some()) {
            let spec = &self.hosts[job.host].spec;
            if job.peak + spec.os_ram > spec.ram {
                misfits += 1;
            }
        }
        for (job, seen) in self.jobs.iter().filter_map(|job| {
            job.started_at?;
            Some((job, self.seen.contains(&(job.spec.repo.into(), job.spec.name.into()))))
        }) {
            let spec = &self.hosts[job.host].spec;
            if seen && job.peak + spec.os_ram > spec.ram {
                misfits_measured += 1;
            }
        }
        let shares: Vec<u64> = self
            .hosts
            .iter()
            .map(|host| {
                host.busy_ms * 100 / (u64::from(host.spec.slots) * makespan.max(1))
            })
            .collect();
        let starved = self
            .jobs
            .iter()
            .filter(|job| {
                job.started_at
                    .map_or(true, |at| at - job.queued_at > STARVED_MS)
            })
            .count() as u32;
        let mean_run = if ran.is_empty() {
            0
        } else {
            ran.iter().map(|job| job.run_ms).sum::<u64>() / ran.len() as u64
        };
        Metrics {
            makespan_s: makespan / 1000,
            wait_p50_s: seconds(percentile(&waits, 50)),
            wait_p95_s: seconds(percentile(&waits, 95)),
            wait_max_s: seconds(waits.iter().max().copied()),
            mean_run_s: mean_run / 1000,
            over_s: self.over_ms / 1000,
            over_gib_s: (self.over_gib_ms / 1000.0) as u64,
            over_peak_gib: self.over_peak / GIB,
            misfits,
            misfits_measured,
            spread_pct: shares.iter().max().unwrap_or(&0) - shares.iter().min().unwrap_or(&0),
            starved,
            lost: self.jobs.iter().filter(|job| job.lost).count() as u32,
        }
    }
}

/// Results are means over these seeds; single runs differ by more than some of
/// the effects measured.
const SEEDS: [u64; 3] = [0x5eed_0001, 0x5eed_0002, 0x5eed_0003];

/// Baselines do not learn: their last two rounds say all they have to say.
const BASELINE_ROUNDS: usize = 2;

async fn run(scenario: &Scenario, policy: Policy, seed: u64) -> Vec<Metrics> {
    let mut sim = Sim::new(scenario, policy, seed);
    let first = if policy == Policy::Weighted {
        1
    } else {
        scenario.rounds + 1 - BASELINE_ROUNDS
    };
    let mut rounds = Vec::new();
    for round in first..=scenario.rounds {
        rounds.push(sim.round(scenario, round).await);
    }
    rounds
}

/// Times and memory averaged; the counts added up, so one misfit in a seed shows.
fn merged(rounds: &[Metrics]) -> Metrics {
    let count = rounds.len().max(1) as u64;
    let mean = |field: fn(&Metrics) -> u64| rounds.iter().map(field).sum::<u64>() / count;
    let total = |field: fn(&Metrics) -> u32| rounds.iter().map(field).sum::<u32>();
    Metrics {
        makespan_s: mean(|m| m.makespan_s),
        wait_p50_s: mean(|m| m.wait_p50_s),
        wait_p95_s: mean(|m| m.wait_p95_s),
        wait_max_s: mean(|m| m.wait_max_s),
        mean_run_s: mean(|m| m.mean_run_s),
        over_s: mean(|m| m.over_s),
        over_gib_s: mean(|m| m.over_gib_s),
        over_peak_gib: mean(|m| m.over_peak_gib),
        misfits: total(|m| m.misfits),
        misfits_measured: total(|m| m.misfits_measured),
        spread_pct: mean(|m| m.spread_pct),
        starved: total(|m| m.starved),
        lost: total(|m| m.lost),
    }
}

fn row(scenario: &str, policy: &str, round: &str, m: &Metrics) -> String {
    format!(
        "| {scenario} | {policy} | {round} | {} | {} | {} | {} | {} | {}s / {} / {} | {} ({}) | {} | {} | {} |",
        m.makespan_s,
        m.wait_p50_s,
        m.wait_p95_s,
        m.wait_max_s,
        m.mean_run_s,
        m.over_s,
        m.over_gib_s,
        m.over_peak_gib,
        m.misfits,
        m.misfits_measured,
        m.spread_pct,
        m.starved,
        m.lost,
    )
}

struct ScenarioResult {
    name: &'static str,
    /// Every round of every seed, merged.
    round_robin: Metrics,
    no_statistics: Metrics,
    /// Per round, merged over the seeds.
    weighted: Vec<Metrics>,
}

impl ScenarioResult {
    /// The weighted rounds from `round` (1-based) on, merged.
    fn weighted_from(&self, round: usize) -> Metrics {
        merged(&self.weighted[round - 1..])
    }
}

fn table(results: &[ScenarioResult]) -> String {
    let mut table = String::from(
        "| Scenario | Policy | Round | Makespan s | Wait p50 s | p95 s | max s | Mean run s | \
         Over RAM (time / GiB·s / peak GiB) | Misfits (measured) | Spread pts | Starved | Lost |\n\
         |---|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|\n",
    );
    for result in results {
        let name = result.name;
        writeln!(table, "{}", row(name, "round-robin", "all", &result.round_robin))
            .expect("a string");
        writeln!(table, "{}", row(name, "no statistics", "all", &result.no_statistics))
            .expect("a string");
        for (index, metrics) in result.weighted.iter().enumerate() {
            writeln!(
                table,
                "{}",
                row(name, "statistics", &(index + 1).to_string(), metrics)
            )
            .expect("a string");
        }
    }
    table
}

async fn simulate() -> Vec<ScenarioResult> {
    let mut results = Vec::new();
    for scenario in scenarios() {
        let mut round_robin = Vec::new();
        let mut no_statistics = Vec::new();
        let mut per_round = vec![Vec::new(); scenario.rounds];
        for seed in SEEDS {
            round_robin.extend(run(&scenario, Policy::RoundRobin, seed).await);
            no_statistics.extend(run(&scenario, Policy::NoStatistics, seed).await);
            let weighted = run(&scenario, Policy::Weighted, seed).await;
            for (index, metrics) in weighted.into_iter().enumerate() {
                per_round[index].push(metrics);
            }
        }
        results.push(ScenarioResult {
            name: scenario.name,
            round_robin: merged(&round_robin),
            no_statistics: merged(&no_statistics),
            weighted: per_round.iter().map(|rounds| merged(rounds)).collect(),
        });
    }
    results
}

#[tokio::test(start_paused = true)]
async fn placement_balances_load_across_hosts() {
    let results = simulate().await;
    // Past the test harness's capture: the numbers are the point of this test.
    writeln!(std::io::stderr().lock(), "\n{}", table(&results)).expect("stderr");
}
