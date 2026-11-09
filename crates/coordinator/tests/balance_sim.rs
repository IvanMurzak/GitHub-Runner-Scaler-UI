//! Does placement balance load across several hosts? A deterministic simulation.
//!
//! Live load experiments can use one host per pool at most, so choosing between
//! hosts is measured here: the **real** [`Placement`] and [`Statistics`], fed the
//! messages and webhooks `server.rs` feeds them, in its order as copied by hand
//! here (nothing keeps the two in step), on tokio's paused clock. Only the hosts and GitHub are fake.
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
//! A host may carry `rm-pool-any` beside its OS pool, have CPU load of its own
//! (which slows its jobs and which its heartbeats report, with a share per
//! running job), and little free disk (which its heartbeats report).
//!
//! What this cannot show, compared with real hosts: CPU contention between jobs
//! (a job's speed depends on the host's own background load only), swap and
//! out-of-memory kills (memory above a host's RAM is measured, and the job
//! carries on), a disk filling up and network, GitHub's actual choice of job, a
//! runner with both an OS pool and `rm-pool-any` taking a job of the queue it was
//! not launched for, and lost or reordered webhooks beyond a seeded delay.

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
    DEFAULT_CPU_BUSY_PERCENT, DEFAULT_MIN_DISK_FREE, JobIdentity, JobTimes, Statistics,
    StatsConfig, percentile,
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
const ANY: &str = "rm-pool-any";

/// What placement treats as busy and as low disk, by default.
const BUSY_PERCENT: u32 = DEFAULT_CPU_BUSY_PERCENT;
const LOW_DISK: u64 = DEFAULT_MIN_DISK_FREE;

/// Xorshift: all this needs is a seeded, stable stream.
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
    /// It also answers `rm-pool-any`, on the same profile.
    any: bool,
    os: &'static str,
    cores: u32,
    /// CPU load of its own, in percent: it slows the host's jobs.
    background_cpu: u32,
    disk_free: u64,
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
        any: false,
        os: "linux",
        cores: 16,
        background_cpu: 0,
        disk_free: 200 * GIB,
        warm: &[],
    }
}

impl HostSpec {
    /// Whether a runner of this host may take a job of `pool`.
    fn serves(&self, pool: &str) -> bool {
        pool == self.pool || (self.any && pool == ANY)
    }

    /// Its own load slows a job: at 100 % a job takes twice as long.
    fn effective_speed(&self) -> f64 {
        self.speed * (1.0 - f64::from(self.background_cpu.min(100)) / 200.0)
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
        .map(|index| job(index * 10, "octo/app", "build", 300, 5.0))
        .collect()
}

/// One `rm-pool-any` job at a time, so memory never decides, between OS jobs that
/// only their own host may take.
fn any_os(_round: usize) -> Vec<JobSpec> {
    let mut jobs: Vec<JobSpec> = (0..5)
        .map(|index| JobSpec {
            pool: ANY,
            ..job(index * 660, "octo/tool", "package", 360, 3.0)
        })
        .collect();
    for (index, pool) in [LINUX, MACOS].into_iter().enumerate() {
        jobs.push(JobSpec {
            pool,
            ..job(300 + index as u64 * 660, "octo/tool", "native", 120, 1.0)
        });
    }
    jobs
}

/// A job every 40 s, about six at a time: one host can take them all.
fn light_stream(_round: usize) -> Vec<JobSpec> {
    (0..20)
        .map(|index| job(index * 40, "octo/app", "test", 240, 2.0))
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
            rounds: 4,
            jobs: mixed_one_queue,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "1b mixed, two queues",
            hosts: linux_trio(),
            rounds: 4,
            jobs: mixed_two_queues,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "2 burst over capacity",
            hosts: linux_trio(),
            rounds: 3,
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
            rounds: 3,
            jobs: one_at_a_time,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "4 repositories, warm",
            hosts: vec![host("big-64", 64, 8, 1.0, LINUX), warm_mid, warm_slow],
            rounds: 6,
            jobs: several_repositories,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "5 grows heavier",
            hosts: linux_trio(),
            rounds: 6,
            jobs: grows_heavier,
            vanishes: None,
            history: &[
                ("octo/app", "grower", 6, 30),
                ("octo/app", "filler", 18, 30),
            ],
        },
        Scenario {
            name: "6 host vanishes",
            hosts: linux_trio(),
            rounds: 3,
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
            rounds: 4,
            jobs: owner_fleet,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "8 any OS, fast and slow",
            hosts: vec![
                HostSpec {
                    any: true,
                    ..host("linux-fast-23", 23, 4, 1.6, LINUX)
                },
                HostSpec {
                    any: true,
                    os: "macos",
                    ..host("mac-slow-64", 64, 4, 0.6, MACOS)
                },
                // The roomiest of all, and not in the pool: never a candidate.
                HostSpec {
                    os: "windows",
                    ..host("windows-128", 128, 8, 2.0, WINDOWS)
                },
            ],
            rounds: 4,
            jobs: any_os,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "9 CPU-busy host",
            hosts: vec![
                HostSpec {
                    background_cpu: 95,
                    ..host("busy-64", 64, 8, 1.0, LINUX)
                },
                host("calm-32", 32, 8, 1.0, LINUX),
            ],
            rounds: 3,
            jobs: light_stream,
            vanishes: None,
            history: &[],
        },
        Scenario {
            name: "10 low-disk host",
            hosts: vec![
                HostSpec {
                    disk_free: 4 * GIB,
                    ..host("full-disk-64", 64, 8, 1.0, LINUX)
                },
                host("roomy-32", 32, 8, 1.0, LINUX),
            ],
            rounds: 3,
            jobs: light_stream,
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
    /// Jobs started on a host busy with load of its own, on one low on disk, and
    /// on one whose pools do not include the job's.
    busy_starts: u32,
    low_disk_starts: u32,
    wrong_pool_starts: u32,
}

#[derive(Debug)]
struct Job {
    id: u64,
    spec: JobSpec,
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
    /// Its host said so (`attempt_started`): that launch is no longer among the
    /// open ones its heartbeats list.
    reported: bool,
    state: RunnerState,
}

struct Host {
    spec: HostSpec,
    connection: u64,
    connected: bool,
    rx: mpsc::Receiver<Outbound>,
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
    events: BTreeMap<(u64, u64), Event>,
    seq: u64,
    rng: Rng,
    jobs: Vec<Job>,
    runners: Vec<Runner>,
    /// GitHub's queues: what a runner of each can take.
    github: BTreeMap<JobKey, BTreeSet<(u64, usize)>>,
    next_job_id: u64,
    next_runner: u64,
    next_host: usize,
    /// Job keys that finished at least once.
    seen: HashSet<(String, String)>,
    over_ms: u64,
    over_gib_ms: f64,
    over_peak: u64,
    misfits_measured: u32,
}

fn required_of(pool: &str) -> Vec<Label> {
    required_labels(&[pool.to_string()]).expect("a pool label")
}

fn wall(ms: u64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).expect("a date") + TimeDelta::milliseconds(ms as i64)
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
            misfits_measured: 0,
        };
        for spec in &scenario.hosts {
            let (_, rx) = mpsc::channel(1);
            sim.hosts.push(Host {
                spec: spec.clone(),
                connection: 0,
                connected: false,
                rx,
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
                os: spec.os.into(),
                arch: "x64".into(),
                cores: spec.cores,
                ram_bytes: Some(spec.ram),
                disk_free_bytes: Some(spec.disk_free),
                targets: self
                    .repos
                    .iter()
                    .map(|repo| Target {
                        scope: TargetScope::Repo,
                        name: (*repo).to_string(),
                        profiles: vec![Profile {
                            name: "pool".into(),
                            labels: std::iter::once(spec.pool)
                                .chain(spec.any.then_some(ANY))
                                .map(ToString::to_string)
                                .collect(),
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
        (job.spec.peak as f64 * share) as u64
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
        let running = self
            .runners
            .iter()
            .filter(|runner| runner.host == host && runner.state == RunnerState::Running)
            .count() as u32;
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
            // A running job keeps one core busy.
            cpu_load_percent: Some((spec.background_cpu + running * 100 / spec.cores).min(100)),
            disk_free_bytes: Some(spec.disk_free),
            free_ram_bytes: Some(spec.ram.saturating_sub(self.used_ram(host, self.now()))),
            unfit: false,
            draining: false,
            open_leases: Some(
                self.runners
                    .iter()
                    .filter(|runner| {
                        runner.host == host && runner.state != RunnerState::Gone && !runner.reported
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
            reported: false,
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
                            // Its runner serves the queue of the job it was launched
                            // for: `repository#job id`.
                            let key = launch
                                .job_key
                                .rsplit_once('#')
                                .and_then(|(_, id)| id.parse::<u64>().ok())
                                .and_then(|id| self.jobs.iter().find(|job| job.id == id))
                                .map(|job| job.key.clone())
                                .expect("every queued job here is named: a launch names one");
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
                                // A host starts a launch's runner at once: one already
                                // started stays, and may take any job (`Launches::cancel`).
                                if matches!(runner.state, RunnerState::Booting | RunnerState::Idle)
                                {
                                    runner.lease = None;
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
                            && key
                                .labels
                                .iter()
                                .any(|label| host.spec.serves(label.as_str()))
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
        let Some(&(queued_at, job_index)) = queue.iter().nth(position) else {
            return false;
        };
        queue.remove(&(queued_at, job_index));
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
        job.run_ms = (job.spec.secs * 1000.0 * warm / spec.effective_speed()) as u64;
        job.started_at = Some(now);
        job.host = host_index;
        job.runner = runner_index;
        let run_ms = job.run_ms;
        if job.spec.peak + spec.os_ram > spec.ram
            && self
                .seen
                .contains(&(job.spec.repo.to_string(), job.spec.name.to_string()))
        {
            self.misfits_measured += 1;
        }
        self.runners[runner_index].state = RunnerState::Running;
        let in_progress = self.webhook_delay();
        self.after(in_progress, Event::InProgressWebhook(job_index));
        self.after(ATTEMPT_STARTED_MS, Event::AttemptStarted(runner_index));
        self.after(run_ms, Event::JobDone(job_index));
        true
    }

    fn identity_of(job: &Job) -> JobIdentity {
        JobIdentity::new(job.spec.repo, Some(job.spec.name)).expect("named")
    }

    /// A `workflow_job` webhook for a job a runner took: `in_progress`, or
    /// `completed`.
    fn webhook(&mut self, index: usize, in_progress: bool) {
        let job = &self.jobs[index];
        let runner = self.runners[job.runner].name.clone();
        let key = job.key.clone();
        let identity = Self::identity_of(job);
        let times = JobTimes {
            created_at: Some(wall(job.queued_at)),
            started_at: job.started_at.map(wall),
            completed_at: job
                .started_at
                .filter(|_| !in_progress)
                .map(|started| wall(started + job.run_ms)),
            failed: job.lost,
        };
        let took = in_progress.then_some(runner.as_str());
        if let Some(placement) = &self.placement {
            placement.dequeued_by(job.spec.repo, &job.required, job.id, took);
            self.after(CLAIM_GRACE.as_millis() as u64, Event::Rebalance(key));
        }
        if let Some(stats) = &self.stats {
            stats.job_identified(&runner, identity, times);
        }
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
                self.github
                    .entry(key.clone())
                    .or_default()
                    .insert((now, index));
                if let Some(placement) = &self.placement {
                    placement.queued_job(repo, &required, id, Some(identity.key()));
                }
                // A runner already waiting takes it at once.
                let idle = self
                    .runners
                    .iter()
                    .position(|runner| runner.key == key && runner.state == RunnerState::Idle);
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
            Event::InProgressWebhook(index) => self.webhook(index, true),
            Event::AttemptStarted(index) => {
                self.runners[index].reported = true;
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
            Event::CompletedWebhook(index) => self.webhook(index, false),
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
                    peak_rss_bytes: job.spec.peak,
                    cpu_avg_millicores: 1000,
                    cpu_peak_millicores: 2000,
                    samples: 10,
                });
                let outcome = finished.map_or(AttemptOutcomeKind::IdleExit, |_| {
                    AttemptOutcomeKind::CompletedJob
                });
                if let Some(job) = finished {
                    self.seen
                        .insert((job.spec.repo.into(), job.spec.name.into()));
                }
                self.report_finished(host, lease, name, outcome, usage);
                self.after(0, Event::RetryAll);
                self.send_heartbeat(host);
            }
            Event::Rebalance(key) => self.rebalance(&key).await,
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
                    if let Some(started) = job.started_at.filter(|_| job.host == host && !job.done)
                    {
                        job.done = true;
                        job.lost = true;
                        // What it ran until it was lost is all it used.
                        job.run_ms = now - started;
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
        self.events.clear();
        self.jobs.clear();
        self.runners.clear();
        self.github.clear();
        self.over_ms = 0;
        self.over_gib_ms = 0.0;
        self.over_peak = 0;
        self.misfits_measured = 0;
        for index in 0..self.hosts.len() {
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
        for (index, mut spec) in specs.into_iter().enumerate() {
            let mut draw = Rng::new(
                self.seed
                    ^ (round as u64).wrapping_mul(0x1000_0000_01b3)
                    ^ (index as u64 + 1).wrapping_mul(0x0100_0193_0000_0001),
            );
            spec.secs = draw.jitter(spec.secs, 5);
            spec.peak = draw.jitter(spec.peak as f64, 3) as u64;
            let required = required_of(spec.pool);
            let key = JobKey::new(spec.repo, &required);
            self.at(start + spec.at_ms, Event::Queued(index));
            self.jobs.push(Job {
                id: self.next_job_id,
                spec,
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
            // No two events share a moment: "the oldest" always means one lease.
            let now = self.now();
            advance(Duration::from_millis(at.max(now + 1) - now)).await;
            if self.round_finished() || at > deadline {
                break;
            }
            self.drain_hosts();
            self.handle(event).await;
            self.drain_hosts();
        }
        self.finish_round(start)
    }

    /// How many jobs that started did so on a host for which `on` holds.
    fn started_on(&self, on: impl Fn(&HostSpec, &Job) -> bool) -> u32 {
        self.jobs
            .iter()
            .filter(|job| job.started_at.is_some() && on(&self.hosts[job.host].spec, job))
            .count() as u32
    }

    fn finish_round(&mut self, start: u64) -> Metrics {
        let now = self.now();
        // Whatever never ran is forgotten, so it does not haunt the next round.
        for (_, index) in self.github.values().flatten() {
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
        for job in self.jobs.iter().filter(|job| job.started_at.is_some()) {
            let spec = &self.hosts[job.host].spec;
            if job.spec.peak + spec.os_ram > spec.ram {
                misfits += 1;
            }
        }
        let shares: Vec<u64> = (0..self.hosts.len())
            .map(|host| {
                let busy_ms: u64 = self
                    .jobs
                    .iter()
                    .filter(|job| job.started_at.is_some() && job.host == host)
                    .map(|job| job.run_ms)
                    .sum();
                busy_ms * 100 / (u64::from(self.hosts[host].spec.slots) * makespan.max(1))
            })
            .collect();
        let starved = self
            .jobs
            .iter()
            .filter(|job| {
                job.started_at
                    .is_none_or(|at| at - job.queued_at > STARVED_MS)
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
            over_gib_s: (self.over_gib_ms / 1000.0).ceil() as u64,
            over_peak_gib: self.over_peak.div_ceil(GIB),
            misfits,
            misfits_measured: self.misfits_measured,
            spread_pct: shares.iter().max().unwrap_or(&0) - shares.iter().min().unwrap_or(&0),
            starved,
            lost: self.jobs.iter().filter(|job| job.lost).count() as u32,
            busy_starts: self.started_on(|host, _| host.background_cpu >= BUSY_PERCENT),
            low_disk_starts: self.started_on(|host, _| host.disk_free < LOW_DISK),
            wrong_pool_starts: self.started_on(|host, job| !host.serves(job.spec.pool)),
        }
    }
}

/// Results are means over these seeds; single runs differ by more than some of
/// the effects measured.
const SEEDS: [u64; 3] = [0x5eed_0001, 0x5eed_0002, 0x5eed_0003];

/// Baselines do not learn: their last round says all they have to say.
const BASELINE_ROUNDS: usize = 1;

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
    // Up, not down: any overcommit in any round of any seed stays above zero.
    let mean_up =
        |field: fn(&Metrics) -> u64| rounds.iter().map(field).sum::<u64>().div_ceil(count);
    let total = |field: fn(&Metrics) -> u32| rounds.iter().map(field).sum::<u32>();
    Metrics {
        makespan_s: mean(|m| m.makespan_s),
        wait_p50_s: mean(|m| m.wait_p50_s),
        wait_p95_s: mean(|m| m.wait_p95_s),
        wait_max_s: mean(|m| m.wait_max_s),
        mean_run_s: mean(|m| m.mean_run_s),
        over_s: mean_up(|m| m.over_s),
        over_gib_s: mean_up(|m| m.over_gib_s),
        over_peak_gib: mean_up(|m| m.over_peak_gib),
        misfits: total(|m| m.misfits),
        misfits_measured: total(|m| m.misfits_measured),
        spread_pct: mean(|m| m.spread_pct),
        starved: total(|m| m.starved),
        lost: total(|m| m.lost),
        busy_starts: total(|m| m.busy_starts),
        low_disk_starts: total(|m| m.low_disk_starts),
        wrong_pool_starts: total(|m| m.wrong_pool_starts),
    }
}

fn row(scenario: &str, policy: &str, round: &str, m: &Metrics) -> String {
    format!(
        "| {scenario} | {policy} | {round} | {} | {} | {} | {} | {} | {}s / {} / {} | {} ({}) | {} | {} | {} | {} / {} / {} |",
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
        m.busy_starts,
        m.low_disk_starts,
        m.wrong_pool_starts,
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
         Over RAM (time / GiB·s / peak GiB) | Misfits (measured) | Spread pts | Starved | Lost | \
         Starts busy / low disk / wrong pool |\n\
         |---|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---|\n",
    );
    let mut add = |name: &str, policy: &str, round: &str, metrics: &Metrics| {
        writeln!(table, "{}", row(name, policy, round, metrics)).expect("a string");
    };
    for result in results {
        let name = result.name;
        add(name, "round-robin", "all", &result.round_robin);
        add(name, "no statistics", "all", &result.no_statistics);
        for (index, metrics) in result.weighted.iter().enumerate() {
            add(name, "statistics", &(index + 1).to_string(), metrics);
        }
    }
    table
}

async fn simulate(scenario: &Scenario) -> ScenarioResult {
    let mut round_robin = Vec::new();
    let mut no_statistics = Vec::new();
    let mut per_round = vec![Vec::new(); scenario.rounds];
    for seed in SEEDS {
        round_robin.extend(run(scenario, Policy::RoundRobin, seed).await);
        no_statistics.extend(run(scenario, Policy::NoStatistics, seed).await);
        let weighted = run(scenario, Policy::Weighted, seed).await;
        for (index, metrics) in weighted.into_iter().enumerate() {
            per_round[index].push(metrics);
        }
    }
    ScenarioResult {
        name: scenario.name,
        round_robin: merged(&round_robin),
        no_statistics: merged(&no_statistics),
        weighted: per_round.iter().map(|rounds| merged(rounds)).collect(),
    }
}

/// Every scenario on a thread and a paused clock of its own: they share nothing.
fn simulate_all() -> Vec<ScenarioResult> {
    let scenarios = scenarios();
    std::thread::scope(|scope| {
        let threads: Vec<_> = scenarios
            .iter()
            .map(|scenario| {
                scope.spawn(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .start_paused(true)
                        .build()
                        .expect("a runtime")
                        .block_on(simulate(scenario))
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().expect("a scenario"))
            .collect()
    })
}

/// What every placement here must do. Tolerances leave room for the seeds, not
/// for a real change in behaviour: each was measured, see the PR's table.
fn check(results: &[ScenarioResult]) -> Vec<String> {
    let mut failures = Vec::new();
    let mut expect = |ok: bool, what: String| {
        if !ok {
            failures.push(what);
        }
    };
    let of = |name: &str| {
        results
            .iter()
            .find(|result| result.name.starts_with(name))
            .expect("a scenario")
    };

    for result in results {
        let name = result.name;
        let learned = result.weighted_from(2);
        let every_round = result.weighted_from(1);
        let first = &result.weighted[0];
        let rounds = (result.weighted.len() - 1) as u32;
        // Nothing waits for good, whatever the policy.
        for (policy, metrics) in [
            ("round-robin", &result.round_robin),
            ("no statistics", &result.no_statistics),
            ("statistics", &every_round),
        ] {
            expect(
                metrics.starved == 0,
                format!("{name}: {policy} starved a job"),
            );
        }
        // Learning pays: later rounds are not worse than the first.
        if !name.starts_with('5') {
            expect(
                learned.over_gib_s <= first.over_gib_s + 5,
                format!(
                    "{name}: more memory overcommit after learning: {} > {} GiB·s",
                    learned.over_gib_s, first.over_gib_s
                ),
            );
            expect(
                learned.misfits <= first.misfits * rounds,
                format!(
                    "{name}: more misfits after learning: {} > {} over {rounds} rounds",
                    learned.misfits, first.misfits
                ),
            );
            expect(
                learned.mean_run_s * 100 <= first.mean_run_s * 105,
                format!(
                    "{name}: jobs ran slower after learning: {} s > {} s",
                    learned.mean_run_s, first.mean_run_s
                ),
            );
        }
    }

    // Scenarios 1: heavy jobs that fit only the big host. In one queue a runner
    // started for a light job can still take a heavy one queued after it, which
    // cannot be stopped: rare, not never. In a queue of their own, never.
    for (name, allowed) in [("1a", 2), ("1b", 0)] {
        let result = of(name);
        let learned = result.weighted_from(2);
        expect(
            learned.misfits_measured <= allowed,
            format!(
                "{name}: {} measured jobs on a host too small",
                learned.misfits_measured
            ),
        );
        expect(
            result.round_robin.misfits > 0,
            format!("{name}: round-robin should misplace these jobs"),
        );
        expect(
            learned.over_gib_s * 10 < result.round_robin.over_gib_s,
            format!(
                "{name}: statistics should overcommit a tenth of round-robin: {} vs {} GiB·s",
                learned.over_gib_s, result.round_robin.over_gib_s
            ),
        );
        expect(
            learned.over_gib_s * 10 < result.no_statistics.over_gib_s,
            format!(
                "{name}: statistics should overcommit a tenth of none: {} vs {} GiB·s",
                learned.over_gib_s, result.no_statistics.over_gib_s
            ),
        );
    }
    // Their own queue spares the light jobs the heavy ones' wait.
    expect(
        of("1b").weighted_from(2).wait_p50_s * 5 < of("1a").weighted_from(2).wait_p50_s,
        "1: a queue of their own should spare light jobs the heavy ones' wait".to_string(),
    );

    // Scenario 2: over capacity, memory safe at little cost.
    let burst = of("2");
    let learned = burst.weighted_from(2);
    expect(
        learned.over_gib_s * 10 <= burst.round_robin.over_gib_s,
        format!(
            "2: statistics should overcommit a tenth of round-robin: {} vs {} GiB·s",
            learned.over_gib_s, burst.round_robin.over_gib_s
        ),
    );
    expect(
        learned.makespan_s * 100 <= burst.round_robin.makespan_s * 120,
        format!(
            "2: safety should cost at most a fifth in makespan: {} vs {} s",
            learned.makespan_s, burst.round_robin.makespan_s
        ),
    );

    // Scenario 3: it finds the faster host, though the other has more memory.
    let faster = of("3");
    let learned = faster.weighted_from(2);
    expect(
        learned.mean_run_s * 100 <= faster.no_statistics.mean_run_s * 50,
        format!(
            "3: learning should halve run time against no statistics: {} vs {} s",
            learned.mean_run_s, faster.no_statistics.mean_run_s
        ),
    );
    expect(
        learned.mean_run_s < faster.round_robin.mean_run_s,
        format!(
            "3: statistics should beat round-robin: {} vs {} s",
            learned.mean_run_s, faster.round_robin.mean_run_s
        ),
    );

    // Scenario 4: a warm host wins, unless measured slower than a cold one.
    let warm = of("4");
    // A warm host is judged after 3 runs of a job of its own.
    let learned = warm.weighted_from(5);
    expect(
        learned.mean_run_s * 100 <= warm.no_statistics.mean_run_s * 92,
        format!(
            "4: statistics should beat none by 8%: {} vs {} s",
            learned.mean_run_s, warm.no_statistics.mean_run_s
        ),
    );
    expect(
        learned.mean_run_s < warm.round_robin.mean_run_s,
        format!(
            "4: statistics should beat round-robin: {} vs {} s",
            learned.mean_run_s, warm.round_robin.mean_run_s
        ),
    );

    // Scenario 5: one run may surprise; the next ones know.
    let grown = of("5");
    let settled = grown.weighted_from(GROWS_AT_ROUND + 1);
    expect(
        settled.misfits == 0,
        format!("5: {} misfits after the first heavy run", settled.misfits),
    );
    let settled = grown.weighted_from(GROWS_AT_ROUND + 2);
    expect(
        settled.over_gib_s == 0,
        format!(
            "5: {} GiB·s overcommitted after it was learned",
            settled.over_gib_s
        ),
    );

    // Scenario 6: every job is accounted for, the rest run on what is left.
    let vanishes = of("6");
    let learned = vanishes.weighted_from(2);
    expect(
        learned.misfits == 0 && learned.over_gib_s == 0,
        format!(
            "6: the survivors were overloaded: {} misfits, {} GiB·s",
            learned.misfits, learned.over_gib_s
        ),
    );
    expect(
        learned.lost > 0,
        "6: a host vanishing should lose its jobs".to_string(),
    );

    // Scenario 7: the owner's fleet stays inside its memory once measured.
    let fleet = of("7");
    let learned = fleet.weighted_from(2);
    expect(
        learned.misfits == 0 && learned.over_s <= 5,
        format!(
            "7: {} misfits and {} s overcommitted once measured",
            learned.misfits, learned.over_s
        ),
    );
    expect(
        learned.over_gib_s * 10 < fleet.round_robin.over_gib_s,
        format!(
            "7: statistics should overcommit a tenth of round-robin: {} vs {} GiB·s",
            learned.over_gib_s, fleet.round_robin.over_gib_s
        ),
    );

    // No job, whatever the policy, starts on a host whose pools do not include its.
    for result in results {
        for (policy, metrics) in [
            ("round-robin", &result.round_robin),
            ("no statistics", &result.no_statistics),
            ("statistics", &result.weighted_from(1)),
        ] {
            expect(
                metrics.wrong_pool_starts == 0,
                format!(
                    "{}: {policy} started {} jobs outside their pool",
                    result.name, metrics.wrong_pool_starts
                ),
            );
        }
    }

    // Scenario 8: across operating systems, it finds the faster host, though the
    // other has more memory.
    let any = of("8");
    let learned = any.weighted_from(2);
    expect(
        learned.mean_run_s * 100 <= any.no_statistics.mean_run_s * 60,
        format!(
            "8: learning should cut run time by 40% against no statistics: {} vs {} s",
            learned.mean_run_s, any.no_statistics.mean_run_s
        ),
    );
    expect(
        learned.mean_run_s < any.round_robin.mean_run_s,
        format!(
            "8: statistics should beat round-robin: {} vs {} s",
            learned.mean_run_s, any.round_robin.mean_run_s
        ),
    );

    // Scenarios 9 and 10: a busy or nearly full host is a last resort, and with
    // room elsewhere never needed.
    for (name, starts) in [
        ("9", (|m: &Metrics| m.busy_starts) as fn(&Metrics) -> u32),
        ("10", |m: &Metrics| m.low_disk_starts),
    ] {
        let result = of(name);
        expect(
            starts(&result.round_robin) > 0,
            format!("{name}: round-robin should use the last-resort host"),
        );
        for (policy, metrics) in [
            ("no statistics", &result.no_statistics),
            ("statistics", &result.weighted_from(1)),
        ] {
            expect(
                starts(metrics) == 0,
                format!(
                    "{name}: {policy} started {} jobs on the last-resort host",
                    starts(metrics)
                ),
            );
        }
    }
    let busy = of("9");
    expect(
        busy.weighted_from(1).mean_run_s < busy.round_robin.mean_run_s,
        format!(
            "9: avoiding the busy host should run jobs faster: {} vs {} s",
            busy.weighted_from(1).mean_run_s,
            busy.round_robin.mean_run_s
        ),
    );
    failures
}

#[test]
fn placement_balances_load_across_hosts() {
    let results = simulate_all();
    let table = table(&results);
    // Past the test harness's capture: the numbers are the point of this test.
    writeln!(std::io::stderr().lock(), "\n{table}").expect("stderr");
    let failures = check(&results);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The same seed gives the same numbers: no real time, no hash order and no lease
/// id reaches a result.
#[tokio::test(start_paused = true)]
async fn the_simulation_is_deterministic() {
    let scenario = scenarios().swap_remove(0);
    let first = run(&scenario, Policy::Weighted, SEEDS[0]).await;
    let second = run(&scenario, Policy::Weighted, SEEDS[0]).await;
    assert_eq!(first, second);
}
