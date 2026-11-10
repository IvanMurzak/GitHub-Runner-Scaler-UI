//! Job weight statistics and the weighted placement score (stage 4, design
//! 4.5 and 4.6).
//!
//! # Where a sample comes from
//!
//! A host reports, in `attempt_finished`, how long its runner lived and what
//! its process tree used ([`AttemptUsage`]). Which job that runner took, and
//! when, is GitHub's to say: the `workflow_job` webhooks `in_progress` and
//! `completed` name the `runner_name` together with the repository, the
//! job (the matrix-expanded name, as GitHub gives it) and the
//! job's `created_at`, `started_at` and `completed_at`. The [`Correlator`]
//! joins them in whichever order they arrive, and an attempt that ran a job
//! becomes one [`JobSample`] under the job key `owner/repo/job`.
//!
//! A sample's duration is the **job's** run time, `started_at` to
//! `completed_at`: the host's attempt also spans the runner's start, its wait
//! for a job and its cleanup, which made a 14-second job read as a minute. Its
//! queue wait is `created_at` to `started_at`. A host report waits up to
//! [`COMPLETION_WAIT`] for the `completed` webhook once the job is known; past
//! that (a lost delivery) it is recorded with the host's attempt duration.
//!
//! # What is kept
//!
//! Per job key, the newest [`StatsConfig::samples_per_job`] samples (30), none
//! older than [`StatsConfig::retention`] (90 days), in SQLite with the host
//! that ran them. From them: p50 duration, p90 peak memory, p90 average CPU,
//! and per host the median duration over the usual one (the mean of every
//! host's median).
//!
//! # How placement uses it
//!
//! A runner takes *any* queued job its labels cover (design 4.4), so the
//! demand of a pool queue is its **heaviest** queued job: the largest expected
//! peak memory ([`Aggregates::expected_peak`]) among the job keys queued there.
//! A key never measured counts
//! as its repository's p90 (every sample of that repository), and a
//! repository never measured as [`StatsConfig::default_job_ram`]. See
//! [`score`] for the filter and the weights. With no statistics at all for a
//! queue, nothing is filtered and the order is stage 3's.
//!
//! # Logging
//!
//! Host ids, byte counts, scores and fixed words. Repository, job
//! and runner names came off the wire: they are stored and shown to the
//! owner by `stats`, never logged.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use runner_manager_domain::coordinator_protocol::{
    AttemptFinished, AttemptOutcomeKind, ConnectedHostStats, HostJobStats, HostScore, HostStats,
    JobStats, MAX_MESSAGE_BYTES, OpenLease, PendingQueue, PlacementDecision, ServerMessage,
    StatsReport, TargetEstimate, TargetRef, is_managed_runner_name, printable,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::store::{JobSample, Store, StoreError};

/// The longest repository or job name kept.
const MAX_NAME_CHARS: usize = 120;

/// Runs whose workflow is remembered, and asked about at once.
const RUN_MEMORY: usize = 20_000;

/// How many samples with memory figures a workflow's job needs before they alone
/// stand for it.
const ENOUGH_OF_ITS_OWN: usize = 3;

/// How much slower than usual, in [`speed`]'s terms, a host with a warm checkout
/// may run a job and keep the cache term.
const WARM_NOT_WORTH_IT: f64 = -0.1;

/// How many runs of a job a warm host must have before they judge it: its first is
/// likely a full clone.
const WARM_JUDGED_AFTER: usize = 3;

/// How many of a job's newest samples its expected memory never falls below.
const RECENT_SAMPLES: usize = 3;

/// How long a webhook's runner-to-job mapping waits for its attempt report,
/// and the other way round.
const CORRELATION_MEMORY: Duration = Duration::from_secs(6 * 60 * 60);
const PENDING_MEMORY: Duration = Duration::from_secs(15 * 60);

/// How long a report whose job is known waits for the `completed` webhook
/// (normally seconds behind it, or ahead) before it is recorded without the
/// job's own times.
pub const COMPLETION_WAIT: Duration = Duration::from_secs(2 * 60);

/// Mappings and pending reports remembered at most.
const MAX_CORRELATIONS: usize = 10_000;

/// Jobs listed by `stats`, placement decisions kept and shown.
const REPORT_JOBS: usize = 20;
const REPORT_HOSTS_PER_JOB: usize = 8;
const KEEP_DECISIONS: u32 = 50;
const REPORT_DECISIONS: u32 = 10;

/// A queue no host fits is recorded as a decision at most this often.
const UNPLACED_DECISION_EVERY: Duration = Duration::from_secs(60);

/// The weights of the placement score (design 4.5, step 4). Each term is in
/// [0, 1] (speed in [-1, 1]) before its weight.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Weights {
    /// A persistent workspace for the repository: a warm checkout.
    pub cache: f64,
    /// The share of the host's memory still free after this job.
    pub headroom: f64,
    /// How much faster than usual this host ran these job keys.
    pub speed: f64,
    /// Subtracted when this host is the only one a heavier queued job fits.
    pub bigfit: f64,
    /// The host's idle cores (its cores less its CPU load, by its last
    /// heartbeat), as a share of the most any contender has idle.
    pub cpu: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            cache: 4.0,
            headroom: 2.0,
            speed: 1.0,
            bigfit: 1.5,
            cpu: 1.0,
        }
    }
}

/// When a host is tried only after every other host that fits: placed on
/// only when nothing better can take the job now, never excluded outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guards {
    /// A last heartbeat's CPU load at or above this, in percent, is busy.
    pub cpu_busy_percent: u32,
    /// Less free disk on the runner root's volume than this is low.
    pub min_disk_free: u64,
}

/// [`Guards::default`]'s figures, for the server's options too.
pub const DEFAULT_CPU_BUSY_PERCENT: u32 = 90;
pub const DEFAULT_MIN_DISK_FREE: u64 = 10 << 30;

impl Default for Guards {
    fn default() -> Self {
        Self {
            cpu_busy_percent: DEFAULT_CPU_BUSY_PERCENT,
            min_disk_free: DEFAULT_MIN_DISK_FREE,
        }
    }
}

impl Guards {
    /// Whether, and why, a host with this load and disk is a last resort.
    /// Low disk is the worse: a job may fail for it, where on a busy CPU it is
    /// only slow.
    #[must_use]
    pub fn last_resort(&self, cpu_load_percent: Option<u32>, disk_free: Option<u64>) -> LastResort {
        if disk_free.is_some_and(|free| free < self.min_disk_free) {
            LastResort::LowDisk
        } else if cpu_load_percent.is_some_and(|load| load >= self.cpu_busy_percent) {
            LastResort::CpuBusy
        } else {
            LastResort::No
        }
    }
}

/// Why a host is tried after the others, in the order tried: `No` first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LastResort {
    #[default]
    No,
    CpuBusy,
    LowDisk,
}

impl LastResort {
    #[must_use]
    pub const fn as_str(self) -> Option<&'static str> {
        match self {
            Self::No => None,
            Self::CpuBusy => Some("cpu_busy"),
            Self::LowDisk => Some("low_disk"),
        }
    }
}

/// The statistics' settings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StatsConfig {
    pub samples_per_job: u32,
    pub retention: Duration,
    /// The memory a job of a repository never measured is assumed to need.
    pub default_job_ram: u64,
    /// Free memory a host must keep beyond the estimate to be placed on.
    pub ram_margin: u64,
    pub weights: Weights,
    pub guards: Guards,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            samples_per_job: 30,
            retention: Duration::from_secs(90 * 24 * 60 * 60),
            default_job_ram: 2 << 30,
            ram_margin: 512 << 20,
            weights: Weights::default(),
            guards: Guards::default(),
        }
    }
}

impl StatsConfig {
    fn oldest(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now - chrono::TimeDelta::from_std(self.retention).unwrap_or(chrono::TimeDelta::MAX)
    }
}

// ---------------------------------------------------------------------------
// Job identity and correlation
// ---------------------------------------------------------------------------

/// Which job a runner took, as GitHub names it.
///
/// GitHub's `workflow_name` on a job is the **run's title**, so a workflow with a
/// `run-name` (`load light [1,2] (tag)`) has a different one at every dispatch: a
/// key holding it never meets its own samples, and every queue falls back to its
/// repository's p90. Nothing on a `workflow_job` webhook names the workflow
/// stably. Its run does (`path`), and the run comes from the sweep or a request of
/// its own, so a job's workflow is known only sometimes: see [`Aggregates::job`]
/// for what a sample without one counts as.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JobIdentity {
    /// `owner/name`, lower-cased.
    pub repository: String,
    /// The job's name, matrix values included as GitHub expands them:
    /// `build (ubuntu, 3.12)`.
    pub job: String,
    /// Its run's workflow file, when that is known: `.github/workflows/ci.yml`.
    pub workflow: Option<String>,
}

/// Between a job and its workflow in a sample's key. A control character, so no
/// name can hold one: [`clean`] takes them out of what comes off the wire.
pub(crate) const WORKFLOW_SEPARATOR: char = '\u{1f}';

/// The part of `key` that names the job alone: what a sample of an older version
/// is keyed by, and one whose workflow was not known.
fn job_alone(key: &str) -> &str {
    key.split_once(WORKFLOW_SEPARATOR)
        .map_or(key, |(job, _)| job)
}

/// `key`, for people.
fn display_key(key: &str) -> String {
    match key.split_once(WORKFLOW_SEPARATOR) {
        Some((job, workflow)) => format!("{job} [{workflow}]"),
        None => key.to_string(),
    }
}

/// A name off the wire, reduced to something safe to store and print: no
/// control characters, at most [`MAX_NAME_CHARS`].
fn clean(raw: &str) -> String {
    printable(raw)
        .chars()
        .take(MAX_NAME_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

impl JobIdentity {
    /// From a webhook's or a job listing's fields; `None` without a job name.
    #[must_use]
    pub fn new(repository: &str, job: Option<&str>) -> Option<Self> {
        let identity = Self {
            repository: clean(repository).to_ascii_lowercase(),
            job: clean(job?),
            workflow: None,
        };
        (!identity.repository.is_empty() && !identity.job.is_empty()).then_some(identity)
    }

    /// With its run's workflow file, when known.
    #[must_use]
    pub fn in_workflow(mut self, workflow: Option<&str>) -> Self {
        self.workflow = workflow.map(clean).filter(|path| !path.is_empty());
        self
    }

    /// `owner/repo/job`, and its workflow when known: what samples are kept and
    /// aggregated by.
    #[must_use]
    pub fn key(&self) -> String {
        match &self.workflow {
            Some(workflow) => format!(
                "{}/{}{WORKFLOW_SEPARATOR}{workflow}",
                self.repository, self.job
            ),
            None => format!("{}/{}", self.repository, self.job),
        }
    }
}

/// Which workflow each run belongs to, as far as anyone has said: a webhook names
/// only the run, and the job's key wants its workflow.
#[derive(Debug, Default)]
pub struct RunWorkflows {
    known: Mutex<KnownRuns>,
    asked: Notify,
}

/// A run with `None` was asked about, and no answer has come.
#[derive(Debug, Default)]
struct KnownRuns {
    runs: HashMap<u64, Option<String>>,
    order: VecDeque<u64>,
    wanted: VecDeque<(String, u64)>,
}

impl KnownRuns {
    fn remember(&mut self, run_id: u64, workflow: Option<String>) {
        if self.runs.insert(run_id, workflow).is_none() {
            self.order.push_back(run_id);
        }
        if self.order.len() > RUN_MEMORY
            && let Some(oldest) = self.order.pop_front()
        {
            self.runs.remove(&oldest);
        }
    }
}

impl RunWorkflows {
    /// A sweep's run listing, or a request's answer.
    pub fn learn(&self, run_id: u64, workflow: String) {
        lock(&self.known).remember(run_id, Some(workflow));
    }

    /// `run_id`'s workflow file, if known.
    #[must_use]
    pub fn of(&self, run_id: u64) -> Option<String> {
        lock(&self.known).runs.get(&run_id).cloned().flatten()
    }

    /// Asks for `run_id`'s workflow once. The sweeper answers.
    pub fn want(&self, repository: &str, run_id: u64) {
        let mut known = lock(&self.known);
        if known.runs.contains_key(&run_id) {
            return;
        }
        known.remember(run_id, None);
        known.wanted.push_back((repository.to_string(), run_id));
        if known.wanted.len() > RUN_MEMORY {
            known.wanted.pop_front();
        }
        drop(known);
        self.asked.notify_one();
    }

    /// Waits until a run is asked about.
    pub async fn asked(&self) {
        self.asked.notified().await;
    }

    /// The runs to ask GitHub about, by repository and run id.
    pub fn take_wanted(&self) -> Vec<(String, u64)> {
        let mut known = lock(&self.known);
        let wanted = std::mem::take(&mut known.wanted);
        // A sweep may have listed one since it was asked about.
        wanted
            .into_iter()
            .filter(|(_, run_id)| matches!(known.runs.get(run_id), Some(None)))
            .collect()
    }
}

/// Joins a webhook's "runner R took job J" (and when it ran) with the host's
/// "runner R ended", in either order.
#[derive(Debug, Default)]
pub struct Correlator {
    identities: HashMap<String, (JobIdentity, JobTimes, Instant)>,
    /// Reports waiting for their job, or for its `completed` webhook.
    pending: HashMap<String, (String, AttemptFinished, Instant)>,
}

/// A host's report, now that its job is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correlated {
    pub host_id: String,
    pub identity: JobIdentity,
    pub times: JobTimes,
    pub finished: AttemptFinished,
}

/// When GitHub says a job was queued, started and completed: the
/// `workflow_job` webhook's `created_at`, `started_at` and `completed_at`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JobTimes {
    pub created_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    /// GitHub says the job did not succeed: how long it took says nothing of how
    /// fast its host is.
    pub failed: bool,
}

/// Whole seconds from `from` to `to`; `None` unless both are known and in
/// that order.
fn seconds_between(from: Option<DateTime<Utc>>, to: Option<DateTime<Utc>>) -> Option<u64> {
    u64::try_from((to? - from?).num_seconds()).ok()
}

impl JobTimes {
    /// From a webhook's fields. A time that does not parse is unknown: a
    /// malformed timestamp costs that figure, never the event.
    #[must_use]
    pub fn parse(created: Option<&str>, started: Option<&str>, completed: Option<&str>) -> Self {
        let at = |raw: Option<&str>| {
            DateTime::parse_from_rfc3339(raw?)
                .ok()
                .map(|at| at.with_timezone(&Utc))
        };
        Self {
            created_at: at(created),
            started_at: at(started),
            completed_at: at(completed),
            failed: false,
        }
    }

    /// The job's own run time on the runner.
    #[must_use]
    pub fn run_secs(&self) -> Option<u64> {
        seconds_between(self.started_at, self.completed_at)
    }

    /// How long the job waited for a runner.
    #[must_use]
    pub fn queue_wait_secs(&self) -> Option<u64> {
        seconds_between(self.created_at, self.started_at)
    }

    /// `newer`'s times over these, keeping a time `newer` does not have.
    fn merge(&mut self, newer: Self) {
        self.created_at = newer.created_at.or(self.created_at);
        self.started_at = newer.started_at.or(self.started_at);
        self.completed_at = newer.completed_at.or(self.completed_at);
        self.failed |= newer.failed;
    }
}

/// Makes room in `map` for one more entry: the oldest goes when it is full.
fn make_room<V>(map: &mut HashMap<String, V>, at: impl Fn(&V) -> Instant) {
    if map.len() < MAX_CORRELATIONS {
        return;
    }
    if let Some(oldest) = map
        .iter()
        .min_by_key(|(_, value)| at(value))
        .map(|(key, _)| key.clone())
    {
        map.remove(&oldest);
        tracing::warn!("job statistics correlation is full; the oldest entry was dropped");
    }
}

impl Correlator {
    fn forget_old(&mut self, now: Instant) {
        self.identities
            .retain(|_, (_, _, at)| now.saturating_duration_since(*at) < CORRELATION_MEMORY);
        self.pending
            .retain(|_, (_, _, at)| now.saturating_duration_since(*at) < PENDING_MEMORY);
    }

    /// A webhook named the job `runner` took (`in_progress`) or finished
    /// (`completed`), with its times; returns the host's report once the job
    /// is complete and the report is in.
    pub fn identified(
        &mut self,
        runner: &str,
        identity: JobIdentity,
        times: JobTimes,
        now: Instant,
    ) -> Option<Correlated> {
        // A runner this tool did not register (GitHub-hosted, another
        // scaler) never reports an attempt: nothing to remember.
        if !is_managed_runner_name(runner) {
            return None;
        }
        self.forget_old(now);
        let runner = runner.to_ascii_lowercase();
        let times = match self.identities.remove(&runner) {
            Some((_, mut known, _)) => {
                known.merge(times);
                known
            }
            None => {
                make_room(&mut self.identities, |(_, _, at)| *at);
                times
            }
        };
        if times.completed_at.is_some()
            && let Some((host_id, finished, _)) = self.pending.remove(&runner)
        {
            return Some(Correlated {
                host_id,
                identity,
                times,
                finished,
            });
        }
        self.identities.insert(runner, (identity, times, now));
        None
    }

    /// A host's attempt ended; returns it with its job if the webhooks
    /// already said everything. An attempt that took no job (an idle exit)
    /// is dropped: it has nothing to say about a job's weight. One that
    /// failed after taking a job (an out-of-memory kill) is exactly what
    /// placement must learn.
    pub fn finished(
        &mut self,
        host_id: &str,
        finished: AttemptFinished,
        now: Instant,
    ) -> Option<Correlated> {
        if !is_managed_runner_name(&finished.runner_name) {
            return None;
        }
        self.forget_old(now);
        let runner = finished.runner_name.to_ascii_lowercase();
        if !matches!(
            finished.outcome,
            AttemptOutcomeKind::CompletedJob | AttemptOutcomeKind::Failed
        ) {
            self.identities.remove(&runner);
            return None;
        }
        if self
            .identities
            .get(&runner)
            .is_some_and(|(_, times, _)| times.completed_at.is_some())
            && let Some((identity, times, _)) = self.identities.remove(&runner)
        {
            return Some(Correlated {
                host_id: host_id.to_string(),
                identity,
                times,
                finished,
            });
        }
        make_room(&mut self.pending, |(_, _, at)| *at);
        self.pending
            .insert(runner, (host_id.to_string(), finished, now));
        None
    }

    /// Reports whose job is known but whose `completed` webhook has not come
    /// within [`COMPLETION_WAIT`]: recorded with what is known.
    pub fn overdue(&mut self, now: Instant) -> Vec<Correlated> {
        let due: Vec<String> = self
            .pending
            .iter()
            .filter(|(runner, (_, _, at))| {
                now.saturating_duration_since(*at) >= COMPLETION_WAIT
                    && self.identities.contains_key(*runner)
            })
            .map(|(runner, _)| runner.clone())
            .collect();
        due.into_iter()
            .filter_map(|runner| {
                let (host_id, finished, _) = self.pending.remove(&runner)?;
                let (identity, times, _) = self.identities.remove(&runner)?;
                Some(Correlated {
                    host_id,
                    identity,
                    times,
                    finished,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Aggregates
// ---------------------------------------------------------------------------

pub use runner_manager_domain::memory::percentile;

/// The percentile `p` of one optional field over `samples`.
fn field_percentile<T: Copy + Ord>(
    samples: &[&JobSample],
    field: impl Fn(&JobSample) -> Option<T>,
    p: u32,
) -> Option<T> {
    percentile(
        &samples.iter().filter_map(|s| field(s)).collect::<Vec<_>>(),
        p,
    )
}

/// One host's figures for one job key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRatio {
    /// Its median duration over the usual one, in thousandths.
    pub ratio: Option<u32>,
    pub samples: usize,
    /// Those with a duration: a failed job has none.
    pub timed: usize,
    pub median_secs: Option<u64>,
}

/// How much faster than usual `host` ran the keys whose [`HostRatio`]s are
/// `ratios`, in [-1, 1]: 0.5 for half the usual time, -1 for twice or more;
/// `None` with no sample.
#[must_use]
pub fn speed(ratios: &[BTreeMap<String, HostRatio>], host: &str) -> Option<f64> {
    let terms: Vec<f64> = ratios
        .iter()
        .filter_map(|by_host| by_host.get(host)?.ratio)
        .map(|ratio| (1.0 - f64::from(ratio) / 1000.0).clamp(-1.0, 1.0))
        .collect();
    #[allow(clippy::cast_precision_loss, reason = "a handful of terms")]
    let count = terms.len() as f64;
    (!terms.is_empty()).then(|| terms.iter().sum::<f64>() / count)
}

/// [`speed`] for a placement to go by: a host that never ran a key other hosts
/// have run counts as the fastest there could be for that key. Otherwise the host
/// with the most headroom keeps every job, and how the others compare is never
/// found out. Its first finished run settles it. A bonus, not a rule: a warm host,
/// or much more headroom, can still outscore it.
#[must_use]
pub fn speed_to_try(ratios: &[BTreeMap<String, HostRatio>], host: &str) -> f64 {
    let terms: Vec<f64> = ratios
        .iter()
        .filter(|by_host| by_host.values().any(|figures| figures.ratio.is_some()))
        .map(|by_host| {
            if by_host.contains_key(host) {
                speed(std::slice::from_ref(by_host), host).unwrap_or(0.0)
            } else {
                1.0
            }
        })
        .collect();
    #[allow(clippy::cast_precision_loss, reason = "a handful of terms")]
    let count = terms.len() as f64;
    if terms.is_empty() {
        0.0
    } else {
        terms.iter().sum::<f64>() / count
    }
}

/// The samples kept, grouped for the questions placement and `stats` ask.
#[derive(Debug, Default, Clone)]
pub struct Aggregates {
    by_key: BTreeMap<String, Vec<JobSample>>,
}

/// One job key's figures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobFigures {
    pub samples: usize,
    pub p50_duration_secs: Option<u64>,
    pub p50_queue_wait_secs: Option<u64>,
    pub p90_queue_wait_secs: Option<u64>,
    pub p90_peak_rss_bytes: Option<u64>,
    pub p90_cpu_millicores: Option<u32>,
}

impl Aggregates {
    /// `samples`, oldest first, keeping the newest `keep` per key.
    #[must_use]
    pub fn from_samples(samples: Vec<JobSample>, keep: usize) -> Self {
        let mut aggregates = Self::default();
        for sample in samples {
            aggregates.add(sample, keep);
        }
        aggregates
    }

    fn add(&mut self, sample: JobSample, keep: usize) {
        let samples = self.by_key.entry(sample.job_key.clone()).or_default();
        samples.push(sample);
        if samples.len() > keep {
            let surplus = samples.len() - keep;
            samples.drain(..surplus);
        }
    }

    fn expire(&mut self, oldest: DateTime<Utc>) {
        for samples in self.by_key.values_mut() {
            samples.retain(|sample| sample.finished_at >= oldest);
        }
        self.by_key.retain(|_, samples| !samples.is_empty());
    }

    /// The samples that speak for `key`.
    ///
    /// A key with a workflow: its own samples once [`ENOUGH_OF_ITS_OWN`] of them
    /// measured memory. Until then those of its job alone count too, kept by an
    /// older version or taken when the run's workflow was not known, so one quick
    /// failure does not stand for a job with a long history. Two workflows' jobs
    /// of one name were kept together there.
    ///
    /// A key without one: every sample of that job. A queued job's workflow is
    /// often not known yet, so this is what keeps it from reading as never
    /// measured. Its estimate may be another workflow's job of the same name, as
    /// it always was.
    fn speaking_for(&self, key: &str) -> Vec<&JobSample> {
        let own = self.by_key.get(key).into_iter().flatten();
        if key.contains(WORKFLOW_SEPARATOR) {
            let measured = own
                .clone()
                .filter(|sample| sample.peak_rss_bytes.is_some())
                .count();
            if measured >= ENOUGH_OF_ITS_OWN {
                return own.collect();
            }
            return own
                .chain(self.by_key.get(job_alone(key)).into_iter().flatten())
                .collect();
        }
        let variants = format!("{key}{WORKFLOW_SEPARATOR}");
        own.chain(
            self.by_key
                .range(variants.clone()..)
                .take_while(|(candidate, _)| candidate.starts_with(&variants))
                .flat_map(|(_, samples)| samples),
        )
        .collect()
    }

    /// The memory `key` is expected to need: its p90 peak, or more if one of its
    /// newest [`RECENT_SAMPLES`] needed more. A p90 over a long history answers
    /// slowly: with 30 samples kept, a job that turned heavy goes on being placed
    /// as light for three more runs, and each of those is what the host's
    /// out-of-memory killer finds.
    #[must_use]
    pub fn expected_peak(&self, key: &str) -> Option<u64> {
        expected_of(self.speaking_for(key))
    }

    /// What a runner `host_id` starts for `target` is expected to need: the
    /// heaviest of the target's job keys by [`Self::expected_peak`]'s rule. A
    /// runner takes any job its labels match, so the heaviest stands for them
    /// all. Only `host_id`'s own samples count once it has any for the target:
    /// a job key measured only elsewhere is likely one its labels never take
    /// (another OS's build), and would hold its memory for nothing. A target it
    /// never ran falls back to every host's samples. `None` without any sample
    /// measuring memory.
    #[must_use]
    pub fn target_estimate(&self, host_id: &str, target: &TargetRef) -> Option<TargetEstimate> {
        let measured = |own_only: bool| {
            self.by_key.values().map(move |key_samples| {
                key_samples
                    .iter()
                    .filter(|sample| sample.peak_rss_bytes.is_some())
                    .filter(|sample| target.covers(&sample.repository))
                    .filter(|sample| !own_only || sample.host_id == host_id)
                    .collect::<Vec<&JobSample>>()
            })
        };
        let own = measured(true).any(|samples| !samples.is_empty());
        let mut heaviest: Option<u64> = None;
        let mut samples = 0usize;
        for key_samples in measured(own) {
            samples += key_samples.len();
            heaviest = heaviest.max(expected_of(key_samples));
        }
        Some(TargetEstimate {
            target: target.clone(),
            peak_rss_bytes: heaviest?,
            samples: u32::try_from(samples).unwrap_or(u32::MAX),
            own,
        })
    }

    /// What placement weighs `key` by. See [`Self::speaking_for`].
    #[must_use]
    pub fn job(&self, key: &str) -> Option<JobFigures> {
        figures_of(&self.speaking_for(key))
    }

    /// What was kept under exactly `key`, for `stats`, which lists every key.
    fn kept_under(&self, key: &str) -> Vec<&JobSample> {
        self.by_key.get(key).into_iter().flatten().collect()
    }

    /// The p90 peak memory over every sample of `repository`.
    #[must_use]
    pub fn repository_p90_rss(&self, repository: &str) -> Option<u64> {
        let repository = repository.to_ascii_lowercase();
        let values: Vec<u64> = self
            .by_key
            .values()
            .flatten()
            .filter(|sample| sample.repository == repository)
            .filter_map(|sample| sample.peak_rss_bytes)
            .collect();
        percentile(&values, 90)
    }

    /// Per host: its median duration for `key` over the usual duration (the
    /// mean of every host's median, so one host's many samples do not make
    /// it the norm).
    #[must_use]
    pub fn host_ratios(&self, key: &str) -> BTreeMap<String, HostRatio> {
        ratios_of(&self.speaking_for(key))
    }
}

/// The memory `samples` of one job are expected to need: their p90 peak, or
/// more if one of the newest [`RECENT_SAMPLES`] needed more.
fn expected_of(mut samples: Vec<&JobSample>) -> Option<u64> {
    let p90 = field_percentile(&samples, |sample| sample.peak_rss_bytes, 90)?;
    samples.sort_unstable_by_key(|sample| std::cmp::Reverse(sample.finished_at));
    samples
        .iter()
        .filter_map(|sample| sample.peak_rss_bytes)
        .take(RECENT_SAMPLES)
        .chain([p90])
        .max()
}

/// A job's figures from `samples`; `None` without any.
fn figures_of(samples: &[&JobSample]) -> Option<JobFigures> {
    if samples.is_empty() {
        return None;
    }
    Some(JobFigures {
        samples: samples.len(),
        p50_duration_secs: field_percentile(samples, |s| s.duration_secs, 50),
        p50_queue_wait_secs: field_percentile(samples, |s| s.queue_wait_secs, 50),
        p90_queue_wait_secs: field_percentile(samples, |s| s.queue_wait_secs, 90),
        p90_peak_rss_bytes: field_percentile(samples, |s| s.peak_rss_bytes, 90),
        p90_cpu_millicores: field_percentile(samples, |s| s.cpu_avg_millicores, 90),
    })
}

/// Per host in `samples`, its median duration over the usual one.
fn ratios_of(samples: &[&JobSample]) -> BTreeMap<String, HostRatio> {
    let mut by_host: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for sample in samples {
        *counts.entry(&sample.host_id).or_default() += 1;
        by_host
            .entry(&sample.host_id)
            .or_default()
            .extend(sample.duration_secs);
    }
    let medians: BTreeMap<&str, Option<u64>> = by_host
        .iter()
        .map(|(host, durations)| (*host, percentile(durations, 50)))
        .collect();
    let known: Vec<u64> = medians.values().flatten().copied().collect();
    let usual = (!known.is_empty())
        .then(|| known.iter().sum::<u64>() / u64::try_from(known.len()).unwrap_or(1));
    counts
        .into_iter()
        .map(|(host, count)| {
            let median = medians.get(host).copied().flatten();
            let ratio = match (median, usual) {
                (Some(median), Some(usual)) if usual > 0 => {
                    u32::try_from(median.saturating_mul(1000) / usual).ok()
                }
                _ => None,
            };
            (
                host.to_string(),
                HostRatio {
                    ratio,
                    samples: count,
                    timed: by_host.get(host).map_or(0, Vec::len),
                    median_secs: median,
                },
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Demand and score
// ---------------------------------------------------------------------------

/// Where a queue's memory estimate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimateSource {
    /// A queued job key's own p90.
    Job,
    /// The repository's p90, for a job key never measured.
    Repository,
    /// [`StatsConfig::default_job_ram`]: nothing measured at all.
    Default,
}

impl EstimateSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Job => "job",
            Self::Repository => "repository",
            Self::Default => "default",
        }
    }
}

/// What a pool queue is expected to need from the host that takes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Demand {
    pub estimate: u64,
    pub source: EstimateSource,
    /// The heaviest queued job with samples of its own: what hosts are filtered
    /// by. A guess at a job never measured may exceed it, and only ranks.
    pub measured_job: Option<u64>,
    /// The named job keys queued, for the speed term.
    pub job_keys: Vec<String>,
    /// Any statistics at all for this queue: its keys or its repository.
    pub measured: bool,
    /// The most memory of any host that could serve this queue but is no contender
    /// now, its slots taken (`u64::MAX` when one's memory is unknown).
    pub fleet_ram: Option<u64>,
}

impl Aggregates {
    /// The demand of a queue of `repository` holding `job_keys` (and
    /// `unnamed` jobs the webhook never named): its heaviest job.
    #[must_use]
    pub fn demand(
        &self,
        repository: &str,
        job_keys: &[String],
        unnamed: bool,
        default_job_ram: u64,
    ) -> Demand {
        let mut job_keys = job_keys.to_vec();
        job_keys.sort();
        job_keys.dedup();
        let repository_p90 = self.repository_p90_rss(repository);
        let fallback = repository_p90.map_or((default_job_ram, EstimateSource::Default), |bytes| {
            (bytes, EstimateSource::Repository)
        });
        let mut heaviest: Option<(u64, EstimateSource)> = None;
        let mut measured_job: Option<u64> = None;
        let mut measured = repository_p90.is_some();
        let mut consider = |candidate: (u64, EstimateSource)| {
            if heaviest.is_none_or(|(bytes, _)| candidate.0 > bytes) {
                heaviest = Some(candidate);
            }
        };
        for key in &job_keys {
            match self.expected_peak(key) {
                Some(bytes) => {
                    measured = true;
                    measured_job = Some(measured_job.map_or(bytes, |known| known.max(bytes)));
                    consider((bytes, EstimateSource::Job));
                }
                None => consider(fallback),
            }
        }
        if unnamed || job_keys.is_empty() {
            consider(fallback);
        }
        let (estimate, source) = heaviest.unwrap_or(fallback);
        Demand {
            estimate,
            source,
            measured_job,
            job_keys,
            measured,
            fleet_ram: None,
        }
    }
}

impl Aggregates {
    /// What a lease of each queued job reserves, heaviest first: its expected peak,
    /// else the lesser of its repository's and `default_job_ram`, a guess that
    /// must not hold memory a measured job needs. `unnamed` jobs have no key.
    /// A lease reserves one of these: five jobs hold one heaviest job, not five.
    #[must_use]
    pub fn job_estimates(
        &self,
        repository: &str,
        job_keys: &[String],
        unnamed: usize,
        default_job_ram: u64,
    ) -> Vec<u64> {
        let fallback = self
            .repository_p90_rss(repository)
            .map_or(default_job_ram, |bytes| bytes.min(default_job_ram));
        let mut estimates: Vec<u64> = job_keys
            .iter()
            .map(|key| self.expected_peak(key).unwrap_or(fallback))
            .chain(std::iter::repeat_n(fallback, unnamed))
            .collect();
        estimates.sort_unstable_by(|a, b| b.cmp(a));
        estimates
    }
}

/// The memory a host must have free for a queue. Only a job's own samples filter:
/// its repository's p90 is a guess at a job never measured, and heavy samples of
/// another job must not keep it waiting. Nor when no host could ever hold it:
/// waiting would be forever, and the job is better run somewhere. A host big enough
/// with every slot taken still holds it, soon: its job waits for that host rather
/// than start on one too small.
fn required_memory(contenders: &[Contender], demand: &Demand, config: &StatsConfig) -> Option<u64> {
    let bytes = demand.measured_job?;
    let needed = bytes.saturating_add(config.ram_margin);
    let totals = contenders
        .iter()
        .map(|contender| contender.total_ram.unwrap_or(u64::MAX));
    let biggest = demand.fleet_ram.into_iter().chain(totals).max()?;
    if biggest < needed {
        return None;
    }
    // The biggest hosts all here, doing nothing and still too short: what holds their
    // memory is nothing placement can wait out, and a job that never starts never
    // says it has grown lighter. It asks for what they have, so it runs on one of
    // them; if that is less than the margin, on whichever the score says.
    let biggest_hosts = || {
        contenders
            .iter()
            .filter(move |contender| contender.total_ram == Some(biggest))
    };
    if demand.fleet_ram.is_none_or(|ram| ram < biggest)
        && biggest_hosts().next().is_some()
        && biggest_hosts().all(|host| host.idle() && !host.fits(bytes, config.ram_margin))
    {
        return biggest_hosts()
            .filter_map(Contender::available)
            .max()
            .and_then(|available| available.checked_sub(config.ram_margin));
    }
    Some(bytes)
}

/// The figures behind a fit, for the log: a host fits when `free_ram` less
/// `reserved`, and `total_ram` less `committed`, both hold `required` and
/// `ram_margin`. So a reading can tell a stale or low `free_ram` from memory spoken
/// for by open launches and running jobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FitFigures {
    pub host_id: String,
    pub free_ram: Option<u64>,
    pub total_ram: Option<u64>,
    pub reserved: u64,
    pub committed: u64,
    pub ram_margin: u64,
    pub required: Option<u64>,
}

/// The figures of the candidate with the most memory available: the one nearest
/// to fitting, if none does. One that reports no free memory is never filtered.
#[must_use]
pub fn roomiest(
    contenders: &[Contender],
    demand: &Demand,
    config: &StatsConfig,
) -> Option<FitFigures> {
    let required = required_memory(contenders, demand, config);
    contenders
        .iter()
        .max_by_key(|contender| contender.available().unwrap_or(u64::MAX))
        .map(|contender| FitFigures {
            host_id: contender.host_id.clone(),
            free_ram: contender.free_ram,
            total_ram: contender.total_ram,
            reserved: contender.reserved,
            committed: contender.committed,
            ram_margin: config.ram_margin,
            required,
        })
}

/// One host that could take the queue, as placement sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contender {
    pub host_id: String,
    pub warm: bool,
    /// Free memory by its last heartbeat.
    pub free_ram: Option<u64>,
    /// Its total memory, by its `hello`.
    pub total_ram: Option<u64>,
    pub busy_slots: u32,
    /// The estimates of the launches it accepted whose runner took no job
    /// yet: memory its heartbeat still shows free but that is spoken for.
    pub reserved: u64,
    /// The estimates of every launch on it whose job has not ended: what its
    /// total memory is spoken for by, whatever its jobs have grown to so far.
    pub committed: u64,
    /// Its CPU and disk by its last heartbeat, and its cores by its `hello`.
    pub load: Load,
}

/// A contender's CPU and disk, and whether they make it a last resort.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Load {
    pub cores: u32,
    pub cpu_load_percent: Option<u32>,
    pub disk_free: Option<u64>,
    pub last_resort: LastResort,
}

impl Load {
    /// Thousandths of a core idle; none known without a CPU load.
    fn idle_millicores(&self) -> u64 {
        self.cpu_load_percent.map_or(0, |load| {
            u64::from(self.cores) * 10 * u64::from(100u32.saturating_sub(load.min(100)))
        })
    }
}

impl Contender {
    /// What a new job can count on: what the host says is free, less what is
    /// still to come of its launches, and no more than its memory less all of
    /// them. A build's peak can come long after its reservation lapses, with the
    /// host's heartbeat showing that memory free until then.
    fn available(&self) -> Option<u64> {
        self.free_ram.map(|free| {
            let unclaimed = free.saturating_sub(self.reserved);
            self.total_ram.map_or(unclaimed, |total| {
                unclaimed.min(total.saturating_sub(self.committed))
            })
        })
    }

    const fn idle(&self) -> bool {
        self.busy_slots == 0 && self.reserved == 0 && self.committed == 0
    }

    fn fits(&self, bytes: u64, margin: u64) -> bool {
        self.available()
            .is_none_or(|available| available >= bytes.saturating_add(margin))
    }
}

/// Whether `host` has run these jobs enough to be judged, and came out slower than
/// usual by more than its checkout is worth.
fn warm_not_worth_it(ratios: &[BTreeMap<String, HostRatio>], host: &str) -> bool {
    let judged: Vec<BTreeMap<String, HostRatio>> = ratios
        .iter()
        .filter(|by_host| {
            by_host
                .get(host)
                .is_some_and(|figures| figures.timed >= WARM_JUDGED_AFTER)
        })
        .cloned()
        .collect();
    speed(&judged, host).is_some_and(|speed| speed < WARM_NOT_WORTH_IT)
}

/// Stage 3's order: a warm workspace, the most free memory, the fewest busy
/// slots, then the host id so the order is stable.
fn stage_three_order(a: &Contender, b: &Contender) -> std::cmp::Ordering {
    b.warm
        .cmp(&a.warm)
        .then_with(|| b.free_ram.unwrap_or(0).cmp(&a.free_ram.unwrap_or(0)))
        .then_with(|| a.busy_slots.cmp(&b.busy_slots))
        .then_with(|| a.host_id.cmp(&b.host_id))
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "a score is a few points; thousandths fit an i64 easily"
)]
fn thousandths(points: f64) -> i64 {
    (points * 1000.0).round() as i64
}

#[allow(
    clippy::cast_precision_loss,
    reason = "a ratio of two memory sizes; a few bits of precision lost are irrelevant"
)]
fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64 / whole as f64).clamp(0.0, 1.0)
    }
}

/// Scores `contenders` for `demand`, best first, the ones that do not fit
/// last (design 4.5, steps 2-4).
///
/// * **Filter**: with the job's own samples behind the estimate, a host whose
///   [available memory](Contender) cannot hold the estimate plus `margin` does not
///   fit. A guess (a repository's p90, or the default) filters nothing, and only
///   ranks.
/// * **Score** = `cache`·warm (unless measured slower than usual) +
///   `headroom`·(memory free after this job, as a share of the host's memory) +
///   `speed`·([`speed_to_try`]: how much faster than usual it
///   ran these job keys) + `cpu`·(its idle cores, as a share of the most any
///   contender has idle; 0 without a CPU load) − `bigfit`·(1 when a heavier
///   queued job, `heavier`, fits this host and no other, and this queue fits
///   another).
/// * **Order**: the hosts that fit first; among them, a [last resort](Guards)
///   (busy CPU, then low disk) after the rest; then by score, then stage 3's
///   order. With no statistics for this queue, stage 3's order alone after the
///   last-resort rule.
#[must_use]
pub fn score(
    contenders: &[Contender],
    demand: &Demand,
    heavier: Option<u64>,
    config: &StatsConfig,
    aggregates: &Aggregates,
) -> Vec<(Contender, HostScore)> {
    let weights = config.weights;
    // Only a job's own samples filter: its repository's p90 is a guess at a
    // job never measured, and heavy samples of another job must not keep it
    // waiting. Nor when no host could ever hold it: waiting would be forever,
    // and the job is better run somewhere.
    let required = required_memory(contenders, demand, config);
    let ratios: Vec<BTreeMap<String, HostRatio>> = demand
        .job_keys
        .iter()
        .map(|key| aggregates.host_ratios(key))
        .collect();
    let fits = |contender: &Contender| {
        required.is_none_or(|bytes| contender.fits(bytes, config.ram_margin))
    };
    let most_idle = contenders
        .iter()
        .map(|contender| contender.load.idle_millicores())
        .max()
        .unwrap_or(0);
    let mut scored: Vec<(Contender, HostScore)> = contenders
        .iter()
        .map(|contender| {
            let fit = fits(contender);
            let free_after = contender
                .available()
                .map(|available| available.saturating_sub(demand.estimate));
            let whole = contender.total_ram.or(contender.available()).unwrap_or(0);
            let headroom = free_after.map_or(0.0, |free| share(free, whole));
            let speed = speed_to_try(&ratios, &contender.host_id);
            // Measured durations already hold what its checkout saves: a warm host
            // measured slower than usual is not worth waiting out for its cache.
            let cache = if contender.warm && !warm_not_worth_it(&ratios, &contender.host_id) {
                1.0
            } else {
                0.0
            };
            let others_fit_this = contenders
                .iter()
                .any(|other| other.host_id != contender.host_id && fits(other));
            let bigfit = heavier.is_some_and(|heavier| {
                heavier >= demand.estimate.saturating_mul(2)
                    && others_fit_this
                    && contender.fits(heavier, config.ram_margin)
                    && !contenders.iter().any(|other| {
                        other.host_id != contender.host_id && other.fits(heavier, config.ram_margin)
                    })
            });
            let bigfit = if bigfit { 1.0 } else { 0.0 };
            let cpu = share(contender.load.idle_millicores(), most_idle);
            let total = weights.cache * cache
                + weights.headroom * headroom
                + weights.speed * speed
                + weights.cpu * cpu
                - weights.bigfit * bigfit;
            let score = HostScore {
                host_id: contender.host_id.clone(),
                fits: fit,
                free_after_bytes: free_after,
                cache: thousandths(weights.cache * cache),
                headroom: thousandths(weights.headroom * headroom),
                speed: thousandths(weights.speed * speed),
                bigfit: thousandths(weights.bigfit * bigfit),
                cpu: thousandths(weights.cpu * cpu),
                cpu_load_percent: contender.load.cpu_load_percent,
                disk_free_bytes: contender.load.disk_free,
                last_resort: contender.load.last_resort.as_str().map(str::to_string),
                total: thousandths(total),
            };
            (contender.clone(), score)
        })
        .collect();
    let weighted = demand.measured;
    scored.sort_by(|(a, a_score), (b, b_score)| {
        b_score
            .fits
            .cmp(&a_score.fits)
            .then_with(|| a.load.last_resort.cmp(&b.load.last_resort))
            .then_with(|| {
                if weighted {
                    b_score.total.cmp(&a_score.total)
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .then_with(|| stage_three_order(a, b))
    });
    scored
}

// ---------------------------------------------------------------------------
// The statistics service
// ---------------------------------------------------------------------------

/// The statistics the server keeps: samples in SQLite with an in-memory
/// copy for placement, the counters, and the last decisions.
#[derive(Debug)]
pub struct Statistics {
    db: Arc<Mutex<Store>>,
    config: StatsConfig,
    aggregates: Mutex<Aggregates>,
    correlator: Mutex<Correlator>,
    /// Not yet added to the database's counters.
    launches: AtomicU64,
    wakes: AtomicU64,
    unplaced: Mutex<HashMap<String, Instant>>,
    workflows: Arc<RunWorkflows>,
}

impl Statistics {
    /// What is known of runs' workflows, for the webhook and the sweep.
    #[must_use]
    pub fn run_workflows(&self) -> Arc<RunWorkflows> {
        Arc::clone(&self.workflows)
    }

    /// Loads the samples kept in `db`; starts empty (and says so) when they
    /// cannot be read: placement then falls back to stage 3's order.
    #[must_use]
    pub fn load(db: Arc<Mutex<Store>>, config: StatsConfig) -> Self {
        let samples = lock(&db)
            .samples(config.oldest(Utc::now()))
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "the job statistics could not be read; starting without");
                Vec::new()
            });
        Self {
            db,
            config,
            aggregates: Mutex::new(Aggregates::from_samples(
                samples,
                config.samples_per_job as usize,
            )),
            correlator: Mutex::new(Correlator::default()),
            launches: AtomicU64::new(0),
            wakes: AtomicU64::new(0),
            unplaced: Mutex::new(HashMap::new()),
            workflows: Arc::default(),
        }
    }

    #[must_use]
    pub const fn config(&self) -> &StatsConfig {
        &self.config
    }

    /// Runs `read` over the aggregates without copying them.
    pub fn with_aggregates<T>(&self, read: impl FnOnce(&Aggregates) -> T) -> T {
        read(&lock(&self.aggregates))
    }

    pub fn count_launch(&self) {
        self.launches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count_wakes(&self, woken: u64) {
        self.wakes.fetch_add(woken, Ordering::Relaxed);
    }

    /// Records the reports that waited [`COMPLETION_WAIT`] in vain for their
    /// `completed` webhook, and adds the counted launches and wakes to the
    /// database.
    pub fn flush(&self) {
        let overdue = lock(&self.correlator).overdue(crate::clock::now());
        for correlated in overdue {
            self.record(correlated);
        }
        let launches = self.launches.swap(0, Ordering::Relaxed);
        let wakes = self.wakes.swap(0, Ordering::Relaxed);
        if launches + wakes == 0 {
            return;
        }
        if let Err(error) = lock(&self.db).add_counters(launches, wakes) {
            tracing::warn!(%error, "the statistics counters could not be stored");
            self.launches.fetch_add(launches, Ordering::Relaxed);
            self.wakes.fetch_add(wakes, Ordering::Relaxed);
        }
    }

    /// A webhook said `runner` took (or finished) the job `identity`, at
    /// `times`.
    pub fn job_identified(&self, runner: &str, identity: JobIdentity, times: JobTimes) {
        let correlated =
            lock(&self.correlator).identified(runner, identity, times, crate::clock::now());
        if let Some(correlated) = correlated {
            self.record(correlated);
        }
    }

    /// `host_id`, whose memory is `host_ram` by its `hello`, reported an
    /// attempt that ended. A peak above the host's memory (shared pages
    /// counted once per process, or a confused host) is capped at it, so one
    /// bad sample cannot make a job too heavy for every host.
    pub fn attempt_finished(
        &self,
        host_id: &str,
        finished: &AttemptFinished,
        host_ram: Option<u64>,
    ) {
        let mut finished = finished.clone();
        if let (Some(usage), Some(ram)) = (finished.usage.as_mut(), host_ram) {
            usage.peak_rss_bytes = usage.peak_rss_bytes.min(ram);
        }
        let correlated = lock(&self.correlator).finished(host_id, finished, crate::clock::now());
        if let Some(correlated) = correlated {
            self.record(correlated);
        }
    }

    fn record(
        &self,
        Correlated {
            host_id,
            identity,
            times,
            finished,
        }: Correlated,
    ) {
        let usage = finished.usage;
        let now = Utc::now();
        // The job's own run time; the host's attempt (start, wait for a job,
        // cleanup) only when GitHub's times are missing.
        let (duration_secs, duration_source) = match times.run_secs() {
            // Its memory still counts, and a failure may be why it ended. Its time
            // does not: one that fails at once would read as the fastest host there is.
            _ if times.failed || finished.outcome == AttemptOutcomeKind::Failed => (None, "failed"),
            Some(secs) => (Some(secs), "webhook"),
            None => (finished.duration_secs, "host"),
        };
        let sample = JobSample {
            job_key: identity.key(),
            repository: identity.repository,
            host_id: host_id.clone(),
            finished_at: now,
            duration_secs,
            queue_wait_secs: times.queue_wait_secs(),
            peak_rss_bytes: usage
                .filter(|usage| usage.samples > 0)
                .map(|usage| usage.peak_rss_bytes),
            cpu_avg_millicores: usage
                .filter(|usage| usage.samples > 1)
                .map(|usage| usage.cpu_avg_millicores),
            cpu_peak_millicores: usage
                .filter(|usage| usage.samples > 1)
                .map(|usage| usage.cpu_peak_millicores),
        };
        let oldest = self.config.oldest(now);
        if let Err(error) =
            lock(&self.db).record_sample(&sample, self.config.samples_per_job, oldest)
        {
            tracing::warn!(%error, "a job sample could not be stored");
            return;
        }
        let queue_wait_secs = sample.queue_wait_secs;
        let mut aggregates = lock(&self.aggregates);
        aggregates.add(sample, self.config.samples_per_job as usize);
        aggregates.expire(oldest);
        tracing::info!(
            %host_id,
            peak_rss_bytes = usage.map_or(0, |usage| usage.peak_rss_bytes),
            duration_secs = duration_secs.unwrap_or_default(),
            duration_source,
            queue_wait_secs = queue_wait_secs.unwrap_or_default(),
            "a job sample was recorded"
        );
    }

    /// Records a placement decision; a queue no host fits only once a minute.
    pub fn decided(&self, decision: &PlacementDecision) {
        if decision.chosen.is_none() {
            let key = format!("{}|{}", decision.repository, decision.labels);
            let mut unplaced = lock(&self.unplaced);
            let now = crate::clock::now();
            unplaced.retain(|_, at| now.saturating_duration_since(*at) < UNPLACED_DECISION_EVERY);
            if unplaced.contains_key(&key) {
                return;
            }
            unplaced.insert(key, now);
        }
        let Ok(json) = serde_json::to_string(decision) else {
            return;
        };
        if let Err(error) = lock(&self.db).record_decision(&json, KEEP_DECISIONS) {
            tracing::warn!(%error, "a placement decision could not be stored");
        }
    }

    /// The report `stats` shows, counters not yet flushed included.
    ///
    /// # Errors
    /// SQLite's.
    pub fn report(&self, now: DateTime<Utc>) -> Result<StatsReport, StoreError> {
        self.report_with(now, None)
    }

    /// [`Self::report`] with placement's `live` state instead of the copy
    /// last saved.
    ///
    /// # Errors
    /// SQLite's.
    pub fn report_with(
        &self,
        now: DateTime<Utc>,
        live: Option<LiveState>,
    ) -> Result<StatsReport, StoreError> {
        let mut report = report(&lock(&self.db), &self.config, now)?;
        report.launches += self.launches.load(Ordering::Relaxed);
        report.wakes += self.wakes.load(Ordering::Relaxed);
        if let Some(live) = live {
            report.pending = live.pending;
            report.leases = live.leases;
            report.connected = live.connected;
            report.live_at = Some(now.timestamp());
        }
        Ok(fit_report(report))
    }

    /// Saves placement's `live` state for the admin CLI's `stats`.
    pub fn save_live(&self, live: &LiveState) {
        let Ok(json) = serde_json::to_string(live) else {
            return;
        };
        if let Err(error) = lock(&self.db).save_live_state(&json, Utc::now()) {
            tracing::warn!(%error, "the placement state could not be saved for stats");
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The report from the database alone: what the admin CLI prints.
///
/// # Errors
/// SQLite's.
pub fn report(
    store: &Store,
    config: &StatsConfig,
    now: DateTime<Utc>,
) -> Result<StatsReport, StoreError> {
    let samples = store.samples(config.oldest(now))?;
    let names: HashMap<String, String> = store
        .hosts()?
        .into_iter()
        .map(|host| (host.id, host.name))
        .collect();
    let counters = store.counters()?;
    let aggregates = Aggregates::from_samples(samples, config.samples_per_job as usize);

    let mut jobs: Vec<JobStats> = aggregates
        .by_key
        .keys()
        .filter_map(|key| {
            let samples = aggregates.kept_under(key);
            let figures = figures_of(&samples)?;
            let hosts = ratios_of(&samples)
                .into_iter()
                .map(|(host_id, figures)| HostJobStats {
                    host_name: names.get(&host_id).cloned(),
                    host_id,
                    samples: u32::try_from(figures.samples).unwrap_or(u32::MAX),
                    p50_duration_secs: figures.median_secs,
                    duration_ratio_permille: figures.ratio,
                })
                .take(REPORT_HOSTS_PER_JOB)
                .collect();
            Some(JobStats {
                job_key: display_key(key),
                samples: u32::try_from(figures.samples).unwrap_or(u32::MAX),
                p50_duration_secs: figures.p50_duration_secs,
                p50_queue_wait_secs: figures.p50_queue_wait_secs,
                p90_queue_wait_secs: figures.p90_queue_wait_secs,
                p90_peak_rss_bytes: figures.p90_peak_rss_bytes,
                p90_cpu_millicores: figures.p90_cpu_millicores,
                hosts,
            })
        })
        .collect();
    jobs.sort_by(|a, b| {
        b.p90_peak_rss_bytes
            .cmp(&a.p90_peak_rss_bytes)
            .then_with(|| a.job_key.cmp(&b.job_key))
    });
    jobs.truncate(REPORT_JOBS);

    let mut by_host: BTreeMap<&str, (u32, HashSet<&str>, Vec<u64>)> = BTreeMap::new();
    for sample in aggregates.by_key.values().flatten() {
        let entry = by_host.entry(&sample.host_id).or_default();
        entry.0 += 1;
        entry.1.insert(&sample.job_key);
        entry.2.extend(sample.peak_rss_bytes);
    }
    let hosts = by_host
        .into_iter()
        .map(|(host_id, (count, keys, rss))| HostStats {
            host_id: host_id.to_string(),
            host_name: names.get(host_id).cloned(),
            samples: count,
            job_keys: u32::try_from(keys.len()).unwrap_or(u32::MAX),
            p90_peak_rss_bytes: percentile(&rss, 90),
        })
        .collect();

    let waits: Vec<u64> = aggregates
        .by_key
        .values()
        .flatten()
        .filter_map(|sample| sample.queue_wait_secs)
        .collect();

    let decisions = store
        .decisions(REPORT_DECISIONS)?
        .iter()
        .filter_map(|json| serde_json::from_str(json).ok())
        .collect();
    let (live, live_at) = saved_live(store)?
        .map(|(live, at)| (live, Some(at.timestamp())))
        .unwrap_or_default();
    Ok(StatsReport {
        generated_at: now.timestamp(),
        samples_per_job: config.samples_per_job,
        retention_days: u32::try_from(config.retention.as_secs() / 86_400).unwrap_or(u32::MAX),
        launches: counters.launches,
        wakes: counters.wakes,
        samples: counters.samples,
        p50_queue_wait_secs: percentile(&waits, 50),
        p90_queue_wait_secs: percentile(&waits, 90),
        jobs,
        hosts,
        decisions,
        connected: live.connected,
        pending: live.pending,
        leases: live.leases,
        live_at,
    })
}

/// The live state the server last saved, and when; `None` when it saved none
/// or it cannot be read.
///
/// # Errors
/// SQLite's.
pub fn saved_live(store: &Store) -> Result<Option<(LiveState, DateTime<Utc>)>, StoreError> {
    Ok(store.live_state()?.and_then(|(json, at)| {
        serde_json::from_str::<LiveState>(&json)
            .ok()
            .map(|live| (live, at))
    }))
}

/// Placement's pending queues and open leases, and the connected hosts, as
/// the server saves them for the admin CLI.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LiveState {
    pub pending: Vec<PendingQueue>,
    pub leases: Vec<OpenLease>,
    /// Absent from a copy saved before 0.4.52.
    #[serde(default)]
    pub connected: Vec<ConnectedHostStats>,
}

/// Trims a report until its message fits one WebSocket frame: decisions
/// first, then the lightest jobs.
#[must_use]
pub fn fit_report(mut report: StatsReport) -> StatsReport {
    let budget = MAX_MESSAGE_BYTES - 1024;
    while ServerMessage::Stats(report.clone()).encode().len() > budget {
        if report.decisions.pop().is_some()
            || report.connected.pop().is_some()
            || report.leases.pop().is_some()
            || report.pending.pop().is_some()
            || report.jobs.pop().is_some()
        {
            continue;
        }
        if report.hosts.pop().is_none() {
            break;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use runner_manager_domain::coordinator_protocol::AttemptUsage;

    use super::*;

    const GIB: u64 = 1 << 30;

    fn finished(runner: &str, outcome: AttemptOutcomeKind, rss: u64) -> AttemptFinished {
        AttemptFinished {
            lease_id: None,
            runner_name: runner.into(),
            outcome,
            duration_secs: Some(100),
            usage: Some(AttemptUsage {
                peak_rss_bytes: rss,
                cpu_avg_millicores: 1000,
                cpu_peak_millicores: 4000,
                samples: 10,
            }),
        }
    }

    fn identity(job: &str) -> JobIdentity {
        JobIdentity::new("Octo/App", Some(job)).expect("named")
    }

    /// Jobs of one name in two workflows keep their own figures once their
    /// workflows are known; samples from before that keep working.
    #[test]
    fn a_jobs_workflow_tells_it_from_another_of_the_same_name() {
        let ci = identity("build")
            .in_workflow(Some(".github/workflows/ci.yml"))
            .key();
        let nightly = identity("build")
            .in_workflow(Some(".github/workflows/nightly.yml"))
            .key();
        let alone = identity("build").key();
        assert_eq!(alone, "octo/app/build", "as an older version kept it");

        // Only old data: both workflows, and a queued job not yet placed in one,
        // read what was kept for the job.
        let mut aggregates = Aggregates::default();
        aggregates.add(sample(&alone, "h1", 60, 3 * GIB), 30);
        for key in [&ci, &nightly, &alone] {
            assert_eq!(
                aggregates.job(key).unwrap().p90_peak_rss_bytes,
                Some(3 * GIB)
            );
        }

        // One quick sample does not stand for its history.
        aggregates.add(sample(&ci, "h1", 60, GIB), 30);
        assert_eq!(aggregates.job(&ci).unwrap().samples, 2);
        assert_eq!(
            aggregates.job(&ci).unwrap().p90_peak_rss_bytes,
            Some(3 * GIB)
        );

        // Enough of its own, and they alone speak for a workflow.
        for _ in 1..ENOUGH_OF_ITS_OWN {
            aggregates.add(sample(&ci, "h1", 60, GIB), 30);
        }
        for _ in 0..ENOUGH_OF_ITS_OWN {
            aggregates.add(sample(&nightly, "h1", 60, 8 * GIB), 30);
        }
        assert_eq!(aggregates.job(&ci).unwrap().p90_peak_rss_bytes, Some(GIB));
        assert_eq!(aggregates.job(&ci).unwrap().samples, ENOUGH_OF_ITS_OWN);
        assert_eq!(
            aggregates.job(&nightly).unwrap().p90_peak_rss_bytes,
            Some(8 * GIB)
        );

        // A job whose workflow is not known yet counts all of them, so it does
        // not read as never measured.
        let everything = 1 + 2 * ENOUGH_OF_ITS_OWN;
        let any = aggregates.job(&alone).unwrap();
        assert_eq!(any.samples, everything);
        assert_eq!(any.p90_peak_rss_bytes, Some(8 * GIB));
        assert_eq!(aggregates.host_ratios(&alone)["h1"].samples, everything);
        assert_eq!(aggregates.host_ratios(&ci)["h1"].samples, ENOUGH_OF_ITS_OWN);

        // A job whose name starts the same is another job.
        let other = identity("build2").key();
        aggregates.add(sample(&other, "h1", 60, GIB), 30);
        assert_eq!(aggregates.job(&alone).unwrap().samples, everything);
    }

    /// The candidate nearest to fitting, with what decides it. Reading these, a
    /// host short of free memory is told from one whose memory is spoken for.
    #[test]
    fn the_roomiest_candidate_says_why_it_does_not_fit() {
        let contender = |host: &str, free, reserved| Contender {
            host_id: host.into(),
            warm: false,
            free_ram: free,
            total_ram: Some(32 * GIB),
            busy_slots: 1,
            reserved,
            committed: 0,
            load: Load::default(),
        };
        let config = StatsConfig::default();
        let demand = Demand {
            estimate: 4 * GIB,
            source: EstimateSource::Job,
            measured_job: Some(4 * GIB),
            job_keys: vec![],
            measured: true,
            fleet_ram: None,
        };
        let figures = roomiest(
            &[
                contender("low", Some(2 * GIB), 0),
                contender("spoken-for", Some(23 * GIB), 20 * GIB),
            ],
            &demand,
            &config,
        )
        .expect("a candidate");
        assert_eq!(figures.host_id, "spoken-for");
        assert_eq!(figures.free_ram, Some(23 * GIB));
        assert_eq!(figures.reserved, 20 * GIB);
        assert_eq!(figures.required, Some(4 * GIB));
        assert_eq!(figures.ram_margin, config.ram_margin);
        assert_eq!(roomiest(&[], &demand, &config), None);
    }

    /// `stats` lists each key once, as it was kept, and readably.
    #[test]
    fn stats_lists_a_jobs_workflows_apart() {
        let mut store = Store::open_in_memory().expect("store");
        let now = Utc::now();
        let ci = identity("build")
            .in_workflow(Some(".github/workflows/ci.yml"))
            .key();
        for key in ["octo/app/build", &ci] {
            let mut kept = sample(key, "h1", 60, GIB);
            kept.finished_at = now;
            store
                .record_sample(&kept, 30, now - chrono::Duration::days(1))
                .expect("stored");
        }
        let report = report(&store, &StatsConfig::default(), now).expect("report");
        let mut keys: Vec<(&str, u32)> = report
            .jobs
            .iter()
            .map(|job| (job.job_key.as_str(), job.samples))
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                ("octo/app/build", 1),
                ("octo/app/build [.github/workflows/ci.yml]", 1)
            ]
        );
    }

    #[test]
    fn a_runs_workflow_is_asked_for_once_and_remembered() {
        let workflows = RunWorkflows::default();
        assert_eq!(workflows.of(9), None);
        workflows.want("octo/app", 9);
        workflows.want("octo/app", 9);
        assert_eq!(workflows.take_wanted(), vec![("octo/app".to_string(), 9)]);
        assert!(workflows.take_wanted().is_empty());
        workflows.want("octo/app", 9);
        assert!(workflows.take_wanted().is_empty(), "already asked");
        workflows.learn(9, ".github/workflows/ci.yml".into());
        assert_eq!(workflows.of(9).as_deref(), Some(".github/workflows/ci.yml"));
        workflows.learn(10, "ci.yml".into());
        workflows.want("octo/app", 10);
        assert!(workflows.take_wanted().is_empty(), "already known");
    }

    #[test]
    fn a_workflow_name_is_cleaned_like_any_other() {
        let key = identity("build")
            .in_workflow(Some("a\u{1f}b\u{202e}.yml"))
            .key();
        assert_eq!(key.matches(WORKFLOW_SEPARATOR).count(), 1);
        assert_eq!(
            identity("build").in_workflow(Some(" \u{1f} ")).workflow,
            None
        );
    }

    fn sample(key: &str, host: &str, secs: u64, rss: u64) -> JobSample {
        JobSample {
            job_key: key.into(),
            repository: "octo/app".into(),
            host_id: host.into(),
            finished_at: Utc::now(),
            duration_secs: Some(secs),
            queue_wait_secs: None,
            peak_rss_bytes: Some(rss),
            cpu_avg_millicores: Some(1000),
            cpu_peak_millicores: None,
        }
    }

    #[test]
    fn a_targets_estimate_is_its_heaviest_job_from_the_hosts_own_runs_first() {
        use runner_manager_domain::coordinator_protocol::TargetScope;
        let gib = 1u64 << 30;
        let mut samples = Vec::new();
        // MacM6 ran the smoke and the macOS build; the Windows build ran
        // only on the Windows host.
        for _ in 0..5 {
            samples.push(sample("octo/app/smoke", "macm6", 10, gib / 4));
            samples.push(sample("octo/app/build-macos", "macm6", 10, 6 * gib));
            samples.push(sample("octo/app/build-windows", "win", 10, 12 * gib));
        }
        let mut other = sample("other/repo/x", "win", 10, 40 * gib);
        other.repository = "other/repo".into();
        samples.push(other);
        let aggregates = Aggregates::from_samples(samples, 30);
        let repo = TargetRef {
            scope: TargetScope::Repo,
            name: "Octo/App".into(),
        };
        let mac = aggregates
            .target_estimate("macm6", &repo)
            .expect("measured");
        assert_eq!(mac.peak_rss_bytes, 6 * gib, "its own heaviest job");
        assert_eq!(mac.samples, 10);
        assert!(mac.own);
        let win = aggregates.target_estimate("win", &repo).expect("measured");
        assert_eq!(win.peak_rss_bytes, 12 * gib);
        // A host that never ran the target: every host's runs, the heaviest.
        let new = aggregates
            .target_estimate("linux", &repo)
            .expect("measured");
        assert_eq!(new.peak_rss_bytes, 12 * gib);
        assert_eq!(new.samples, 15);
        assert!(!new.own);
        // An organization covers every repository of its owner.
        let org = TargetRef {
            scope: TargetScope::Org,
            name: "other".into(),
        };
        assert_eq!(
            aggregates
                .target_estimate("macm6", &org)
                .map(|e| e.peak_rss_bytes),
            Some(40 * gib)
        );
        let unknown = TargetRef {
            scope: TargetScope::Repo,
            name: "nobody/here".into(),
        };
        assert_eq!(aggregates.target_estimate("macm6", &unknown), None);
    }

    #[test]
    fn percentiles_use_the_nearest_rank() {
        let values: Vec<u64> = (1..=10).collect();
        assert_eq!(percentile(&values, 50), Some(5));
        assert_eq!(percentile(&values, 90), Some(9));
        assert_eq!(percentile(&values, 100), Some(10));
        assert_eq!(percentile(&[7u64], 90), Some(7));
        assert_eq!(percentile::<u64>(&[], 50), None);
        let mut shuffled = vec![30u64, 10, 20];
        assert_eq!(percentile(&shuffled, 50), Some(20));
        shuffled.clear();
    }

    /// GitHub's times for a job queued at 10:00:00, started 4 s later and,
    /// with `completed`, done 14 s after that.
    fn times(completed: bool) -> JobTimes {
        JobTimes::parse(
            Some("2026-11-07T10:00:00Z"),
            Some("2026-11-07T10:00:04Z"),
            completed.then_some("2026-11-07T10:00:18Z"),
        )
    }

    #[test]
    fn a_webhook_identity_and_a_host_report_meet_in_either_order() {
        let mut correlator = Correlator::default();
        let now = Instant::now();
        // Both webhooks first, then the report.
        for completed in [false, true] {
            assert!(
                correlator
                    .identified(
                        "runner-manager-A",
                        identity("build (linux, 3.12)"),
                        times(completed),
                        now
                    )
                    .is_none()
            );
        }
        let met = correlator
            .finished(
                "h1",
                finished("runner-manager-a", AttemptOutcomeKind::CompletedJob, GIB),
                now,
            )
            .expect("matched case-blind");
        assert_eq!(met.host_id, "h1");
        assert_eq!(met.identity.key(), "octo/app/build (linux, 3.12)");
        assert_eq!(
            (met.times.run_secs(), met.times.queue_wait_secs()),
            (Some(14), Some(4))
        );
        // `in_progress`, the report, then `completed`: the report waits for it.
        correlator.identified("runner-manager-b", identity("test"), times(false), now);
        assert!(
            correlator
                .finished(
                    "h2",
                    finished("runner-manager-b", AttemptOutcomeKind::CompletedJob, GIB),
                    now,
                )
                .is_none(),
            "the job's end is not known yet"
        );
        let met = correlator
            .identified("runner-manager-b", identity("test"), times(true), now)
            .expect("the pending report");
        assert_eq!(
            (met.host_id.as_str(), met.finished.runner_name.as_str()),
            ("h2", "runner-manager-b")
        );
        assert_eq!(met.times.run_secs(), Some(14));
        // The report before any webhook: `completed` alone completes it.
        assert!(
            correlator
                .finished(
                    "h2",
                    finished("runner-manager-f", AttemptOutcomeKind::CompletedJob, GIB),
                    now,
                )
                .is_none()
        );
        assert!(
            correlator
                .identified("runner-manager-f", identity("test"), times(true), now)
                .is_some()
        );
        // An idle exit took no job: nothing to record, nothing kept.
        correlator.identified("runner-manager-c", identity("lint"), times(false), now);
        assert!(
            correlator
                .finished(
                    "h1",
                    finished("runner-manager-c", AttemptOutcomeKind::IdleExit, GIB),
                    now,
                )
                .is_none()
        );
        assert!(correlator.identities.is_empty() && correlator.pending.is_empty());
        // A failed attempt that had taken a job (an out-of-memory kill) is a
        // sample; a runner this tool never registers is not remembered.
        correlator.identified("runner-manager-e", identity("heavy"), times(true), now);
        assert!(
            correlator
                .finished(
                    "h1",
                    finished("runner-manager-e", AttemptOutcomeKind::Failed, GIB),
                    now,
                )
                .is_some()
        );
        correlator.identified("GitHub Actions 7", identity("hosted"), times(true), now);
        assert!(correlator.identities.is_empty());
        // A report nobody names is forgotten after a while.
        correlator.finished(
            "h1",
            finished("runner-manager-d", AttemptOutcomeKind::CompletedJob, GIB),
            now,
        );
        assert!(
            correlator
                .identified(
                    "runner-manager-d",
                    identity("x"),
                    times(true),
                    now + PENDING_MEMORY
                )
                .is_none()
        );
    }

    #[test]
    fn a_report_whose_completion_never_arrives_is_recorded_after_a_while() {
        let mut correlator = Correlator::default();
        let now = Instant::now();
        correlator.identified("runner-manager-l", identity("lost"), times(false), now);
        correlator.finished(
            "h1",
            finished("runner-manager-l", AttemptOutcomeKind::CompletedJob, GIB),
            now,
        );
        // A report with no job named at all is not due: it waits for one.
        correlator.finished(
            "h1",
            finished("runner-manager-u", AttemptOutcomeKind::CompletedJob, GIB),
            now,
        );
        assert!(correlator.overdue(now + COMPLETION_WAIT / 2).is_empty());
        let due = correlator.overdue(now + COMPLETION_WAIT);
        assert_eq!(due.len(), 1);
        // Known: when it waited and started; unknown: when it ended.
        assert_eq!(
            (due[0].times.run_secs(), due[0].times.queue_wait_secs()),
            (None, Some(4))
        );
        assert!(correlator.overdue(now + COMPLETION_WAIT * 2).is_empty());
        assert_eq!(correlator.pending.len(), 1, "the unnamed one still waits");
    }

    #[test]
    fn without_the_jobs_own_times_a_sample_counts_the_hosts_attempt() {
        let db = Arc::new(Mutex::new(Store::open_in_memory().expect("store")));
        let stats = Statistics::load(Arc::clone(&db), StatsConfig::default());
        stats.record(Correlated {
            host_id: "h1".into(),
            identity: identity("lost"),
            times: times(false),
            finished: finished("runner-manager-l", AttemptOutcomeKind::CompletedJob, GIB),
        });
        let figures = stats
            .with_aggregates(|aggregates| aggregates.job("octo/app/lost"))
            .expect("recorded");
        assert_eq!(figures.p50_duration_secs, Some(100), "the host's attempt");
        assert_eq!(
            figures.p50_queue_wait_secs,
            Some(4),
            "what is known is kept"
        );
    }

    /// A guess can exceed a measured job without hiding it: the queue's own
    /// samples still filter, and the guess alone does not.
    #[test]
    fn a_guess_never_hides_a_measured_heavy_job_from_the_filter() {
        // `build` is the repository's only job, at 6 GiB; `new` was never run.
        let aggregates = Aggregates::from_samples(
            (0..5)
                .map(|_| sample("octo/app/build", "h", 60, 6 * GIB))
                .collect(),
            30,
        );
        let contender = |free| Contender {
            host_id: "small".into(),
            warm: false,
            free_ram: Some(free),
            total_ram: Some(64 * GIB),
            busy_slots: 1,
            reserved: 0,
            committed: 0,
            load: Load::default(),
        };
        let config = StatsConfig::default();
        let fits = |job_keys: &[String]| {
            let demand = aggregates.demand("octo/app", job_keys, false, config.default_job_ram);
            score(&[contender(GIB)], &demand, None, &config, &aggregates)[0]
                .1
                .fits
        };
        let (build, new) = ("octo/app/build".to_string(), "octo/app/new".to_string());
        assert!(
            !fits(&[new.clone(), build]),
            "`new` first: `build` still filters"
        );
        assert!(fits(&[new]), "a guess alone does not");
        // A guess reserves at most the default, not the repository's p90.
        assert_eq!(
            aggregates.job_estimates("octo/app", &["octo/app/new".into()], 1, 2 * GIB),
            vec![2 * GIB, 2 * GIB]
        );
    }

    #[test]
    fn webhook_times_parse_leniently_and_never_go_backwards() {
        let backwards = JobTimes::parse(
            Some("2026-11-07T10:00:10Z"),
            Some("2026-11-07T10:00:04+00:00"),
            Some("2026-11-07T10:00:01Z"),
        );
        assert_eq!(
            (backwards.run_secs(), backwards.queue_wait_secs()),
            (None, None)
        );
        let garbled = JobTimes::parse(Some("yesterday"), None, Some(""));
        assert_eq!(garbled, JobTimes::default());
        let mut merged = times(false);
        merged.merge(JobTimes::parse(None, None, Some("2026-11-07T10:01:04Z")));
        assert_eq!(
            (merged.run_secs(), merged.queue_wait_secs()),
            (Some(60), Some(4))
        );
    }

    #[test]
    fn wire_names_are_cleaned_and_a_nameless_job_has_no_identity() {
        let identity =
            JobIdentity::new("Octo/App", Some(&format!("b\u{1b}[31m{}", "j".repeat(500))))
                .expect("named");
        assert!(identity.job.starts_with("b[31m"));
        assert_eq!(identity.job.len(), MAX_NAME_CHARS);
        assert!(JobIdentity::new("octo/app", None).is_none());
        assert!(JobIdentity::new("octo/app", Some("  ")).is_none());
    }

    #[test]
    fn aggregates_give_percentiles_ratios_and_a_repository_default() {
        let mut samples = Vec::new();
        for (index, rss) in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].into_iter().enumerate() {
            let host = if index % 2 == 0 { "fast" } else { "slow" };
            let secs = if host == "fast" { 50 } else { 200 };
            samples.push(sample("octo/app/build", host, secs, rss * GIB));
        }
        samples.push(sample("octo/app/lint", "fast", 10, GIB / 2));
        let aggregates = Aggregates::from_samples(samples, 30);
        let build = aggregates.job("octo/app/build").expect("figures");
        assert_eq!(build.samples, 10);
        assert_eq!(build.p90_peak_rss_bytes, Some(9 * GIB));
        assert_eq!(build.p50_duration_secs, Some(50));
        let ratios = aggregates.host_ratios("octo/app/build");
        // The usual time is the mean of the two medians, 125 s.
        assert_eq!(ratios["fast"].ratio, Some(400));
        assert_eq!(ratios["slow"].ratio, Some(1600));
        let ratios = [ratios];
        let close = |a: Option<f64>, b: f64| a.is_some_and(|a| (a - b).abs() < 1e-9);
        assert!(close(speed(&ratios, "slow"), -0.6));
        assert!(close(speed(&ratios, "fast"), 0.6));
        assert_eq!(speed(&ratios, "elsewhere"), None);
        assert_eq!(aggregates.repository_p90_rss("Octo/App"), Some(9 * GIB));
        assert_eq!(aggregates.repository_p90_rss("other/repo"), None);
    }

    #[test]
    fn a_queue_needs_its_heaviest_job_and_falls_back_to_its_repository_then_the_default() {
        let aggregates = Aggregates::from_samples(
            vec![
                sample("octo/app/build", "h", 60, 6 * GIB),
                sample("octo/app/lint", "h", 60, GIB),
            ],
            30,
        );
        let demand = aggregates.demand(
            "octo/app",
            &["octo/app/lint".into(), "octo/app/build".into()],
            false,
            2 * GIB,
        );
        assert_eq!(
            (demand.estimate, demand.source),
            (6 * GIB, EstimateSource::Job)
        );
        assert!(demand.measured);
        // A key never measured: the repository's p90.
        let demand = aggregates.demand("octo/app", &["octo/app/new".into()], false, 2 * GIB);
        assert_eq!(demand.source, EstimateSource::Repository);
        assert_eq!(demand.estimate, 6 * GIB);
        // A repository never measured, and a job only the sweep counted.
        let demand = aggregates.demand("other/repo", &[], true, 2 * GIB);
        assert_eq!(
            (demand.estimate, demand.source),
            (2 * GIB, EstimateSource::Default)
        );
        assert!(!demand.measured);
    }

    fn contender(id: &str, free: u64, total: u64) -> Contender {
        Contender {
            host_id: id.into(),
            warm: false,
            free_ram: Some(free),
            total_ram: Some(total),
            busy_slots: 0,
            reserved: 0,
            committed: 0,
            load: Load::default(),
        }
    }

    fn order(scored: &[(Contender, HostScore)]) -> Vec<(&str, bool)> {
        scored
            .iter()
            .map(|(contender, score)| (contender.host_id.as_str(), score.fits))
            .collect()
    }

    #[test]
    fn a_host_that_cannot_hold_the_estimate_with_its_margin_and_leases_does_not_fit() {
        let config = StatsConfig::default();
        let demand = Demand {
            estimate: 4 * GIB,
            source: EstimateSource::Job,
            measured_job: Some(4 * GIB),
            job_keys: vec![],
            measured: true,
            fleet_ram: None,
        };
        let mut leased = contender("leased", 8 * GIB, 64 * GIB);
        leased.reserved = 4 * GIB;
        let scored = score(
            &[
                contender("small", 4 * GIB, 8 * GIB),
                leased,
                contender("big", 40 * GIB, 64 * GIB),
            ],
            &demand,
            None,
            &config,
            &Aggregates::default(),
        );
        assert_eq!(
            order(&scored),
            vec![("big", true), ("leased", false), ("small", false)]
        );
        assert_eq!(scored[0].1.free_after_bytes, Some(36 * GIB));
    }

    #[test]
    fn busy_cpu_and_low_disk_make_a_last_resort_by_their_settings() {
        let guards = Guards::default();
        assert_eq!(guards.last_resort(None, None), LastResort::No);
        assert_eq!(guards.last_resort(Some(89), Some(10 * GIB)), LastResort::No);
        assert_eq!(guards.last_resort(Some(90), None), LastResort::CpuBusy);
        assert_eq!(
            guards.last_resort(Some(100), Some(10 * GIB - 1)),
            LastResort::LowDisk,
            "low disk is the worse"
        );
        assert!(LastResort::No < LastResort::CpuBusy && LastResort::CpuBusy < LastResort::LowDisk);
        assert_eq!(LastResort::CpuBusy.as_str(), Some("cpu_busy"));
        assert_eq!(LastResort::No.as_str(), None);
    }

    fn loaded(id: &str, cores: u32, cpu: Option<u32>, disk: Option<u64>) -> Contender {
        let mut host = contender(id, 30 * GIB, 32 * GIB);
        host.load = Load {
            cores,
            cpu_load_percent: cpu,
            disk_free: disk,
            last_resort: Guards::default().last_resort(cpu, disk),
        };
        host
    }

    #[test]
    fn idle_cores_add_to_the_score_and_a_last_resort_goes_after_every_host_that_fits() {
        let config = StatsConfig::default();
        let demand = Demand {
            estimate: GIB,
            source: EstimateSource::Job,
            measured_job: Some(GIB),
            job_keys: vec![],
            measured: true,
            fleet_ram: None,
        };
        let scored = score(
            &[
                loaded("half-busy", 16, Some(50), None),
                loaded("idle", 16, Some(0), None),
                loaded("unknown", 16, None, None),
            ],
            &demand,
            None,
            &config,
            &Aggregates::default(),
        );
        let cpu: Vec<(&str, i64)> = scored
            .iter()
            .map(|(contender, score)| (contender.host_id.as_str(), score.cpu))
            .collect();
        // The most idle cores score the weight; half of them half; no reading, 0.
        assert_eq!(cpu, [("idle", 1000), ("half-busy", 500), ("unknown", 0)]);
        // Cores count: 32 at half load have as many idle as 16 at none.
        let scored = score(
            &[
                loaded("big", 32, Some(50), None),
                loaded("small", 16, Some(0), None),
            ],
            &demand,
            None,
            &config,
            &Aggregates::default(),
        );
        assert_eq!(scored[0].1.cpu, scored[1].1.cpu);

        // A last resort scores best yet comes after every host that fits, but
        // before one that does not.
        let mut too_full = loaded("too-full", 16, Some(0), None);
        too_full.free_ram = Some(0);
        let mut roomy_low_disk = loaded("low-disk", 64, Some(0), Some(GIB));
        roomy_low_disk.total_ram = Some(256 * GIB);
        roomy_low_disk.free_ram = Some(250 * GIB);
        let scored = score(
            &[
                too_full,
                roomy_low_disk,
                loaded("busy", 16, Some(95), None),
                loaded("plain", 16, Some(60), None),
            ],
            &demand,
            None,
            &config,
            &Aggregates::default(),
        );
        assert_eq!(
            order(&scored),
            [
                ("plain", true),
                ("busy", true),
                ("low-disk", true),
                ("too-full", false)
            ]
        );
        assert!(scored[2].1.total > scored[0].1.total);
        assert_eq!(scored[2].1.last_resort.as_deref(), Some("low_disk"));
    }

    #[test]
    fn the_score_prefers_warm_then_headroom_then_speed_and_spares_the_only_big_host() {
        let config = StatsConfig::default();
        let aggregates = Aggregates::from_samples(
            vec![
                sample("k", "fast", 50, GIB),
                sample("k", "fast", 50, GIB),
                sample("k", "slow", 150, GIB),
            ],
            30,
        );
        let light = Demand {
            estimate: GIB,
            source: EstimateSource::Job,
            measured_job: Some(GIB),
            job_keys: vec!["k".into()],
            measured: true,
            fleet_ram: None,
        };
        // A warm workspace outweighs more headroom.
        let mut warm = contender("warm", 6 * GIB, 16 * GIB);
        warm.warm = true;
        let scored = score(
            &[contender("roomy", 30 * GIB, 32 * GIB), warm.clone()],
            &light,
            None,
            &config,
            &aggregates,
        );
        assert_eq!(order(&scored)[0].0, "warm");
        // Equal hosts but for their history: the faster one.
        let scored = score(
            &[
                contender("slow", 8 * GIB, 16 * GIB),
                contender("fast", 8 * GIB, 16 * GIB),
            ],
            &light,
            None,
            &config,
            &aggregates,
        );
        assert_eq!(order(&scored)[0].0, "fast");
        assert!(scored[0].1.speed > 0 && scored[1].1.speed < 0);
        // A 40 GiB job is queued too and only `big` can hold it: the light
        // job goes to the smaller host although `big` has more headroom.
        let scored = score(
            &[
                contender("big", 60 * GIB, 64 * GIB),
                contender("mid", 10 * GIB, 16 * GIB),
            ],
            &light,
            Some(40 * GIB),
            &config,
            &Aggregates::default(),
        );
        assert_eq!(order(&scored)[0].0, "mid", "{scored:?}");
        assert!(
            scored
                .iter()
                .any(|(c, s)| c.host_id == "big" && s.bigfit > 0)
        );
        // Without that heavy job, the roomier host wins.
        let scored = score(
            &[
                contender("big", 60 * GIB, 64 * GIB),
                contender("mid", 10 * GIB, 16 * GIB),
            ],
            &light,
            None,
            &config,
            &Aggregates::default(),
        );
        assert_eq!(order(&scored)[0].0, "big");
    }

    #[test]
    fn an_estimate_no_host_could_ever_hold_filters_nothing() {
        let config = StatsConfig::default();
        let demand = Demand {
            estimate: 40 * GIB,
            source: EstimateSource::Job,
            measured_job: Some(40 * GIB),
            job_keys: vec![],
            measured: true,
            fleet_ram: None,
        };
        let scored = score(
            &[
                contender("a", 10 * GIB, 16 * GIB),
                contender("b", 12 * GIB, 32 * GIB),
            ],
            &demand,
            None,
            &config,
            &Aggregates::default(),
        );
        assert!(scored.iter().all(|(_, score)| score.fits), "{scored:?}");
        // One host big enough, though busy now: the queue waits for it.
        let scored = score(
            &[
                contender("a", 10 * GIB, 16 * GIB),
                Contender {
                    busy_slots: 1,
                    ..contender("big", 12 * GIB, 64 * GIB)
                },
            ],
            &demand,
            None,
            &config,
            &Aggregates::default(),
        );
        assert!(scored.iter().all(|(_, score)| !score.fits));
    }

    #[test]
    fn with_no_statistics_nothing_is_filtered_and_the_order_is_stage_threes() {
        let config = StatsConfig::default();
        let demand = Aggregates::default().demand("octo/app", &[], true, config.default_job_ram);
        let mut warm_small = contender("warm-small", GIB, 8 * GIB);
        warm_small.warm = true;
        let mut busy = contender("busy", 32 * GIB, 64 * GIB);
        busy.busy_slots = 3;
        let idle = contender("idle", 32 * GIB, 64 * GIB);
        let unknown = Contender {
            free_ram: None,
            total_ram: None,
            ..contender("unknown", 0, 0)
        };
        let contenders = vec![unknown, idle, busy, warm_small];
        let scored = score(
            &contenders,
            &demand,
            Some(60 * GIB),
            &config,
            &Aggregates::default(),
        );
        let mut stage_three = contenders.clone();
        stage_three.sort_by(stage_three_order);
        assert_eq!(
            scored
                .iter()
                .map(|(c, _)| c.host_id.clone())
                .collect::<Vec<_>>(),
            stage_three
                .iter()
                .map(|c| c.host_id.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            order(&scored),
            vec![
                ("warm-small", true),
                ("idle", true),
                ("busy", true),
                ("unknown", true)
            ]
        );
    }

    #[test]
    fn statistics_record_a_correlated_attempt_and_report_it() {
        let db = Arc::new(Mutex::new(Store::open_in_memory().expect("store")));
        let stats = Statistics::load(Arc::clone(&db), StatsConfig::default());
        stats.job_identified("runner-manager-1", identity("build"), times(true));
        // A peak above the host's memory is capped at it.
        stats.job_identified("runner-manager-9", identity("inflated"), times(true));
        stats.attempt_finished(
            "h1",
            &finished(
                "runner-manager-9",
                AttemptOutcomeKind::CompletedJob,
                99 * GIB,
            ),
            Some(16 * GIB),
        );
        assert_eq!(
            stats.with_aggregates(|a| a
                .job("octo/app/inflated")
                .and_then(|j| j.p90_peak_rss_bytes)),
            Some(16 * GIB)
        );
        stats.attempt_finished(
            "h1",
            &finished(
                "runner-manager-1",
                AttemptOutcomeKind::CompletedJob,
                3 * GIB,
            ),
            None,
        );
        // An attempt nobody identified records nothing.
        stats.attempt_finished(
            "h1",
            &finished("runner-manager-2", AttemptOutcomeKind::CompletedJob, GIB),
            None,
        );
        stats.count_launch();
        stats.count_wakes(4);
        let figures = stats
            .with_aggregates(|aggregates| aggregates.job("octo/app/build"))
            .expect("in memory");
        assert_eq!(figures.p90_peak_rss_bytes, Some(3 * GIB));
        // The job's 14 s, not the host's 100 s attempt; and its 4 s wait.
        assert_eq!(figures.p50_duration_secs, Some(14));
        assert_eq!(figures.p90_queue_wait_secs, Some(4));
        let report = stats.report(Utc::now()).expect("report");
        assert_eq!((report.launches, report.wakes, report.samples), (1, 4, 2));
        assert_eq!(report.jobs.len(), 2);
        assert_eq!(
            (report.p50_queue_wait_secs, report.p90_queue_wait_secs),
            (Some(4), Some(4))
        );
        assert_eq!(report.jobs[0].p50_queue_wait_secs, Some(4));
        assert_eq!(report.hosts[0].host_id, "h1");
        // Flushed, the counters survive into a fresh load (the admin CLI).
        stats.flush();
        let again = Statistics::load(db, StatsConfig::default());
        let report = again.report(Utc::now()).expect("report");
        assert_eq!((report.launches, report.wakes), (1, 4));
        assert!(again.with_aggregates(|aggregates| aggregates.job("octo/app/build").is_some()));

        // Placement's live state: the server's own report shows it as of now;
        // the admin CLI reads the copy the server saved.
        let live = || LiveState {
            pending: vec![PendingQueue {
                repository: "octo/app".into(),
                queued: 2,
                reason: Some("no_free_slot".into()),
                ..PendingQueue::default()
            }],
            leases: Vec::new(),
            connected: vec![ConnectedHostStats {
                host_id: "h".into(),
                disk_free_bytes: Some(5 << 30),
                ..ConnectedHostStats::default()
            }],
        };
        let now = Utc::now();
        let report = again.report_with(now, Some(live())).expect("report");
        assert_eq!(
            (report.pending.len(), report.connected.len(), report.live_at),
            (1, 1, Some(now.timestamp()))
        );
        assert!(
            again.report(now).expect("report").pending.is_empty(),
            "nothing saved yet"
        );
        again.save_live(&live());
        let saved = again.report(now).expect("report");
        assert_eq!(saved.pending[0].queued, 2);
        assert_eq!(saved.connected[0].disk_free_bytes, Some(5 << 30));
        assert!(saved.live_at.is_some());
    }

    #[test]
    fn an_unplaceable_queue_is_recorded_once_a_minute_and_a_report_fits_one_frame() {
        let db = Arc::new(Mutex::new(Store::open_in_memory().expect("store")));
        let stats = Statistics::load(Arc::clone(&db), StatsConfig::default());
        let unplaced = PlacementDecision {
            repository: "octo/app".into(),
            labels: "rm-pool-linux".into(),
            ..PlacementDecision::default()
        };
        stats.decided(&unplaced);
        stats.decided(&unplaced);
        assert_eq!(lock(&db).decisions(10).expect("read").len(), 1);

        let huge = StatsReport {
            jobs: (0..200)
                .map(|index| JobStats {
                    job_key: format!("{index}-{}", "x".repeat(400)),
                    ..JobStats::default()
                })
                .collect(),
            decisions: (0..50)
                .map(|_| PlacementDecision {
                    repository: "y".repeat(400),
                    ..PlacementDecision::default()
                })
                .collect(),
            ..StatsReport::default()
        };
        let fitted = fit_report(huge);
        assert!(ServerMessage::Stats(fitted.clone()).encode().len() < MAX_MESSAGE_BYTES);
        assert!(fitted.decisions.is_empty() && !fitted.jobs.is_empty());
    }

    fn heavy_demand(fleet_ram: Option<u64>) -> Demand {
        Demand {
            estimate: 28 * GIB,
            source: EstimateSource::Job,
            measured_job: Some(28 * GIB),
            job_keys: vec!["octo/app/build".into()],
            measured: true,
            fleet_ram,
        }
    }

    /// The only host big enough has no slot free, so it is no contender: the job
    /// waits for it. It runs where it can only when no host could ever hold it.
    #[test]
    fn a_heavy_job_waits_for_a_big_host_with_no_slot_free_rather_than_start_too_small() {
        let config = StatsConfig::default();
        let aggregates = Aggregates::default();
        let small = [contender("small", 20 * GIB, 23 * GIB)];
        let fits = |fleet_ram| {
            score(&small, &heavy_demand(fleet_ram), None, &config, &aggregates)[0]
                .1
                .fits
        };
        assert!(!fits(Some(64 * GIB)));
        assert!(fits(Some(23 * GIB)));
        assert!(fits(None));
    }

    /// A build's peak can come long after its reservation lapsed, with the host's
    /// heartbeat showing that memory free until then.
    #[test]
    fn memory_spoken_for_counts_against_the_hosts_total_whatever_it_shows_free() {
        let mut host = contender("h", 40 * GIB, 64 * GIB);
        assert_eq!(host.available(), Some(40 * GIB));
        host.committed = 56 * GIB;
        assert_eq!(host.available(), Some(8 * GIB));
        host.reserved = 35 * GIB;
        assert_eq!(host.available(), Some(5 * GIB));
        // A host that reports no free memory is never filtered.
        host.free_ram = None;
        assert_eq!(host.available(), None);
    }

    /// The host with the most headroom would otherwise keep every job, and how
    /// the others compare would never be found out.
    #[test]
    fn a_host_that_never_ran_a_job_is_tried_once_and_then_judged_by_its_runs() {
        let config = StatsConfig::default();
        let demand = Demand {
            estimate: 4 * GIB,
            source: EstimateSource::Job,
            measured_job: Some(4 * GIB),
            job_keys: vec!["octo/app/build".into()],
            measured: true,
            fleet_ram: None,
        };
        let hosts = [
            contender("big", 60 * GIB, 64 * GIB),
            contender("small", 20 * GIB, 23 * GIB),
        ];
        let best = |samples: Vec<JobSample>| {
            let aggregates = Aggregates::from_samples(samples, 30);
            score(&hosts, &demand, None, &config, &aggregates)[0]
                .0
                .host_id
                .clone()
        };
        // Nothing measured anywhere: nothing to compare, headroom decides.
        assert_eq!(best(vec![]), "big");
        assert_eq!(
            best(vec![sample("octo/app/build", "big", 600, 4 * GIB)]),
            "small"
        );
        assert_eq!(
            best(vec![
                sample("octo/app/build", "big", 600, 4 * GIB),
                sample("octo/app/build", "small", 240, 4 * GIB),
            ]),
            "small"
        );
        assert_eq!(
            best(vec![
                sample("octo/app/build", "big", 240, 4 * GIB),
                sample("octo/app/build", "small", 600, 4 * GIB),
            ]),
            "big"
        );
    }

    #[test]
    fn a_warm_host_measured_slower_than_usual_is_not_kept_for_its_checkout() {
        let config = StatsConfig::default();
        let demand = Demand {
            estimate: GIB,
            source: EstimateSource::Job,
            measured_job: Some(GIB),
            job_keys: vec!["octo/app/build".into()],
            measured: true,
            fleet_ram: None,
        };
        let hosts = [
            Contender {
                warm: true,
                ..contender("warm", 6 * GIB, 8 * GIB)
            },
            contender("cold", 60 * GIB, 64 * GIB),
        ];
        let best = |warm: u64, cold: u64, runs: usize| {
            let mut samples = vec![sample("octo/app/build", "cold", cold, GIB)];
            samples.extend(vec![sample("octo/app/build", "warm", warm, GIB); runs]);
            let aggregates = Aggregates::from_samples(samples, 30);
            score(&hosts, &demand, None, &config, &aggregates)[0]
                .0
                .host_id
                .clone()
        };
        assert_eq!(best(200, 240, 3), "warm");
        // A little slower is noise; the checkout still counts.
        assert_eq!(best(250, 240, 3), "warm");
        assert_eq!(best(360, 240, 3), "cold");
        // Too few runs to judge by: the first is likely a full clone.
        assert_eq!(best(360, 240, 2), "warm");
    }

    /// One spike among a job's newest samples, above what its host has free even
    /// with nothing running: waiting would never end, and without a run the spike
    /// would never leave the newest samples.
    #[test]
    fn a_job_runs_on_the_biggest_host_idle_and_still_short_rather_than_wait_for_ever() {
        let config = StatsConfig::default();
        let fits = |busy_slots| {
            score(
                &[Contender {
                    busy_slots,
                    ..contender("h", 58 * GIB, 64 * GIB)
                }],
                &Demand {
                    estimate: 61 * GIB,
                    measured_job: Some(61 * GIB),
                    ..heavy_demand(None)
                },
                None,
                &config,
                &Aggregates::default(),
            )[0]
            .1
            .fits
        };
        assert!(!fits(2), "it has jobs to wait out");
        assert!(fits(0));
        // It runs on that host, not on whatever else scores best with no filter.
        let scored = |big: Contender| {
            score(
                &[big, contender("small", 14 * GIB, 16 * GIB)],
                &Demand {
                    estimate: 61 * GIB,
                    measured_job: Some(61 * GIB),
                    ..heavy_demand(None)
                },
                None,
                &config,
                &Aggregates::default(),
            )
        };
        let hosts = scored(contender("big", 58 * GIB, 64 * GIB));
        assert_eq!(hosts[0].0.host_id, "big");
        assert!(hosts[0].1.fits);
        assert!(!hosts[1].1.fits);
        // Another as big, its slots taken: the job waits for it.
        assert!(
            required_memory(
                &[contender("idle", 58 * GIB, 64 * GIB)],
                &Demand {
                    measured_job: Some(61 * GIB),
                    ..heavy_demand(Some(64 * GIB))
                },
                &config,
            ) == Some(61 * GIB)
        );
        // Another as big as it that would hold the job: nothing is relaxed.
        let required = required_memory(
            &[
                contender("idle", 50 * GIB, 64 * GIB),
                Contender {
                    busy_slots: 2,
                    ..contender("busy", 62 * GIB, 64 * GIB)
                },
            ],
            &Demand {
                measured_job: Some(58 * GIB),
                ..heavy_demand(None)
            },
            &config,
        );
        assert_eq!(required, Some(58 * GIB));
    }

    /// A job that fails at once says nothing of how fast its host is, or that host
    /// would take every job. Its memory still counts.
    #[test]
    fn a_failed_job_keeps_its_memory_figure_and_gives_no_speed() {
        let db = Arc::new(Mutex::new(Store::open_in_memory().expect("store")));
        let stats = Statistics::load(db, StatsConfig::default());
        let times = JobTimes {
            failed: true,
            ..JobTimes::parse(
                Some("2026-11-07T10:00:00Z"),
                Some("2026-11-07T10:00:00Z"),
                Some("2026-11-07T10:00:05Z"),
            )
        };
        stats.job_identified(
            "runner-manager-1",
            JobIdentity::new("octo/app", Some("build")).expect("named"),
            times,
        );
        stats.attempt_finished(
            "broken",
            &AttemptFinished {
                lease_id: None,
                runner_name: "runner-manager-1".into(),
                outcome: AttemptOutcomeKind::CompletedJob,
                duration_secs: Some(9),
                usage: Some(AttemptUsage {
                    peak_rss_bytes: GIB,
                    samples: 3,
                    ..AttemptUsage::default()
                }),
            },
            None,
        );
        stats.with_aggregates(|aggregates| {
            let key = "octo/app/build";
            let figures = aggregates.job(key).expect("a sample");
            assert_eq!(figures.p50_duration_secs, None);
            assert_eq!(figures.p90_peak_rss_bytes, Some(GIB));
            // No other host's time to weigh it against, and it has been tried.
            let ratios = [aggregates.host_ratios(key)];
            assert!((speed_to_try(&ratios, "broken") - 0.0).abs() < 1e-9);
        });
        let ratios = [Aggregates::from_samples(
            vec![
                JobSample {
                    duration_secs: None,
                    ..sample("octo/app/build", "broken", 5, GIB)
                },
                sample("octo/app/build", "good", 60, GIB),
            ],
            30,
        )
        .host_ratios("octo/app/build")];
        assert!((speed_to_try(&ratios, "broken") - 0.0).abs() < 1e-9);
        assert!((speed_to_try(&ratios, "unknown") - 1.0).abs() < 1e-9);
    }

    /// Thirty samples: a p90 would not see this for three more runs.
    #[test]
    fn a_job_that_turned_heavy_is_expected_heavy_from_its_next_run() {
        let at = |seconds| Utc::now() + chrono::TimeDelta::seconds(seconds);
        let mut samples: Vec<JobSample> = (0..29)
            .map(|index| JobSample {
                finished_at: at(index),
                ..sample("octo/app/build", "h", 60, 6 * GIB)
            })
            .collect();
        samples.push(JobSample {
            finished_at: at(100),
            ..sample("octo/app/build", "h", 60, 30 * GIB)
        });
        let aggregates = Aggregates::from_samples(samples.clone(), 30);
        let key = "octo/app/build";
        assert_eq!(
            aggregates.job(key).and_then(|job| job.p90_peak_rss_bytes),
            Some(6 * GIB)
        );
        assert_eq!(aggregates.expected_peak(key), Some(30 * GIB));
        // Three light runs later, a single spike has had its say.
        for index in 0..3 {
            samples.push(JobSample {
                finished_at: at(200 + index),
                ..sample(key, "h", 60, 6 * GIB)
            });
        }
        let aggregates = Aggregates::from_samples(samples, 30);
        assert_eq!(aggregates.expected_peak(key), Some(6 * GIB));
        assert_eq!(aggregates.expected_peak("octo/app/unknown"), None);
    }
}
