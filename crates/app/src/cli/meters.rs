//! What each runner attempt uses, for the coordinator's job weight
//! statistics (`.taskflow/2026-11-07-coordinator-server`, stage 4, design
//! 4.6).
//!
//! While this host has joined a coordinator, every [`SAMPLE_EVERY`] the link
//! looks at the process tree of each live native attempt of its own policies
//! ([`runner_manager_platform::resource_usage::sample_trees`]) on a blocking
//! thread, so a slow `/proc` or process snapshot never holds up the reconcile
//! loop or the link. When the attempt ends, its `attempt_finished` carries
//! what the samples saw ([`AttemptUsage`]): the peak resident memory of the
//! tree, its average CPU over the attempt and its busiest interval.
//!
//! An isolated attempt (a container, a VM, a WSL distribution) has no host
//! process to look at and reports no usage. Nothing here is a figure the
//! host acts on; the coordinator uses it to estimate how heavy a job is.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runner_manager_coordinator_protocol::AttemptUsage;
use runner_manager_domain::model::{AttemptId, HostId};
use runner_manager_domain::store::Store;
use runner_manager_platform::resource_usage::{TreeUsage, sample_trees};
use tokio::time::Instant;

/// How often each live attempt's process tree is sampled.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(2);

/// How long a meter outlives its attempt's last sample, waiting for the
/// attempt report that takes it.
const KEEP_AFTER_LAST_SAMPLE: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy)]
struct Meter {
    first_at: Instant,
    first_cpu: Duration,
    last_at: Instant,
    last_cpu: Duration,
    peak_rss: u64,
    peak_millicores: u32,
    samples: u32,
}

/// CPU time over wall time, in thousandths of a CPU.
fn millicores(cpu: Duration, wall: Duration) -> Option<u32> {
    if wall.is_zero() {
        return None;
    }
    u32::try_from(cpu.as_micros().saturating_mul(1000) / wall.as_micros().max(1)).ok()
}

impl Meter {
    fn usage(&self) -> AttemptUsage {
        AttemptUsage {
            peak_rss_bytes: self.peak_rss,
            cpu_avg_millicores: millicores(
                self.last_cpu.saturating_sub(self.first_cpu),
                self.last_at.saturating_duration_since(self.first_at),
            )
            .unwrap_or(0),
            cpu_peak_millicores: self.peak_millicores,
            samples: self.samples,
        }
    }
}

/// The meters of this host's live attempts, keyed by attempt.
#[derive(Debug, Default)]
pub struct AttemptMeters {
    meters: Mutex<HashMap<AttemptId, Meter>>,
}

impl AttemptMeters {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<AttemptId, Meter>> {
        self.meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// One sample of `attempt`'s tree, taken at `at`.
    pub fn record(&self, attempt: AttemptId, at: Instant, usage: TreeUsage) {
        let mut meters = self.lock();
        let meter = meters.entry(attempt).or_insert(Meter {
            first_at: at,
            first_cpu: usage.cpu_time,
            last_at: at,
            last_cpu: usage.cpu_time,
            peak_rss: 0,
            peak_millicores: 0,
            samples: 0,
        });
        // A descendant that exited unreaped takes its CPU time with it: the
        // total never goes back.
        let cpu = usage.cpu_time.max(meter.last_cpu);
        if let Some(busy) = millicores(
            cpu.saturating_sub(meter.last_cpu),
            at.saturating_duration_since(meter.last_at),
        ) {
            meter.peak_millicores = meter.peak_millicores.max(busy);
        }
        meter.last_at = at;
        meter.last_cpu = cpu;
        meter.peak_rss = meter.peak_rss.max(usage.rss_bytes);
        meter.samples = meter.samples.saturating_add(1);
    }

    /// What `attempt` used, once: the meter is gone afterwards.
    pub fn take(&self, attempt: AttemptId) -> Option<AttemptUsage> {
        self.lock().remove(&attempt).map(|meter| meter.usage())
    }

    /// Forgets meters not sampled for a long while and not in `live`: an
    /// attempt whose report was never sent (the link was down when it ended).
    pub fn forget_stale(&self, live: &HashSet<AttemptId>, now: Instant) {
        self.lock().retain(|attempt, meter| {
            live.contains(attempt)
                || now.saturating_duration_since(meter.last_at) < KEEP_AFTER_LAST_SAMPLE
        });
    }

    /// One pass: samples every live native attempt of `host`'s own policies.
    /// Blocking: SQLite and the process table.
    pub fn sample_once(&self, store: &dyn Store, host: HostId) {
        let policies = store.policies().unwrap_or_default();
        let mut live = HashSet::new();
        let mut roots: Vec<(AttemptId, u32)> = Vec::new();
        for policy in policies.iter().filter(|policy| policy.is_owned_by(host)) {
            let Ok(attempts) = store.active_attempts_for_policy(policy.id) else {
                continue;
            };
            for attempt in attempts {
                live.insert(attempt.id);
                roots.extend(attempt.process_id().map(|pid| (attempt.id, pid)));
            }
        }
        // One look at the process table for every attempt.
        let pids: Vec<u32> = roots.iter().map(|(_, pid)| *pid).collect();
        let trees = sample_trees(&pids);
        let now = Instant::now();
        for (attempt, pid) in roots {
            if let Some(usage) = trees.get(&pid) {
                self.record(attempt, now, *usage);
            }
        }
        self.forget_stale(&live, now);
    }
}

/// Samples this host's attempts every [`SAMPLE_EVERY`] while `joined` says
/// it has joined a coordinator. Never returns.
pub async fn sample_attempts(
    meters: Arc<AttemptMeters>,
    store: Arc<dyn Store>,
    host: HostId,
    joined: impl Fn() -> bool + Send,
) {
    let mut ticks = tokio::time::interval(SAMPLE_EVERY);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        if !joined() {
            continue;
        }
        let (meters, store) = (Arc::clone(&meters), Arc::clone(&store));
        // A pass that panics or is cancelled loses one sample, nothing more.
        let _ = tokio::task::spawn_blocking(move || meters.sample_once(store.as_ref(), host)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(rss: u64, cpu_ms: u64) -> TreeUsage {
        TreeUsage {
            rss_bytes: rss,
            cpu_time: Duration::from_millis(cpu_ms),
            processes: 2,
        }
    }

    #[test]
    fn a_meter_keeps_the_peak_memory_and_the_average_and_busiest_cpu() {
        let meters = AttemptMeters::default();
        let attempt = AttemptId::new_random();
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        meters.record(attempt, at(0), tree(100, 0));
        // Two CPUs busy for two seconds.
        meters.record(attempt, at(2), tree(500, 4_000));
        // Idle for two, and a child that exited took 1 s of CPU with it.
        meters.record(attempt, at(4), tree(300, 3_000));
        // Half a CPU for four.
        meters.record(attempt, at(8), tree(200, 6_000));
        let usage = meters.take(attempt).expect("measured");
        assert_eq!(
            usage,
            AttemptUsage {
                peak_rss_bytes: 500,
                cpu_avg_millicores: 750,
                cpu_peak_millicores: 2000,
                samples: 4,
            }
        );
        assert_eq!(meters.take(attempt), None, "taken once");
    }

    #[test]
    fn a_single_sample_has_memory_and_no_cpu_rate() {
        let meters = AttemptMeters::default();
        let attempt = AttemptId::new_random();
        meters.record(attempt, Instant::now(), tree(42, 1_000));
        let usage = meters.take(attempt).expect("measured");
        assert_eq!(usage.peak_rss_bytes, 42);
        assert_eq!(
            (usage.cpu_avg_millicores, usage.cpu_peak_millicores),
            (0, 0)
        );
    }

    #[test]
    fn a_stale_meter_is_forgotten_and_a_live_one_kept() {
        let meters = AttemptMeters::default();
        let (live, stale) = (AttemptId::new_random(), AttemptId::new_random());
        let start = Instant::now();
        meters.record(live, start, tree(1, 0));
        meters.record(stale, start, tree(1, 0));
        meters.forget_stale(
            &HashSet::from([live]),
            start + KEEP_AFTER_LAST_SAMPLE + Duration::from_secs(1),
        );
        assert!(meters.take(live).is_some());
        assert!(meters.take(stale).is_none());
    }
}
