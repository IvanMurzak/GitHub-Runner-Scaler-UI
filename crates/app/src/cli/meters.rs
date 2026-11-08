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
//!
//! The same look notices a live attempt whose runner process is gone and
//! nudges its target loop, so the next pass concludes it and frees its slot
//! within seconds instead of at the next scheduled poll (up to 60 s). The
//! pass decides; a nudge only means "look now".

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runner_manager_domain::coordinator_protocol::AttemptUsage;
use runner_manager_domain::model::{AttemptId, HostId, ScaleTarget};
use runner_manager_domain::store::Store;
use runner_manager_platform::resource_usage::{TreeUsage, sample_trees};
use tokio::time::Instant;

/// How often each live attempt's process tree is sampled.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(2);

/// How soon an exited runner whose attempt is still live is announced again:
/// the 30-second floor of a target's own active polling.
const ANNOUNCE_AGAIN: Duration = Duration::from_secs(30);

/// How long a meter outlives its attempt's last sample, waiting for the
/// attempt report that takes it.
const KEEP_AFTER_LAST_SAMPLE: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy)]
struct Meter {
    first_at: Instant,
    last_at: Instant,
    /// The tree's CPU total at the last look.
    last_cpu: Duration,
    /// The increases of that total, added up: a descendant that exits takes
    /// its time out of the total, and new work after that must still count.
    used_cpu: Duration,
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
                self.used_cpu,
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
    /// Live attempts whose runner process was seen gone, and when that was
    /// last announced: again only after [`ANNOUNCE_AGAIN`], so an attempt a
    /// pass cannot conclude yet (GitHub unreachable) does not pull every poll
    /// forward, and one misread process table does not silence it for good.
    exited: Mutex<HashMap<AttemptId, Instant>>,
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
            last_at: at,
            last_cpu: usage.cpu_time,
            used_cpu: Duration::ZERO,
            peak_rss: 0,
            peak_millicores: 0,
            samples: 0,
        });
        // A descendant that exited took its CPU time out of the total: only
        // increases count, from wherever the total now stands.
        let increase = usage.cpu_time.saturating_sub(meter.last_cpu);
        if let Some(busy) = millicores(increase, at.saturating_duration_since(meter.last_at)) {
            meter.peak_millicores = meter.peak_millicores.max(busy);
        }
        meter.used_cpu = meter.used_cpu.saturating_add(increase);
        meter.last_at = at;
        meter.last_cpu = usage.cpu_time;
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
    /// Returns the targets of the attempts whose runner process is newly
    /// seen gone. Blocking: SQLite and the process table.
    pub fn sample_once(&self, store: &dyn Store, host: HostId) -> Vec<ScaleTarget> {
        let policies = store.policies().unwrap_or_default();
        let mut live = HashSet::new();
        let mut roots: Vec<(AttemptId, u32, &ScaleTarget)> = Vec::new();
        for policy in policies.iter().filter(|policy| policy.is_owned_by(host)) {
            let Ok(attempts) = store.active_attempts_for_policy(policy.id) else {
                continue;
            };
            for attempt in attempts {
                live.insert(attempt.id);
                roots.extend(
                    attempt
                        .process_id()
                        .map(|pid| (attempt.id, pid, &policy.target)),
                );
            }
        }
        // One look at the process table for every attempt.
        let pids: Vec<u32> = roots.iter().map(|(_, pid, _)| *pid).collect();
        let trees = sample_trees(&pids);
        let now = Instant::now();
        let mut exited = Vec::new();
        let mut seen = self
            .exited
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        seen.retain(|attempt, _| live.contains(attempt));
        for (attempt, pid, target) in roots {
            let Some(usage) = trees.get(&pid) else {
                let due = seen
                    .get(&attempt)
                    .is_none_or(|at| now.saturating_duration_since(*at) >= ANNOUNCE_AGAIN);
                if due {
                    seen.insert(attempt, now);
                    // A repeated target is harmless: a nudge is one permit.
                    exited.push(target.clone());
                }
                continue;
            };
            seen.remove(&attempt);
            self.record(attempt, now, *usage);
        }
        drop(seen);
        self.forget_stale(&live, now);
        exited
    }
}

/// Samples this host's attempts every [`SAMPLE_EVERY`] while `joined` says
/// it has joined a coordinator, and hands `exited` the targets whose runner
/// process just went away. Never returns.
pub async fn sample_attempts(
    meters: Arc<AttemptMeters>,
    store: Arc<dyn Store>,
    host: HostId,
    joined: impl Fn() -> bool + Send,
    exited: impl Fn(&ScaleTarget) + Send,
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
        let gone = tokio::task::spawn_blocking(move || meters.sample_once(store.as_ref(), host))
            .await
            .unwrap_or_default();
        for target in &gone {
            exited(target);
        }
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
        // Three quarters of a CPU for four: counted although the total only
        // now passes where it stood before the child exited.
        meters.record(attempt, at(8), tree(200, 6_000));
        let usage = meters.take(attempt).expect("measured");
        assert_eq!(
            usage,
            AttemptUsage {
                peak_rss_bytes: 500,
                cpu_avg_millicores: 875,
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

    /// A live attempt whose runner process is gone is announced by its
    /// target, so its loop concludes it now, and again only after a while;
    /// a running one is sampled.
    #[test]
    fn a_runner_whose_process_exited_is_announced_and_again_while_it_stays_live() {
        use runner_manager_domain::attempt::AttemptState;
        use runner_manager_domain::store::SqliteStore;
        use runner_manager_testkit::fixtures;

        let host = fixtures::host().build();
        let policy = fixtures::policy()
            .repository("octo/app")
            .host(host.id)
            .autoscale("home", 2)
            .active()
            .build();
        let store = SqliteStore::open_in_memory().expect("store");
        store.put_host(&host).expect("host");
        store.insert_policy(&policy).expect("policy");
        // A process that ran and was reaped: its PID names nothing now.
        let mut child = std::process::Command::new(std::env::current_exe().expect("exe"))
            .args(["--exact", "no-such-test", "--quiet"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("a short-lived child");
        let exited_pid = child.id();
        child.wait().expect("reaped");
        let (running, exited) = (AttemptId::new_random(), AttemptId::new_random());
        for (id, pid) in [(running, std::process::id()), (exited, exited_pid)] {
            store
                .record_attempt(
                    &fixtures::attempt()
                        .id(id)
                        .policy_id(policy.id)
                        .state(AttemptState::Busy)
                        .process_id(pid)
                        .build(),
                )
                .expect("recorded");
        }
        let meters = AttemptMeters::default();
        assert_eq!(
            meters.sample_once(&store, host.id),
            vec![policy.target.clone()]
        );
        assert!(
            meters.sample_once(&store, host.id).is_empty(),
            "not announced again at once"
        );
        // Still live a while later (its pass could not conclude it): again.
        meters
            .exited
            .lock()
            .expect("lock")
            .values_mut()
            .for_each(|at| *at = at.checked_sub(ANNOUNCE_AGAIN).expect("earlier"));
        assert_eq!(
            meters.sample_once(&store, host.id),
            vec![policy.target.clone()]
        );
        assert!(
            meters.take(running).is_some(),
            "the live runner was sampled"
        );
        assert!(meters.take(exited).is_none());
    }
}
