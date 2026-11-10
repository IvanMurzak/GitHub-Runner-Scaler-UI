//! Host memory admission in the daemon (0.4.53): whether this machine has the
//! memory for one more runner, asked before every start.
//!
//! The rule is [`runner_manager_domain::memory`]'s. This module supplies its
//! inputs:
//!
//! * **Free memory** — [`host_fitness::available_memory_bytes`], read at the
//!   moment of the decision.
//! * **Each profile's estimate** — the coordinator's figure for its target
//!   when one was sent ([`MemoryEstimates`]), else the p90 of this host's own
//!   measured peaks for the profile ([`AttemptMeters::peaks_of`]), else
//!   [`DEFAULT_ESTIMATE_BYTES`](runner_manager_domain::memory::DEFAULT_ESTIMATE_BYTES).
//!   A runner takes any job its labels match, so a figure stands for the
//!   heaviest of them, never for one job.
//! * **What running attempts may still use** — each holds its profile's
//!   estimate less what its process tree uses now ([`AttemptMeters::current_rss`]).
//! * **The setting** — `config/memory.toml` (`host set-memory-margin`), read at
//!   each decision so a change applies without a restart.
//!
//! A refused start is deferred, not failed: the demand stays queued and the
//! next pass asks again. Which profiles are waiting is written to
//! `state/memory-admission.toml` for `status`.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use runner_manager_agent::reconcile::MemoryGate;
use runner_manager_domain::attempt::RunnerAttempt;
use runner_manager_domain::coordinator_protocol::MemoryEstimates;
use runner_manager_domain::memory::{
    Estimate, MemoryFigures, MemorySettings, MemoryVerdict, Running, admit, gib, local_estimate,
    parse_size,
};
use runner_manager_domain::model::PolicyId;
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::Store;
use runner_manager_platform::host_fitness;
use runner_manager_platform::memory_admission::{self as records, Waiting};
use runner_manager_platform::paths::AppPaths;

use serde::Serialize;

use super::coordinator::target_ref;
use super::meters::AttemptMeters;
use super::{CliError, Context, Failure, HostSetMemoryMarginArgs, write_failed};

type FreeMemory = Box<dyn Fn() -> Option<u64> + Send + Sync>;

/// The daemon's memory admission, shared by every target loop, the
/// coordinator's launches and the link that receives the estimates.
pub struct HostMemory {
    paths: AppPaths,
    store: Arc<dyn Store>,
    meters: Arc<AttemptMeters>,
    coordinator: Mutex<MemoryEstimates>,
    waiting: Mutex<BTreeMap<PolicyId, Waiting>>,
    free: FreeMemory,
}

impl std::fmt::Debug for HostMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostMemory").finish_non_exhaustive()
    }
}

impl HostMemory {
    /// Admission over this machine's free memory, with the peaks kept under
    /// `paths`' state directory.
    #[must_use]
    pub fn new(paths: AppPaths, store: Arc<dyn Store>) -> Self {
        let meters = Arc::new(AttemptMeters::with_peaks_file(records::peaks_path(&paths)));
        Self {
            paths,
            store,
            meters,
            coordinator: Mutex::new(MemoryEstimates::default()),
            waiting: Mutex::new(BTreeMap::new()),
            free: Box::new(host_fitness::available_memory_bytes),
        }
    }

    /// Reads free memory from `free` instead of the machine.
    #[cfg(test)]
    #[must_use]
    pub fn with_free_memory(
        mut self,
        free: impl Fn() -> Option<u64> + Send + Sync + 'static,
    ) -> Self {
        self.free = Box::new(free);
        self
    }

    /// The meters admission reads, which the sampler and the link share.
    #[must_use]
    pub fn meters(&self) -> Arc<AttemptMeters> {
        Arc::clone(&self.meters)
    }

    /// The setting in force: the default when the file cannot be read, which
    /// `host show` reports.
    #[must_use]
    pub fn settings(&self) -> MemorySettings {
        records::settings(&self.paths).unwrap_or_default()
    }

    /// The coordinator's newest estimates replace the ones it sent before.
    pub fn set_coordinator_estimates(&self, estimates: MemoryEstimates) {
        *self
            .coordinator
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = estimates;
    }

    /// What one runner of `policy` is expected to need.
    #[must_use]
    pub fn estimate(&self, policy: &ScalePolicy) -> Estimate {
        let coordinator = self
            .coordinator
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .for_target(&target_ref(&policy.target))
            .map(|estimate| estimate.peak_rss_bytes);
        Estimate::choose(
            coordinator,
            local_estimate(&self.meters.peaks_of(policy.id)),
        )
    }

    /// Whether one more runner of `policy` fits beside `attempts` (every
    /// attempt on the host) and `pending` (runners promised but not yet
    /// started, by their estimates).
    #[must_use]
    pub fn verdict(
        &self,
        policy: &ScalePolicy,
        attempts: &[RunnerAttempt],
        pending: &[u64],
    ) -> MemoryVerdict {
        let settings = self.settings();
        if !settings.enabled {
            return MemoryVerdict::Unchecked;
        }
        // Unreadable: every attempt counts at the default estimate.
        let policies: HashMap<PolicyId, ScalePolicy> = self
            .store
            .policies()
            .unwrap_or_default()
            .into_iter()
            .map(|policy| (policy.id, policy))
            .collect();
        // A concluded attempt still awaiting cleanup holds a slot, but what it
        // still holds of memory (an isolated environment not yet removed) is
        // in `free` already, and it grows no more.
        let running: Vec<Running> = attempts
            .iter()
            .filter(|attempt| attempt.counts_against_capacity() && !attempt.state().is_terminal())
            .map(|attempt| Running {
                estimate: policies
                    .get(&attempt.policy_id)
                    .map_or_else(
                        || Estimate::choose(None, None),
                        |owner| self.estimate(owner),
                    )
                    .bytes,
                current_rss: self.meters.current_rss(attempt.id),
            })
            .chain(
                pending
                    .iter()
                    .copied()
                    .chain(self.claim_ahead_of(policy.id))
                    .map(|estimate| Running {
                        estimate,
                        current_rss: None,
                    }),
            )
            .collect();
        admit(
            (self.free)(),
            &running,
            self.estimate(policy),
            settings.margin_bytes,
        )
    }

    /// The estimate of the profile that has waited longest for memory, when
    /// it began waiting before `policy` did and was refused recently: it is
    /// served first. Without this a heavy profile could wait for ever behind
    /// light ones, each taking the memory the last one freed.
    fn claim_ahead_of(&self, policy: PolicyId) -> Option<u64> {
        let now = Utc::now();
        let fresh = chrono::TimeDelta::from_std(CLAIM_HELD_FOR).unwrap_or(chrono::TimeDelta::MAX);
        let waiting = self.waiting();
        let mine = waiting.get(&policy).and_then(|own| own.since);
        waiting
            .iter()
            .filter(|(other, _)| **other != policy)
            .filter(|(_, wait)| wait.at.is_some_and(|at| now - at <= fresh))
            .filter_map(|(_, wait)| Some((wait.since?, wait.estimate_bytes)))
            .filter(|(since, _)| mine.is_none_or(|mine| *since < mine))
            .min_by_key(|(since, _)| *since)
            .map(|(_, estimate)| estimate)
    }

    fn waiting(&self) -> std::sync::MutexGuard<'_, BTreeMap<PolicyId, Waiting>> {
        self.waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_waiting(&self, waiting: &BTreeMap<PolicyId, Waiting>) {
        let now = Utc::now();
        if let Err(error) =
            records::record_waiting(&self.paths, waiting.values().cloned().collect(), now)
        {
            tracing::warn!(%error, "the memory admission state could not be written");
        }
    }
}

impl MemoryGate for HostMemory {
    fn admit(&self, policy: &ScalePolicy, attempts: &[RunnerAttempt]) -> MemoryVerdict {
        let verdict = self.verdict(policy, attempts, &[]);
        if let MemoryVerdict::Defer(figures) = verdict {
            let mut waiting = self.waiting();
            note_waiting(&mut waiting, policy, &figures);
            self.write_waiting(&waiting);
        }
        verdict
    }

    fn admitted(&self, policy: &ScalePolicy) {
        let mut waiting = self.waiting();
        if waiting.remove(&policy.id).is_some() {
            self.write_waiting(&waiting);
        }
    }
}

/// Records that `policy` waits, keeping when its wait began.
fn note_waiting(
    waiting: &mut BTreeMap<PolicyId, Waiting>,
    policy: &ScalePolicy,
    figures: &MemoryFigures,
) {
    let now = Utc::now();
    let shown_for = chrono::TimeDelta::from_std(WAIT_SHOWN_FOR).unwrap_or(chrono::TimeDelta::MAX);
    // A wait whose demand went away is never cleared; one refused again long
    // after is a new wait.
    let since = waiting
        .get(&policy.id)
        .filter(|earlier| earlier.at.is_some_and(|at| now - at <= shown_for))
        .and_then(|earlier| earlier.since)
        .unwrap_or(now);
    waiting.insert(
        policy.id,
        Waiting::new(
            (
                policy.id.to_string(),
                policy.target.to_string(),
                policy.profile_name().as_str().to_string(),
            ),
            figures,
            since,
            now,
        ),
    );
}

// ---------------------------------------------------------------------------
// `host set-memory-margin`, `host show`, `status`
// ---------------------------------------------------------------------------

/// How long after its last refusal a waiting profile is still shown: the
/// daemon asks again at every pass while the demand is queued, and a wait
/// whose demand went away is never cleared otherwise.
pub const WAIT_SHOWN_FOR: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// How long after its last refusal the longest-waiting profile keeps its
/// claim on memory ahead of others: a few passes. Its demand gone, the claim
/// lapses.
const CLAIM_HELD_FOR: std::time::Duration = std::time::Duration::from_secs(2 * 60);

/// `host set-memory-margin SIZE|off|on`.
///
/// # Errors
/// [`Failure::InvalidArgument`] for a value that is not a size, `off` or `on`
/// (nothing is written then), and the local-state failures.
pub fn set_margin(
    context: &Context,
    args: &HostSetMemoryMarginArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this host's memory admission");
    // An unreadable file is replaced: this is the command that repairs it.
    let previous = records::settings(context.paths()).unwrap_or_default();
    let value = args.margin.trim();
    let next = match value.to_ascii_lowercase().as_str() {
        "off" => MemorySettings {
            enabled: false,
            ..previous
        },
        "on" => MemorySettings {
            enabled: true,
            ..previous
        },
        _ => MemorySettings {
            enabled: true,
            margin_bytes: parse_size(value).map_err(|reason| {
                CliError::with_remedy(
                    Failure::InvalidArgument,
                    reason,
                    "runner-manager host set-memory-margin 1GiB",
                )
            })?,
        },
    };
    records::set_settings(context.paths(), next).map_err(|error| {
        CliError::new(
            Failure::LocalState,
            format!("cannot write this host's memory admission setting: {error}"),
        )
    })?;
    writeln!(
        out,
        "memory admission: {} -> {}",
        describe(previous),
        describe(next)
    )
    .map_err(failed)?;
    writeln!(
        out,
        "Applies to the next runner the service starts; nothing running is stopped."
    )
    .map_err(failed)?;
    if next.enabled
        && host_fitness::physical_memory_bytes().is_some_and(|total| next.margin_bytes >= total)
    {
        writeln!(
            out,
            "Warning: the margin is at least this machine's memory, so only one runner at a \
             time will start (one always starts when nothing else runs)."
        )
        .map_err(failed)?;
    }
    Ok(())
}

/// `on, margin 1.0 GiB` or `off`.
#[must_use]
pub fn describe(settings: MemorySettings) -> String {
    if settings.enabled {
        format!("on, margin {}", gib(settings.margin_bytes))
    } else {
        "off".to_string()
    }
}

/// The setting as `host show` prints it, with what it is read from.
#[must_use]
pub fn describe_setting(context: &Context) -> String {
    match records::settings(context.paths()) {
        Ok(settings) => {
            let free =
                host_fitness::available_memory_bytes().map_or_else(|| "unknown".to_string(), gib);
            format!(
                "{} (`host set-memory-margin`); {free} free now",
                describe(settings)
            )
        }
        Err(error) => format!("unreadable, so the default applies: {error}"),
    }
}

/// Memory admission in `status --json`.
#[derive(Debug, Clone, Serialize)]
pub struct MemorySnapshot {
    pub enabled: bool,
    pub margin_bytes: u64,
    /// Why `config/memory.toml` could not be read; the defaults then apply.
    pub setting_unreadable: Option<String>,
    /// Profiles whose runners wait for memory, as the service last recorded,
    /// refused within the last five minutes.
    pub waiting: Vec<Waiting>,
}

impl MemorySnapshot {
    /// Read from `paths` at `now`.
    #[must_use]
    pub fn read(paths: &AppPaths, now: chrono::DateTime<Utc>) -> Self {
        let (settings, setting_unreadable) = match records::settings(paths) {
            Ok(settings) => (settings, None),
            Err(error) => (MemorySettings::default(), Some(error.to_string())),
        };
        let shown_for =
            chrono::TimeDelta::from_std(WAIT_SHOWN_FOR).unwrap_or(chrono::TimeDelta::MAX);
        // Off: nothing waits, whatever an earlier run recorded.
        let recorded = settings
            .enabled
            .then(|| records::last_waiting(paths).ok().flatten())
            .flatten()
            .map(|state| state.waiting)
            .unwrap_or_default();
        let waiting = recorded
            .into_iter()
            .filter(|waiting| waiting.at.is_some_and(|at| now - at <= shown_for))
            .collect();
        Self {
            enabled: settings.enabled,
            margin_bytes: settings.margin_bytes,
            setting_unreadable,
            waiting,
        }
    }

    /// One line when the setting is unreadable, and one per waiting
    /// profile: `waiting for memory: …`.
    ///
    /// # Errors
    /// The writer's.
    pub fn write_waiting(&self, out: &mut dyn Write) -> std::io::Result<()> {
        if let Some(reason) = &self.setting_unreadable {
            writeln!(
                out,
                "  memory setting            unreadable, so the defaults apply: {reason}"
            )?;
        }
        for waiting in &self.waiting {
            writeln!(
                out,
                "  waiting for memory: {} ({}) needs {} ({} {} estimate + {} margin), {} free less {} reserved for running jobs",
                waiting.target,
                waiting.profile,
                gib(waiting.needed_bytes()),
                gib(waiting.estimate_bytes),
                waiting.estimate_source,
                gib(waiting.margin_bytes),
                gib(waiting.free_bytes),
                gib(waiting.reserved_bytes),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runner_manager_domain::attempt::AttemptState;
    use runner_manager_domain::coordinator_protocol::TargetEstimate;
    use runner_manager_domain::memory::{DEFAULT_ESTIMATE_BYTES, EstimateSource};
    use runner_manager_domain::model::AttemptId;
    use runner_manager_domain::store::SqliteStore;
    use runner_manager_testkit::fixtures;

    const GIB: u64 = 1 << 30;

    fn setup(free: u64) -> (tempfile::TempDir, Arc<SqliteStore>, ScalePolicy, HostMemory) {
        let dir = tempfile::tempdir().expect("dir");
        let store = Arc::new(SqliteStore::open(dir.path().join("journal.db")).expect("store"));
        let host = fixtures::host().build();
        store.put_host(&host).expect("host");
        let policy = fixtures::policy()
            .repository("acme/unreal")
            .host(host.id)
            .autoscale("home", 4)
            .active()
            .build();
        store.insert_policy(&policy).expect("policy");
        let paths = AppPaths::rooted_at(dir.path());
        let memory = HostMemory::new(paths, Arc::clone(&store) as Arc<dyn Store>)
            .with_free_memory(move || Some(free));
        (dir, store, policy, memory)
    }

    fn busy(policy: &ScalePolicy) -> RunnerAttempt {
        fixtures::attempt()
            .id(AttemptId::new_random())
            .policy_id(policy.id)
            .state(AttemptState::Busy)
            .github_runner_id(1)
            .build()
    }

    fn coordinator_says(memory: &HostMemory, policy: &ScalePolicy, bytes: u64) {
        memory.set_coordinator_estimates(MemoryEstimates {
            estimates: vec![TargetEstimate {
                target: target_ref(&policy.target),
                peak_rss_bytes: bytes,
                samples: 5,
                own: true,
            }],
        });
    }

    #[test]
    fn the_estimate_is_the_coordinators_then_the_hosts_own_then_the_default() {
        let (_dir, _store, policy, memory) = setup(32 * GIB);
        assert_eq!(
            memory.estimate(&policy),
            Estimate {
                bytes: DEFAULT_ESTIMATE_BYTES,
                source: EstimateSource::Default
            }
        );
        memory
            .meters
            .set_peaks(policy.id, vec![3 * GIB, 5 * GIB, 4 * GIB]);
        assert_eq!(
            memory.estimate(&policy),
            Estimate {
                bytes: 5 * GIB,
                source: EstimateSource::Local
            }
        );
        coordinator_says(&memory, &policy, 12 * GIB);
        assert_eq!(
            memory.estimate(&policy),
            Estimate {
                bytes: 12 * GIB,
                source: EstimateSource::Coordinator
            }
        );
        // A newer message without this target: the host's own figure again.
        memory.set_coordinator_estimates(MemoryEstimates::default());
        assert_eq!(memory.estimate(&policy).source, EstimateSource::Local);
    }

    #[test]
    fn a_heavy_profile_waits_for_memory_and_says_so_until_admitted() {
        // MacM6: 24 GiB, one Unreal build (11.8 GiB by the coordinator)
        // running and not sampled yet, 14 GiB free.
        let (dir, _store, policy, memory) = setup(14 * GIB);
        coordinator_says(&memory, &policy, 11_800 << 20);
        let running = [busy(&policy)];
        let verdict = MemoryGate::admit(&memory, &policy, &running);
        let MemoryVerdict::Defer(figures) = verdict else {
            panic!("a second build does not fit: {verdict:?}");
        };
        assert_eq!(figures.reserved, 11_800 << 20, "nothing sampled yet");
        let paths = AppPaths::rooted_at(dir.path());
        let state = records::last_waiting(&paths)
            .expect("read")
            .expect("written");
        assert_eq!(state.waiting.len(), 1);
        assert_eq!(state.waiting[0].estimate_source, "coordinator");
        assert_eq!(state.waiting[0].free_bytes, 14 * GIB);

        // Nothing else running: admitted, even when it needs more than is free.
        assert!(matches!(
            MemoryGate::admit(&memory, &policy, &[]),
            MemoryVerdict::Admit(_)
        ));
        coordinator_says(&memory, &policy, 20 * GIB);
        assert!(matches!(
            MemoryGate::admit(&memory, &policy, &[]),
            MemoryVerdict::AdmitAlone(_)
        ));
        memory.admitted(&policy);
        let state = records::last_waiting(&paths)
            .expect("read")
            .expect("written");
        assert!(state.waiting.is_empty(), "the wait is over");
    }

    #[test]
    fn the_longest_waiting_profile_is_served_before_a_lighter_one() {
        let (_dir, store, heavy, memory) = setup(10 * GIB);
        let light = fixtures::policy()
            .id(PolicyId::from_u128(0x11))
            .repository("acme/app")
            .host(heavy.host_id)
            .autoscale("home", 4)
            .active()
            .build();
        store.insert_policy(&light).expect("policy");
        memory.set_coordinator_estimates(MemoryEstimates {
            estimates: vec![
                TargetEstimate {
                    target: target_ref(&heavy.target),
                    peak_rss_bytes: 8 * GIB,
                    samples: 5,
                    own: true,
                },
                TargetEstimate {
                    target: target_ref(&light.target),
                    peak_rss_bytes: 2 * GIB,
                    samples: 5,
                    own: true,
                },
            ],
        });
        let running = [busy(&light)];
        // 10 GiB free, 2 GiB reserved by the light build: the heavy one
        // (9 GiB with the margin) waits.
        assert!(!MemoryGate::admit(&memory, &heavy, &running).admits());
        // A second light build would fit (6 GiB available, 3 needed), but
        // the heavy one claims its 8 GiB first.
        assert!(!MemoryGate::admit(&memory, &light, &running).admits());
        // The heavy one is not held back by the light one waiting after it.
        assert!(MemoryGate::admit(&memory, &heavy, &[]).admits());
        memory.admitted(&heavy);
        assert!(MemoryGate::admit(&memory, &light, &running).admits());
    }

    #[test]
    fn status_shows_recent_waits_only_and_none_while_off() {
        let (dir, _store, policy, memory) = setup(GIB);
        coordinator_says(&memory, &policy, 4 * GIB);
        let _ = MemoryGate::admit(&memory, &policy, &[busy(&policy)]);
        let paths = AppPaths::rooted_at(dir.path());
        let now = Utc::now();
        assert_eq!(MemorySnapshot::read(&paths, now).waiting.len(), 1);
        let later = now + chrono::TimeDelta::minutes(6);
        assert!(MemorySnapshot::read(&paths, later).waiting.is_empty());
        records::set_settings(
            &paths,
            MemorySettings {
                enabled: false,
                margin_bytes: GIB,
            },
        )
        .expect("off");
        let off = MemorySnapshot::read(&paths, now);
        assert!(!off.enabled);
        assert!(off.waiting.is_empty());
    }

    #[test]
    fn a_promised_launch_holds_its_estimate_and_off_checks_nothing() {
        let (dir, _store, policy, memory) = setup(10 * GIB);
        coordinator_says(&memory, &policy, 4 * GIB);
        assert!(memory.verdict(&policy, &[], &[]).admits());
        assert!(
            !memory.verdict(&policy, &[], &[4 * GIB, 4 * GIB]).admits(),
            "two launches accepted and not started yet"
        );
        records::set_settings(
            &AppPaths::rooted_at(dir.path()),
            MemorySettings {
                enabled: false,
                margin_bytes: GIB,
            },
        )
        .expect("off");
        assert_eq!(
            memory.verdict(&policy, &[], &[4 * GIB, 4 * GIB]),
            MemoryVerdict::Unchecked
        );
    }
}
