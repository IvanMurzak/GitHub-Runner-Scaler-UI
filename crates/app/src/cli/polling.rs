// owner: f1-cli-auth-host-status (demand polling intervals and their measured cost)

//! `host set-poll-interval`, the daemon's polling monitor, and how the measured
//! cost of polling is shown by `host show`, `status` and `host doctor`.
//!
//! # Two intervals
//!
//! * **Active** — `hosts.refresh_interval_secs`, default 60 s, floor 30 s. A
//!   target with a runner up, or with runs whose listings are changing, is
//!   polled this often. Its responses are full `200`s and each one is charged
//!   against the account's hourly quota.
//! * **Idle** — `config/polling.toml`, default 10 s, floor 5 s. A target with
//!   nothing happening is polled this often. Its polls are conditional
//!   requests GitHub answers `304 Not Modified`, which "does not count against
//!   your primary rate limit"
//!   (<https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#use-conditional-requests-if-appropriate>).
//!
//! # The projection is not the cost any more
//!
//! `host show` used to print a projection: every target priced at its
//! unconditional request count, every interval. With conditional polling an
//! idle target's real cost against the hourly quota is close to zero, so the
//! projection overstates it by roughly the share of `304`s. What is shown first
//! now is what the daemon **measured** (`state/poll-traffic.toml`): `200`s and
//! `304`s per hour, the account's remaining quota, and this host's busiest
//! minute against the secondary limit. The projection stays in `status --json`
//! for compatibility, described as the cost without conditional requests.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use runner_manager_agent::reconcile::{NextPoll, PollPace};
use runner_manager_domain::model::{
    Clock, HostId, IdlePollInterval, RefreshInterval, ScaleTarget, TargetScope,
};
use runner_manager_domain::store::Store;
use runner_manager_github::demand::RestDemand;
use runner_manager_github::rest::RateLimitKind;
use runner_manager_github::traffic::{
    PrimaryPressure, RateLimitSnapshot, SECONDARY_POINTS_PER_MINUTE, secondary_share_percent,
};
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::polling::{self as settings, PollTraffic};
use serde::Serialize;

use super::host::{local_host, local_host_or_create};
use super::{CliError, Context, Failure, HostSetPollIntervalArgs, write_failed};

/// Requests one idle repository costs per poll: the queued and the
/// in-progress run listings.
pub const IDLE_REQUESTS_PER_REPOSITORY: u32 = 2;

/// How often the daemon re-reads the intervals, so `host set-poll-interval`
/// takes effect without a restart.
const RELOAD_EVERY: Duration = Duration::from_secs(15);

/// How often the daemon rewrites `state/poll-traffic.toml`.
const WRITE_EVERY: Duration = Duration::from_secs(30);

/// A measurement older than this is reported as stale: the daemon writes it
/// every [`WRITE_EVERY`] while it runs.
pub const STALE_AFTER: Duration = Duration::from_secs(10 * 60);

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// `10s`, `2m`, `1m30s` or a bare number of seconds, as whole seconds.
///
/// # Errors
/// Anything else, or a value that does not fit in `u16` seconds.
pub fn parse_interval(text: &str) -> Result<u16, String> {
    let text = text.trim();
    let invalid = || format!("`{text}` is not a duration; write it as `10s`, `2m` or `90`");
    if text.is_empty() {
        return Err(invalid());
    }
    if text.bytes().all(|b| b.is_ascii_digit()) {
        return text.parse::<u16>().map_err(|_| invalid());
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        let unit = match ch {
            's' | 'S' => 1,
            'm' | 'M' => 60,
            'h' | 'H' => 3_600,
            _ => return Err(invalid()),
        };
        let value: u64 = digits.parse().map_err(|_| invalid())?;
        digits.clear();
        total = total.saturating_add(value.saturating_mul(unit));
    }
    if !digits.is_empty() {
        return Err(invalid());
    }
    u16::try_from(total).map_err(|_| format!("`{text}` is longer than {} seconds", u16::MAX))
}

// ---------------------------------------------------------------------------
// The intervals in force
// ---------------------------------------------------------------------------

/// The two intervals, as `host show` and `status` report them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intervals {
    pub active: RefreshInterval,
    pub idle: IdlePollInterval,
}

impl Intervals {
    /// `active`, with the default idle interval: what a reader that could
    /// not read `polling.toml` falls back to.
    #[must_use]
    pub fn with_default_idle(active: RefreshInterval) -> Self {
        Self {
            active,
            idle: IdlePollInterval::default(),
        }
    }

    /// The idle interval the daemon actually uses: never longer than the
    /// active one.
    #[must_use]
    pub fn effective_idle(&self) -> Duration {
        self.idle
            .as_duration()
            .min(Duration::from_secs(u64::from(self.active.as_secs())))
    }

    /// Requests a minute `repositories` idle repositories cost this host, at
    /// the effective idle interval. Each is a `304` while nothing changes, so
    /// free against the hourly quota, but each still counts against the
    /// secondary limit.
    #[must_use]
    pub fn idle_requests_per_minute(&self, repositories: u32) -> u32 {
        let secs = self.effective_idle().as_secs().max(1);
        u32::try_from(u64::from(repositories) * u64::from(IDLE_REQUESTS_PER_REPOSITORY) * 60 / secs)
            .unwrap_or(u32::MAX)
    }
}

/// The intervals configured for this host: the active one from its row (or
/// the default before it has one), the idle one from `config/polling.toml`.
///
/// An unreadable or below-floor `polling.toml` does not fail this: the
/// default idle interval stands in, which is also what the daemon polls at,
/// and the second half of the answer says why. Refusing instead would make
/// `host set-poll-interval`, the command that repairs the file, fail on the
/// file it is about to replace.
///
/// # Errors
/// The local-state failures reading the host row.
pub fn configured(
    context: &Context,
    store: &dyn Store,
) -> Result<(Intervals, Option<String>), CliError> {
    let active = local_host(store)?.map_or_else(RefreshInterval::default, |h| h.refresh_interval);
    Ok(match settings::idle_interval(context.paths()) {
        Ok(idle) => (Intervals { active, idle }, None),
        Err(error) => (
            Intervals::with_default_idle(active),
            Some(error.to_string()),
        ),
    })
}

/// Repository targets, and organization targets, among `targets`. An
/// organization's repository count is not known without asking GitHub.
#[must_use]
pub fn count_targets(targets: &[ScaleTarget]) -> (u32, u32) {
    let unique: std::collections::BTreeSet<&ScaleTarget> = targets.iter().collect();
    let organizations = unique
        .iter()
        .filter(|target| target.scope() == TargetScope::Organization)
        .count();
    let repositories = unique.len() - organizations;
    (
        u32::try_from(repositories).unwrap_or(u32::MAX),
        u32::try_from(organizations).unwrap_or(u32::MAX),
    )
}

// ---------------------------------------------------------------------------
// host set-poll-interval
// ---------------------------------------------------------------------------

/// # Errors
/// [`Failure::InvalidArgument`] for an interval under its floor or an idle
/// interval longer than the active one, and the local-state failures.
pub fn set_poll_interval(
    context: &Context,
    args: &HostSetPollIntervalArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this host's poll intervals");
    let store = context.store()?;
    let (before, unreadable) = configured(context, &store)?;
    let targets: Vec<ScaleTarget> = store
        .policies()
        .map(|policies| policies.into_iter().map(|policy| policy.target).collect())
        .unwrap_or_default();

    let invalid = |message: String| {
        CliError::with_remedy(
            Failure::InvalidArgument,
            format!("{message}. Nothing was changed."),
            "runner-manager host set-poll-interval --idle 10s --active 60s",
        )
    };
    let active = match args.active {
        Some(secs) => RefreshInterval::from_secs(secs).map_err(|error| {
            invalid(format!(
                "the active poll interval cannot be {secs}s: {error}. Active polls are full, \
                 charged responses: at the 30-second floor ten busy repositories already \
                 project about 4,800 an hour, nearly the account's whole hourly quota"
            ))
        })?,
        None => before.active,
    };
    let idle = match args.idle {
        Some(secs) => IdlePollInterval::from_secs(secs).map_err(|error| {
            invalid(format!(
                "the idle poll interval cannot be {secs}s: {error}. Idle polls are free against \
                 the hourly quota, but every one still counts toward GitHub's secondary limit \
                 of {SECONDARY_POINTS_PER_MINUTE} requests a minute"
            ))
        })?,
        None => before.idle,
    };
    if idle.as_secs() > active.as_secs() {
        return Err(invalid(format!(
            "an idle interval of {idle} is longer than the active interval of {active}, which \
             would make a target with nothing happening slower to notice new work than a busy one"
        )));
    }
    // The same gate the dashboard applies to the refresh interval, and only
    // for a shorter one: lengthening never adds load. Active polls are
    // charged, so the projection is the right yardstick for them.
    if active < before.active {
        let budget = super::host::HostBudget::of(active, &targets);
        if budget.exceeds_allowance() {
            return Err(CliError::with_remedy(
                Failure::BudgetRefused,
                format!(
                    "a {}-second active interval projects {} requests/hour for the configured \
                     targets, over the {} this host may plan to spend. Nothing was changed.",
                    active.as_secs(),
                    budget.requests_per_hour(),
                    budget.allowance()
                ),
                "choose a longer active interval or remove a target",
            ));
        }
    }

    // An unreadable file is rewritten even when the value is unchanged: that
    // is how this command repairs it.
    let idle_written = idle != before.idle || unreadable.is_some();
    if idle_written {
        settings::set_idle_interval(context.paths(), idle).map_err(|source| {
            CliError::new(
                Failure::LocalState,
                format!("cannot store the idle poll interval: {source}. Nothing was changed."),
            )
        })?;
    }
    if active != before.active {
        let stored = local_host_or_create(context, &store).and_then(|mut host| {
            host.refresh_interval = active;
            store
                .put_host(&host)
                .map_err(|source| CliError::new(Failure::LocalState, source.to_string()))
        });
        if let Err(error) = stored {
            return Err(CliError::new(
                Failure::LocalState,
                format!(
                    "cannot store the active poll interval: {error}{}",
                    if idle_written {
                        format!("; the idle interval was already stored as {idle}")
                    } else {
                        String::new()
                    }
                ),
            ));
        }
    }
    if let Some(reason) = &unreadable {
        writeln!(out, "replaced an unreadable config/polling.toml ({reason})").map_err(failed)?;
    }

    writeln!(out, "idle poll interval:   {} -> {idle}", before.idle).map_err(failed)?;
    writeln!(out, "active poll interval: {} -> {active}", before.active).map_err(failed)?;
    let after = Intervals { active, idle };
    let (repositories, organizations) = count_targets(&targets);
    writeln!(out).map_err(failed)?;
    write_idle_load(out, after, repositories, organizations).map_err(failed)?;
    writeln!(
        out,
        "A running service reads the intervals again every {} seconds and each target adopts \
         them at its next poll; nothing restarts.",
        RELOAD_EVERY.as_secs()
    )
    .map_err(failed)?;
    Ok(())
}

/// One paragraph on what idle polling costs this host, against the
/// secondary limit.
fn write_idle_load(
    out: &mut dyn Write,
    intervals: Intervals,
    repositories: u32,
    organizations: u32,
) -> io::Result<()> {
    let per_minute = intervals.idle_requests_per_minute(repositories);
    writeln!(
        out,
        "  idle polling costs about {per_minute} requests/minute for {repositories} repository \
         target(s){}",
        if organizations > 0 {
            format!(
                ", plus {} per repository in {organizations} organization target(s)",
                intervals.idle_requests_per_minute(1)
            )
        } else {
            String::new()
        }
    )?;
    writeln!(
        out,
        "  ({}% of GitHub's {SECONDARY_POINTS_PER_MINUTE}/minute secondary limit, which every host \
         signed in as the same user shares). Each is a conditional request answered `304`, free \
         against the hourly quota while nothing changes.",
        secondary_share_percent(per_minute)
    )
}

/// Whether a measurement written at `written_at` should be read as left
/// behind by a daemon that is no longer running.
///
/// The daemon's own heartbeat decides first. A loop asleep through a long
/// wait (a primary rate limit until its reset, an offline back-off, a
/// stretched active interval) writes no measurement meanwhile, and calling
/// that "not running" would hide the throttling the record exists to show,
/// at the moment it matters. Only without a beating daemon does the record's
/// age decide.
#[must_use]
pub fn is_stale(paths: &AppPaths, written_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    if matches!(
        runner_manager_platform::daemon_heartbeat::liveness(paths, now),
        runner_manager_platform::daemon_heartbeat::Liveness::Beating { .. }
    ) {
        return false;
    }
    now.signed_duration_since(written_at)
        .to_std()
        .is_ok_and(|age| age > STALE_AFTER)
}

// ---------------------------------------------------------------------------
// What host show, status and doctor print
// ---------------------------------------------------------------------------

/// The polling section of `status --json`.
#[derive(Debug, Clone, Serialize)]
pub struct PollingSnapshot {
    /// The configured idle interval.
    pub idle_interval_secs: u16,
    /// The idle interval the daemon uses: the configured one, capped at the
    /// active interval.
    pub effective_idle_interval_secs: u16,
    /// Why `config/polling.toml` could not be read, when it could not; the
    /// default idle interval stands in.
    pub idle_interval_unreadable: Option<String>,
    pub active_interval_secs: u16,
    /// Requests a minute idle polling of this host's repository targets costs,
    /// at the idle interval.
    pub idle_requests_per_minute: u32,
    pub secondary_limit_points_per_minute: u32,
    /// The daemon's last measurement, or `null` when no daemon has written
    /// one.
    pub measured: Option<MeasuredPolling>,
}

/// What the daemon measured. Counts are per hour, scaled from
/// `observed_minutes` when the daemon has run for less than an hour.
#[derive(Debug, Clone, Serialize)]
pub struct MeasuredPolling {
    pub written_at: DateTime<Utc>,
    /// `true` when the daemon has not rewritten this for [`STALE_AFTER`]: it
    /// is probably not running.
    pub stale: bool,
    pub observed_minutes: u32,
    /// The raw counts the per-hour figures are scaled from. Under ten
    /// minutes of observation the scaled figures overstate: a new daemon's
    /// first poll of every listing is a full `200`.
    pub full_responses: u32,
    pub not_modified_responses: u32,
    pub failed_responses: u32,
    pub full_responses_per_hour: u32,
    pub not_modified_responses_per_hour: u32,
    pub failed_responses_per_hour: u32,
    /// The share of all responses that were `304`, in whole percent.
    pub not_modified_percent: Option<u32>,
    pub peak_requests_per_minute: u32,
    /// The busiest minute against the secondary limit, in whole percent.
    pub secondary_limit_percent: u32,
    pub pace: String,
    pub targets_idle: u32,
    pub targets_total: u32,
    pub throttled: bool,
    pub throttled_because: Option<String>,
    pub rate_limit_limit: Option<u64>,
    pub rate_limit_remaining: Option<u64>,
    pub rate_limit_used: Option<u64>,
    pub rate_limit_reset: Option<DateTime<Utc>>,
    /// Since the daemon started: repository readings fetched, how many of
    /// them were all `304`, readings handed to a second target instead of
    /// fetched again, and polls withheld inside a rate-limit quiet period.
    pub demand_reads: u64,
    pub demand_unchanged_reads: u64,
    pub demand_shared_reads: u64,
    pub demand_suppressed: u64,
}

impl MeasuredPolling {
    #[must_use]
    pub fn of(paths: &AppPaths, traffic: &PollTraffic, now: DateTime<Utc>) -> Self {
        Self {
            written_at: traffic.written_at,
            stale: is_stale(paths, traffic.written_at, now),
            observed_minutes: traffic.observed_minutes,
            full_responses: traffic.full,
            not_modified_responses: traffic.not_modified,
            failed_responses: traffic.failed,
            full_responses_per_hour: traffic.per_hour(traffic.full),
            not_modified_responses_per_hour: traffic.per_hour(traffic.not_modified),
            failed_responses_per_hour: traffic.per_hour(traffic.failed),
            not_modified_percent: traffic.not_modified_percent(),
            peak_requests_per_minute: traffic.peak_requests_per_minute,
            secondary_limit_percent: secondary_share_percent(traffic.peak_requests_per_minute),
            pace: traffic.pace.clone(),
            targets_idle: traffic.targets_idle,
            targets_total: traffic.targets_total,
            throttled: traffic.is_throttled(),
            throttled_because: traffic.throttled_because.clone(),
            rate_limit_limit: traffic.rate_limit_limit,
            rate_limit_remaining: traffic.rate_limit_remaining,
            rate_limit_used: traffic.rate_limit_used,
            rate_limit_reset: traffic.rate_limit_reset,
            demand_reads: traffic.demand_reads,
            demand_unchanged_reads: traffic.demand_unchanged_reads,
            demand_shared_reads: traffic.demand_shared_reads,
            demand_suppressed: traffic.demand_suppressed,
        }
    }
}

/// Everything `status` and `host show` need, read from local state only.
#[must_use]
pub fn snapshot(
    context: &Context,
    (intervals, unreadable): (Intervals, Option<String>),
    targets: &[ScaleTarget],
) -> PollingSnapshot {
    let (repositories, _) = count_targets(targets);
    let now = context.clock().now();
    PollingSnapshot {
        idle_interval_secs: intervals.idle.as_secs(),
        effective_idle_interval_secs: u16::try_from(intervals.effective_idle().as_secs())
            .unwrap_or(u16::MAX),
        idle_interval_unreadable: unreadable,
        active_interval_secs: intervals.active.as_secs(),
        idle_requests_per_minute: intervals.idle_requests_per_minute(repositories),
        secondary_limit_points_per_minute: SECONDARY_POINTS_PER_MINUTE,
        // A record that cannot be read is reported as absent rather than
        // failing `status`, which must answer when everything else is broken.
        measured: settings::last_traffic(context.paths())
            .ok()
            .flatten()
            .map(|traffic| MeasuredPolling::of(context.paths(), &traffic, now)),
    }
}

/// The polling section of `host show`, and the head of `status`'s budget
/// lines.
///
/// # Errors
/// Whatever `out` fails with.
pub fn write_section(out: &mut dyn Write, polling: &PollingSnapshot) -> io::Result<()> {
    writeln!(out, "GitHub polling")?;
    writeln!(
        out,
        "  idle interval             {}s   (a target with nothing happening; conditional, 304s){}",
        polling.effective_idle_interval_secs,
        if polling.effective_idle_interval_secs == polling.idle_interval_secs {
            String::new()
        } else {
            format!(
                "; {}s configured, capped at the active interval",
                polling.idle_interval_secs
            )
        }
    )?;
    if let Some(reason) = &polling.idle_interval_unreadable {
        writeln!(
            out,
            "  UNREADABLE                config/polling.toml ({reason}); the default stands in. \
             `runner-manager host set-poll-interval --idle 10s` rewrites it"
        )?;
    }
    writeln!(
        out,
        "  active interval           {}s   (a target with runners up or runs changing)",
        polling.active_interval_secs
    )?;
    let Some(measured) = &polling.measured else {
        writeln!(
            out,
            "  measured                  nothing yet: no daemon has written a measurement"
        )?;
        return Ok(());
    };
    writeln!(
        out,
        "  measured over             {} minute(s), written {}{}",
        measured.observed_minutes,
        measured.written_at.format("%Y-%m-%d %H:%M:%SZ"),
        if measured.stale {
            " (STALE: the daemon is probably not running)"
        } else {
            ""
        }
    )?;
    if measured.observed_minutes < 10 {
        writeln!(
            out,
            "  responses so far          {} full (200, charged) / {} not modified (304, free) / {} \
             failed; too early for an hourly rate",
            measured.full_responses, measured.not_modified_responses, measured.failed_responses
        )?;
    } else {
        writeln!(
            out,
            "  responses per hour        {} full (200, charged) / {} not modified (304, free) / {} \
             failed",
            measured.full_responses_per_hour,
            measured.not_modified_responses_per_hour,
            measured.failed_responses_per_hour
        )?;
    }
    if let Some(percent) = measured.not_modified_percent {
        writeln!(out, "  share answered 304        {percent}%")?;
    }
    writeln!(
        out,
        "  secondary limit           busiest minute {} of {} requests ({}%); every host on \
         the account shares it",
        measured.peak_requests_per_minute,
        polling.secondary_limit_points_per_minute,
        measured.secondary_limit_percent
    )?;
    if let (Some(remaining), Some(limit)) =
        (measured.rate_limit_remaining, measured.rate_limit_limit)
    {
        writeln!(
            out,
            "  account hourly quota      {remaining} of {limit} left{} (every host and tool \
             signed in as this user)",
            measured
                .rate_limit_reset
                .map(|reset| format!(", resets {}", reset.format("%H:%M:%SZ")))
                .unwrap_or_default()
        )?;
    }
    writeln!(
        out,
        "  repository readings       {} fetched ({} all 304), {} shared between targets, {} \
         withheld while rate limited",
        measured.demand_reads,
        measured.demand_unchanged_reads,
        measured.demand_shared_reads,
        measured.demand_suppressed
    )?;
    writeln!(
        out,
        "  pace                      {} ({} of {} target(s) idle)",
        measured.pace, measured.targets_idle, measured.targets_total
    )?;
    match &measured.throttled_because {
        Some(reason) => writeln!(out, "  THROTTLED                 {reason}")?,
        None => writeln!(out, "  throttled                 no")?,
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The daemon's monitor
// ---------------------------------------------------------------------------

/// The daemon side: re-reads the intervals so an operator's change is picked
/// up live, and writes what polling has cost to `state/poll-traffic.toml`.
///
/// One per daemon, shared by every target loop.
pub struct PollingMonitor {
    paths: AppPaths,
    store: Arc<dyn Store>,
    host_id: HostId,
    demand: Arc<RestDemand>,
    clock: Arc<dyn Clock>,
    state: Mutex<MonitorState>,
}

struct MonitorState {
    intervals: Intervals,
    read_at: Instant,
    paces: BTreeMap<ScaleTarget, PollPace>,
    written_at: Option<Instant>,
}

impl std::fmt::Debug for PollingMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PollingMonitor").finish_non_exhaustive()
    }
}

impl PollingMonitor {
    #[must_use]
    pub fn new(
        paths: AppPaths,
        store: Arc<dyn Store>,
        host_id: HostId,
        demand: Arc<RestDemand>,
        clock: Arc<dyn Clock>,
        intervals: Intervals,
    ) -> Self {
        demand.set_shared_window(intervals.effective_idle());
        Self {
            paths,
            store,
            host_id,
            demand,
            clock,
            state: Mutex::new(MonitorState {
                intervals,
                read_at: Instant::now(),
                paces: BTreeMap::new(),
                written_at: None,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MonitorState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The intervals in force, re-read from disk at most every
    /// [`RELOAD_EVERY`]. A read that fails keeps the last good pair: a loop
    /// must not stop because a settings file is mid-write.
    pub fn intervals(&self) -> Intervals {
        let current = {
            let mut state = self.lock();
            if state.read_at.elapsed() < RELOAD_EVERY {
                return state.intervals;
            }
            // Claimed before the reads, so the other loops keep the current
            // pair instead of all reading at once.
            state.read_at = Instant::now();
            state.intervals
        };
        // No lock across the database and the file: every loop would block
        // behind a busy database otherwise.
        let active = match self.store.host(self.host_id) {
            Ok(Some(host)) => host.refresh_interval,
            _ => current.active,
        };
        let idle = settings::idle_interval(&self.paths).unwrap_or_else(|error| {
            tracing::warn!(%error, "the idle poll interval could not be read; keeping the last one");
            current.idle
        });
        let next = Intervals { active, idle };
        let mut state = self.lock();
        if next != state.intervals {
            tracing::info!(
                idle_secs = idle.as_secs(),
                active_secs = active.as_secs(),
                "poll intervals changed"
            );
            self.demand.set_shared_window(next.effective_idle());
            state.intervals = next;
        }
        next
    }

    /// Record one target's next poll, and write the measurement when it is
    /// due.
    pub fn observe(&self, target: &ScaleTarget, next: &NextPoll) {
        let mut state = self.lock();
        match state.paces.get_mut(target) {
            Some(pace) => *pace = next.pace,
            None => {
                state.paces.insert(target.clone(), next.pace);
            }
        }
        if state
            .written_at
            .is_some_and(|written| written.elapsed() < WRITE_EVERY)
        {
            return;
        }
        state.written_at = Some(Instant::now());
        let record = self.measure(&state);
        drop(state);
        if let Err(error) = settings::record_traffic(&self.paths, &record) {
            tracing::warn!(%error, "cannot record the measured polling cost");
        }
    }

    fn measure(&self, state: &MonitorState) -> PollTraffic {
        let now = self.clock.now();
        let summary = self.demand.client().traffic().summary(now);
        let stats = self.demand.stats();
        let mut record = PollTraffic::new(now);
        record.idle_interval_secs = state.intervals.idle.as_secs();
        record.active_interval_secs = state.intervals.active.as_secs();
        let worst = state
            .paces
            .values()
            .copied()
            .max_by_key(pace_severity)
            .unwrap_or(PollPace::Nominal);
        record.pace = worst.as_str().to_string();
        record.targets_total = u32::try_from(state.paces.len()).unwrap_or(u32::MAX);
        record.targets_idle = u32::try_from(
            state
                .paces
                .values()
                .filter(|pace| matches!(pace, PollPace::Idle))
                .count(),
        )
        .unwrap_or(u32::MAX);
        record.throttled_because = throttled_because(worst, summary.rate_limit.as_ref(), now);
        record.observed_minutes = summary.observed_minutes;
        record.full = summary.full;
        record.not_modified = summary.not_modified;
        record.failed = summary.failed;
        record.peak_requests_per_minute = summary.peak_requests_per_minute;
        if let Some(quota) = summary.rate_limit {
            record.rate_limit_limit = Some(quota.limit);
            record.rate_limit_remaining = Some(quota.remaining);
            record.rate_limit_used = quota.used;
            record.rate_limit_reset = i64::try_from(quota.reset_unix_secs)
                .ok()
                .and_then(|secs| DateTime::from_timestamp(secs, 0));
        }
        record.demand_reads = stats.reads;
        record.demand_unchanged_reads = stats.unchanged_reads;
        record.demand_shared_reads = stats.shared_reads;
        record.demand_suppressed = stats.suppressed;
        record
    }
}

/// Which pace a host-wide summary should name: the most severe one.
const fn pace_severity(pace: &PollPace) -> u8 {
    match pace {
        PollPace::Idle => 0,
        PollPace::Nominal => 1,
        PollPace::Blocked => 2,
        PollPace::Stretched { .. } => 3,
        PollPace::Offline { .. } => 4,
        PollPace::LockedOut => 5,
        PollPace::RateLimited { .. } => 6,
    }
}

/// Why polling is slower than configured, in words, or `None` when it is not.
fn throttled_because(
    pace: PollPace,
    quota: Option<&RateLimitSnapshot>,
    now: DateTime<Utc>,
) -> Option<String> {
    match pace {
        PollPace::Idle | PollPace::Nominal => None,
        PollPace::Stretched { pressure } => {
            let factor = pressure.stretch_factor();
            let level = match pressure {
                PrimaryPressure::Critical => "critically low",
                _ => "low",
            };
            Some(match quota {
                Some(quota) => format!(
                    "the account's hourly GitHub quota is {level}: {} of {} left, resetting in \
                     {} minute(s). Polls wait {factor}x the active interval until it recovers. \
                     Every host and tool signed in as the same GitHub user draws on this quota.",
                    quota.remaining,
                    quota.limit,
                    quota.reset_in(now).as_secs().div_ceil(60)
                ),
                None => format!(
                    "the account's hourly GitHub quota is {level}; polls wait {factor}x the \
                     active interval"
                ),
            })
        }
        PollPace::RateLimited { kind } => Some(match kind {
            RateLimitKind::Primary => "GitHub's hourly quota for this account is exhausted; no \
                                       demand request leaves this host until it resets"
                .to_string(),
            RateLimitKind::Secondary => "GitHub's secondary rate limit answered; no demand \
                                         request leaves this host until the time GitHub named, \
                                         doubling if it recurs"
                .to_string(),
        }),
        PollPace::LockedOut => {
            Some("GitHub's temporary authentication lockout; polls wait it out".to_string())
        }
        PollPace::Offline { consecutive } => Some(format!(
            "GitHub is unreachable ({consecutive} poll(s) in a row); polls back off. Check this \
             machine's network"
        )),
        PollPace::Blocked => Some(
            "a target cannot be read: GitHub rejected the credential or a permission is missing. \
             It is polled at the active interval so a fix is noticed; `runner-manager status` \
             and `runner-manager auth status` say which"
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_parse_in_the_forms_an_operator_writes() {
        assert_eq!(parse_interval("10s"), Ok(10));
        assert_eq!(parse_interval("10"), Ok(10));
        assert_eq!(parse_interval("2m"), Ok(120));
        assert_eq!(parse_interval("1m30s"), Ok(90));
        assert_eq!(parse_interval(" 45S "), Ok(45));
        assert!(parse_interval("").is_err());
        assert!(parse_interval("ten").is_err());
        assert!(parse_interval("10x").is_err());
        assert!(parse_interval("s").is_err());
        assert!(parse_interval("10s5").is_err());
        assert!(
            parse_interval("24h").is_err(),
            "86400 does not fit in u16 seconds"
        );
    }

    #[test]
    fn idle_load_is_two_listings_per_repository_per_idle_interval() {
        let intervals = Intervals {
            active: RefreshInterval::default(),
            idle: IdlePollInterval::default(),
        };
        // The owner's IVANPC: ten repository targets at 10 s.
        assert_eq!(intervals.idle_requests_per_minute(10), 120);
        let clamped = Intervals {
            active: RefreshInterval::from_secs(30).expect("the floor"),
            idle: IdlePollInterval::from_secs(60).expect("valid"),
        };
        assert_eq!(clamped.effective_idle(), Duration::from_secs(30));
    }

    #[test]
    fn every_throttling_reason_reads_without_a_run_of_spaces() {
        let now = Utc::now();
        let quota = RateLimitSnapshot {
            limit: 5_000,
            remaining: 100,
            used: Some(4_900),
            reset_unix_secs: u64::try_from(now.timestamp() + 600).expect("positive"),
            observed_at: now,
        };
        for pace in [
            PollPace::Stretched {
                pressure: PrimaryPressure::Low,
            },
            PollPace::Stretched {
                pressure: PrimaryPressure::Critical,
            },
            PollPace::RateLimited {
                kind: RateLimitKind::Primary,
            },
            PollPace::RateLimited {
                kind: RateLimitKind::Secondary,
            },
            PollPace::LockedOut,
            PollPace::Offline { consecutive: 2 },
            PollPace::Blocked,
        ] {
            for quota in [None, Some(&quota)] {
                let reason = throttled_because(pace, quota, now).expect("a slowdown says why");
                assert!(!reason.contains("  "), "{pace}: {reason}");
            }
        }
    }

    #[test]
    fn a_beating_daemon_makes_an_old_measurement_current_and_a_dead_one_stale() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(dir.path());
        let now = Utc::now();
        let hour_ago = now - chrono::TimeDelta::hours(1);
        assert!(
            is_stale(&paths, hour_ago, now),
            "no daemon, and an hour old: left behind"
        );
        assert!(!is_stale(&paths, now, now), "fresh is never stale");
        runner_manager_platform::daemon_heartbeat::beat(&paths, now).expect("a heartbeat");
        assert!(
            !is_stale(&paths, hour_ago, now),
            "a daemon asleep through a long rate-limit wait writes nothing, and is not gone"
        );
    }

    fn measured(observed_minutes: u32) -> PollingSnapshot {
        let mut traffic = PollTraffic::new(Utc::now());
        traffic.observed_minutes = observed_minutes;
        traffic.full = 20;
        traffic.not_modified = 0;
        let dir = tempfile::tempdir().expect("a temporary directory");
        PollingSnapshot {
            idle_interval_secs: 10,
            effective_idle_interval_secs: 10,
            idle_interval_unreadable: None,
            active_interval_secs: 60,
            idle_requests_per_minute: 12,
            secondary_limit_points_per_minute: SECONDARY_POINTS_PER_MINUTE,
            measured: Some(MeasuredPolling::of(
                &AppPaths::rooted_at(dir.path()),
                &traffic,
                Utc::now(),
            )),
        }
    }

    fn rendered(snapshot: &PollingSnapshot) -> String {
        let mut out = Vec::new();
        write_section(&mut out, snapshot).expect("rendered");
        String::from_utf8(out).expect("UTF-8")
    }

    #[test]
    fn a_new_daemons_first_minutes_are_shown_as_counts_not_as_an_hourly_rate() {
        let early = rendered(&measured(1));
        assert!(
            early.contains("responses so far          20 full"),
            "{early}"
        );
        assert!(
            !early.contains("1200"),
            "twenty first polls in one minute are not 1,200 an hour: {early}"
        );
        let later = rendered(&measured(30));
        assert!(
            later.contains("responses per hour        40 full"),
            "{later}"
        );
    }

    #[test]
    fn the_idle_interval_shown_is_the_one_the_daemon_uses() {
        let mut snapshot = measured(30);
        snapshot.idle_interval_secs = 50;
        snapshot.effective_idle_interval_secs = 30;
        snapshot.active_interval_secs = 30;
        let text = rendered(&snapshot);
        assert!(
            text.contains("idle interval             30s")
                && text.contains("50s configured, capped at the active interval"),
            "{text}"
        );
    }

    #[test]
    fn the_host_wide_pace_names_the_most_severe_loop() {
        let paces = [
            PollPace::Idle,
            PollPace::Nominal,
            PollPace::Stretched {
                pressure: PrimaryPressure::Low,
            },
        ];
        assert_eq!(
            paces.iter().copied().max_by_key(pace_severity),
            Some(PollPace::Stretched {
                pressure: PrimaryPressure::Low
            })
        );
        assert!(throttled_because(PollPace::Idle, None, Utc::now()).is_none());
        assert!(
            throttled_because(
                PollPace::Stretched {
                    pressure: PrimaryPressure::Low
                },
                None,
                Utc::now()
            )
            .is_some_and(|reason| reason.contains("2x"))
        );
    }
}
