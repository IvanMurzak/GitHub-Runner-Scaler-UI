// owner: f1-cli-auth-host-status

//! `host set-capacity` and `host show` (D9), and the shared REST budget (`c3`).
//!
//! # `host_capacity` is never inferred
//!
//! `02-target-architecture.md`'s third principle is *"scale to physical truth:
//! capacity is owner-configured … not inferred from the number of archived
//! runner directories"*, and `f1`'s scope repeats it: the number comes from an
//! observed workload measurement, which is a thing only the operator has. So
//! nothing here derives a capacity from a runner count, an inventory, a core
//! count, or anything else — [`super::DEFAULT_HOST_CAPACITY`] is a chosen
//! constant of **one**, and every other value arrives through
//! `host set-capacity`.
//!
//! # The two budget numbers, and why this file computes one of them itself
//!
//! `host show` prints *"the projected hourly request count"* and *"the maximum
//! number of targets this host can serve at that interval"*. `c3` offers both,
//! and **they disagree**:
//!
//! * [`BudgetProjection::admit`] — the call `f2`'s `repo add` makes — takes its
//!   candidate [`TargetCost`] from the caller, so a caller that builds one
//!   through `c4`'s seam gets an admission computed from the **measured** cost
//!   of one demand request per repository per poll.
//! * [`BudgetProjection::max_repository_targets`] builds `TargetCost::repository()`
//!   internally. That constructor cannot see the seam, so it still prices demand
//!   at `c3`'s pre-decision estimate of two.
//!
//! At the 60-second default the first would take **13** repository targets and
//! the second prints **10**. `crates/github`'s own
//! `the_printed_target_ceiling_still_projects_the_pre_decision_estimate` records
//! the gap and states that it is not fixable from `c4`'s file: both remedies are
//! edits to `crates/github/src/rest.rs`, which `c3` owns and this task does not.
//!
//! An operator reading `host show` would see both numbers at once. So this file
//! prints **neither of c3's two answers separately**: [`measured`] is the single
//! place a cost is priced, [`max_repository_targets`] derives the ceiling from
//! it, and [`HostBudget`] derives the projection from it too. Whatever that one
//! source says, the two numbers agree — and
//! `the_printed_ceiling_is_the_number_admit_actually_takes` asserts the
//! agreement against `admit` itself rather than against a copy of the
//! arithmetic. `c3s_ceiling_still_prices_demand_at_the_pre_decision_estimate`
//! pins the divergence at the source, so closing it there is visible here.
//!
//! # The projection is a best case, and says so
//!
//! Both per-repository classes are priced at **one** request and both can spend
//! up to [`FALLBACK_COST_MULTIPLE`] when GitHub omits `total_count` and the
//! count has to walk pages. A ceiling presented as exact would therefore be
//! optimistic by a factor of four in the worst case, and an operator planning a
//! host against it deserves to know that before they are refused an eleventh
//! target. `c3` absorbs the gap with `BUDGET_SHARE_DIVISOR` — the projection is
//! compared against half the ceiling precisely so the half nobody models has
//! somewhere to go — and this file states the assumption where the number is
//! read.

use std::io::{self, Write};
use std::num::NonZeroU16;

use runner_manager_domain::capacity::HostAllocator;
use runner_manager_domain::model::{Host, RefreshInterval, ScaleTarget, StartMode};
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_github::demand::DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL;
use runner_manager_github::rest::{
    BudgetProjection, TargetCost, budget_allowance, refreshes_per_hour,
};
use runner_manager_platform::secrets::SecretStore;

use super::{CliError, Context, Failure, HostCommand, HostSetCapacityArgs};

// ---------------------------------------------------------------------------
// The one place a target is priced
// ---------------------------------------------------------------------------

/// How far one per-repository request class can exceed the price this
/// projection puts on it.
///
/// `c3` prices the activity count at its best case of one request and states
/// that a count taking the no-`total_count` fallback costs up to
/// `MAX_ACTIVITY_FALLBACK_PAGES`; `c4` says exactly the same of the demand poll
/// and `MAX_DEMAND_FALLBACK_PAGES`. Both bounds are four, and
/// `the_stated_fallback_multiple_is_the_one_the_gateways_can_spend` is what
/// keeps this constant equal to them rather than merely near them.
pub const FALLBACK_COST_MULTIPLE: u32 = 4;

/// `cost` with `c4`'s **measured** demand figure substituted for `c3`'s
/// estimate.
///
/// This is the single source of truth the module documentation describes.
/// `crates/github`'s `demand::target_cost` is the same substitution applied to
/// an [`ActivityScope`]; `the_measured_cost_is_the_one_c4_reports` asserts the
/// two agree, so this function is a re-spelling of that seam and not a second
/// opinion about what a target costs. It exists in this shape because the
/// ceiling below has no scope to price — it is a statement about a hypothetical
/// eleventh repository, not about a configured one.
#[must_use]
pub fn measured(cost: TargetCost) -> TargetCost {
    cost.with_demand_requests_per_repository(DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL)
}

/// How many **repository** targets one host can serve at `interval`.
///
/// Deliberately not [`BudgetProjection::max_repository_targets`]: see the
/// module documentation. Repository targets rather than targets in general
/// because a repository is the only target whose cost is a constant — an
/// organization's grows with the number of repositories the App is installed
/// on, so "how many organizations fit" has no single answer and this does not
/// invent one.
#[must_use]
pub fn max_repository_targets(interval: RefreshInterval) -> u32 {
    let per_target = measured(TargetCost::repository()).requests_per_hour(interval);
    if per_target == 0 {
        return 0;
    }
    budget_allowance() / per_target
}

/// What this host's configured target set costs per hour, and what still fits.
#[derive(Debug, Clone)]
pub struct HostBudget {
    interval: RefreshInterval,
    projection: BudgetProjection,
    /// Organization targets in the set. Non-zero makes the projection a
    /// **floor** rather than an estimate; see [`HostBudget::is_floor`].
    organization_targets: usize,
    /// Policies priced, whatever their state.
    priced_policies: usize,
}

impl HostBudget {
    /// Prices every persisted policy, at this host's refresh interval.
    ///
    /// # Every policy is priced, including the ones not polling
    ///
    /// A `pending`, `disabled` or `monitor_only` policy costs less than this
    /// says — a monitor-only policy never polls demand at all, and a disabled
    /// one polls nothing. Pricing them anyway overstates the spend, which is
    /// the safe direction for a number an operator plans against, and it keeps
    /// the rule simple enough to state in one line of output: *everything
    /// configured is priced as if it were polling*. A projection that shrank
    /// when a policy was disabled would also grow again when it was re-enabled,
    /// which is a worse thing to discover at the moment of re-enabling.
    ///
    /// # An organization's cost is a floor
    ///
    /// An organization target costs one inventory request plus two per
    /// installed repository, and how many repositories that is cannot be known
    /// without asking GitHub. `host show` reads no network, so an organization
    /// is priced at exactly one repository — its floor, and the point at which
    /// `c3`'s two cost formulas agree — and [`HostBudget::is_floor`] makes the
    /// shortfall sayable instead of silent.
    #[must_use]
    pub fn of(interval: RefreshInterval, targets: &[ScaleTarget]) -> Self {
        let mut costs = Vec::with_capacity(targets.len());
        let mut organization_targets = 0;
        for target in targets {
            costs.push(measured(match target {
                ScaleTarget::Repository(_) => TargetCost::repository(),
                ScaleTarget::Organization(_) => {
                    organization_targets += 1;
                    TargetCost::organization(1)
                }
            }));
        }
        Self {
            interval,
            projection: BudgetProjection::new(interval, costs),
            organization_targets,
            priced_policies: targets.len(),
        }
    }

    #[must_use]
    pub fn requests_per_hour(&self) -> u32 {
        self.projection.requests_per_hour()
    }

    #[must_use]
    pub fn allowance(&self) -> u32 {
        self.projection.allowance()
    }

    #[must_use]
    pub fn ceiling(&self) -> u32 {
        self.projection.ceiling()
    }

    #[must_use]
    pub fn headroom(&self) -> u32 {
        self.projection.headroom()
    }

    #[must_use]
    pub fn exceeds_allowance(&self) -> bool {
        self.projection.exceeds_allowance()
    }

    /// The ceiling this host prints, derived from [`measured`].
    #[must_use]
    pub fn max_repository_targets(&self) -> u32 {
        max_repository_targets(self.interval)
    }

    /// Whether the projected total is a floor rather than an estimate.
    #[must_use]
    pub const fn is_floor(&self) -> bool {
        self.organization_targets > 0
    }

    /// Writes the budget section of `host show`.
    ///
    /// # Errors
    /// Whatever `out` fails with.
    pub fn write(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "Shared REST budget")?;
        writeln!(out, "  refresh interval          {}", self.interval)?;
        writeln!(
            out,
            "  refreshes per hour        {}",
            refreshes_per_hour(self.interval)
        )?;
        writeln!(
            out,
            "  projected requests/hour   {}{}",
            self.requests_per_hour(),
            if self.is_floor() { " (a floor)" } else { "" }
        )?;
        writeln!(
            out,
            "  this host may spend       {} per hour (half of GitHub's {} ceiling)",
            self.allowance(),
            self.ceiling()
        )?;
        writeln!(out, "  headroom                  {}", self.headroom())?;
        writeln!(out, "  policies priced           {}", self.priced_policies)?;
        writeln!(
            out,
            "  repository targets that fit at this interval: about {}",
            self.max_repository_targets()
        )?;
        writeln!(out)?;

        if self.exceeds_allowance() {
            writeln!(
                out,
                "  OVER BUDGET: this host's configured targets already project more than it"
            )?;
            writeln!(
                out,
                "  may plan to spend. Lengthen the refresh interval or remove a target."
            )?;
            writeln!(out)?;
        }

        writeln!(
            out,
            "  About: every configured policy is priced as if it were polling, whatever its"
        )?;
        writeln!(
            out,
            "  state, so this total is never an under-estimate of the set you have."
        )?;
        if self.is_floor() {
            writeln!(
                out,
                "  {} of them are organization targets, whose cost grows with the number of",
                self.organization_targets
            )?;
            writeln!(
                out,
                "  repositories the App is installed on. That count is not known without"
            )?;
            writeln!(
                out,
                "  contacting GitHub, so each is priced as one repository and the total above"
            )?;
            writeln!(out, "  is a floor rather than an estimate.")?;
        }
        write_best_case_caveat(out)?;
        Ok(())
    }
}

/// States the one assumption a reader would otherwise take the ceiling for.
///
/// The projection prices each per-repository request class at its **best case**
/// of one request. Both classes fall back to walking pages when GitHub omits
/// `total_count`, and both walks are bounded at [`FALLBACK_COST_MULTIPLE`]
/// pages. So "about N targets" is a best-case figure, and a host whose
/// repositories all take the fallback path spends up to four times what the
/// per-repository half of this projection says.
///
/// # Errors
/// Whatever `out` fails with.
pub fn write_best_case_caveat(out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "  About: these are BEST-CASE costs. Each repository is priced at one request for"
    )?;
    writeln!(
        out,
        "  its in-progress count and one for its queued-run count, which is what GitHub"
    )?;
    writeln!(
        out,
        "  charges when it sends a total with the first page. When it does not, each of"
    )?;
    writeln!(
        out,
        "  those counts walks pages instead and costs up to {FALLBACK_COST_MULTIPLE}x as much. Treat the"
    )?;
    writeln!(
        out,
        "  target figure as approximate, not as a threshold: the other half of GitHub's"
    )?;
    writeln!(
        out,
        "  hourly ceiling is deliberately left unplanned to absorb exactly this."
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The local host record
// ---------------------------------------------------------------------------

/// This machine's host row, if it has one yet.
///
/// The database lives under this host's own `config/`, so it describes one
/// machine and holds at most one host. More than one row is a database that has
/// been merged, copied between machines, or written by something else, and
/// guessing which row is "this" one would attach this host's policies and
/// capacity to another machine's identity. Public because `f2` needs the same
/// answer before it can create a policy.
///
/// # Errors
/// [`Failure::LocalState`] on a read failure, or when more than one host is
/// recorded.
pub fn local_host(store: &dyn Store) -> Result<Option<Host>, CliError> {
    let mut hosts = store.hosts().map_err(store_failure)?;
    match hosts.len() {
        0 => Ok(None),
        1 => Ok(hosts.pop()),
        n => Err(CliError::new(
            Failure::LocalState,
            format!(
                "this host's database records {n} hosts, and it should record one. It was \
                 probably copied from another machine. Point --data-dir at a fresh directory, \
                 or remove the database and run `runner-manager auth login` again."
            ),
        )),
    }
}

/// This machine's host row, creating it if this is the first command to need
/// one.
///
/// # Errors
/// As [`local_host`], plus [`Failure::UnsupportedHost`] on an OS/architecture
/// pair outside GitHub's documented matrix.
pub fn local_host_or_create(context: &Context, store: &dyn Store) -> Result<Host, CliError> {
    match local_host(store)? {
        Some(host) => Ok(host),
        None => super::create_local_host(store, context.clock().as_ref()),
    }
}

fn store_failure(source: StoreError) -> CliError {
    CliError::with_remedy(
        Failure::LocalState,
        format!("cannot read this host's local database: {source}"),
        "runner-manager host show",
    )
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// # Errors
/// Whatever the routed command returns.
pub fn dispatch(
    context: &Context,
    command: &HostCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        HostCommand::SetCapacity(args) => set_capacity(context, args, out),
        HostCommand::Show => show(context, out),
    }
}

// ---------------------------------------------------------------------------
// host set-capacity
// ---------------------------------------------------------------------------

/// # Errors
/// [`Failure::InvalidArgument`] for a zero, and the local-state failures.
pub fn set_capacity(
    context: &Context,
    args: &HostSetCapacityArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let capacity = NonZeroU16::new(args.capacity).ok_or_else(|| {
        CliError::with_remedy(
            Failure::InvalidArgument,
            "a host capacity of 0 is not a configured host, it is a disabled one. Set at \
             least 1, or drain the policies you do not want running.",
            "runner-manager host set-capacity 1",
        )
    })?;

    let store = context.store()?;
    let mut host = local_host_or_create(context, &store)?;
    let previous = host.host_capacity();
    host.host_capacity = capacity;
    store.put_host(&host).map_err(store_failure)?;

    let attempts = store.attempts().map_err(store_failure)?;
    let allocator = HostAllocator::from_attempts(&host, attempts.iter());
    let in_use = allocator.active_total();

    writeln!(
        out,
        "host_capacity: {previous} -> {}   (in use right now: {in_use})",
        capacity.get()
    )
    .map_err(write_failed)?;

    if in_use > capacity.get() {
        writeln!(out).map_err(write_failed)?;
        writeln!(
            out,
            "This host already holds {in_use} runner attempts, which is more than the ceiling\n\
             you just set. Nothing was terminated: a busy runner is never stopped to scale\n\
             down. No new attempt will start until the total falls below {}.",
            capacity.get()
        )
        .map_err(write_failed)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// host show
// ---------------------------------------------------------------------------

/// Everything `05-infrastructure.md` and `f1` require to be visible here.
///
/// Reads no network. Every number is either local state or arithmetic over
/// local state, which is what makes this the command an operator can run when
/// GitHub is unreachable and the tool is behaving oddly.
///
/// # Errors
/// The local-state and secret-store failures.
pub fn show(context: &Context, out: &mut dyn Write) -> Result<(), CliError> {
    let store = context.store()?;
    let host = local_host(&store)?;

    match &host {
        None => {
            writeln!(
                out,
                "This machine has no host record yet, so the values below are the defaults a\n\
                 host would be created with. `host set-capacity` creates one."
            )
            .map_err(write_failed)?;
            writeln!(out).map_err(write_failed)?;
        }
        Some(host) => {
            writeln!(
                out,
                "Host: {} ({} {})",
                host.display_name, host.os, host.architecture
            )
            .map_err(write_failed)?;
            writeln!(out, "  id                        {}", host.id).map_err(write_failed)?;
        }
    }

    let start_mode = host
        .as_ref()
        .map_or_else(StartMode::default, |h| h.service_start_mode);
    let interval = host
        .as_ref()
        .map_or_else(RefreshInterval::default, |h| h.refresh_interval);
    let capacity = host
        .as_ref()
        .map_or(super::DEFAULT_HOST_CAPACITY, Host::host_capacity);

    let attempts = store.attempts().map_err(store_failure)?;
    let in_use = match &host {
        Some(host) => HostAllocator::from_attempts(host, attempts.iter()).active_total(),
        None => 0,
    };

    writeln!(out, "  host_capacity             {capacity}").map_err(write_failed)?;
    writeln!(out, "  in use across policies    {in_use}").map_err(write_failed)?;
    writeln!(
        out,
        "  headroom                  {}",
        capacity.saturating_sub(in_use)
    )
    .map_err(write_failed)?;
    writeln!(out, "  service start mode        {start_mode}").map_err(write_failed)?;

    // -- the secret store ------------------------------------------------
    let secrets = context.secret_store(start_mode)?;
    writeln!(
        out,
        "  secret store              {}-scoped",
        secrets.scope()
    )
    .map_err(write_failed)?;
    writeln!(out, "  store location            {}", secrets.location()).map_err(write_failed)?;
    match secrets.protection() {
        Ok(protection) => {
            writeln!(out, "  protected by              {protection}").map_err(write_failed)?;
        }
        Err(source) => {
            // Not a failure of `host show`: on a host that has never signed in
            // there is nothing to inspect yet, and refusing to print a capacity
            // because of that would be the wrong trade.
            writeln!(
                out,
                "  protected by              not readable yet ({source})"
            )
            .map_err(write_failed)?;
        }
    }
    writeln!(out).map_err(write_failed)?;

    // -- the shared budget ------------------------------------------------
    let targets: Vec<ScaleTarget> = store
        .policies()
        .map_err(store_failure)?
        .into_iter()
        .map(|policy| policy.target)
        .collect();
    HostBudget::of(interval, &targets)
        .write(out)
        .map_err(write_failed)?;
    Ok(())
}

fn write_failed(source: io::Error) -> CliError {
    CliError::new(
        Failure::Unclassified,
        format!("cannot write to this terminal: {source}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use runner_manager_domain::model::{Org, OwnerRepo};
    use runner_manager_github::demand::{self, MAX_DEMAND_FALLBACK_PAGES};
    use runner_manager_github::rest::{
        ACTIVITY_REQUESTS_PER_REPOSITORY_PER_REFRESH, ActivityScope, MAX_ACTIVITY_FALLBACK_PAGES,
    };

    fn repository(slug: &str) -> ScaleTarget {
        ScaleTarget::Repository(OwnerRepo::parse(slug).expect("a valid slug"))
    }

    fn organization(name: &str) -> ScaleTarget {
        ScaleTarget::Organization(Org::new(name).expect("a valid organization"))
    }

    fn budget_text(budget: &HostBudget) -> String {
        let mut rendered = Vec::new();
        budget.write(&mut rendered).expect("writing to a Vec");
        String::from_utf8(rendered).expect("ASCII")
    }

    // -- the single source of truth ----------------------------------------

    /// [`measured`] must be `c4`'s seam and not a second opinion about what a
    /// target costs. If `c4` ever changes what it reports, this fails here
    /// rather than in a number an operator reads.
    #[test]
    fn the_measured_cost_is_the_one_c4_reports() {
        let repository = ActivityScope::repository(OwnerRepo::parse("o/r").unwrap());
        assert_eq!(
            measured(TargetCost::from_activity_scope(&repository)),
            demand::target_cost(&repository),
            "the CLI must price a target the way `c4` reports it, through \
             `TargetCost::with_demand_requests_per_repository`"
        );

        let org = ActivityScope::organization(
            Org::new("acme").unwrap(),
            [
                OwnerRepo::parse("acme/one").unwrap(),
                OwnerRepo::parse("acme/two").unwrap(),
            ],
        );
        assert_eq!(
            measured(TargetCost::from_activity_scope(&org)),
            demand::target_cost(&org)
        );
    }

    /// The property this file exists to guarantee: the ceiling `host show`
    /// prints is the number `admit` will actually take.
    ///
    /// Asserted by *admitting targets one at a time until refused*, not by
    /// recomputing the division. A test that recomputed it would agree with a
    /// broken ceiling as readily as with a correct one.
    #[test]
    fn the_printed_ceiling_is_the_number_admit_actually_takes() {
        for secs in [
            RefreshInterval::MIN_SECS,
            RefreshInterval::DEFAULT_SECS,
            120,
        ] {
            let interval = RefreshInterval::from_secs(secs).expect("at or above the floor");
            let printed = max_repository_targets(interval);

            let mut admitted = 0_u32;
            let mut costs: Vec<TargetCost> = Vec::new();
            loop {
                let projection = BudgetProjection::new(interval, costs.clone());
                let candidate = measured(TargetCost::repository());
                if !projection.admit(candidate).is_admitted() {
                    break;
                }
                costs.push(candidate);
                admitted += 1;
                assert!(admitted < 10_000, "the loop must terminate");
            }

            assert_eq!(
                printed, admitted,
                "at a {interval} interval `host show` would print {printed} repository \
                 targets while `admit` takes {admitted}. Those two numbers appear in the \
                 same product, one in host settings and one in the refusal an operator gets \
                 when they add a target, and they must be the same number."
            );
        }
    }

    /// **A known gap at the source, pinned so that closing it is visible.**
    ///
    /// `c3`'s [`BudgetProjection::max_repository_targets`] builds
    /// `TargetCost::repository()` internally and so cannot see `c4`'s seam. It
    /// therefore still prices demand at the pre-decision estimate of two
    /// requests per repository per refresh, and prints a ceiling that
    /// `BudgetProjection::admit` does not honour.
    ///
    /// This file avoids the contradiction by never calling that function. The
    /// remedy is in `crates/github/src/rest.rs`, which `c3` owns: either change
    /// `DEMAND_REQUESTS_PER_REPOSITORY_PER_REFRESH` to one, or give
    /// `max_repository_targets` a `TargetCost` argument. When either lands,
    /// this test fails — and at that point it, and the note in the module
    /// documentation above, should go, and [`max_repository_targets`] can
    /// become a call into `c3`'s.
    #[test]
    fn c3s_ceiling_still_prices_demand_at_the_pre_decision_estimate() {
        let interval = RefreshInterval::default();

        assert_eq!(
            TargetCost::repository().requests_per_hour(interval),
            240,
            "c3's estimate: 1 inventory + 1 activity + 2 demand, 60 times an hour"
        );
        assert_eq!(
            measured(TargetCost::repository()).requests_per_hour(interval),
            180,
            "the measured cost: 1 inventory + 1 activity + 1 demand, 60 times an hour"
        );

        assert_eq!(
            BudgetProjection::max_repository_targets(interval),
            10,
            "c3's printed ceiling, computed from the estimate"
        );
        assert_eq!(
            max_repository_targets(interval),
            13,
            "this CLI's ceiling, computed from the cost `c4` actually issues"
        );
        assert!(
            BudgetProjection::max_repository_targets(interval) < max_repository_targets(interval),
            "the gap must stay in the conservative direction. If it ever inverts, c3's \
             figure would be admitting targets the budget cannot pay for, and the direction \
             of the fix changes."
        );
    }

    // -- the best-case caveat ----------------------------------------------

    /// [`FALLBACK_COST_MULTIPLE`] is a claim about `c3` and `c4`'s page bounds,
    /// so it is asserted against them rather than merely written down.
    #[test]
    fn the_stated_fallback_multiple_is_the_one_the_gateways_can_spend() {
        assert_eq!(
            ACTIVITY_REQUESTS_PER_REPOSITORY_PER_REFRESH, 1,
            "the projection prices the activity count at one request"
        );
        assert_eq!(
            u32::try_from(MAX_ACTIVITY_FALLBACK_PAGES).unwrap(),
            FALLBACK_COST_MULTIPLE,
            "and c3's fallback walk may spend this many, which is the multiple the caveat \
             states"
        );
        assert_eq!(
            DEMAND_REQUESTS_PER_REPOSITORY_PER_POLL, 1,
            "the projection prices the demand poll at one request"
        );
        assert_eq!(
            u32::try_from(MAX_DEMAND_FALLBACK_PAGES).unwrap(),
            FALLBACK_COST_MULTIPLE,
            "and c4's fallback walk may spend this many"
        );
    }

    /// The number is never printed bare. An operator reading "13 targets" as a
    /// threshold has been told something the model does not support.
    #[test]
    fn the_target_ceiling_is_never_presented_as_exact() {
        let budget = HostBudget::of(RefreshInterval::default(), &[repository("o/r")]);
        let rendered = budget_text(&budget);

        let ceiling = budget.max_repository_targets();
        assert!(
            rendered.contains(&format!("about {ceiling}")),
            "the ceiling must be hedged where it is printed: {rendered}"
        );
        assert!(
            rendered.contains("BEST-CASE"),
            "the caveat must be in the same output as the number: {rendered}"
        );
        assert!(
            rendered.contains(&format!("{FALLBACK_COST_MULTIPLE}x")),
            "the caveat must state by how much the best case can be exceeded: {rendered}"
        );
        assert!(
            rendered.contains("not as a threshold"),
            "the caveat must say what the number is not: {rendered}"
        );
    }

    // -- the projection ----------------------------------------------------

    #[test]
    fn an_empty_host_projects_nothing_and_has_the_whole_allowance() {
        let budget = HostBudget::of(RefreshInterval::default(), &[]);
        assert_eq!(budget.requests_per_hour(), 0);
        assert_eq!(budget.headroom(), budget_allowance());
        assert!(!budget.exceeds_allowance());
        assert!(!budget.is_floor(), "no organization target, no floor");
    }

    #[test]
    fn each_repository_target_costs_the_measured_amount() {
        let interval = RefreshInterval::default();
        let one = HostBudget::of(interval, &[repository("o/one")]);
        let three = HostBudget::of(
            interval,
            &[
                repository("o/one"),
                repository("o/two"),
                repository("o/three"),
            ],
        );
        assert_eq!(one.requests_per_hour(), 180);
        assert_eq!(three.requests_per_hour(), 540);
        assert!(
            budget_text(&three).contains("policies priced           3"),
            "the output must say how many policies the total covers, or an operator              cannot tell an under-count from a cheap set"
        );
    }

    /// An organization's real cost is unknown locally, so the total must be
    /// labelled a floor rather than quietly under-reported.
    #[test]
    fn an_organization_target_makes_the_total_a_floor_and_says_so() {
        let budget = HostBudget::of(RefreshInterval::default(), &[organization("acme")]);
        assert!(budget.is_floor());
        let rendered = budget_text(&budget);
        assert!(rendered.contains("(a floor)"), "{rendered}");
        assert!(
            rendered.contains("priced as one repository"),
            "the output must say why it is a floor, not merely that it is: {rendered}"
        );

        let repositories_only = HostBudget::of(RefreshInterval::default(), &[repository("o/r")]);
        assert!(
            !budget_text(&repositories_only).contains("(a floor)"),
            "a set with no organization target must not be labelled a floor, or the label \
             means nothing"
        );
    }

    /// A shorter interval costs proportionally more, and fewer targets fit —
    /// `04-subsystem-contracts.md` states both halves.
    ///
    /// The spend is an exact doubling; the ceiling is *not* exactly a halving,
    /// because it is an integer division and 2500/360 is 6 rather than 6.5.
    /// Asserting a clean halving would have been asserting arithmetic this
    /// model does not do.
    #[test]
    fn halving_the_interval_doubles_the_spend_and_lowers_the_ceiling() {
        let default = RefreshInterval::default();
        let floor = RefreshInterval::from_secs(RefreshInterval::MIN_SECS).unwrap();
        let targets = [repository("o/r")];

        assert_eq!(
            HostBudget::of(floor, &targets).requests_per_hour(),
            2 * HostBudget::of(default, &targets).requests_per_hour()
        );
        assert!(
            max_repository_targets(floor) < max_repository_targets(default),
            "a 30-second interval must fit fewer targets than a 60-second one: {} against {}",
            max_repository_targets(floor),
            max_repository_targets(default)
        );
        assert_eq!(max_repository_targets(floor), 6);
        assert_eq!(max_repository_targets(default), 13);
    }

    #[test]
    fn a_host_over_its_allowance_says_so_rather_than_only_showing_a_zero_headroom() {
        let interval = RefreshInterval::from_secs(RefreshInterval::MIN_SECS).unwrap();
        let targets: Vec<ScaleTarget> = (0..20)
            .map(|n| repository(&format!("owner/repo{n}")))
            .collect();
        let budget = HostBudget::of(interval, &targets);
        assert!(budget.exceeds_allowance());
        assert_eq!(budget.headroom(), 0);
        let rendered = budget_text(&budget);
        assert!(rendered.contains("OVER BUDGET"), "{rendered}");
    }

    /// The projection and the ceiling must be derived from one cost, so a
    /// target set exactly at the printed ceiling must fit.
    #[test]
    fn a_target_set_at_the_printed_ceiling_still_fits() {
        let interval = RefreshInterval::default();
        let ceiling = max_repository_targets(interval);
        let targets: Vec<ScaleTarget> = (0..ceiling)
            .map(|n| repository(&format!("owner/repo{n}")))
            .collect();
        let budget = HostBudget::of(interval, &targets);
        assert!(
            !budget.exceeds_allowance(),
            "the printed ceiling promised {ceiling} targets fit, and the projection says \
             {} requests/hour against an allowance of {}",
            budget.requests_per_hour(),
            budget.allowance()
        );

        let one_more: Vec<ScaleTarget> = (0..=ceiling)
            .map(|n| repository(&format!("owner/repo{n}")))
            .collect();
        assert!(
            HostBudget::of(interval, &one_more).exceeds_allowance(),
            "and one target past the ceiling must not fit, or the ceiling is not a ceiling"
        );
    }
}
