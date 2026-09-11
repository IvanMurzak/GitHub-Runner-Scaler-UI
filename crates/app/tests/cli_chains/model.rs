// owner: b1-local-model-corpus
//
//! The reference model: only the externally observable local state.
//!
//! `02-target-architecture.md`, "Executable reference model": host
//! capacity/runtime-root selection, credential presence, repository and
//! organization policies with their capacities, enabled state, labels and
//! workspace mode, and expected diagnostics retention. This file holds that
//! state and the read projections a runner compares against real output. The
//! transition function lives in [`super::transition`].
//!
//! # Independence
//!
//! Nothing here imports `runner-manager` code. The constants below — the exit
//! codes, the default host capacity, the REST prices — are restatements of the
//! published contract, so a product change that moves one of them makes the
//! model disagree with the product instead of silently following it.

use std::collections::{BTreeMap, BTreeSet};

use super::action::TargetKey;
use super::values::{PathValue, Scope, derived_symbol};

/// `DEFAULT_HOST_CAPACITY`: the capacity a host record is created with.
pub const DEFAULT_HOST_CAPACITY: u16 = 1;

/// Requests per hour a host may plan to spend: half of GitHub's 5 000.
pub const BUDGET_ALLOWANCE_PER_HOUR: u32 = 2_500;

/// Refreshes per hour at the default 60-second interval.
pub const REFRESHES_PER_HOUR: u32 = 60;

/// Runner-inventory requests per refresh, per target, at either scope.
pub const INVENTORY_REQUESTS_PER_TARGET_REFRESH: u32 = 1;

/// What `repo add` / `org add` prices each covered repository at when
/// admitting a target: one activity request plus the two-request demand
/// estimate, per refresh. A repository target covers one repository; an
/// organization covers every repository its installation reaches.
pub const ADMISSION_REQUESTS_PER_REPOSITORY_REFRESH: u32 = 3;

/// What `status` and `host show` price every policy at: the measured demand
/// cost (four) on one repository, with organizations priced at their floor of
/// one repository — `1 + 1 * (1 + 4)` requests per refresh.
pub const PROJECTION_REQUESTS_PER_POLICY_REFRESH: u32 = 6;

/// What admitting one repository target costs per hour: 240 at the default
/// interval, so ten fit under the allowance and the eleventh does not.
#[must_use]
pub const fn repository_admission_cost() -> u32 {
    (INVENTORY_REQUESTS_PER_TARGET_REFRESH + ADMISSION_REQUESTS_PER_REPOSITORY_REFRESH)
        * REFRESHES_PER_HOUR
}

/// The fake GitHub a scenario runs against.
///
/// Every account is an organization installation; `acme` is on every
/// non-empty fixture so repository and organization policies for the same
/// account can coexist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Installation {
    /// Signed in, App not installed anywhere.
    None,
    /// `acme` (`widgets`, `gadgets`) and `globex` (`portal`).
    Standard,
    /// `acme` alone, reaching thirteen repositories: enough to cross the REST
    /// budget with repository targets, and to make one organization target
    /// nearly fill it.
    Wide,
}

/// One installation the fake GitHub reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationSpec {
    pub id: u64,
    /// An organization login.
    pub account: &'static str,
    /// `owner/name`, lower case, in the order the fixture lists them.
    pub repositories: Vec<String>,
}

impl Installation {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Installation::None => "no-installation",
            Installation::Standard => "standard",
            Installation::Wide => "wide",
        }
    }

    /// What `GET /user/installations` and each
    /// `GET /user/installations/{id}/repositories` answer.
    #[must_use]
    pub fn specs(self) -> Vec<InstallationSpec> {
        match self {
            Installation::None => Vec::new(),
            Installation::Standard => vec![
                InstallationSpec {
                    id: 101,
                    account: "acme",
                    repositories: vec!["acme/widgets".to_string(), "acme/gadgets".to_string()],
                },
                InstallationSpec {
                    id: 202,
                    account: "globex",
                    repositories: vec!["globex/portal".to_string()],
                },
            ],
            Installation::Wide => {
                let mut repositories = vec!["acme/widgets".to_string(), "acme/gadgets".to_string()];
                repositories.extend((1..=11).map(|n| format!("acme/fleet-{n:02}")));
                vec![InstallationSpec {
                    id: 303,
                    account: "acme",
                    repositories,
                }]
            }
        }
    }

    /// Whether an installation covers the target.
    #[must_use]
    pub fn reaches(self, key: &TargetKey) -> bool {
        self.specs().iter().any(|spec| match key.scope {
            Scope::Repository => spec.repositories.contains(&key.slug),
            Scope::Organization => spec.account == key.slug,
        })
    }

    /// How many repositories the organization's installation reaches, zero
    /// when it has none.
    #[must_use]
    pub fn repositories_of(self, organization: &str) -> u32 {
        self.specs()
            .iter()
            .find(|spec| spec.account == organization)
            .map_or(0, |spec| {
                u32::try_from(spec.repositories.len()).unwrap_or(u32::MAX)
            })
    }
}

/// The observed lifecycle state of a policy the local suite can reach.
///
/// `authentication_failed` is a daemon outcome and has no local road in; it is
/// deliberately absent rather than modelled and never produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyState {
    Pending,
    Active,
    Draining,
    Disabled,
    RepairRequired,
}

impl PolicyState {
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            PolicyState::Pending => "pending",
            PolicyState::Active => "active",
            PolicyState::Draining => "draining",
            PolicyState::Disabled => "disabled",
            PolicyState::RepairRequired => "repair_required",
        }
    }
}

/// Monitor-only or autoscale (D19).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// No routing labels, no capacity, never starts a runner.
    MonitorOnly,
    /// A ceiling and the optional labels beside the derived host label.
    Autoscale {
        max_capacity: u16,
        /// Folded optional labels. The derived host label is never in here.
        extra_labels: BTreeSet<String>,
    },
}

impl Mode {
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Mode::MonitorOnly => "monitor_only",
            Mode::Autoscale { .. } => "autoscale",
        }
    }
}

/// Seeded runner attempts, by what they count as.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tally {
    pub active: u16,
    pub awaiting_cleanup: u16,
    pub cleaned: u16,
}

impl Tally {
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.active == 0 && self.awaiting_cleanup == 0 && self.cleaned == 0
    }

    /// Attempts that still own a directory: non-terminal or not yet cleaned.
    #[must_use]
    pub const fn uncleaned(self) -> u16 {
        self.active.saturating_add(self.awaiting_cleanup)
    }

    #[must_use]
    pub const fn plus(self, other: Tally) -> Tally {
        Tally {
            active: self.active.saturating_add(other.active),
            awaiting_cleanup: self.awaiting_cleanup.saturating_add(other.awaiting_cleanup),
            cleaned: self.cleaned.saturating_add(other.cleaned),
        }
    }
}

/// One policy, as its owner can observe it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Policy {
    /// The target exactly as it was typed on the `add` that created it. The
    /// product preserves that spelling for display.
    pub display: String,
    /// The folded `--host-label`, kept even while monitor-only.
    pub host_label: String,
    pub mode: Mode,
    /// Operator intent.
    pub enabled: bool,
    pub state: PolicyState,
    /// `Some(root)` when persistent, `None` when ephemeral.
    pub workspace: Option<PathValue>,
    /// Attempts journaled against this policy.
    pub attempts: Tally,
}

impl Policy {
    /// The derived routing label, symbolically.
    #[must_use]
    pub fn derived_label(&self) -> String {
        derived_symbol(&self.host_label)
    }

    /// Every routing label, host label first, `None` while monitor-only.
    #[must_use]
    pub fn routing_labels(&self) -> Option<Vec<String>> {
        match &self.mode {
            Mode::MonitorOnly => None,
            Mode::Autoscale { extra_labels, .. } => {
                let mut labels = vec![self.derived_label()];
                labels.extend(extra_labels.iter().cloned());
                Some(labels)
            }
        }
    }

    #[must_use]
    pub const fn max_capacity(&self) -> Option<u16> {
        match &self.mode {
            Mode::MonitorOnly => None,
            Mode::Autoscale { max_capacity, .. } => Some(*max_capacity),
        }
    }
}

/// This machine's host record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostModel {
    pub capacity: u16,
    /// `None` is the platform default.
    pub runner_root: Option<PathValue>,
}

/// The whole modelled state of one scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    pub installation: Installation,
    /// Whether the secret store holds a credential for the recorded start
    /// mode. The fake GitHub accepts every credential it issued.
    pub credential: bool,
    /// `None` until a command creates this machine's host record.
    pub host: Option<HostModel>,
    pub policies: BTreeMap<TargetKey, Policy>,
    /// Attempts journaled against policies that were removed without
    /// `--purge`: the retained diagnostics, by the target they belonged to.
    /// They still count host-wide, and a later policy for the same target does
    /// not inherit them (it has a new identity).
    pub retained: BTreeMap<TargetKey, Tally>,
    /// Creatable scratch directories that exist. `<roots>` and
    /// `<roots>/occupied.txt` always exist and are not listed.
    pub directories: BTreeSet<PathValue>,
    /// Whether `<data>/state/packages` exists.
    pub package_cache: bool,
}

impl Model {
    /// A fresh data root against the given fake GitHub.
    #[must_use]
    pub fn fresh(installation: Installation) -> Self {
        Self {
            installation,
            credential: false,
            host: None,
            policies: BTreeMap::new(),
            retained: BTreeMap::new(),
            directories: BTreeSet::new(),
            package_cache: false,
        }
    }

    #[must_use]
    pub fn host_capacity(&self) -> u16 {
        self.host
            .map_or(DEFAULT_HOST_CAPACITY, |host| host.capacity)
    }

    #[must_use]
    pub fn runner_root(&self) -> Option<PathValue> {
        self.host.and_then(|host| host.runner_root)
    }

    /// Every attempt still journaled, across live policies and retained
    /// diagnostics.
    #[must_use]
    pub fn journal(&self) -> Tally {
        self.policies
            .values()
            .map(|policy| policy.attempts)
            .chain(self.retained.values().copied())
            .fold(Tally::default(), Tally::plus)
    }

    /// Retained diagnostics, host-wide.
    #[must_use]
    pub fn retained_total(&self) -> Tally {
        self.retained
            .values()
            .copied()
            .fold(Tally::default(), Tally::plus)
    }

    /// The structural invariants every reachable model satisfies.
    ///
    /// These are properties of the *shape*, independent of which action led
    /// here, so a corrupted expectation that breaks one is caught even when it
    /// happens to be self-consistent with its own deltas.
    ///
    /// # Errors
    /// The first violated invariant.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(host) = self.host
            && host.capacity == 0
        {
            return Err("a host record never holds a zero capacity".to_string());
        }
        if let Some(root) = self.runner_root() {
            if root.location().is_none() || root == PathValue::InsideAppState {
                return Err(format!(
                    "{root:?} can never be a configured host runner root"
                ));
            }
            if root.is_creatable_leaf() && !self.directories.contains(&root) {
                return Err(format!("the configured host root {root:?} must exist"));
            }
        }
        for path in &self.directories {
            if !path.is_creatable_leaf() {
                return Err(format!("{path:?} is not a directory a command can create"));
            }
            if let Some(parent) = path.creatable_parent()
                && !self.directories.contains(&parent)
            {
                return Err(format!("{path:?} exists without its parent {parent:?}"));
            }
        }
        let roots: Vec<(&TargetKey, PathValue)> = self
            .policies
            .iter()
            .filter_map(|(key, policy)| policy.workspace.map(|root| (key, root)))
            .collect();
        for (index, (key, root)) in roots.iter().enumerate() {
            if key.scope != Scope::Repository {
                return Err(format!("{key} is an organization and cannot be persistent"));
            }
            if !self.directory_exists(*root) {
                return Err(format!("{key}'s persistent root {root:?} must exist"));
            }
            if let Some(host) = self.runner_root()
                && root.relation(host) != super::values::Relation::Disjoint
            {
                return Err(format!(
                    "{key}'s root {root:?} overlaps the host root {host:?}"
                ));
            }
            for (other_key, other) in &roots[index + 1..] {
                if root.relation(*other) != super::values::Relation::Disjoint {
                    return Err(format!(
                        "{key}'s root {root:?} overlaps {other_key}'s root {other:?}"
                    ));
                }
            }
        }
        for (key, policy) in &self.policies {
            if policy.enabled != (policy.state == PolicyState::Active) {
                return Err(format!(
                    "{key}: enabled={} with state {}; only an active policy is enabled",
                    policy.enabled,
                    policy.state.token()
                ));
            }
            match &policy.mode {
                Mode::MonitorOnly => {
                    if !matches!(
                        policy.state,
                        PolicyState::Pending | PolicyState::RepairRequired
                    ) {
                        return Err(format!(
                            "{key}: a monitor-only policy is never armed, so it cannot be {}",
                            policy.state.token()
                        ));
                    }
                }
                Mode::Autoscale {
                    max_capacity,
                    extra_labels,
                } => {
                    if *max_capacity == 0 {
                        return Err(format!("{key}: an autoscale ceiling is at least one"));
                    }
                    if extra_labels.contains(&policy.derived_label()) {
                        return Err(format!(
                            "{key}: the derived host label is never an optional label"
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Attempts occupying host capacity, host-wide.
    #[must_use]
    pub fn in_use(&self) -> u16 {
        self.journal().active
    }

    /// Whether a scratch path exists as a directory.
    #[must_use]
    pub fn directory_exists(&self, path: PathValue) -> bool {
        path == PathValue::RootsDir || self.directories.contains(&path)
    }

    /// What admitting one more target of this identity would cost per hour,
    /// at the price `add` uses.
    #[must_use]
    pub fn admission_cost(&self, key: &TargetKey) -> u32 {
        let repositories = match key.scope {
            Scope::Repository => 1,
            Scope::Organization => self.installation.repositories_of(&key.slug),
        };
        (INVENTORY_REQUESTS_PER_TARGET_REFRESH
            + repositories * ADMISSION_REQUESTS_PER_REPOSITORY_REFRESH)
            * REFRESHES_PER_HOUR
    }

    /// The hourly cost of every configured policy, at the admission price.
    #[must_use]
    pub fn admitted_cost(&self) -> u32 {
        self.policies
            .keys()
            .map(|key| self.admission_cost(key))
            .sum()
    }

    /// Whether any policy of the other scope exists.
    #[must_use]
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.policies.keys().any(|key| key.scope == scope)
    }

    /// The local snapshot `status --json` must agree with.
    #[must_use]
    pub fn status(&self) -> StatusProjection {
        let journal = self.journal();
        let capacity = self.host_capacity();
        let count = u32::try_from(self.policies.len()).unwrap_or(u32::MAX);
        StatusProjection {
            credential_present: self.credential,
            host_configured: self.host.is_some(),
            capacity,
            in_use: journal.active,
            headroom: capacity.saturating_sub(journal.active),
            runner_root_source: if self.runner_root().is_some() {
                "configured"
            } else {
                "platform_default"
            },
            configured_runner_root: self.runner_root(),
            active_ephemeral_attempts: journal.active,
            cleanup_blocked_ephemeral_attempts: journal.awaiting_cleanup,
            projected_requests_per_hour: count
                * PROJECTION_REQUESTS_PER_POLICY_REFRESH
                * REFRESHES_PER_HOUR,
            projection_is_floor: self.has_scope(Scope::Organization),
            policies: self
                .policies
                .iter()
                .map(|(key, policy)| PolicyProjection {
                    target: policy.display.clone(),
                    scope: key.scope.token(),
                    mode: policy.mode.token(),
                    state: policy.state.token(),
                    enabled: policy.enabled,
                    min_capacity: 0,
                    max_capacity: policy.max_capacity(),
                    routing_labels: policy.routing_labels().unwrap_or_default(),
                    active_attempts: policy.attempts.active,
                    cleanup_blocked_attempts: policy.attempts.awaiting_cleanup,
                    workspace_mode: if policy.workspace.is_some() {
                        "persistent"
                    } else {
                        "ephemeral"
                    },
                    workspace_root: policy.workspace,
                    workspace_root_source: match (policy.workspace, self.runner_root()) {
                        (Some(_), _) => "repository",
                        (None, Some(_)) => "configured",
                        (None, None) => "platform_default",
                    },
                })
                .collect(),
        }
    }

    /// The first line `repo list` / `org list` prints for each policy of the
    /// scope, in key order. The product's own order is its store's; compare as
    /// a set.
    #[must_use]
    pub fn list_lines(&self, scope: Scope) -> Vec<String> {
        self.policies
            .iter()
            .filter(|(key, _)| key.scope == scope)
            .map(|(_, policy)| {
                format!(
                    "{}\t{}\t{}\tenabled={}\tmax={}\tworkspace={}",
                    policy.display,
                    policy.mode.token(),
                    policy.state.token(),
                    policy.enabled,
                    policy
                        .max_capacity()
                        .map_or_else(|| "-".to_string(), |n| n.to_string()),
                    if policy.workspace.is_some() {
                        "persistent"
                    } else {
                        "ephemeral"
                    }
                )
            })
            .collect()
    }
}

/// What `status --json` must report, field for field, with paths and derived
/// labels left symbolic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusProjection {
    pub credential_present: bool,
    pub host_configured: bool,
    pub capacity: u16,
    pub in_use: u16,
    pub headroom: u16,
    pub runner_root_source: &'static str,
    pub configured_runner_root: Option<PathValue>,
    pub active_ephemeral_attempts: u16,
    pub cleanup_blocked_ephemeral_attempts: u16,
    pub projected_requests_per_hour: u32,
    pub projection_is_floor: bool,
    /// In target-key order.
    pub policies: Vec<PolicyProjection>,
}

/// One entry of `status --json`'s `policies`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyProjection {
    pub target: String,
    pub scope: &'static str,
    pub mode: &'static str,
    pub state: &'static str,
    pub enabled: bool,
    pub min_capacity: u16,
    pub max_capacity: Option<u16>,
    /// Host label first (symbolic), then the optional labels in order.
    pub routing_labels: Vec<String>,
    pub active_attempts: u16,
    pub cleanup_blocked_attempts: u16,
    pub workspace_mode: &'static str,
    pub workspace_root: Option<PathValue>,
    pub workspace_root_source: &'static str,
}
