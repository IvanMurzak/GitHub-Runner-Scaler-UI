// owner: b1-domain-core

//! Policies: routing identity, mode, lifecycle state, and ownership.
//!
//! Three things live here, and after D4 they are the whole of the product's
//! routing identity and configuration safety:
//!
//! 1. [`RoutingLabels`] — the routing token that replaced the scale-set name,
//!    with derivation and `runs-on` matching.
//! 2. [`PolicyMode`] — D19's monitor-only/autoscale split, expressed so that the
//!    illegal combinations cannot be constructed rather than being rejected on
//!    the way in.
//! 3. [`PolicyState`] — the lifecycle state machine, which rejects every
//!    transition outside the diagram in `04-subsystem-contracts.md`.
//!
//! **There is no reservation here, and none may be added.** `AcquireJobs` has no
//! REST equivalent (`01-current-architecture.md`, edge case 6), so demand is
//! advisory and a surplus runner is an accepted, bounded cost. The bounding
//! controls are the host-scoped default label derived below, plus the two
//! capacity ceilings in [`crate::capacity`]. A lease, claim, or local
//! reservation table added here would not fix the surplus case; it would only
//! hide it from the tests that measure it (`h1` scenario 8).

use std::collections::BTreeSet;
use std::fmt;
use std::num::{NonZeroU16, NonZeroUsize};

use serde::{Deserialize, Serialize};

use crate::model::{
    Arch, CachePolicy, HostId, HostLabel, Label, NonEmpty, Os, PolicyId, ScaleTarget,
    ValidationError,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error(transparent)]
    Invalid(#[from] ValidationError),

    #[error(
        "an Autoscale policy requires routing labels; a policy with none is a \
         MonitorOnly policy (D19)"
    )]
    AutoscaleWithoutRoutingLabels,

    #[error(
        "an Autoscale policy requires max_capacity; without a ceiling it could \
         oversubscribe the host (D7, D19)"
    )]
    AutoscaleWithoutMaxCapacity,

    // There was a `MonitorOnlyWithRoutingLabels` variant here, meaning "this
    // *stored row* has an illegal shape". It is deleted rather than kept for
    // `b2`, because nothing can construct it and nothing can construct it later
    // either: `PolicyMode::from_persisted` matches exhaustively across four arms
    // and never returns it, and `PersistedPolicy` -- the only shape `b2` loads
    // through -- has no `mode` field, so no schema reachable from here can
    // express "monitor-only *with* labels" in the first place. A row carrying
    // routing labels is autoscale-shaped by definition, and
    // labels-without-`max_capacity` is caught as `AutoscaleWithoutMaxCapacity`
    // first. Keeping it would have had `f2` write a match arm and a user-facing
    // message for a condition that cannot occur and that no test can cover.
    #[error(
        "a MonitorOnly policy must not carry a non-zero min_capacity ({min}); it \
         never starts a runner (D19)"
    )]
    MonitorOnlyWithMinCapacity { min: u16 },

    #[error("min_capacity ({min}) must not exceed max_capacity ({max})")]
    InvertedCapacityRange { min: u16, max: u16 },

    #[error("{to} is not a legal transition from {from}")]
    IllegalTransition { from: PolicyState, to: PolicyState },

    #[error(
        "only a MonitorOnly policy can be promoted to Autoscale; this one is already Autoscale"
    )]
    AlreadyAutoscale,

    #[error(
        "this operation needs an Autoscale policy; a MonitorOnly policy has no \
         capacity and no routing labels to change (D19)"
    )]
    NotAutoscale,

    #[error("the host label {label} is the routing identity of this policy and cannot be removed")]
    HostLabelNotRemovable { label: Label },
}

// ---------------------------------------------------------------------------
// Routing labels
// ---------------------------------------------------------------------------

/// A policy's routing label set: the token `runs-on` targets.
///
/// `04-subsystem-contracts.md` types this as `Option<NonEmpty<Label>>`. This
/// type is the `NonEmpty<Label>` half, and it is deliberately *stronger* than a
/// non-empty vector, because the contract has two separate requirements that a
/// bare `NonEmpty` only covers one of:
///
/// * **Non-empty.** Guaranteed by [`RoutingLabels::host_label`] always existing.
///   `generate-jitconfig` rejects `labels: []` with `422`
///   (`docs/spikes/d18-org-jit-verification.md`, Point 3), so an empty set is
///   not a case to handle downstream.
/// * **The derived host label may not be dropped.** `b1`: "Optional descriptive
///   labels may be added to the set; the derived host label may not be dropped
///   from it." A `Vec<Label>` cannot express that. Here the host label is a
///   separate field with no removal path, so dropping it is not a rule anyone
///   has to remember.
///
/// The `Option` half of `Option<NonEmpty<Label>>` is carried by [`PolicyMode`]:
/// `MonitorOnly` has no routing labels because the variant has no field for
/// them, not because the field happens to be `None`.
///
/// **Why the default is host-scoped.** With no `AcquireJobs`, nothing reserves a
/// queued job for one host. Two hosts whose policies carry the same label will
/// both start a runner for the same job, and the loser pays a capacity slot and
/// a cold start (`01-current-architecture.md`, edge case 6). The host identity
/// baked into the derived label is the only control that prevents that by
/// default — the capacity ceilings only bound it once it happens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RoutingLabelsRepr", into = "RoutingLabelsRepr")]
pub struct RoutingLabels {
    host_label: Label,
    additional: BTreeSet<Label>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoutingLabelsRepr {
    host_label: Label,
    #[serde(default)]
    additional: BTreeSet<Label>,
}

impl From<RoutingLabelsRepr> for RoutingLabels {
    fn from(repr: RoutingLabelsRepr) -> Self {
        // Normalising on the way in rather than erroring: a stored set that
        // happens to repeat the host label among the optional labels is not
        // corrupt, it is redundant, and silently de-duplicating it keeps
        // `count()` honest.
        Self::from_parts(repr.host_label, repr.additional)
    }
}

impl From<RoutingLabels> for RoutingLabelsRepr {
    fn from(value: RoutingLabels) -> Self {
        Self {
            host_label: value.host_label,
            additional: value.additional,
        }
    }
}

impl RoutingLabels {
    /// The product prefix in a derived label.
    pub const PREFIX: &'static str = "rm";

    /// Derive the host-scoped default label, `rm-<host>-<os>-<arch>`.
    ///
    /// `02-target-architecture.md`: "The label set … encodes the product, host
    /// identity, and host OS — for example `rm-home-win-x64`." Read against that
    /// sentence the four segments are product / host identity / OS /
    /// architecture, so `--host-label home` on a Windows x64 host derives
    /// `rm-home-win-x64`.
    ///
    /// Note that the worked command in `03-control-flows.md` step 3 passes
    /// `--host-label home-win`, which under this rule derives
    /// `rm-home-win-win-x64`. That is a redundant example rather than a
    /// different rule — `b1`'s Scope names the three inputs explicitly — but it
    /// is recorded here because it is the obvious thing for a reader to trip on.
    #[must_use]
    pub fn derive(host_label: &HostLabel, os: Os, arch: Arch) -> Self {
        let derived = format!(
            "{}-{}-{}-{}",
            Self::PREFIX,
            host_label.as_str(),
            os.label_token(),
            arch.label_token()
        );
        Self {
            host_label: Label::new(derived).expect(
                "a HostLabel is ASCII alphanumeric plus `-`/`_` and the other three \
                 segments are fixed tokens, so the concatenation is always a valid Label",
            ),
            additional: BTreeSet::new(),
        }
    }

    /// Build from an explicit host label, for the operator override `f2`
    /// supports, and for `b2` reloading a stored set.
    ///
    /// **This accepts any [`Label`] as the host label, including one that is not
    /// host-scoped at all.** "Host-scoped by construction" is a property of
    /// [`Self::derive`], not of this type: `f2` deliberately supports an
    /// operator override, so a hard rejection here would break a supported
    /// workflow, and this is also the serde path, so `b2` reaches it for every
    /// stored row. A hand-edited row can therefore set `host_label` to
    /// `self-hosted`, and [`Self::remove`] will then defend *that* as immovable
    /// while two hosts happily serve each other's jobs. Ask
    /// [`Self::is_derived_shape`] before trusting the collision control.
    #[must_use]
    pub fn from_parts(host_label: Label, additional: impl IntoIterator<Item = Label>) -> Self {
        let additional = additional
            .into_iter()
            .filter(|l| *l != host_label)
            .collect();
        Self {
            host_label,
            additional,
        }
    }

    /// Build from an explicit host label with no optional labels.
    #[must_use]
    pub fn from_host_label(host_label: Label) -> Self {
        Self::from_parts(host_label, Vec::new())
    }

    /// The one label that carries host identity and cannot be removed.
    #[must_use]
    pub fn host_label(&self) -> &Label {
        &self.host_label
    }

    /// Whether the host label still has the shape [`Self::derive`] produces:
    /// `rm-<host>-<os>-<arch>`, with the OS and architecture segments being
    /// tokens this crate actually emits.
    ///
    /// **This is a warning predicate, not a validation rule.** It is `false` for
    /// an operator override, and an override is supported — `f2` offers one on
    /// purpose. What it detects is that the *collision control has been turned
    /// off*: the derived shape is what keeps two hosts from answering each
    /// other's jobs, so a policy whose host label is `self-hosted` or
    /// `ubuntu-latest` will route work that belongs to another machine, and
    /// [`Self::remove`] will refuse to remove that label because it cannot tell
    /// the difference. `f2` and `g2` should say so rather than fail; nothing
    /// here rejects it.
    ///
    /// Matching is structural rather than a check against a known host label,
    /// because the host label this was derived from is not stored — only the
    /// concatenation is.
    ///
    /// **The middle segments are not inspected, only counted.** An earlier
    /// version also required every one of them to be non-empty, meaning to
    /// reject an empty host segment — but a [`HostLabel`] cannot be empty, so
    /// that condition never rejected anything [`Self::derive`] could produce and
    /// only ever produced false negatives: `HostLabel::new("home--pc")` is legal
    /// (only a *leading* or *trailing* `-` is refused), derives
    /// `rm-home--pc-win-x64`, and was reported as not derived. The consequence
    /// was `f2`/`g2` warning an operator that their collision control was off
    /// when they had done nothing wrong, which is worse than the residual it
    /// leaves: a hand-edited `rm--win-x64` now reads as derived. That row is
    /// still host-scoped in shape, so it does not mislead in the direction this
    /// predicate exists to catch.
    #[must_use]
    pub fn is_derived_shape(&self) -> bool {
        let segments: Vec<&str> = self.host_label.as_str().split('-').collect();
        // `rm` / host / os / arch. The host segment is a HostLabel, which never
        // contains `-`... except that it may: `--host-label home-win` is legal
        // and derives `rm-home-win-win-x64`. So the fixed ends are what is
        // checked, and everything between them is the host identity.
        let [prefix, middle @ .., os, arch] = segments.as_slice() else {
            return false;
        };
        // `Os::ALL` / `Arch::ALL` rather than a literal list, so a fourth OS or
        // architecture is recognised here the moment it exists.
        *prefix == Self::PREFIX
            && !middle.is_empty()
            && Os::ALL
                .iter()
                .any(|candidate| candidate.label_token() == *os)
            && Arch::ALL
                .iter()
                .any(|candidate| candidate.label_token() == *arch)
    }

    /// The optional descriptive labels, in sorted order.
    pub fn additional(&self) -> impl Iterator<Item = &Label> {
        self.additional.iter()
    }

    /// Add an optional descriptive label. Returns `false` if it was already in
    /// the set (including as the host label).
    pub fn add(&mut self, label: Label) -> bool {
        if label == self.host_label {
            return false;
        }
        self.additional.insert(label)
    }

    /// Remove an optional descriptive label.
    ///
    /// # Errors
    /// [`PolicyError::HostLabelNotRemovable`] when asked to remove the host
    /// label. There is deliberately no override: this is the routing identity
    /// that keeps two hosts from serving each other's jobs.
    pub fn remove(&mut self, label: &Label) -> Result<bool, PolicyError> {
        if *label == self.host_label {
            return Err(PolicyError::HostLabelNotRemovable {
                label: label.clone(),
            });
        }
        Ok(self.additional.remove(label))
    }

    #[must_use]
    pub fn contains(&self, label: &Label) -> bool {
        self.host_label == *label || self.additional.contains(label)
    }

    /// Every label, host label first.
    pub fn iter(&self) -> impl Iterator<Item = &Label> {
        std::iter::once(&self.host_label).chain(self.additional.iter())
    }

    /// Never zero.
    #[must_use]
    pub fn count(&self) -> NonZeroUsize {
        NonZeroUsize::new(1 + self.additional.len()).expect("the host label is always present")
    }

    /// The same set in the shape `04-subsystem-contracts.md` names.
    #[must_use]
    pub fn to_non_empty(&self) -> NonEmpty<Label> {
        let mut out = NonEmpty::of(self.host_label.clone());
        for label in &self.additional {
            out.push(label.clone());
        }
        out
    }

    /// The `labels` array for `generate-jitconfig`
    /// (`04-subsystem-contracts.md`, "Generate JIT configuration").
    ///
    /// `c4` sends exactly this. It matters that it is exactly this: the `v1`
    /// spike established that **no labels are added implicitly** — the `201`
    /// carries the requested labels and nothing else, so a runner registered
    /// from this array does not answer `runs-on: self-hosted` unless
    /// `self-hosted` is in it (`docs/spikes/d18-org-jit-verification.md`,
    /// Point 3, findings 1 and 2).
    #[must_use]
    pub fn as_registration_labels(&self) -> Vec<String> {
        self.iter().map(|l| l.as_str().to_string()).collect()
    }

    /// Decide whether this policy should serve a queued job.
    ///
    /// GitHub assigns a job to a runner whose label set is a **superset** of the
    /// job's required labels, so the predicate is subset-in-the-other-direction:
    /// the job's required labels must all be present here.
    #[must_use]
    pub fn matches(&self, runs_on: &RunsOn) -> RunsOnMatch {
        let required = match runs_on.required_labels() {
            Ok(required) => required,
            Err(unresolvable) => return RunsOnMatch::Unresolvable(unresolvable),
        };

        let missing: Vec<Label> = required
            .iter()
            .filter(|label| !self.contains(label))
            .cloned()
            .collect();

        if missing.is_empty() {
            RunsOnMatch::Match {
                runner_group: runs_on.runner_group().map(str::to_string),
            }
        } else {
            RunsOnMatch::NoMatch { missing }
        }
    }

    /// Tally a poll's worth of queued jobs into a demand signal.
    ///
    /// The three counts are kept apart on purpose. An unresolvable `runs-on` is
    /// neither counted as demand nor dropped: `b1` requires it be "reported as
    /// unresolvable rather than silently counted or silently dropped", because
    /// counting it would start a runner for a job that may not be ours and
    /// dropping it would hide a workflow this host can never serve.
    #[must_use]
    pub fn tally<'a>(&self, jobs: impl IntoIterator<Item = &'a RunsOn>) -> DemandTally {
        let mut tally = DemandTally::default();
        for job in jobs {
            match self.matches(job) {
                RunsOnMatch::Match { .. } => tally.matched += 1,
                RunsOnMatch::NoMatch { .. } => tally.not_matched += 1,
                RunsOnMatch::Unresolvable(reason) => tally.unresolvable.push(reason),
            }
        }
        tally
    }
}

impl fmt::Display for RoutingLabels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined: Vec<&str> = self.iter().map(Label::as_str).collect();
        f.write_str(&joined.join(","))
    }
}

/// The result of one poll's label matching.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemandTally {
    /// Jobs this policy should serve. This is the demand signal `e1` clamps.
    pub matched: u32,
    /// Jobs whose required labels this policy does not carry.
    pub not_matched: u32,
    /// Jobs whose `runs-on` could not be resolved statically. Never demand,
    /// never discarded — `g2` surfaces these so an operator can see that a
    /// workflow this host will never serve is sitting in the queue.
    pub unresolvable: Vec<UnresolvableRunsOn>,
}

impl DemandTally {
    #[must_use]
    pub fn demand(&self) -> u32 {
        self.matched
    }

    #[must_use]
    pub fn total_seen(&self) -> u32 {
        self.matched + self.not_matched + self.unresolvable.len() as u32
    }
}

/// The outcome of matching one job's `runs-on` against a policy's labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunsOnMatch {
    /// The job's required labels are all present.
    ///
    /// `runner_group` carries the `group:` key when the map form named one. The
    /// domain does not evaluate it — a policy has no runner-group field, and
    /// `c4` resolves the group id at registration time — but it is returned
    /// rather than discarded so that a caller which *can* evaluate it is not
    /// forced to re-parse the `runs-on`.
    Match { runner_group: Option<String> },
    /// At least one required label is absent. `missing` is what to tell an
    /// operator who expected this policy to pick the job up.
    NoMatch { missing: Vec<Label> },
    /// The `runs-on` cannot be resolved without evaluating the workflow.
    Unresolvable(UnresolvableRunsOn),
}

impl RunsOnMatch {
    #[must_use]
    pub const fn is_match(&self) -> bool {
        matches!(self, RunsOnMatch::Match { .. })
    }

    #[must_use]
    pub const fn is_unresolvable(&self) -> bool {
        matches!(self, RunsOnMatch::Unresolvable(_))
    }
}

/// Why a `runs-on` could not be resolved statically.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnresolvableRunsOn {
    /// A GitHub Actions expression, `${{ … }}`. Its value depends on the run's
    /// context, which this process does not have.
    #[error("`runs-on` contains an expression that only GitHub can evaluate: {raw}")]
    Expression { raw: String },

    /// `runs-on: {group: X}` with no `labels`. The job constrains the runner
    /// *group*, and a policy records no group, so nothing here can decide it.
    #[error("`runs-on` names runner group {group} but no labels, so no label predicate applies")]
    RunnerGroupWithoutLabels { group: String },

    /// A `runs-on` naming no labels at all.
    #[error("`runs-on` names no labels")]
    NoLabels,

    /// A label that is not a label — a comma or a control character.
    #[error("`runs-on` contains {raw:?}, which is not a usable label: {source}")]
    InvalidLabel {
        raw: String,
        #[source]
        source: ValidationError,
    },
}

/// A queued job's `runs-on`, in each documented form.
///
/// GitHub's "List jobs for a workflow run" response gives a job's labels as a
/// flat array, so in practice `c4` will build [`RunsOn::Many`]. The string and
/// map forms are supported because they are what a workflow file contains and
/// what `b1`'s Definition of Done enumerates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RunsOn {
    /// `runs-on: ubuntu-latest`
    Single(String),
    /// `runs-on: [self-hosted, linux]`
    Many(Vec<String>),
    /// `runs-on: {group: g, labels: [a, b]}`
    Grouped {
        #[serde(default)]
        group: Option<String>,
        #[serde(default)]
        labels: RunsOnLabels,
    },
}

/// The `labels` key of the map form, which GitHub allows as a scalar or a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RunsOnLabels {
    One(String),
    Many(Vec<String>),
}

impl Default for RunsOnLabels {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl RunsOnLabels {
    fn as_slice(&self) -> &[String] {
        match self {
            RunsOnLabels::One(one) => std::slice::from_ref(one),
            RunsOnLabels::Many(many) => many,
        }
    }
}

impl RunsOn {
    /// The array form, which is what the jobs API returns.
    #[must_use]
    pub fn from_job_labels(labels: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Many(labels.into_iter().map(Into::into).collect())
    }

    /// The runner group the map form named, if any.
    #[must_use]
    pub fn runner_group(&self) -> Option<&str> {
        match self {
            RunsOn::Grouped { group, .. } => group.as_deref(),
            _ => None,
        }
    }

    fn raw_labels(&self) -> &[String] {
        match self {
            RunsOn::Single(one) => std::slice::from_ref(one),
            RunsOn::Many(many) => many,
            RunsOn::Grouped { labels, .. } => labels.as_slice(),
        }
    }

    /// The normalised labels this job requires.
    ///
    /// **Whitespace-only array elements are dropped, not rejected.** A
    /// `runs-on: ["self-hosted", "", "linux"]` is a workflow that GitHub itself
    /// accepts, and the empty element carries no routing meaning, so treating it
    /// as an [`UnresolvableRunsOn::InvalidLabel`] would report a job as
    /// unresolvable — and so exclude it from demand and surface it to an
    /// operator — over a stray comma in someone's YAML. The elements that
    /// remain are what the job actually requires. If *every* element is
    /// whitespace the array resolves to nothing at all, and that **is**
    /// reported, as [`UnresolvableRunsOn::NoLabels`] or
    /// [`UnresolvableRunsOn::RunnerGroupWithoutLabels`].
    ///
    /// # Errors
    /// Every reason the value cannot be turned into a label set — each of which
    /// the caller reports rather than treating as "no demand".
    pub fn required_labels(&self) -> Result<Vec<Label>, UnresolvableRunsOn> {
        let raws = self.raw_labels();

        if let Some(raw) = raws.iter().find(|r| is_expression(r)) {
            return Err(UnresolvableRunsOn::Expression { raw: raw.clone() });
        }

        let usable: Vec<&String> = raws.iter().filter(|r| !r.trim().is_empty()).collect();

        if usable.is_empty() {
            return match self.runner_group() {
                Some(group) => Err(UnresolvableRunsOn::RunnerGroupWithoutLabels {
                    group: group.to_string(),
                }),
                None => Err(UnresolvableRunsOn::NoLabels),
            };
        }

        usable
            .into_iter()
            .map(|raw| {
                Label::new(raw).map_err(|source| UnresolvableRunsOn::InvalidLabel {
                    raw: raw.clone(),
                    source,
                })
            })
            .collect()
    }
}

fn is_expression(raw: &str) -> bool {
    raw.contains("${{")
}

// ---------------------------------------------------------------------------
// PolicyMode (D19)
// ---------------------------------------------------------------------------

/// The autoscale half of [`PolicyMode`].
///
/// Every field an `Autoscale` policy requires lives here, unconditionally. That
/// is the whole trick: there is no `Option` to be `None` and no separate
/// validator to forget, so "an autoscale policy with no capacity ceiling" is not
/// a state this program can hold in memory, let alone persist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AutoscaleConfigRepr")]
pub struct AutoscaleConfig {
    routing_labels: RoutingLabels,
    min_capacity: u16,
    max_capacity: NonZeroU16,
}

#[derive(Debug, Deserialize)]
struct AutoscaleConfigRepr {
    routing_labels: RoutingLabels,
    min_capacity: u16,
    max_capacity: NonZeroU16,
}

impl TryFrom<AutoscaleConfigRepr> for AutoscaleConfig {
    type Error = PolicyError;

    fn try_from(repr: AutoscaleConfigRepr) -> Result<Self, Self::Error> {
        Self::new(repr.routing_labels, repr.min_capacity, repr.max_capacity)
    }
}

impl AutoscaleConfig {
    /// # Errors
    /// [`PolicyError::InvertedCapacityRange`] when `min > max`. Validated here
    /// so `clamp(demand, min, max)` in [`crate::capacity`] is always
    /// well-defined — an inverted range makes `clamp` panic in Rust, so this is
    /// not a stylistic check.
    pub fn new(
        routing_labels: RoutingLabels,
        min_capacity: u16,
        max_capacity: NonZeroU16,
    ) -> Result<Self, PolicyError> {
        if min_capacity > max_capacity.get() {
            return Err(PolicyError::InvertedCapacityRange {
                min: min_capacity,
                max: max_capacity.get(),
            });
        }
        Ok(Self {
            routing_labels,
            min_capacity,
            max_capacity,
        })
    }

    /// The v1 shape: `min_capacity` fixed at 0 (D7).
    ///
    /// # Errors
    /// Never fails, because 0 cannot exceed a [`NonZeroU16`]; the `Result` is
    /// kept so that lifting the D7 restriction later is not a signature change.
    pub fn v1(
        routing_labels: RoutingLabels,
        max_capacity: NonZeroU16,
    ) -> Result<Self, PolicyError> {
        Self::new(routing_labels, 0, max_capacity)
    }

    #[must_use]
    pub fn routing_labels(&self) -> &RoutingLabels {
        &self.routing_labels
    }

    #[must_use]
    pub fn routing_labels_mut(&mut self) -> &mut RoutingLabels {
        &mut self.routing_labels
    }

    #[must_use]
    pub const fn min_capacity(&self) -> u16 {
        self.min_capacity
    }

    #[must_use]
    pub const fn max_capacity(&self) -> NonZeroU16 {
        self.max_capacity
    }

    /// # Errors
    /// [`PolicyError::InvertedCapacityRange`] if the new ceiling is below the
    /// existing floor.
    pub fn set_max_capacity(&mut self, max_capacity: NonZeroU16) -> Result<(), PolicyError> {
        if self.min_capacity > max_capacity.get() {
            return Err(PolicyError::InvertedCapacityRange {
                min: self.min_capacity,
                max: max_capacity.get(),
            });
        }
        self.max_capacity = max_capacity;
        Ok(())
    }
}

/// D19, as an enforced invariant rather than a convention.
///
/// `04-subsystem-contracts.md`:
///
/// * "`MonitorOnly` requires `routing_labels` and `max_capacity` to be `None`."
/// * "`Autoscale` requires both to be `Some`."
///
/// The contract writes those as three flat, independently-`Option`al fields on
/// `ScalePolicy`, which admits four combinations of which two are illegal. This
/// enum admits exactly the two legal ones, so the illegal pair has no
/// representation — `b1` asks for that explicitly: "Prefer a representation
/// where the illegal combination cannot be built at all over one that is merely
/// validated on the way in."
///
/// The flat shape is still reachable: [`PolicyMode::routing_labels`],
/// [`PolicyMode::min_capacity`], and [`PolicyMode::max_capacity`] return exactly
/// the `Option`s the contract names, and [`PolicyMode::from_persisted`] rebuilds
/// the mode from them. That is `b2`'s load path, and it is where a hand-edited
/// database row is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PolicyMode {
    /// Contributes runners and workflow counts to the dashboard; owns no
    /// routing label; skipped entirely by reconciliation.
    MonitorOnly,
    /// Starts runners, up to `max_capacity` and the host ceiling.
    Autoscale(AutoscaleConfig),
}

impl PolicyMode {
    #[must_use]
    pub const fn monitor_only() -> Self {
        Self::MonitorOnly
    }

    /// # Errors
    /// [`PolicyError::InvertedCapacityRange`].
    pub fn autoscale(
        routing_labels: RoutingLabels,
        min_capacity: u16,
        max_capacity: NonZeroU16,
    ) -> Result<Self, PolicyError> {
        Ok(Self::Autoscale(AutoscaleConfig::new(
            routing_labels,
            min_capacity,
            max_capacity,
        )?))
    }

    /// Rebuild the mode from the flat persisted shape.
    ///
    /// This is the gate `b2` puts every load through. All four combinations of
    /// `routing_labels`/`max_capacity` arrive here, and two of them are refused
    /// with a named error rather than being coerced into something plausible.
    ///
    /// # Errors
    /// Each illegal shape gets its own variant, so `b2` can say which column of
    /// which row is wrong rather than "invalid policy".
    pub fn from_persisted(
        routing_labels: Option<RoutingLabels>,
        min_capacity: u16,
        max_capacity: Option<NonZeroU16>,
    ) -> Result<Self, PolicyError> {
        match (routing_labels, max_capacity) {
            (None, None) => {
                if min_capacity != 0 {
                    // Not stated as a shape rule in `04`, but a MonitorOnly
                    // policy never starts a runner, so a non-zero floor is data
                    // that cannot mean anything. Refusing it loudly beats
                    // loading it and silently ignoring it.
                    return Err(PolicyError::MonitorOnlyWithMinCapacity { min: min_capacity });
                }
                Ok(Self::MonitorOnly)
            }
            (Some(_), None) => Err(PolicyError::AutoscaleWithoutMaxCapacity),
            (None, Some(_)) => Err(PolicyError::AutoscaleWithoutRoutingLabels),
            (Some(labels), Some(max)) => Self::autoscale(labels, min_capacity, max),
        }
    }

    /// The contract's `routing_labels: Option<NonEmpty<Label>>`, in `Option`
    /// form.
    #[must_use]
    pub const fn routing_labels(&self) -> Option<&RoutingLabels> {
        match self {
            PolicyMode::MonitorOnly => None,
            PolicyMode::Autoscale(cfg) => Some(&cfg.routing_labels),
        }
    }

    #[must_use]
    pub const fn min_capacity(&self) -> u16 {
        match self {
            PolicyMode::MonitorOnly => 0,
            PolicyMode::Autoscale(cfg) => cfg.min_capacity,
        }
    }

    #[must_use]
    pub const fn max_capacity(&self) -> Option<NonZeroU16> {
        match self {
            PolicyMode::MonitorOnly => None,
            PolicyMode::Autoscale(cfg) => Some(cfg.max_capacity),
        }
    }

    #[must_use]
    pub const fn autoscale_config(&self) -> Option<&AutoscaleConfig> {
        match self {
            PolicyMode::MonitorOnly => None,
            PolicyMode::Autoscale(cfg) => Some(cfg),
        }
    }

    #[must_use]
    pub const fn is_autoscale(&self) -> bool {
        matches!(self, PolicyMode::Autoscale(_))
    }

    #[must_use]
    pub const fn is_monitor_only(&self) -> bool {
        matches!(self, PolicyMode::MonitorOnly)
    }
}

// ---------------------------------------------------------------------------
// PolicyState
// ---------------------------------------------------------------------------

/// The policy lifecycle, exactly as `04-subsystem-contracts.md` draws it:
///
/// ```text
/// pending -> active | repair_required
/// active  -> draining -> disabled
/// any     -> authentication_failed        (recoverable by re-authentication)
/// ```
///
/// **Every transition outside that diagram is rejected**, which `b1`'s
/// Definition of Done requires. Two consequences are worth stating because they
/// are surprising, and both are recorded as findings rather than papered over:
///
/// * `RepairRequired` has no outgoing edge except the `any` rule. A policy that
///   enters it can never return to `Active` through this state machine.
/// * `Disabled` likewise has no outgoing edge, so a policy that finished
///   draining cannot be re-enabled through `state`. What `set-scale --enabled
///   true` changes is [`ScalePolicy::enabled`], which the contract keeps
///   deliberately independent of `state` ("`enabled` records operator intent;
///   `state` records observed lifecycle"), but nothing in the diagram then moves
///   `state` back.
///
/// The one edge here that the diagram does not draw as an arrow is
/// `AuthenticationFailed -> Pending`, which is the parenthetical "(recoverable
/// by re-authentication)" made executable; `pending` is where it lands because
/// that is the diagram's only entry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Pending,
    Active,
    Draining,
    Disabled,
    RepairRequired,
    AuthenticationFailed,
}

impl PolicyState {
    pub const ALL: [PolicyState; 6] = [
        PolicyState::Pending,
        PolicyState::Active,
        PolicyState::Draining,
        PolicyState::Disabled,
        PolicyState::RepairRequired,
        PolicyState::AuthenticationFailed,
    ];

    /// The complete legal transition list. Nothing outside it is permitted, and
    /// a self-transition is not in it either.
    pub const LEGAL: &'static [(PolicyState, PolicyState)] = &[
        (PolicyState::Pending, PolicyState::Active),
        (PolicyState::Pending, PolicyState::RepairRequired),
        (PolicyState::Active, PolicyState::Draining),
        (PolicyState::Draining, PolicyState::Disabled),
        // `any -> authentication_failed`.
        (PolicyState::Pending, PolicyState::AuthenticationFailed),
        (PolicyState::Active, PolicyState::AuthenticationFailed),
        (PolicyState::Draining, PolicyState::AuthenticationFailed),
        (PolicyState::Disabled, PolicyState::AuthenticationFailed),
        (
            PolicyState::RepairRequired,
            PolicyState::AuthenticationFailed,
        ),
        // "(recoverable by re-authentication)".
        (PolicyState::AuthenticationFailed, PolicyState::Pending),
    ];

    #[must_use]
    pub fn can_transition_to(self, next: PolicyState) -> bool {
        Self::LEGAL.contains(&(self, next))
    }

    /// True while the policy is allowed to be the reason a runner starts.
    #[must_use]
    pub const fn admits_new_runners(self) -> bool {
        matches!(self, PolicyState::Active)
    }
}

impl fmt::Display for PolicyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PolicyState::Pending => "pending",
            PolicyState::Active => "active",
            PolicyState::Draining => "draining",
            PolicyState::Disabled => "disabled",
            PolicyState::RepairRequired => "repair_required",
            PolicyState::AuthenticationFailed => "authentication_failed",
        })
    }
}

// ---------------------------------------------------------------------------
// ScalePolicy
// ---------------------------------------------------------------------------

/// One target, scaled (or merely watched) by one host.
///
/// `mode`, `enabled`, `state`, and `revision` are private: each is governed by an
/// invariant that a direct assignment would bypass. `id`, `target`,
/// `installation_id`, `host_id`, and `cache_policy` are public because they are
/// either immutable identity or self-validating values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalePolicy {
    pub id: PolicyId,
    pub target: ScaleTarget,
    pub installation_id: u64,
    pub host_id: HostId,
    /// Operator-chosen host identity retained even for MonitorOnly policies.
    pub requested_host_label: HostLabel,
    mode: PolicyMode,
    enabled: bool,
    state: PolicyState,
    pub cache_policy: CachePolicy,
    revision: u64,
}

/// Every stored column of one policy, named rather than positional.
///
/// **Why this is a struct.** [`ScalePolicy::from_persisted`] took eleven
/// positional arguments under `#[allow(clippy::too_many_arguments)]`, and two of
/// them — `installation_id` and `revision` — are both bare `u64`. Transposing
/// them type-checked and compiled: the policy would then have authenticated
/// against an installation id of `0` or `1` while presenting its installation id
/// as an optimistic-concurrency token, so every write would have raced and every
/// GitHub call would have failed to authenticate, with nothing in either
/// signature to catch it.
///
/// `b2` maps database columns onto this type. With a struct that mapping is
/// checked by name at compile time; positionally it was checked by nothing.
///
/// **That guarantee covers the Rust side of the mapping and no more.** It is the
/// *field* names that the compiler checks, not the column names they are read
/// from: `PersistedPolicy { installation_id: row.get("revision")?, … }` compiles
/// exactly as happily as the correct version, and reintroduces the very
/// transposition described above. `b2` still owes a test that loads a row whose
/// columns hold distinguishable values and asserts each landed in the field of
/// the same name; this type does not supply one.
///
/// Construct it with a struct literal so every field is written down at the call
/// site — that is the whole point, and a builder or a `Default` would give the
/// omission back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedPolicy {
    pub id: PolicyId,
    pub target: ScaleTarget,
    /// The GitHub App installation this policy authenticates through.
    pub installation_id: u64,
    pub host_id: HostId,
    pub requested_host_label: HostLabel,
    /// `Some` for an Autoscale policy, `None` for a MonitorOnly one (D19).
    pub routing_labels: Option<RoutingLabels>,
    pub min_capacity: u16,
    pub max_capacity: Option<NonZeroU16>,
    /// Operator intent, independent of `state`.
    pub enabled: bool,
    pub state: PolicyState,
    pub cache_policy: CachePolicy,
    /// Optimistic-concurrency token. Not an identifier of anything.
    pub revision: u64,
}

impl ScalePolicy {
    /// A newly added policy.
    ///
    /// D20: `add` never arms a host. The policy starts `Pending` with
    /// `enabled == false`, and only an explicit `set-scale` moves it on. That is
    /// true for a policy created with `--max-capacity` too, which is why this is
    /// a property of the constructor rather than of the caller.
    ///
    /// **This is the `add` path, not the load path.** It resets `state` to
    /// `Pending`, `enabled` to `false` and `revision` to `0`, so calling it on a
    /// row read back from storage silently disarms a live policy and resets its
    /// concurrency token. [`Self::from_persisted`] is the one that reloads a
    /// stored policy; it sits directly below this and takes all three.
    #[must_use]
    pub fn new(
        id: PolicyId,
        target: ScaleTarget,
        installation_id: u64,
        host_id: HostId,
        mode: PolicyMode,
        cache_policy: CachePolicy,
    ) -> Self {
        Self::new_for_host_label(
            id,
            target,
            installation_id,
            host_id,
            HostLabel::new("host").expect("the compatibility host label is valid"),
            mode,
            cache_policy,
        )
    }

    /// New policy retaining the exact operator-requested host identity.
    #[must_use]
    pub fn new_for_host_label(
        id: PolicyId,
        target: ScaleTarget,
        installation_id: u64,
        host_id: HostId,
        requested_host_label: HostLabel,
        mode: PolicyMode,
        cache_policy: CachePolicy,
    ) -> Self {
        Self {
            id,
            target,
            installation_id,
            host_id,
            requested_host_label,
            mode,
            enabled: false,
            state: PolicyState::Pending,
            cache_policy,
            revision: 0,
        }
    }

    /// Rebuild a stored policy, re-validating D19's shape.
    ///
    /// This is the load path. Unlike [`Self::new`] it preserves `state`,
    /// `enabled` and `revision` exactly as stored.
    ///
    /// # Errors
    /// Any illegal `PolicyMode` shape, per [`PolicyMode::from_persisted`].
    pub fn from_persisted(fields: PersistedPolicy) -> Result<Self, PolicyError> {
        let PersistedPolicy {
            id,
            target,
            installation_id,
            host_id,
            requested_host_label,
            routing_labels,
            min_capacity,
            max_capacity,
            enabled,
            state,
            cache_policy,
            revision,
        } = fields;

        let mode = PolicyMode::from_persisted(routing_labels, min_capacity, max_capacity)?;
        Ok(Self {
            id,
            target,
            installation_id,
            host_id,
            requested_host_label,
            mode,
            enabled,
            state,
            cache_policy,
            revision,
        })
    }

    /// Every stored column of this policy, for `b2` to write back.
    ///
    /// The exact inverse of [`Self::from_persisted`], so a round trip through
    /// storage is expressible without this type exposing `mode`, `enabled`,
    /// `state` and `revision` for writing.
    #[must_use]
    pub fn to_persisted(&self) -> PersistedPolicy {
        PersistedPolicy {
            id: self.id,
            target: self.target.clone(),
            installation_id: self.installation_id,
            host_id: self.host_id,
            requested_host_label: self.requested_host_label.clone(),
            routing_labels: self.routing_labels().cloned(),
            min_capacity: self.min_capacity(),
            max_capacity: self.max_capacity(),
            enabled: self.enabled,
            state: self.state,
            cache_policy: self.cache_policy,
            revision: self.revision,
        }
    }

    #[must_use]
    pub const fn mode(&self) -> &PolicyMode {
        &self.mode
    }

    #[must_use]
    pub const fn state(&self) -> PolicyState {
        self.state
    }

    /// Operator intent, independent of `state`
    /// (`04-subsystem-contracts.md`: "`enabled` records operator intent;
    /// `state` records observed lifecycle").
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Optimistic-concurrency token. Every successful mutation below bumps it;
    /// `b2` rejects a write against a stale value.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn routing_labels(&self) -> Option<&RoutingLabels> {
        self.mode.routing_labels()
    }

    #[must_use]
    pub const fn min_capacity(&self) -> u16 {
        self.mode.min_capacity()
    }

    #[must_use]
    pub const fn max_capacity(&self) -> Option<NonZeroU16> {
        self.mode.max_capacity()
    }

    /// Ownership rule 1: a policy's `host_id` and its host-scoped
    /// `routing_labels` determine ownership.
    #[must_use]
    pub fn is_owned_by(&self, host_id: HostId) -> bool {
        self.host_id == host_id
    }

    /// Ownership rule 1, second half: "A `MonitorOnly` policy owns nothing and
    /// can never be the reason a runner starts."
    ///
    /// `e1` is required to assert this directly rather than to rely on
    /// `max_capacity` being absent, which is why it is a predicate on the mode
    /// and not an arithmetic accident.
    #[must_use]
    pub const fn owns_runners(&self) -> bool {
        self.mode.is_autoscale()
    }

    /// Whether reconciliation may start a runner for this policy right now.
    ///
    /// All three conditions matter: monitor-only owns nothing (D19), a disabled
    /// or draining policy takes no new work (`03-control-flows.md`, flow 5), and
    /// a user-requested disable beats demand (precedence rule 4).
    #[must_use]
    #[cfg(not(feature = "test-mutants"))]
    pub const fn may_start_runners(&self) -> bool {
        self.mode.is_autoscale() && self.enabled && self.state.admits_new_runners()
    }

    /// Test-only mutation seam for H1. Release builds do not compile it.
    #[must_use]
    #[cfg(feature = "test-mutants")]
    pub fn may_start_runners(&self) -> bool {
        std::env::var("RUNNER_MANAGER_TEST_MUTANT").as_deref()
            == Ok("start_with_revoked_credential")
            || (self.mode.is_autoscale() && self.enabled && self.state.admits_new_runners())
    }

    /// # Errors
    /// [`PolicyError::IllegalTransition`] for anything outside
    /// [`PolicyState::LEGAL`].
    pub fn transition_to(&mut self, next: PolicyState) -> Result<(), PolicyError> {
        if !self.state.can_transition_to(next) {
            return Err(PolicyError::IllegalTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Whether [`Self::activate`] would succeed right now.
    ///
    /// Exposed so `f2` can implement the idempotent CLI behaviour described on
    /// [`Self::activate`] without either duplicating the state table or calling
    /// and discarding an error.
    #[must_use]
    pub fn can_activate(&self) -> bool {
        self.state.can_transition_to(PolicyState::Active)
    }

    /// Whether [`Self::request_disable`] would succeed right now.
    #[must_use]
    pub fn can_request_disable(&self) -> bool {
        self.state.can_transition_to(PolicyState::Draining)
    }

    /// `set-scale --enabled true` on a `Pending` policy (`03-control-flows.md`,
    /// flow 1.6).
    ///
    /// **Not idempotent, and that is intended.** This is a *transition*
    /// operation, not a desired-state one: it reports what the state machine
    /// permits and never silently accepts a call the diagram has no edge for.
    /// Calling it on an already-`Active` policy is [`PolicyError::IllegalTransition`],
    /// not a no-op.
    ///
    /// The idempotent reading — "make this policy enabled, whatever it is now" —
    /// is a *command-level* behaviour, and it belongs to `f2` because the answer
    /// depends on what `set-scale --enabled true` should mean for a `draining`,
    /// `disabled`, `repair_required` or `authentication_failed` policy, and each
    /// of those is a product decision rather than a domain one. Collapsing them
    /// here would make the domain answer them by accident. `f2` should branch on
    /// [`Self::can_activate`] and report the already-satisfied case as success
    /// without calling this at all.
    ///
    /// # Errors
    /// [`PolicyError::IllegalTransition`] when the policy is not `Pending`.
    pub fn activate(&mut self) -> Result<(), PolicyError> {
        self.transition_to(PolicyState::Active)?;
        self.enabled = true;
        Ok(())
    }

    /// `set-scale --enabled false` (`03-control-flows.md`, flow 5.2).
    ///
    /// Precedence rule 4: a user-requested disable beats demand. `enabled` drops
    /// immediately — which alone is enough to stop new runners, because
    /// [`Self::may_start_runners`] reads it — and the observed state moves to
    /// `Draining`, where busy runners are left to finish.
    ///
    /// **Not idempotent, for the reason given on [`Self::activate`].** In
    /// particular `set-scale --enabled false` on a `pending` policy is
    /// `IllegalTransition { from: pending, to: draining }` rather than a no-op,
    /// even though a `pending` policy is already `enabled == false` and so is
    /// already starting nothing. `f2` translates that through
    /// [`Self::can_request_disable`]: a policy that cannot legally drain and is
    /// already not enabled has nothing to do, which is a successful outcome for
    /// the command and not an error to print.
    ///
    /// # Errors
    /// [`PolicyError::IllegalTransition`] when the policy is not `Active`.
    pub fn request_disable(&mut self) -> Result<PolicyState, PolicyError> {
        self.transition_to(PolicyState::Draining)?;
        self.enabled = false;
        Ok(self.state)
    }

    /// Flow 5.3: "When active local runners reach zero … the policy becomes
    /// `disabled`."
    ///
    /// Returns the state after the call, unchanged when runners remain — a
    /// draining policy with work in flight is not an error, it is the normal
    /// case for the duration of the last job.
    ///
    /// # Errors
    /// [`PolicyError::IllegalTransition`] when the policy is not `Draining`.
    pub fn drain_completed(&mut self, active_attempts: u16) -> Result<PolicyState, PolicyError> {
        if self.state != PolicyState::Draining {
            return Err(PolicyError::IllegalTransition {
                from: self.state,
                to: PolicyState::Disabled,
            });
        }
        if active_attempts == 0 {
            self.transition_to(PolicyState::Disabled)?;
        }
        Ok(self.state)
    }

    /// Any state -> `AuthenticationFailed` (flow 4.5).
    ///
    /// # Errors
    /// Only when already in `AuthenticationFailed`; re-reporting the same
    /// failure is not a transition.
    pub fn authentication_failed(&mut self) -> Result<(), PolicyError> {
        self.transition_to(PolicyState::AuthenticationFailed)
    }

    /// "(recoverable by re-authentication)".
    ///
    /// # Errors
    /// [`PolicyError::IllegalTransition`] unless the policy is in
    /// `AuthenticationFailed`.
    pub fn reauthenticated(&mut self) -> Result<(), PolicyError> {
        self.transition_to(PolicyState::Pending)
    }

    /// Flow 1.4: a local transaction that did not complete.
    ///
    /// # Errors
    /// [`PolicyError::IllegalTransition`] unless the policy is `Pending`.
    pub fn repair_required(&mut self) -> Result<(), PolicyError> {
        self.transition_to(PolicyState::RepairRequired)
    }

    /// D19 promotion: `set-capacity` on a monitor-only policy.
    ///
    /// The routing label is derived at this point and not before, because a
    /// monitor-only policy reserves none (`f2`).
    ///
    /// # Errors
    /// [`PolicyError::AlreadyAutoscale`] when the policy already autoscales, or
    /// [`PolicyError::InvertedCapacityRange`].
    pub fn promote_to_autoscale(
        &mut self,
        routing_labels: RoutingLabels,
        min_capacity: u16,
        max_capacity: NonZeroU16,
    ) -> Result<(), PolicyError> {
        if self.mode.is_autoscale() {
            return Err(PolicyError::AlreadyAutoscale);
        }
        self.mode = PolicyMode::autoscale(routing_labels, min_capacity, max_capacity)?;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// `repo set-capacity` / `org set-capacity` on a policy that already
    /// autoscales.
    ///
    /// # Errors
    /// [`PolicyError::NotAutoscale`] when the policy is monitor-only (use
    /// [`Self::promote_to_autoscale`]), or
    /// [`PolicyError::InvertedCapacityRange`].
    pub fn set_max_capacity(&mut self, max_capacity: NonZeroU16) -> Result<(), PolicyError> {
        match &mut self.mode {
            PolicyMode::MonitorOnly => Err(PolicyError::NotAutoscale),
            PolicyMode::Autoscale(cfg) => {
                cfg.set_max_capacity(max_capacity)?;
                self.revision = self.revision.saturating_add(1);
                Ok(())
            }
        }
    }

    /// Add an optional descriptive routing label.
    ///
    /// # Errors
    /// [`PolicyError::NotAutoscale`] for a monitor-only policy, which owns no
    /// label set to add to. This once reported a `MonitorOnlyWithRoutingLabels`
    /// variant, which said that a *stored row* had an illegal shape — a
    /// different claim from "this operation needs an autoscale policy", and one
    /// that had `f2` rendering a validation failure for an ordinary wrong-mode
    /// refusal. That variant is now gone entirely; see the note where it stood.
    pub fn add_routing_label(&mut self, label: Label) -> Result<bool, PolicyError> {
        match &mut self.mode {
            PolicyMode::MonitorOnly => Err(PolicyError::NotAutoscale),
            PolicyMode::Autoscale(cfg) => {
                let added = cfg.routing_labels_mut().add(label);
                if added {
                    self.revision = self.revision.saturating_add(1);
                }
                Ok(added)
            }
        }
    }

    /// Remove an optional descriptive routing label.
    ///
    /// # Errors
    /// [`PolicyError::HostLabelNotRemovable`] for the derived host label, or
    /// [`PolicyError::NotAutoscale`] for a monitor-only policy — see
    /// [`Self::add_routing_label`] for why that variant.
    pub fn remove_routing_label(&mut self, label: &Label) -> Result<bool, PolicyError> {
        match &mut self.mode {
            PolicyMode::MonitorOnly => Err(PolicyError::NotAutoscale),
            PolicyMode::Autoscale(cfg) => {
                let removed = cfg.routing_labels_mut().remove(label)?;
                if removed {
                    self.revision = self.revision.saturating_add(1);
                }
                Ok(removed)
            }
        }
    }

    /// The demand signal for this policy, given one poll's queued jobs.
    ///
    /// A monitor-only policy has no routing labels, so it has no demand at all —
    /// not "demand that is then ignored". D19: it "is skipped entirely by
    /// reconciliation".
    #[must_use]
    pub fn tally<'a>(&self, jobs: impl IntoIterator<Item = &'a RunsOn>) -> DemandTally {
        match self.routing_labels() {
            Some(labels) => labels.tally(jobs),
            None => DemandTally::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HostId, PolicyId};

    fn nz(v: u16) -> NonZeroU16 {
        NonZeroU16::new(v).expect("test capacity is non-zero")
    }

    fn label(s: &str) -> Label {
        Label::new(s).expect("test label is valid")
    }

    fn host_labels(host: &str) -> RoutingLabels {
        RoutingLabels::derive(&HostLabel::new(host).unwrap(), Os::Windows, Arch::X64)
    }

    fn autoscale_policy(target: ScaleTarget, host: HostId, max: u16) -> ScalePolicy {
        ScalePolicy::new(
            PolicyId::from_u128(1),
            target,
            42,
            host,
            PolicyMode::autoscale(host_labels("home"), 0, nz(max)).unwrap(),
            CachePolicy::default(),
        )
    }

    // =======================================================================
    // Routing-label derivation
    // =======================================================================

    #[test]
    fn the_derived_label_has_the_shape_the_architecture_gives() {
        // `02-target-architecture.md`: "for example `rm-home-win-x64`".
        let labels =
            RoutingLabels::derive(&HostLabel::new("home").unwrap(), Os::Windows, Arch::X64);
        assert_eq!(labels.host_label().as_str(), "rm-home-win-x64");
        assert_eq!(labels.count().get(), 1);
    }

    #[test]
    fn the_derived_label_is_host_scoped_by_construction() {
        // `b1`: "the derived label ... is the only control that stops two hosts
        // from starting a runner for the same queued job". Same target, same OS,
        // same architecture, two hosts -> two different labels.
        let a = RoutingLabels::derive(&HostLabel::new("home").unwrap(), Os::Windows, Arch::X64);
        let b = RoutingLabels::derive(&HostLabel::new("office").unwrap(), Os::Windows, Arch::X64);

        assert_ne!(
            a.host_label(),
            b.host_label(),
            "two hosts must not derive the same routing label; with no job \
             reservation, a shared label means both hosts start a runner for one job"
        );
        assert_eq!(a.host_label().as_str(), "rm-home-win-x64");
        assert_eq!(b.host_label().as_str(), "rm-office-win-x64");

        // The OS and architecture segments are host facts too.
        let mac = RoutingLabels::derive(&HostLabel::new("home").unwrap(), Os::MacOs, Arch::Arm64);
        assert_eq!(mac.host_label().as_str(), "rm-home-osx-arm64");
        assert_ne!(a.host_label(), mac.host_label());
    }

    #[test]
    fn a_mixed_case_host_label_still_derives_a_lower_case_routing_label() {
        // GitHub lower-cases labels on registration
        // (`docs/spikes/d18-org-jit-verification.md`, Point 3, finding 3), so a
        // derived label that kept case would not match what comes back.
        let labels =
            RoutingLabels::derive(&HostLabel::new("Home-PC").unwrap(), Os::Linux, Arch::X64);
        assert_eq!(labels.host_label().as_str(), "rm-home-pc-linux-x64");
    }

    #[test]
    fn optional_labels_can_be_added_and_removed_but_the_host_label_cannot() {
        let mut labels = host_labels("home");
        let derived = labels.host_label().clone();

        assert!(labels.add(label("gpu")));
        assert!(labels.add(label("self-hosted")));
        assert!(
            !labels.add(label("GPU")),
            "adding a label that differs only in case must be a no-op, not a duplicate"
        );
        assert_eq!(labels.count().get(), 3);

        assert!(labels.remove(&label("gpu")).unwrap());
        assert_eq!(labels.count().get(), 2);
        assert!(
            !labels.remove(&label("never-added")).unwrap(),
            "removing an absent optional label is a no-op, not an error"
        );

        // The invariant.
        assert!(
            matches!(
                labels.remove(&derived),
                Err(PolicyError::HostLabelNotRemovable { .. })
            ),
            "the derived host label must not be removable; it is the only thing \
             keeping two hosts from serving each other's jobs"
        );
        assert!(labels.contains(&derived));

        // And not by case-dodging either, since Label folds case.
        assert!(matches!(
            labels.remove(&label("RM-HOME-WIN-X64")),
            Err(PolicyError::HostLabelNotRemovable { .. })
        ));
    }

    #[test]
    fn adding_the_host_label_as_an_optional_label_does_not_duplicate_it() {
        let mut labels = host_labels("home");
        let derived = labels.host_label().clone();
        assert!(!labels.add(derived));
        assert_eq!(labels.count().get(), 1);

        // Nor via a stored set that repeats it.
        let rebuilt = RoutingLabels::from_parts(
            labels.host_label().clone(),
            vec![labels.host_label().clone(), label("gpu")],
        );
        assert_eq!(rebuilt.count().get(), 2);
        assert_eq!(
            rebuilt.as_registration_labels(),
            vec!["rm-home-win-x64", "gpu"]
        );
    }

    #[test]
    fn the_registration_array_is_exactly_the_label_set_and_adds_nothing() {
        // `docs/spikes/d18-org-jit-verification.md`, Point 3, finding 1: "No
        // labels are added implicitly." So this array is the whole contract with
        // GitHub, and it must not quietly gain `self-hosted`, the OS, or the
        // architecture.
        let mut labels = host_labels("home");
        labels.add(label("gpu"));
        assert_eq!(
            labels.as_registration_labels(),
            vec!["rm-home-win-x64", "gpu"]
        );
        assert!(!labels.contains(&label("self-hosted")));
    }

    #[test]
    fn routing_labels_round_trip_through_serde_with_the_host_label_intact() {
        let mut labels = host_labels("home");
        labels.add(label("gpu"));
        let json = serde_json::to_string(&labels).unwrap();
        let back: RoutingLabels = serde_json::from_str(&json).unwrap();
        assert_eq!(labels, back);
        assert_eq!(back.host_label().as_str(), "rm-home-win-x64");
    }

    #[test]
    fn a_non_empty_view_of_the_label_set_is_available_in_the_contract_shape() {
        // `04-subsystem-contracts.md` types this as `Option<NonEmpty<Label>>`.
        let labels = host_labels("home");
        let non_empty = labels.to_non_empty();
        assert_eq!(non_empty.count().get(), 1);
        assert_eq!(non_empty.first().as_str(), "rm-home-win-x64");
    }

    // =======================================================================
    // `runs-on` matching -- the table
    // =======================================================================

    /// One row of the `runs-on` table. `expect` is asserted exactly, so a case
    /// that starts silently returning `Unresolvable` instead of `NoMatch` fails.
    struct Row {
        name: &'static str,
        runs_on: RunsOn,
        expect: Expect,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Expect {
        Match,
        NoMatch,
        Unresolvable,
    }

    fn classify(m: &RunsOnMatch) -> Expect {
        match m {
            RunsOnMatch::Match { .. } => Expect::Match,
            RunsOnMatch::NoMatch { .. } => Expect::NoMatch,
            RunsOnMatch::Unresolvable(_) => Expect::Unresolvable,
        }
    }

    fn table_policy() -> RoutingLabels {
        // rm-home-win-x64 plus two optional labels.
        let mut labels = host_labels("home");
        labels.add(label("self-hosted"));
        labels.add(label("gpu"));
        labels
    }

    fn table() -> Vec<Row> {
        vec![
            // ---- single string form -------------------------------------
            Row {
                name: "string: the derived host label",
                runs_on: RunsOn::Single("rm-home-win-x64".into()),
                expect: Expect::Match,
            },
            Row {
                name: "string: the derived host label in the wrong case",
                runs_on: RunsOn::Single("RM-Home-Win-X64".into()),
                expect: Expect::Match,
            },
            Row {
                name: "string: an optional label alone",
                runs_on: RunsOn::Single("gpu".into()),
                expect: Expect::Match,
            },
            Row {
                name: "string: another host's label",
                runs_on: RunsOn::Single("rm-office-win-x64".into()),
                expect: Expect::NoMatch,
            },
            Row {
                name: "string: a GitHub-hosted runner label",
                runs_on: RunsOn::Single("ubuntu-latest".into()),
                expect: Expect::NoMatch,
            },
            // ---- array form ---------------------------------------------
            Row {
                name: "array: a strict subset of the policy's labels",
                runs_on: RunsOn::Many(vec!["self-hosted".into(), "rm-home-win-x64".into()]),
                expect: Expect::Match,
            },
            Row {
                name: "array: the whole set, out of order and mixed case",
                runs_on: RunsOn::Many(vec![
                    "GPU".into(),
                    "Rm-Home-Win-X64".into(),
                    "Self-Hosted".into(),
                ]),
                expect: Expect::Match,
            },
            Row {
                name: "array: one label the policy does not carry",
                runs_on: RunsOn::Many(vec!["rm-home-win-x64".into(), "arm64".into()]),
                expect: Expect::NoMatch,
            },
            Row {
                name: "array: an empty array names no labels",
                runs_on: RunsOn::Many(vec![]),
                expect: Expect::Unresolvable,
            },
            // ---- group/labels map form ----------------------------------
            Row {
                name: "map: labels only",
                runs_on: RunsOn::Grouped {
                    group: None,
                    labels: RunsOnLabels::Many(vec!["rm-home-win-x64".into()]),
                },
                expect: Expect::Match,
            },
            Row {
                name: "map: a group plus labels the policy carries",
                runs_on: RunsOn::Grouped {
                    group: Some("Default".into()),
                    labels: RunsOnLabels::Many(vec!["rm-home-win-x64".into(), "gpu".into()]),
                },
                expect: Expect::Match,
            },
            Row {
                name: "map: labels as a scalar",
                runs_on: RunsOn::Grouped {
                    group: Some("Default".into()),
                    labels: RunsOnLabels::One("rm-home-win-x64".into()),
                },
                expect: Expect::Match,
            },
            Row {
                name: "map: a group plus a label the policy does not carry",
                runs_on: RunsOn::Grouped {
                    group: Some("Default".into()),
                    labels: RunsOnLabels::Many(vec!["macos".into()]),
                },
                expect: Expect::NoMatch,
            },
            Row {
                name: "map: a group with no labels constrains something we cannot read",
                runs_on: RunsOn::Grouped {
                    group: Some("Default".into()),
                    labels: RunsOnLabels::Many(vec![]),
                },
                expect: Expect::Unresolvable,
            },
            // ---- unresolvable -------------------------------------------
            Row {
                name: "expression: the whole value",
                runs_on: RunsOn::Single("${{ matrix.runner }}".into()),
                expect: Expect::Unresolvable,
            },
            Row {
                name: "expression: one element of an array",
                runs_on: RunsOn::Many(vec!["rm-home-win-x64".into(), "${{ inputs.extra }}".into()]),
                expect: Expect::Unresolvable,
            },
            Row {
                name: "expression: inside the map form",
                runs_on: RunsOn::Grouped {
                    group: None,
                    labels: RunsOnLabels::One("${{ vars.LABEL }}".into()),
                },
                expect: Expect::Unresolvable,
            },
            Row {
                name: "not a usable label at all",
                runs_on: RunsOn::Single("rm-home,win-x64".into()),
                expect: Expect::Unresolvable,
            },
        ]
    }

    #[test]
    fn runs_on_matching_covers_every_documented_form() {
        let policy = table_policy();
        for row in table() {
            let got = policy.matches(&row.runs_on);
            assert_eq!(
                classify(&got),
                row.expect,
                "row {:?}: {:?} produced {got:?}",
                row.name,
                row.runs_on
            );
        }
    }

    #[test]
    fn self_hosted_is_not_implicit_and_must_be_carried_to_be_matched() {
        // `docs/spikes/d18-org-jit-verification.md`, Point 3, finding 1: "A
        // workflow written as `runs-on: self-hosted` will not match a runner
        // registered without that label."
        let without = host_labels("home");
        assert!(
            !without
                .matches(&RunsOn::Single("self-hosted".into()))
                .is_match(),
            "a policy that does not carry `self-hosted` must not claim a job that asks for it"
        );

        let mut with = host_labels("home");
        with.add(label("self-hosted"));
        assert!(
            with.matches(&RunsOn::Single("self-hosted".into()))
                .is_match(),
            "and it must claim it once the operator adds the label explicitly"
        );
    }

    #[test]
    fn a_no_match_names_the_labels_that_were_missing() {
        let policy = host_labels("home");
        let got = policy.matches(&RunsOn::Many(vec![
            "rm-home-win-x64".into(),
            "self-hosted".into(),
            "GPU".into(),
        ]));
        match got {
            RunsOnMatch::NoMatch { missing } => {
                assert_eq!(
                    missing,
                    vec![label("self-hosted"), label("gpu")],
                    "the operator needs to know which labels to add"
                );
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    #[test]
    fn a_matching_map_form_carries_its_runner_group_through_rather_than_dropping_it() {
        let policy = host_labels("home");
        let got = policy.matches(&RunsOn::Grouped {
            group: Some("Default".into()),
            labels: RunsOnLabels::One("rm-home-win-x64".into()),
        });
        assert_eq!(
            got,
            RunsOnMatch::Match {
                runner_group: Some("Default".into())
            },
            "a policy has no runner-group field, so the domain cannot evaluate \
             `group:`; returning it lets `c4`, which can, do so without re-parsing"
        );
    }

    #[test]
    fn each_unresolvable_reason_is_distinct_rather_than_one_catch_all() {
        let policy = host_labels("home");

        let expr = policy.matches(&RunsOn::Single("${{ matrix.os }}".into()));
        assert!(matches!(
            expr,
            RunsOnMatch::Unresolvable(UnresolvableRunsOn::Expression { .. })
        ));

        let group = policy.matches(&RunsOn::Grouped {
            group: Some("g".into()),
            labels: RunsOnLabels::Many(vec![]),
        });
        assert!(matches!(
            group,
            RunsOnMatch::Unresolvable(UnresolvableRunsOn::RunnerGroupWithoutLabels { .. })
        ));

        let none = policy.matches(&RunsOn::Many(vec![]));
        assert!(matches!(
            none,
            RunsOnMatch::Unresolvable(UnresolvableRunsOn::NoLabels)
        ));

        let invalid = policy.matches(&RunsOn::Single("a,b".into()));
        assert!(matches!(
            invalid,
            RunsOnMatch::Unresolvable(UnresolvableRunsOn::InvalidLabel { .. })
        ));
    }

    #[test]
    fn an_unresolvable_runs_on_is_neither_counted_as_demand_nor_dropped() {
        // `b1`: "treat a `runs-on` that cannot be resolved statically ... as
        // **not** demand, reported as unresolvable rather than silently counted
        // or silently dropped."
        let policy = table_policy();
        let jobs = vec![
            RunsOn::Single("rm-home-win-x64".into()),      // matched
            RunsOn::Single("ubuntu-latest".into()),        // not matched
            RunsOn::Single("${{ matrix.runner }}".into()), // unresolvable
            RunsOn::Single("${{ inputs.pool }}".into()),   // unresolvable
        ];
        let tally = policy.tally(&jobs);

        assert_eq!(tally.demand(), 1, "an expression must not inflate demand");
        assert_eq!(tally.not_matched, 1);
        assert_eq!(
            tally.unresolvable.len(),
            2,
            "and it must not vanish either -- `g2` shows these to the operator"
        );
        assert_eq!(
            tally.total_seen(),
            jobs.len() as u32,
            "every job seen is accounted for in exactly one bucket"
        );
    }

    #[test]
    fn runs_on_deserialises_from_each_json_shape_github_and_workflow_files_use() {
        let single: RunsOn = serde_json::from_str(r#""ubuntu-latest""#).unwrap();
        assert_eq!(single, RunsOn::Single("ubuntu-latest".into()));

        let many: RunsOn = serde_json::from_str(r#"["self-hosted","linux"]"#).unwrap();
        assert_eq!(
            many,
            RunsOn::Many(vec!["self-hosted".into(), "linux".into()])
        );

        let grouped: RunsOn = serde_json::from_str(r#"{"group":"g","labels":["a","b"]}"#).unwrap();
        assert_eq!(
            grouped,
            RunsOn::Grouped {
                group: Some("g".into()),
                labels: RunsOnLabels::Many(vec!["a".into(), "b".into()]),
            }
        );

        let scalar_labels: RunsOn = serde_json::from_str(r#"{"labels":"a"}"#).unwrap();
        assert_eq!(
            scalar_labels,
            RunsOn::Grouped {
                group: None,
                labels: RunsOnLabels::One("a".into()),
            }
        );

        let group_only: RunsOn = serde_json::from_str(r#"{"group":"g"}"#).unwrap();
        assert_eq!(
            group_only,
            RunsOn::Grouped {
                group: Some("g".into()),
                labels: RunsOnLabels::Many(vec![]),
            }
        );

        // The array form is what the jobs API actually returns.
        assert_eq!(
            RunsOn::from_job_labels(["rm-home-win-x64", "gpu"]),
            RunsOn::Many(vec!["rm-home-win-x64".into(), "gpu".into()])
        );
    }

    // =======================================================================
    // PolicyMode (D19)
    // =======================================================================

    #[test]
    fn an_autoscale_policy_without_a_ceiling_or_a_label_cannot_be_persisted() {
        let labels = host_labels("home");

        // Autoscale requires both. Neither illegal combination survives the
        // load path.
        assert!(matches!(
            PolicyMode::from_persisted(Some(labels.clone()), 0, None),
            Err(PolicyError::AutoscaleWithoutMaxCapacity)
        ));
        assert!(matches!(
            PolicyMode::from_persisted(None, 0, Some(nz(1))),
            Err(PolicyError::AutoscaleWithoutRoutingLabels)
        ));

        // And both legal shapes do.
        assert!(
            PolicyMode::from_persisted(None, 0, None)
                .unwrap()
                .is_monitor_only()
        );
        assert!(
            PolicyMode::from_persisted(Some(labels), 0, Some(nz(2)))
                .unwrap()
                .is_autoscale()
        );
    }

    #[test]
    fn the_illegal_policy_mode_combinations_have_no_in_memory_representation() {
        // The strongest form of `b1`'s D19 requirement: not merely that the
        // illegal shapes are rejected on the way in, but that they cannot be
        // built. `PolicyMode::Autoscale` holds an `AutoscaleConfig` whose
        // `routing_labels` and `max_capacity` are unconditional, so there is no
        // constructor, field assignment, or `Default` that produces an autoscale
        // policy missing either.
        let autoscale = PolicyMode::autoscale(host_labels("home"), 0, nz(3)).unwrap();
        assert!(autoscale.routing_labels().is_some());
        assert!(autoscale.max_capacity().is_some());

        let monitor = PolicyMode::monitor_only();
        assert!(monitor.routing_labels().is_none());
        assert!(monitor.max_capacity().is_none());
        assert_eq!(monitor.min_capacity(), 0);
    }

    #[test]
    fn a_monitor_only_row_carrying_capacity_or_labels_is_refused_by_name() {
        // `b2` loads a hand-edited database through `from_persisted`, and needs
        // to say which column is wrong.
        let err = PolicyMode::from_persisted(None, 2, None).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::MonitorOnlyWithMinCapacity { min: 2 }
        ));
        assert!(
            err.to_string().contains("MonitorOnly"),
            "the message must name the shape rule, got: {err}"
        );
    }

    #[test]
    fn an_inverted_capacity_range_is_rejected_so_clamp_is_always_well_defined() {
        // `04-subsystem-contracts.md`: "`min_capacity <= max_capacity` is
        // validated on every write of an `Autoscale` policy, so
        // `clamp(demand, min_capacity, max_capacity)` is always well-defined."
        // In Rust an inverted `clamp` panics, so this is the guard that keeps
        // `crate::capacity` total.
        assert!(matches!(
            PolicyMode::autoscale(host_labels("home"), 5, nz(2)),
            Err(PolicyError::InvertedCapacityRange { min: 5, max: 2 })
        ));
        assert!(PolicyMode::autoscale(host_labels("home"), 2, nz(2)).is_ok());
        assert!(PolicyMode::autoscale(host_labels("home"), 0, nz(1)).is_ok());

        // Including when raising the floor past the ceiling later.
        let mut cfg = AutoscaleConfig::new(host_labels("home"), 2, nz(4)).unwrap();
        assert!(matches!(
            cfg.set_max_capacity(nz(1)),
            Err(PolicyError::InvertedCapacityRange { min: 2, max: 1 })
        ));
        assert_eq!(
            cfg.max_capacity().get(),
            4,
            "a refused write changes nothing"
        );
    }

    #[test]
    fn a_policy_mode_round_trips_through_serde_and_the_gate_holds_on_the_way_back() {
        for mode in [
            PolicyMode::monitor_only(),
            PolicyMode::autoscale(host_labels("home"), 0, nz(4)).unwrap(),
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: PolicyMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back, "{json} did not round-trip");
        }

        // A hand-written autoscale payload with an inverted range is refused at
        // deserialisation, not after it.
        let hostile = r#"{"mode":"autoscale","routing_labels":{"host_label":"rm-home-win-x64","additional":[]},"min_capacity":9,"max_capacity":1}"#;
        let err = serde_json::from_str::<PolicyMode>(hostile).unwrap_err();
        assert!(
            err.to_string().contains("min_capacity"),
            "expected the shape error to survive into serde's message, got: {err}"
        );
    }

    #[test]
    fn a_policy_round_trips_through_its_persisted_form() {
        // `PersistedPolicy` exists to stop `installation_id` and `revision` --
        // two bare `u64`s -- being transposed on the way to and from storage.
        // Nothing exercised that: `PersistedPolicy` was constructed nowhere
        // outside `to_persisted`, `ScalePolicy::from_persisted` had no caller
        // and no test, and transposing the two fields inside `to_persisted` left
        // the whole suite green. The defect the type was introduced to prevent
        // was closed for attempts and left open for policies.
        let mut policy = autoscale_policy(
            ScaleTarget::repository("o/r").unwrap(),
            HostId::from_u128(7),
            3,
        );
        policy.add_routing_label(label("gpu")).unwrap();
        // `activate` is what makes the round trip worth asserting: it moves
        // `state` off `Pending`, `enabled` off `false`, and `revision` off `0`,
        // so all three are non-default and a field that failed to survive the
        // trip shows up as an inequality rather than as a default that happens
        // to match.
        policy.activate().unwrap();
        assert_eq!(policy.state(), PolicyState::Active);
        assert!(policy.enabled());

        let stored = policy.to_persisted();
        assert_ne!(
            stored.installation_id, stored.revision,
            "the fixture must distinguish the two u64 columns, or transposing \
             them is unobservable and this test proves nothing"
        );
        assert_eq!(stored.installation_id, 42);
        assert_eq!(stored.revision, policy.revision());

        let restored =
            ScalePolicy::from_persisted(stored).expect("a row this crate produced must load");
        assert_eq!(restored, policy);
        assert_eq!(restored.installation_id, 42);
        assert_eq!(restored.revision(), policy.revision());
        assert_eq!(restored.state(), PolicyState::Active);
        assert!(restored.enabled());
        assert_eq!(
            restored.routing_labels().unwrap().count().get(),
            2,
            "the optional label survives alongside the host label"
        );
    }

    #[test]
    fn a_monitor_only_policy_round_trips_through_its_persisted_form() {
        // The other half of the mode inference. `to_persisted` writes a
        // MonitorOnly policy out through `min_capacity() == 0`,
        // `max_capacity() == None` and `routing_labels() == None`, and
        // `PolicyMode::from_persisted` reads the mode back *from those three
        // columns* rather than from a stored discriminant. That inference is the
        // reason `PolicyError::MonitorOnlyWithRoutingLabels` is unconstructible,
        // and until now it was never exercised end to end.
        let mut policy = ScalePolicy::new(
            PolicyId::from_u128(2),
            ScaleTarget::organization("acme").unwrap(),
            9,
            HostId::from_u128(7),
            PolicyMode::monitor_only(),
            CachePolicy::default(),
        );
        policy.activate().unwrap();

        let stored = policy.to_persisted();
        assert!(stored.routing_labels.is_none());
        assert_eq!(stored.min_capacity, 0);
        assert!(stored.max_capacity.is_none());
        assert_ne!(stored.installation_id, stored.revision);

        let restored =
            ScalePolicy::from_persisted(stored).expect("a row this crate produced must load");
        assert_eq!(restored, policy);
        assert!(
            restored.mode().is_monitor_only(),
            "the mode is inferred back from the three columns, not stored"
        );
        assert!(!restored.owns_runners());
        assert_eq!(restored.installation_id, 9);
        assert_eq!(restored.revision(), 1);
    }

    // =======================================================================
    // PolicyState
    // =======================================================================

    /// The diagram from `04-subsystem-contracts.md`, transcribed by hand.
    ///
    /// **Deliberately a second copy of [`PolicyState::LEGAL`].** A test that
    /// derives its expectation from the constant it is testing asserts only that
    /// the constant equals itself: adding `disabled -> active` to `LEGAL` would
    /// make such a test expect the new edge and pass, which is exactly what
    /// happened to the first version of this test and is why it was rewritten.
    /// Here the two lists must be edited together, so a one-sided change to
    /// either fails.
    ///
    /// ```text
    /// pending -> active | repair_required
    /// active  -> draining -> disabled
    /// any     -> authentication_failed        (recoverable by re-authentication)
    /// ```
    fn diagram_edges() -> Vec<(PolicyState, PolicyState)> {
        use PolicyState::*;
        let mut edges = vec![
            (Pending, Active),
            (Pending, RepairRequired),
            (Active, Draining),
            (Draining, Disabled),
            // The recovery edge for "(recoverable by re-authentication)".
            (AuthenticationFailed, Pending),
        ];
        // `any -> authentication_failed`, which is every state except itself.
        for from in PolicyState::ALL {
            if from != AuthenticationFailed {
                edges.push((from, AuthenticationFailed));
            }
        }
        edges
    }

    #[test]
    fn every_policy_state_transition_is_legal_exactly_where_the_diagram_says() {
        // Both directions, over the full 6x6 product: each of the 10 legal pairs
        // succeeds, each of the other 26 is rejected.
        let expected = diagram_edges();
        assert_eq!(
            expected.len(),
            10,
            "the transcription itself changed; check it against the diagram"
        );

        let mut legal_seen = 0usize;
        let mut illegal_seen = 0usize;

        for from in PolicyState::ALL {
            for to in PolicyState::ALL {
                let expected_legal = expected.contains(&(from, to));
                let mut policy = autoscale_policy(
                    ScaleTarget::repository("o/r").unwrap(),
                    HostId::from_u128(7),
                    1,
                );
                // Force the starting state without going through the machine,
                // which is only possible from inside the module -- exactly the
                // reason this test lives here.
                policy.state = from;

                let result = policy.transition_to(to);
                if expected_legal {
                    legal_seen += 1;
                    assert!(
                        result.is_ok(),
                        "{from} -> {to} is in the diagram and must be accepted"
                    );
                    assert_eq!(policy.state(), to);
                } else {
                    illegal_seen += 1;
                    assert!(
                        matches!(result, Err(PolicyError::IllegalTransition { .. })),
                        "{from} -> {to} is not in the diagram and must be rejected"
                    );
                    assert_eq!(policy.state(), from, "a refused transition changes nothing");
                }
            }
        }

        assert_eq!(legal_seen, 10);
        assert_eq!(illegal_seen, 36 - 10);

        // And the published constant matches the transcription, so a caller
        // reading `PolicyState::LEGAL` sees the same machine the tests exercise.
        let mut published = PolicyState::LEGAL.to_vec();
        let mut transcribed = expected;
        published.sort_unstable();
        transcribed.sort_unstable();
        assert_eq!(published, transcribed);
    }

    #[test]
    fn a_policy_state_cannot_transition_to_itself() {
        for state in PolicyState::ALL {
            assert!(
                !state.can_transition_to(state),
                "{state} -> {state} is not an edge in the diagram; treating it as \
                 one would let a repeated authentication failure look like progress"
            );
        }
    }

    #[test]
    fn the_documented_happy_path_walks_pending_to_disabled() {
        let mut policy = autoscale_policy(
            ScaleTarget::repository("o/r").unwrap(),
            HostId::from_u128(7),
            2,
        );

        // D20: `add` never arms a host.
        assert_eq!(policy.state(), PolicyState::Pending);
        assert!(!policy.enabled());
        assert!(!policy.may_start_runners());

        policy.activate().unwrap();
        assert_eq!(policy.state(), PolicyState::Active);
        assert!(policy.enabled());
        assert!(policy.may_start_runners());

        // Flow 5.2 and 5.3.
        assert_eq!(policy.request_disable().unwrap(), PolicyState::Draining);
        assert_eq!(
            policy.drain_completed(1).unwrap(),
            PolicyState::Draining,
            "a policy with a runner still in flight stays draining"
        );
        assert_eq!(policy.drain_completed(0).unwrap(), PolicyState::Disabled);
    }

    #[test]
    fn a_disable_during_demand_yields_draining_and_beats_demand_immediately() {
        // `b1`: "Disable-during-demand yields draining". Precedence rule 4: "A
        // user-requested disable beats demand and starts draining."
        let mut policy = autoscale_policy(
            ScaleTarget::repository("o/r").unwrap(),
            HostId::from_u128(7),
            5,
        );
        policy.activate().unwrap();

        // Demand exists and is unchanged by the disable -- the queue is left
        // visible (flow 5.2) -- but the policy stops being a reason to start.
        let jobs = vec![RunsOn::Single("rm-home-win-x64".into()); 4];
        assert_eq!(policy.tally(&jobs).demand(), 4);

        assert_eq!(policy.request_disable().unwrap(), PolicyState::Draining);
        assert!(!policy.enabled());
        assert!(
            !policy.may_start_runners(),
            "a draining policy must not be the reason a new runner starts, even \
             with four jobs queued for its labels"
        );
        assert_eq!(
            policy.tally(&jobs).demand(),
            4,
            "queued demand stays visible while draining (flow 5.2)"
        );
    }

    #[test]
    fn re_authentication_is_the_only_way_out_of_authentication_failed() {
        for from in [
            PolicyState::Pending,
            PolicyState::Active,
            PolicyState::Draining,
            PolicyState::Disabled,
            PolicyState::RepairRequired,
        ] {
            let mut policy = autoscale_policy(
                ScaleTarget::repository("o/r").unwrap(),
                HostId::from_u128(7),
                1,
            );
            policy.state = from;
            policy.authentication_failed().unwrap();
            assert_eq!(policy.state(), PolicyState::AuthenticationFailed);

            // Reporting the same failure twice is not a transition.
            assert!(matches!(
                policy.authentication_failed(),
                Err(PolicyError::IllegalTransition { .. })
            ));

            policy.reauthenticated().unwrap();
            assert_eq!(policy.state(), PolicyState::Pending);
        }
    }

    #[test]
    fn a_refused_transition_leaves_the_revision_untouched() {
        let mut policy = autoscale_policy(
            ScaleTarget::repository("o/r").unwrap(),
            HostId::from_u128(7),
            1,
        );
        assert_eq!(policy.revision(), 0);
        policy.activate().unwrap();
        assert_eq!(policy.revision(), 1);

        assert!(policy.activate().is_err());
        assert_eq!(
            policy.revision(),
            1,
            "a rejected write must not bump the optimistic-concurrency token, or \
             `b2`'s stale-revision check would reject the next honest write"
        );
    }

    // =======================================================================
    // Monitor-only, promotion, ownership
    // =======================================================================

    #[test]
    fn a_monitor_only_policy_owns_nothing_and_can_never_start_a_runner() {
        let mut policy = ScalePolicy::new(
            PolicyId::from_u128(2),
            ScaleTarget::organization("acme").unwrap(),
            9,
            HostId::from_u128(7),
            PolicyMode::monitor_only(),
            CachePolicy::default(),
        );
        policy.activate().unwrap();

        assert!(!policy.owns_runners());
        assert!(
            !policy.may_start_runners(),
            "an active, enabled monitor-only policy still starts nothing (D19)"
        );
        assert!(policy.routing_labels().is_none());
        assert!(policy.max_capacity().is_none());

        // Maximum demand changes nothing, because it has no labels to match on.
        let jobs = vec![RunsOn::Single("rm-home-win-x64".into()); 50];
        assert_eq!(
            policy.tally(&jobs).demand(),
            0,
            "a monitor-only policy has no demand at all, rather than demand that \
             is computed and then ignored"
        );

        // And it owns no label set to edit. This is a wrong-mode refusal: the
        // caller asked for the wrong thing, the stored row is not malformed.
        assert!(matches!(
            policy.add_routing_label(label("gpu")),
            Err(PolicyError::NotAutoscale)
        ));
        assert!(matches!(
            policy.remove_routing_label(&label("gpu")),
            Err(PolicyError::NotAutoscale)
        ));
        // The load path reports a *shape* problem, and it is a different one: a
        // row carrying routing labels is autoscale-shaped by definition, so the
        // mode is never in doubt and "monitor-only with labels" has no error to
        // report because it cannot be expressed. This assertion is what pins
        // that -- it fails loudly if `PolicyMode::from_persisted` ever starts
        // reading a stored discriminant instead of inferring the mode, which is
        // the change that would make the deleted variant reachable again.
        assert!(matches!(
            PolicyMode::from_persisted(Some(host_labels("home")), 0, None),
            Err(PolicyError::AutoscaleWithoutMaxCapacity)
        ));
    }

    #[test]
    fn set_capacity_promotes_a_monitor_only_policy_and_derives_its_label_then() {
        // D19 / `f2`: "`set-capacity` later promotes it to `autoscale`, which is
        // also when its routing label is derived."
        let mut policy = ScalePolicy::new(
            PolicyId::from_u128(2),
            ScaleTarget::repository("o/r").unwrap(),
            9,
            HostId::from_u128(7),
            PolicyMode::monitor_only(),
            CachePolicy::default(),
        );
        assert!(policy.routing_labels().is_none());

        policy
            .promote_to_autoscale(host_labels("home"), 0, nz(3))
            .unwrap();

        assert!(policy.owns_runners());
        assert_eq!(
            policy.routing_labels().unwrap().host_label().as_str(),
            "rm-home-win-x64"
        );
        assert_eq!(policy.max_capacity().unwrap().get(), 3);

        // Promotion is one-way; a second promotion is a mistake, not a resize.
        assert!(matches!(
            policy.promote_to_autoscale(host_labels("home"), 0, nz(4)),
            Err(PolicyError::AlreadyAutoscale)
        ));
        policy.set_max_capacity(nz(4)).unwrap();
        assert_eq!(policy.max_capacity().unwrap().get(), 4);
    }

    #[test]
    fn a_policy_is_owned_by_exactly_one_host() {
        let mine = HostId::from_u128(7);
        let theirs = HostId::from_u128(8);
        let policy = autoscale_policy(ScaleTarget::repository("o/r").unwrap(), mine, 1);
        assert!(policy.is_owned_by(mine));
        assert!(!policy.is_owned_by(theirs));
    }

    #[test]
    fn an_overridden_host_label_is_detectable_without_being_rejected() {
        // `f2` supports an operator override, so `from_parts` must accept any
        // label -- but "host-scoped by construction" then holds only for
        // `derive`, and the difference has to be visible to something.
        assert!(host_labels("home").is_derived_shape());
        assert!(
            RoutingLabels::derive(&HostLabel::new("home-win").unwrap(), Os::Linux, Arch::Arm64)
                .is_derived_shape(),
            "a host label containing `-` still derives a four-plus-segment name"
        );
        // `HostLabel::new` refuses only a leading or trailing `-`, so `home--pc`
        // is a legal host label an operator can really type. It derives
        // `rm-home--pc-win-x64`, and reporting that as *not* derived told an
        // operator who had done nothing wrong that their collision control was
        // off.
        assert_eq!(
            host_labels("home--pc").host_label().as_str(),
            "rm-home--pc-win-x64"
        );
        assert!(
            host_labels("home--pc").is_derived_shape(),
            "consecutive dashes are legal inside a host label; the empty middle \
             segment they produce is not evidence of an override"
        );

        // The case the predicate exists for: a hand-edited row that has quietly
        // disabled the collision control. Not an error -- `remove` will still
        // defend it as immovable -- but `f2`/`g2` can now say so.
        for raw in [
            "self-hosted",
            "ubuntu-latest",
            "rm-home-win",
            "rm-home-win-x64-extra",
        ] {
            assert!(
                !RoutingLabels::from_host_label(label(raw)).is_derived_shape(),
                "{raw:?} is not the derived shape"
            );
        }
        // Right segment count, wrong tokens.
        assert!(!RoutingLabels::from_host_label(label("rm-home-bsd-x64")).is_derived_shape());
        assert!(!RoutingLabels::from_host_label(label("rm-home-win-riscv")).is_derived_shape());
        assert!(!RoutingLabels::from_host_label(label("xx-home-win-x64")).is_derived_shape());

        // The additional labels play no part: only host identity is at stake.
        let mut overridden = RoutingLabels::from_host_label(label("self-hosted"));
        overridden.add(label("rm-home-win-x64"));
        assert!(!overridden.is_derived_shape());
    }

    #[test]
    fn the_lifecycle_commands_are_transitions_not_desired_state_requests() {
        // Documented as intended: `activate` and `request_disable` report what
        // the diagram permits, and `f2` translates that into an idempotent CLI
        // using the two predicates rather than by calling and discarding errors.
        let mut policy = autoscale_policy(
            ScaleTarget::repository("o/r").unwrap(),
            HostId::from_u128(7),
            3,
        );

        assert!(policy.can_activate());
        assert!(
            !policy.can_request_disable(),
            "a pending policy cannot drain; it is also already not enabled, \
             which is what makes the command a no-op rather than a failure"
        );
        assert!(matches!(
            policy.request_disable(),
            Err(PolicyError::IllegalTransition {
                from: PolicyState::Pending,
                to: PolicyState::Draining,
            })
        ));

        policy.activate().unwrap();
        assert!(!policy.can_activate(), "already active");
        assert!(policy.can_request_disable());
        assert!(matches!(
            policy.activate(),
            Err(PolicyError::IllegalTransition { .. })
        ));

        policy.request_disable().unwrap();
        assert!(!policy.can_request_disable(), "already draining");
        assert!(!policy.enabled());
    }

    // =======================================================================
    // D18 target equivalence -- one body, both variants
    // =======================================================================

    /// Everything `04-subsystem-contracts.md` says is identical between the two
    /// scopes: "ownership, capacity, and lifecycle rules are identical".
    ///
    /// This is deliberately one function rather than two tests. `b1`'s
    /// Definition of Done asks for the equivalence to be "proven by a shared
    /// test body, not by two copies of the same assertions", and the reason is
    /// not tidiness: two copies drift, and the moment they drift the domain has
    /// quietly acquired a scope-dependent rule that D18 says does not exist.
    ///
    /// **The trace must cover every rule the contract names, not every rule
    /// that happens to live in this file.** `04-subsystem-contracts.md` names
    /// three — "ownership, capacity, and lifecycle rules are identical" — and
    /// two of them are implemented in other modules. A version of this trace
    /// that only exercised `policy.rs` proved lifecycle and left the other two
    /// unguarded: a scope branch in `HostAllocator::allocate` firing only on
    /// `demand > 0`, and one in `attempt::authorize` returning `ForeignHost` for
    /// every organization policy, both left the whole suite green. Anything
    /// added to the contract's list belongs in this body, wherever it is
    /// implemented.
    fn assert_target_behaves_identically(target: ScaleTarget) -> Vec<String> {
        let host = HostId::from_u128(7);
        let mut trace = Vec::new();

        let mut policy = autoscale_policy(target.clone(), host, 3);
        trace.push(format!("owns_runners={}", policy.owns_runners()));
        trace.push(format!("owned_by_host={}", policy.is_owned_by(host)));
        trace.push(format!(
            "owned_by_other={}",
            policy.is_owned_by(HostId::from_u128(8))
        ));
        trace.push(format!("initial_state={}", policy.state()));
        trace.push(format!("initial_enabled={}", policy.enabled()));
        trace.push(format!(
            "may_start_initially={}",
            policy.may_start_runners()
        ));
        trace.push(format!("labels={}", policy.routing_labels().unwrap()));
        trace.push(format!("max_capacity={}", policy.max_capacity().unwrap()));
        trace.push(format!("min_capacity={}", policy.min_capacity()));

        // Lifecycle.
        policy.activate().unwrap();
        trace.push(format!("after_activate={}", policy.state()));
        trace.push(format!("may_start_active={}", policy.may_start_runners()));

        // Demand.
        let jobs = vec![
            RunsOn::Single("rm-home-win-x64".into()),
            RunsOn::Single("ubuntu-latest".into()),
            RunsOn::Single("${{ matrix.os }}".into()),
        ];
        let tally = policy.tally(&jobs);
        trace.push(format!(
            "demand={} not_matched={} unresolvable={}",
            tally.demand(),
            tally.not_matched,
            tally.unresolvable.len()
        ));

        // Capacity (`crate::capacity`). D9's host ceiling and D7's per-policy
        // one are the contract's "capacity rules"; without these lines a scope
        // branch inside `HostAllocator::allocate` is invisible to the suite.
        let host_record = crate::model::Host::new(
            host,
            "home-pc",
            Os::Windows,
            Arch::X64,
            nz(4),
            crate::model::Timestamp::from_timestamp(0, 0).unwrap(),
        )
        .unwrap();
        let mut allocator = crate::capacity::HostAllocator::from_attempts(&host_record, &[]);
        let allocation = allocator.allocate(&policy, 3);
        trace.push(format!(
            "alloc demand={} desired={} active_owned={} headroom_before={} \
             to_start={} limiting={}",
            allocation.demand,
            allocation.desired,
            allocation.active_owned,
            allocation.headroom_before,
            allocation.to_start,
            allocation.limiting_factor
        ));
        trace.push(format!("headroom_after={}", allocator.headroom()));
        // Zero demand as well, so a branch keyed on `demand > 0` cannot hide in
        // the gap between the two.
        trace.push(format!(
            "alloc_zero_to_start={}",
            allocator.allocate(&policy, 0).to_start
        ));

        // Ownership (`crate::attempt`). Ownership rules 1 and 2 are the
        // contract's "ownership rules", and `authorize` is where they are
        // enforced -- `is_owned_by` above only covers rule 2's policy half.
        let attempt = crate::attempt::RunnerAttempt::allocate(
            crate::model::AttemptId::from_u128(11),
            policy.id,
            "C:/runners/eq",
            crate::model::Timestamp::from_timestamp(0, 0).unwrap(),
        );
        trace.push(format!(
            "authorize_own_host={:?}",
            crate::attempt::authorize(host, &policy, &attempt).is_ok()
        ));
        trace.push(format!(
            "authorize_other_host={}",
            crate::attempt::authorize(HostId::from_u128(8), &policy, &attempt)
                .expect_err("an agent on another host must be refused")
        ));
        let foreign_attempt = crate::attempt::RunnerAttempt::allocate(
            crate::model::AttemptId::from_u128(12),
            PolicyId::from_u128(999),
            "C:/runners/eq-other",
            crate::model::Timestamp::from_timestamp(0, 0).unwrap(),
        );
        trace.push(format!(
            "authorize_other_policy={}",
            crate::attempt::authorize(host, &policy, &foreign_attempt)
                .expect_err("an attempt under another policy must be refused")
        ));

        // Drain.
        trace.push(format!("disable={}", policy.request_disable().unwrap()));
        trace.push(format!(
            "drain_with_1={}",
            policy.drain_completed(1).unwrap()
        ));
        trace.push(format!(
            "drain_with_0={}",
            policy.drain_completed(0).unwrap()
        ));

        // Illegal transition, both scopes.
        trace.push(format!(
            "reactivate_err={}",
            policy.transition_to(PolicyState::Active).is_err()
        ));

        // The registration label array `c4` would send.
        trace.push(format!(
            "registration_labels={:?}",
            autoscale_policy(target, host, 3)
                .routing_labels()
                .unwrap()
                .as_registration_labels()
        ));

        trace
    }

    #[test]
    fn repository_and_organization_targets_are_equivalent() {
        let repository = assert_target_behaves_identically(ScaleTarget::repository("o/r").unwrap());
        let organization =
            assert_target_behaves_identically(ScaleTarget::organization("o").unwrap());

        assert_eq!(
            repository, organization,
            "D18: the two scopes differ only in which GitHub endpoint and which \
             App permission the gateway uses. Any difference here is a \
             scope-dependent domain rule that must not exist."
        );

        // The one thing that *is* allowed to differ.
        assert_ne!(
            ScaleTarget::repository("o/r").unwrap().scope(),
            ScaleTarget::organization("o").unwrap().scope()
        );
    }
}
