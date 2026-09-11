// owner: b1-local-model-corpus
//
//! Coverage units and witnesses.
//!
//! A *unit* is one named thing a case proves: a compatible mutating-action
//! pair, a refusal class, a boundary, a cross-scope interaction, a
//! persistence readback, an invariant, or an equivalence-class value.
//! `03-coverage-model.md` retains a generated case only when it contributes at
//! least one unit nothing earlier did, and records which — that is what keeps
//! the count of cases from being padding.
//!
//! # Pairs are success-then-success, and "compatible" is decided by the model
//!
//! A pair `A>B` is witnessed when a successful `A` is followed by a successful
//! `B` with no other mutation between them (reads and seeded facts do not
//! break adjacency: they change nothing a command owns). A pair is
//! *compatible* when some reachable state admits that; the two that are not
//! are listed in [`incompatible_pairs`] with the reason, and
//! `incompatible_pairs_cannot_succeed_back_to_back` proves each claim against
//! the model rather than trusting the comment.

use std::collections::BTreeSet;

use super::action::{Action, ActionKind, Seed, Step};
use super::model::{Installation, Mode, Model, PolicyState};
use super::transition::{self, Transition};

/// One executed step of a simulated case.
#[derive(Debug, Clone)]
pub enum Entry {
    Seed {
        seed: Seed,
        before: Model,
        after: Model,
    },
    Run {
        action: Action,
        before: Model,
        transition: Transition,
    },
}

impl Entry {
    #[must_use]
    pub fn after(&self) -> &Model {
        match self {
            Entry::Seed { after, .. } => after,
            Entry::Run { transition, .. } => &transition.next,
        }
    }
}

/// A case run through the model alone.
#[derive(Debug, Clone)]
pub struct Trace {
    pub initial: Model,
    pub entries: Vec<Entry>,
}

impl Trace {
    #[must_use]
    pub fn last(&self) -> &Model {
        self.entries.last().map_or(&self.initial, Entry::after)
    }
}

/// Runs steps through the model.
///
/// # Errors
/// A seed whose precondition does not hold, with the step index.
pub fn simulate(installation: Installation, steps: &[Step]) -> Result<Trace, String> {
    let initial = Model::fresh(installation);
    let mut current = initial.clone();
    let mut entries = Vec::with_capacity(steps.len());
    for (index, step) in steps.iter().enumerate() {
        match step {
            Step::Seed(seed) => {
                let after = transition::seed(&current, seed)
                    .map_err(|problem| format!("step {}: {problem}", index + 1))?;
                entries.push(Entry::Seed {
                    seed: *seed,
                    before: current.clone(),
                    after: after.clone(),
                });
                current = after;
            }
            Step::Run(action) => {
                let result = transition::apply(&current, action);
                let next = result.next.clone();
                entries.push(Entry::Run {
                    action: action.clone(),
                    before: current.clone(),
                    transition: result,
                });
                current = next;
            }
        }
    }
    Ok(Trace { initial, entries })
}

#[must_use]
pub fn pair_unit(first: ActionKind, second: ActionKind) -> String {
    format!("pair:{first}>{second}")
}

#[must_use]
pub fn readback_unit(mutation: ActionKind, read: ActionKind) -> String {
    format!("readback:{mutation}>{read}")
}

#[must_use]
pub fn refusal_unit(kind: ActionKind, reason: transition::Reason) -> String {
    format!("refusal:{kind}:{}", reason.slug())
}

/// Whether a read renders something the mutation owns, so reading it back in
/// a fresh process proves the mutation persisted.
#[must_use]
pub fn readback_relevant(mutation: ActionKind, read: ActionKind) -> bool {
    use ActionKind as K;
    match read {
        K::StatusJson => mutation.is_mutating(),
        // Capacity, runner root, and the budget's "policies priced".
        K::HostShow => matches!(
            mutation,
            K::HostSetCapacity
                | K::HostSetRuntimeRoot
                | K::HostResetRuntimeRoot
                | K::RepoAdd
                | K::RepoRemove
                | K::OrgAdd
                | K::OrgRemove
        ),
        // Every policy column, plus the effective root an ephemeral policy
        // falls back to.
        K::RepoList => matches!(
            mutation,
            K::RepoAdd
                | K::RepoSetCapacity
                | K::RepoSetScale
                | K::RepoSetWorkspace
                | K::RepoRemove
                | K::HostSetRuntimeRoot
                | K::HostResetRuntimeRoot
        ),
        K::OrgList => matches!(
            mutation,
            K::OrgAdd
                | K::OrgSetCapacity
                | K::OrgSetScale
                | K::OrgRemove
                | K::HostSetRuntimeRoot
                | K::HostResetRuntimeRoot
        ),
        _ => false,
    }
}

/// Every relevant `(mutation, read)` readback.
#[must_use]
pub fn readback_universe() -> Vec<(ActionKind, ActionKind)> {
    let mut universe = Vec::new();
    for mutation in ActionKind::mutating() {
        for read in ActionKind::reads() {
            if readback_relevant(mutation, read) {
                universe.push((mutation, read));
            }
        }
    }
    universe
}

/// The ordered mutating pairs that can never succeed back to back, and why.
#[must_use]
pub fn incompatible_pairs() -> Vec<((ActionKind, ActionKind), &'static str)> {
    vec![
        (
            (ActionKind::AuthLogout, ActionKind::RepoAdd),
            "a successful logout leaves no credential, and add validates the target \
             against GitHub with the stored credential",
        ),
        (
            (ActionKind::AuthLogout, ActionKind::OrgAdd),
            "a successful logout leaves no credential, and add validates the target \
             against GitHub with the stored credential",
        ),
    ]
}

/// Every ordered pair of mutating leaves the corpus must witness.
#[must_use]
pub fn compatible_pairs() -> Vec<(ActionKind, ActionKind)> {
    let excluded: BTreeSet<(ActionKind, ActionKind)> = incompatible_pairs()
        .into_iter()
        .map(|(pair, _)| pair)
        .collect();
    let mut pairs = Vec::new();
    for first in ActionKind::mutating() {
        for second in ActionKind::mutating() {
            if !excluded.contains(&(first, second)) {
                pairs.push((first, second));
            }
        }
    }
    pairs
}

/// The mutating pairs a trace witnesses.
#[must_use]
pub fn witnessed_pairs(trace: &Trace) -> BTreeSet<(ActionKind, ActionKind)> {
    let mut pairs = BTreeSet::new();
    let mut previous: Option<ActionKind> = None;
    for entry in &trace.entries {
        let Entry::Run {
            action, transition, ..
        } = entry
        else {
            continue;
        };
        let kind = action.kind();
        if kind.is_read() {
            continue;
        }
        if transition.exit.is_success() {
            if let Some(first) = previous {
                pairs.insert((first, kind));
            }
            previous = Some(kind);
        } else {
            previous = None;
        }
    }
    pairs
}

/// The compatible pairs no trace in `traces` witnesses.
#[must_use]
pub fn missing_pairs<'a>(
    traces: impl IntoIterator<Item = &'a Trace>,
) -> Vec<(ActionKind, ActionKind)> {
    let mut witnessed = BTreeSet::new();
    for trace in traces {
        witnessed.extend(witnessed_pairs(trace));
    }
    compatible_pairs()
        .into_iter()
        .filter(|pair| !witnessed.contains(pair))
        .collect()
}

/// A policy condition worth proving that unrelated commands preserve.
fn distinction(model: &Model, key: &super::action::TargetKey) -> Option<&'static str> {
    let policy = model.policies.get(key)?;
    Some(match (&policy.mode, policy.state) {
        (_, PolicyState::RepairRequired) => "repair-required",
        (_, PolicyState::Draining) => "draining",
        (_, PolicyState::Disabled) => "disabled",
        (_, PolicyState::Active) => "enabled",
        (Mode::MonitorOnly, _) => "monitor-only",
        (_, PolicyState::Pending) => "pending",
    })
}

/// Every unit a trace witnesses.
#[must_use]
pub fn units(trace: &Trace) -> BTreeSet<String> {
    let mut units = BTreeSet::new();
    for (first, second) in witnessed_pairs(trace) {
        units.insert(pair_unit(first, second));
    }
    let mut last_mutation: Option<ActionKind> = None;
    let mut previous_read: Option<Action> = None;
    for entry in &trace.entries {
        let Entry::Run {
            action,
            before,
            transition,
        } = entry
        else {
            continue;
        };
        let kind = action.kind();
        units.extend(action.value_units());
        units.extend(transition.tags.iter().cloned());
        if let Some(reason) = transition.reason {
            units.insert(refusal_unit(kind, reason));
        }
        if kind.is_read() {
            if let Some(mutation) = last_mutation
                && readback_relevant(mutation, kind)
            {
                units.insert(readback_unit(mutation, kind));
            }
            if previous_read.as_ref() == Some(action) {
                units.insert(format!("invariant:idempotent-read:{kind}"));
            }
            previous_read = Some(action.clone());
            continue;
        }
        previous_read = None;
        if transition.exit.is_success() {
            last_mutation = Some(kind);
            // A distinction that survived a successful command which did not
            // address it.
            let addressed = action.target().and_then(|target| target.key());
            for key in before.policies.keys() {
                if Some(key) == addressed.as_ref() {
                    continue;
                }
                if let (Some(was), Some(is)) =
                    (distinction(before, key), distinction(&transition.next, key))
                    && was == is
                    && was != "pending"
                {
                    units.insert(format!("invariant:{was}-survives-unrelated-commands"));
                }
            }
        } else {
            last_mutation = None;
        }
    }
    units
}
