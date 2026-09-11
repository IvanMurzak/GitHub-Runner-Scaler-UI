// owner: b2-local-chain-runner
//
//! Drives one case, step by step, and stops at the first divergence.
//!
//! # The order inside a step is the whole point
//!
//! For an action: the model computes the transition from the state it holds,
//! **then** the real process runs, **then** the scenario is read back and the
//! two are compared. `03-coverage-model.md`: "The real command is run between
//! calculating the expectation and observing the result, so production state
//! is never used to derive its own expected value." The model state carried to
//! the next step is the model's own `next`, never the observation, so one
//! divergence cannot be laundered into the baseline of the step after it --
//! and the runner stops there anyway, because every later expectation would be
//! built on a state the product did not reach.
//!
//! For a seed: the model's seeded state is computed, the seed is applied
//! through public interfaces, and the store and filesystem planes are checked
//! so a seed that did not land fails as a seed rather than as whatever command
//! happened to run next.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::cli_chains::action::Step;
use crate::cli_chains::corpus::Case;
use crate::cli_chains::model::Model;
use crate::cli_chains::transition::{self, Transition};

use super::observe::{Identities, ObservedState, observe};
use super::oracle::{Mismatch, judge_action, judge_state};
use super::scenario::{Invocation, RealResolver, Scenario};

/// What the model expected of one step.
#[derive(Debug, Clone)]
pub enum Expected {
    /// The state a seed must leave.
    Seed(Model),
    /// The full transition an action must produce.
    Action(Box<Transition>),
}

impl Expected {
    /// The state after the step.
    #[must_use]
    pub fn next(&self) -> &Model {
        match self {
            Expected::Seed(model) => model,
            Expected::Action(transition) => &transition.next,
        }
    }
}

/// One executed step, with everything needed to judge it again.
#[derive(Debug, Clone)]
pub struct StepRecord {
    /// Zero-based position in the case.
    pub index: usize,
    pub step: Step,
    /// Whether the step establishes the case's named initial state.
    pub setup: bool,
    /// The model state the expectation was computed from.
    pub before: Model,
    pub expected: Expected,
    /// The process, for an action.
    pub invocation: Option<Invocation>,
    pub observed: Result<ObservedState, String>,
    pub mismatches: Vec<Mismatch>,
}

/// One executed case.
#[derive(Debug)]
pub struct CaseRun<'c> {
    pub case: &'c Case,
    /// The scenario directory, for the report. Removed once the run is over.
    pub scenario_root: PathBuf,
    /// The service fixture tag every process carried.
    pub service_tag: String,
    /// The loopback base URL of the case's fake GitHub.
    pub github_base: String,
    /// The resolver the case's paths and labels were rendered with.
    pub resolver: RealResolver,
    /// The scenario read back before its first step, so a refusal at step 1
    /// has an observation to be compared against like every later one.
    pub initial: Result<ObservedState, String>,
    /// Steps in order, ending at the first divergence if there was one.
    pub records: Vec<StepRecord>,
    /// Every request the case's fake GitHub answered, in order.
    pub history: Vec<String>,
    pub elapsed: Duration,
}

impl CaseRun<'_> {
    /// The first step that diverged.
    #[must_use]
    pub fn divergence(&self) -> Option<&StepRecord> {
        self.records
            .iter()
            .find(|record| !record.mismatches.is_empty())
    }

    /// Whether every step of the case ran and agreed with the model.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.divergence().is_none() && self.records.len() == self.case.steps.len()
    }

    /// Every process the case started.
    pub fn invocations(&self) -> impl Iterator<Item = &Invocation> {
        self.records
            .iter()
            .filter_map(|record| record.invocation.as_ref())
    }

    /// Re-judges the recorded observations against expectations altered by
    /// `corrupt`, without starting a process, and returns the first diverging
    /// step with its mismatches.
    ///
    /// This is how a deliberately wrong expectation is shown to fail at the
    /// step it was planted in: the observations are real, only the
    /// expectation is changed.
    #[must_use]
    pub fn rejudge(&self, corrupt: &Corruption<'_>) -> Option<(usize, Vec<Mismatch>)> {
        for record in &self.records {
            let mismatches = match (&record.expected, &record.step) {
                (Expected::Seed(model), _) => judge_state(model, &record.observed),
                (Expected::Action(transition), Step::Run(action)) => {
                    let mut transition = (**transition).clone();
                    corrupt(record.index, &mut transition);
                    judge_action(
                        action,
                        &record.before,
                        &transition,
                        record
                            .invocation
                            .as_ref()
                            .expect("every action record holds its invocation"),
                        &record.observed,
                        &self.resolver,
                    )
                }
                (Expected::Action(_), Step::Seed(_)) => {
                    unreachable!("an action expectation always belongs to a run step")
                }
            };
            if !mismatches.is_empty() {
                return Some((record.index, mismatches));
            }
        }
        None
    }
}

/// A deliberate change to one step's expectation, by step index.
pub type Corruption<'a> = dyn Fn(usize, &mut Transition) + Sync + 'a;

/// Runs a case against the real binary.
#[must_use]
pub fn execute(case: &Case) -> CaseRun<'_> {
    execute_with(case, &|_, _| {})
}

/// Runs a case with `corrupt` applied to each action's expectation before the
/// process starts.
///
/// # Panics
/// If a seed's precondition does not hold in the model, which corpus
/// generation already rules out.
#[must_use]
pub fn execute_with<'c>(case: &'c Case, corrupt: &Corruption<'_>) -> CaseRun<'c> {
    let started = Instant::now();
    let scenario = Scenario::new(case.id, case.installation);
    let mut identities = Identities::default();
    let initial = observe(&scenario, &mut identities);
    let mut model = Model::fresh(case.installation);
    let mut records = Vec::with_capacity(case.steps.len());

    for (index, step) in case.steps.iter().enumerate() {
        let (expected, invocation, observed, mismatches) = match step {
            Step::Seed(seed) => {
                let expected = transition::seed(&model, seed).unwrap_or_else(|problem| {
                    panic!(
                        "{}: step {} is not a reachable seed: {problem}",
                        case.id,
                        index + 1
                    )
                });
                let observed = scenario
                    .apply_seed(seed)
                    .and_then(|()| observe(&scenario, &mut identities));
                let mismatches = judge_state(&expected, &observed);
                (Expected::Seed(expected), None, observed, mismatches)
            }
            Step::Run(action) => {
                // The expectation first. The process has not run yet.
                let mut expected = transition::apply(&model, action);
                corrupt(index, &mut expected);
                let invocation = scenario.run_action(action);
                let observed = observe(&scenario, &mut identities);
                let mismatches = judge_action(
                    action,
                    &model,
                    &expected,
                    &invocation,
                    &observed,
                    &scenario.resolver,
                );
                (
                    Expected::Action(Box::new(expected)),
                    Some(invocation),
                    observed,
                    mismatches,
                )
            }
        };
        // The model's own next state, never the observation.
        let next = expected.next().clone();
        let record = StepRecord {
            index,
            step: step.clone(),
            setup: index < case.setup_len,
            before: std::mem::replace(&mut model, next),
            expected,
            invocation,
            observed,
            mismatches,
        };
        let diverged = !record.mismatches.is_empty();
        records.push(record);
        if diverged {
            break;
        }
    }

    CaseRun {
        case,
        scenario_root: scenario.root.clone(),
        service_tag: scenario.tag.clone(),
        github_base: scenario.github.base_url().to_string(),
        resolver: scenario.resolver.clone(),
        initial,
        records,
        history: scenario.github.seen(),
        elapsed: started.elapsed(),
    }
}

/// Runs cases on a small pool of threads and returns the runs in input order.
///
/// Every case owns its directories, its fake GitHub, its service tag and its
/// model, and a child's environment is set on its own `Command` rather than on
/// this process, so cases share no mutable state and may overlap in time.
#[must_use]
pub fn execute_all<'c>(cases: &[&'c Case], workers: usize) -> Vec<CaseRun<'c>> {
    let next = AtomicUsize::new(0);
    let finished: Mutex<Vec<(usize, CaseRun<'c>)>> = Mutex::new(Vec::with_capacity(cases.len()));
    std::thread::scope(|scope| {
        for _ in 0..workers.max(1) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(case) = cases.get(index) else {
                        break;
                    };
                    let run = execute(case);
                    finished
                        .lock()
                        .expect("no worker panics while holding the lock")
                        .push((index, run));
                }
            });
        }
    });
    let mut finished = finished.into_inner().expect("the workers are done");
    finished.sort_by_key(|(index, _)| *index);
    finished.into_iter().map(|(_, run)| run).collect()
}

/// How many cases run at once: the machine's parallelism, capped so a large
/// machine does not turn the suite into a process storm.
#[must_use]
pub fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(1, 8)
}
