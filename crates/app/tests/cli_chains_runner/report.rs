// owner: b2-local-chain-runner
//
//! The failure report: everything needed to replay and diagnose the first
//! divergence, and nothing that needs the machine it happened on.
//!
//! `03-coverage-model.md`, "Replay and diagnostics": "A failure prints the
//! identifier, generation seed/version, pre-state, actions already run,
//! expected transition, observed exit/output/state, and fake call history."
//! Every one of those is a section below, in that order, followed by the exact
//! command that replays the case alone.

use std::fmt::Write as _;

use crate::cli_chains::action::Step;
use crate::cli_chains::corpus::{CORPUS_SEED, CORPUS_VERSION};
use crate::cli_chains::ids::SELECT_VARIABLE;

use super::run::{CaseRun, Expected, StepRecord};

/// The command that replays one case alone.
#[must_use]
pub fn replay_command(case: &str) -> String {
    format!(
        "{SELECT_VARIABLE}={case} cargo test -p runner-manager --test cli_chains_acceptance \
         -- --ignored --exact replay_selected_case"
    )
}

/// The one-line description of a step, as the inventory prints it, with the
/// model's expected outcome.
fn describe(record: &StepRecord) -> String {
    let marker = if record.setup { "setup " } else { "" };
    let text = record.step.describe(&crate::cli_chains::values::Symbolic);
    let outcome = match &record.expected {
        Expected::Seed(_) => String::new(),
        Expected::Action(transition) => {
            let mut outcome = format!(" => {}", transition.exit.describe());
            if let Some(reason) = transition.reason {
                let _ = write!(outcome, " {}", reason.slug());
            }
            if let Some(deviation) = transition.deviation {
                let _ = write!(outcome, " [deviation: {}]", deviation.slug());
            }
            outcome
        }
    };
    let observed = record
        .invocation
        .as_ref()
        .map_or_else(String::new, |invocation| {
            format!(" (observed exit {})", invocation.code)
        });
    format!("{:>2}. {marker}{text}{outcome}{observed}", record.index + 1)
}

/// Renders the divergence report for a run, or `None` when it passed.
#[must_use]
pub fn render(run: &CaseRun<'_>) -> Option<String> {
    let divergence = run.divergence()?;
    let case = run.case;
    let mut text = String::new();
    let _ = writeln!(
        text,
        "CLI chain {} diverged from the model at step {} of {}",
        case.id,
        divergence.index + 1,
        case.steps.len()
    );
    let _ = writeln!(text, "  name:        {}", case.name);
    let _ = writeln!(
        text,
        "  corpus:      version {CORPUS_VERSION}, seed {CORPUS_SEED:#018x}, fingerprint {:016x}, \
         origin {}, fixture {}",
        case.fingerprint,
        case.origin.name(),
        case.installation.name()
    );
    let _ = writeln!(
        text,
        "  replay:      {}",
        replay_command(&case.id.to_string())
    );
    let _ = writeln!(
        text,
        "  scenario:    {} (service fixture tag {})",
        run.scenario_root.display(),
        run.service_tag
    );

    let _ = writeln!(text, "\nMismatches at step {}:", divergence.index + 1);
    for mismatch in &divergence.mismatches {
        let _ = writeln!(text, "  - [{}] {}", mismatch.plane, mismatch.detail);
    }

    let _ = writeln!(text, "\nPre-state (the model before the failing step):");
    let _ = writeln!(text, "  {:#?}", divergence.before);

    let _ = writeln!(
        text,
        "\nAction prefix (steps already run, all of which agreed):"
    );
    if divergence.index == 0 {
        let _ = writeln!(text, "  (none)");
    }
    for record in run.records.iter().take(divergence.index) {
        let _ = writeln!(text, "  {}", describe(record));
    }

    let _ = writeln!(text, "\nFailing step:");
    let _ = writeln!(text, "  {}", describe(divergence));
    if let Some(invocation) = &divergence.invocation {
        let _ = writeln!(text, "  argv: {:?}", invocation.argv);
    }

    let _ = writeln!(text, "\nExpected transition:");
    match &divergence.expected {
        Expected::Seed(model) => {
            let _ = writeln!(text, "  seeded state: {model:#?}");
        }
        Expected::Action(transition) => {
            let _ = writeln!(
                text,
                "  exit: {}  reason: {:?}  deviation: {:?}",
                transition.exit.describe(),
                transition.reason.map(|reason| reason.slug()),
                transition.deviation.map(|deviation| deviation.slug())
            );
            let _ = writeln!(text, "  stdout fragments: {:?}", transition.stdout);
            let _ = writeln!(text, "  stderr fragments: {:?}", transition.stderr);
            let requests: Vec<String> = transition
                .requests
                .iter()
                .map(|request| request.render())
                .collect();
            let _ = writeln!(text, "  requests: {requests:?}");
            let _ = writeln!(text, "  deltas: {:#?}", transition.deltas);
            let _ = writeln!(text, "  next model: {:#?}", transition.next);
        }
    }

    let _ = writeln!(text, "\nObserved:");
    if let Some(invocation) = &divergence.invocation {
        let _ = writeln!(text, "  exit code: {}", invocation.code);
        let _ = writeln!(text, "  requests: {:?}", invocation.requests);
        let _ = writeln!(text, "  stdout:\n{}", indent(&invocation.stdout));
        let _ = writeln!(text, "  stderr:\n{}", indent(&invocation.stderr));
    }
    match &divergence.observed {
        Ok(observed) => {
            let _ = writeln!(text, "  persisted state: {:#?}", observed.model);
            if !observed.anomalies.is_empty() {
                let _ = writeln!(text, "  unmodelled store state: {:?}", observed.anomalies);
            }
            if !observed.stray.is_empty() {
                let _ = writeln!(text, "  stray filesystem entries: {:?}", observed.stray);
            }
        }
        Err(problem) => {
            let _ = writeln!(text, "  persisted state unreadable: {problem}");
        }
    }

    let _ = writeln!(text, "\nFake GitHub call history (whole case, in order):");
    if run.history.is_empty() {
        let _ = writeln!(text, "  (none)");
    }
    for (index, request) in run.history.iter().enumerate() {
        let _ = writeln!(text, "  {:>2}. {request}", index + 1);
    }

    let remaining: Vec<&Step> = case.steps.iter().skip(divergence.index + 1).collect();
    if !remaining.is_empty() {
        let _ = writeln!(text, "\nNot run (after the divergence):");
        for (offset, step) in remaining.iter().enumerate() {
            let _ = writeln!(
                text,
                "  {:>2}. {}",
                divergence.index + 2 + offset,
                step.describe(&crate::cli_chains::values::Symbolic)
            );
        }
    }
    Some(text)
}

fn indent(text: &str) -> String {
    if text.is_empty() {
        return "    (empty)".to_string();
    }
    text.lines()
        .map(|line| format!("    | {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}
