// owner: b3-local-corpus-security
//
// ----------------------------------------------------------------------------
// THE LOCAL CLI CHAINS, EXECUTED: ONE REAL PROCESS PER ACTION, JUDGED BY THE
// MODEL AFTER EVERY TRANSITION.
// ----------------------------------------------------------------------------
// `.taskflow/2026-09-10-cli-chains-acceptance/tasks/b2-local-chain-runner.md`.
//
// `cli_chains/` predicts; `cli_chains_runner/` executes and judges; this file
// is the test target that mounts both and states what must hold:
//
// 1. representative success and refusal journeys across host, repository,
//    organization, workspace, status and authentication setup/teardown agree
//    with the model at every step (the curated journeys; task b3 widens the
//    default run to the whole inventory);
// 2. every process is confined to its scenario's roots and loopback endpoint,
//    and neither the standard application-data locations nor the product's
//    service identity are touched;
// 3. a refused mutation leaves the database and filesystem observations
//    exactly as they were, judged observation against observation;
// 4. a deliberately wrong expectation on each plane -- exit, output, store,
//    filesystem, request history -- fails at the step it was planted in;
// 5. one stable case can be replayed alone, and the default run cannot be
//    narrowed.
//
// Every action is the real `runner-manager` binary, started fresh, so argument
// parsing, exit-code mapping, context resolution, SQLite reopen, logging and
// filesystem persistence are all inside what is measured. Nothing here calls
// `cli::route` or substitutes an in-memory database.
//
// Replay one case:
//
//   CLI_CHAINS_CASE=local-0007 cargo test -p runner-manager \
//     --test cli_chains_acceptance -- --ignored --exact replay_selected_case

mod cli_chains;
mod cli_chains_runner;
mod support;

use std::collections::BTreeSet;
use std::env::VarError;
use std::time::Duration;

use cli_chains::action::{Action, Step};
use cli_chains::corpus::{self, Case};
use cli_chains::ids::{CaseId, SELECT_VARIABLE};
use cli_chains::model::Installation;
use cli_chains::transition::{Exit, Request, Transition};
use cli_chains::values::PathValue;
use cli_chains_runner::confinement::{StandardFootprint, invocation_problems};
use cli_chains_runner::oracle::Plane;
use cli_chains_runner::run::{self, CaseRun, Expected};
use cli_chains_runner::scenario::{Invocation, Scenario};
use cli_chains_runner::{report, security, selection};
use runner_manager_domain::store::{SqliteStore, Store};

const SOFT_RUNTIME_TARGET: Duration = Duration::from_secs(60);

/// Panics with the report of every diverging run, first divergence first.
fn assert_all_agree(runs: &[CaseRun<'_>]) {
    let failing: Vec<&CaseRun<'_>> = runs.iter().filter(|run| !run.passed()).collect();
    if failing.is_empty() {
        return;
    }
    let ids: Vec<String> = failing.iter().map(|run| run.case.id.to_string()).collect();
    let mut text = format!(
        "{} of {} CLI chains diverged from the model: {}\n",
        failing.len(),
        runs.len(),
        ids.join(", ")
    );
    // The first three in full; the identifiers above say how to replay the
    // rest one at a time.
    for run in failing.iter().take(3) {
        text.push('\n');
        text.push_str(
            &report::render(run)
                .unwrap_or_else(|| format!("{} stopped early without a divergence\n", run.case.id)),
        );
    }
    panic!("{text}");
}

/// The suite summary the soft runtime budget is judged from. Printed, never
/// asserted: `02-target-architecture.md` forbids elapsed time as an oracle.
fn summarise(what: &str, runs: &[CaseRun<'_>], wall: Duration) {
    let processes: usize = runs.iter().map(|run| run.invocations().count()).sum();
    let mut slowest: Vec<&CaseRun<'_>> = runs.iter().collect();
    slowest.sort_by_key(|run| std::cmp::Reverse(run.elapsed));
    let slowest: Vec<String> = slowest
        .iter()
        .take(5)
        .map(|run| format!("{} {:.2}s", run.case.id, run.elapsed.as_secs_f64()))
        .collect();
    eprintln!(
        "cli chains ({what}): {} cases, {processes} processes, {:.1}s wall clock; slowest: {}",
        runs.len(),
        wall.as_secs_f64(),
        slowest.join(", ")
    );
    if wall > SOFT_RUNTIME_TARGET {
        eprintln!(
            "SOFT RUNTIME OVERAGE: {:.1}s exceeds the {:.0}s target by {:.1}s; investigate the listed slowest cases",
            wall.as_secs_f64(),
            SOFT_RUNTIME_TARGET.as_secs_f64(),
            (wall - SOFT_RUNTIME_TARGET).as_secs_f64()
        );
    } else {
        eprintln!(
            "soft runtime target met: {:.1}s <= {:.0}s",
            wall.as_secs_f64(),
            SOFT_RUNTIME_TARGET.as_secs_f64()
        );
    }
}

// ---------------------------------------------------------------------------
// DoD 1 (and the per-run halves of DoD 2 and DoD 5): the default run
// ---------------------------------------------------------------------------

/// Every case of the default selection, through the real binary, judged at
/// every step -- and every process of every case confined, and no standard
/// location created while they ran.
#[test]
fn the_complete_local_corpus_agrees_with_the_model_through_real_processes() {
    let selected = selection::default_selection();
    let selection_problems = selection::completeness_problems(&selected);
    assert!(
        selection_problems.is_empty(),
        "the default selection is incomplete:\n  {}",
        selection_problems.join("\n  ")
    );
    let footprint = StandardFootprint::snapshot();
    let started = std::time::Instant::now();
    let runs = run::execute_all(&selected, run::default_workers());
    summarise("default selection", &runs, started.elapsed());

    // The default run executes exactly the selection: every case, once, in
    // order. Nothing ignored, sampled or skipped.
    let executed: Vec<CaseId> = runs.iter().map(|run| run.case.id).collect();
    let expected: Vec<CaseId> = selected.iter().map(|case| case.id).collect();
    assert_eq!(
        executed, expected,
        "the default run must execute its whole selection"
    );

    assert_all_agree(&runs);

    let mut problems: Vec<String> = runs
        .iter()
        .flat_map(|run| {
            invocation_problems(run)
                .into_iter()
                .map(|problem| format!("{}: {problem}", run.case.id))
                .collect::<Vec<_>>()
        })
        .collect();
    problems.extend(footprint.appeared_since());
    assert!(
        problems.is_empty(),
        "the chains escaped their scenarios:\n  {}",
        problems.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// DoD 1 and DoD 5: what the default run is, and what cannot change it
// ---------------------------------------------------------------------------

#[test]
fn the_default_selection_is_representative_and_takes_no_input() {
    let selected = selection::default_selection();
    assert!(
        !selected.is_empty(),
        "the default run must execute something"
    );
    // A pure function of the checked-in corpus: calling it twice gives the
    // same cases, and nothing it reads can be set from outside.
    let again: Vec<CaseId> = selection::default_selection()
        .iter()
        .map(|case| case.id)
        .collect();
    let first: Vec<CaseId> = selected.iter().map(|case| case.id).collect();
    assert_eq!(first, again);
    assert_eq!(
        first.iter().collect::<BTreeSet<_>>().len(),
        first.len(),
        "no case is selected twice"
    );

    for (area, succeeded, refused) in selection::area_counts(&selected) {
        assert!(
            succeeded > 0,
            "the default run never succeeds at a {} command",
            area.name
        );
        assert!(
            !area.needs_refusal || refused > 0,
            "the default run never meets a {} refusal",
            area.name
        );
    }
    assert!(
        selection::has_real_sign_in(&selected),
        "authentication setup must include a real device-flow sign-in, not only a seeded one"
    );
    let fixtures: BTreeSet<&str> = selected
        .iter()
        .map(|case| case.installation.name())
        .collect();
    for fixture in [
        Installation::None,
        Installation::Standard,
        Installation::Wide,
    ] {
        assert!(
            fixtures.contains(fixture.name()),
            "no selected case runs against the {} fake GitHub",
            fixture.name()
        );
    }
}

#[test]
fn omitting_any_inventory_case_fails_the_default_selection_check() {
    let mut selected = selection::default_selection();
    assert!(selection::completeness_problems(&selected).is_empty());
    let omitted = selected.remove(selected.len() / 2);
    let problems = selection::completeness_problems(&selected);
    assert!(
        !problems.is_empty()
            && problems
                .iter()
                .any(|problem| problem.contains(&omitted.id.to_string())),
        "dropping {} must be detected by name: {problems:?}",
        omitted.id
    );
}

#[test]
fn every_coverage_model_invariant_has_named_corpus_evidence() {
    let units: BTreeSet<String> = corpus::corpus()
        .cases
        .iter()
        .flat_map(|case| cli_chains::coverage::units(&case.trace()))
        .collect();
    // Security and confinement are runtime observations in the complete-corpus
    // test above. These are the state-machine invariants whose evidence lives
    // in the immutable inventory.
    for evidence in [
        "invariant:multi-label-refusal-is-atomic",
        "invariant:idempotent-read:status.json",
        "invariant:idempotent-read:host.show",
        "cross:repository-and-organization-policies-coexist",
        "invariant:duplicate-add-keeps-the-existing-policy",
        "invariant:monitor-only-survives-unrelated-commands",
        "invariant:disabled-survives-unrelated-commands",
        "invariant:enabled-survives-unrelated-commands",
        "invariant:draining-survives-unrelated-commands",
        "invariant:repair-required-survives-unrelated-commands",
        "invariant:derived-label-is-never-duplicated",
        "refusal:repo.remove-label:derived-label-not-removable",
        "refusal:host.set-runtime-root:attempts-own-host-root",
        "refusal:repo.set-workspace:attempts-own-workspace",
        "cross:repository-root-overlaps-the-host-root",
        "invariant:non-purge-removal-retains-diagnostics",
        "refusal:repo.remove:purge-with-active-attempts",
    ] {
        assert!(
            units.contains(evidence),
            "no named case witnesses {evidence}"
        );
    }
}

#[test]
fn every_protected_value_is_detected_on_every_scanned_plane() {
    for (name, value) in security::protected_values() {
        let scenario = Scenario::new(
            CaseId::parse("local-0001").expect("a valid fixture case id"),
            Installation::None,
        );
        let logs = scenario.data.join("logs");
        std::fs::create_dir_all(&logs).expect("the planted log directory");
        std::fs::write(logs.join("planted.log"), format!("before {value} after"))
            .expect("the planted log");
        std::fs::write(
            scenario.data.join("planted.txt"),
            format!("before {value} after"),
        )
        .expect("the planted data artifact");

        let database = scenario.database_path();
        std::fs::create_dir_all(database.parent().expect("the database parent"))
            .expect("the planted database directory");
        let store = SqliteStore::open(&database).expect("the planted database");
        store
            .put_host(
                &runner_manager_testkit::fixtures::host()
                    .display_name(&value)
                    .build(),
            )
            .expect("the protected value can be planted in SQLite");
        drop(store);

        let invocation = Invocation {
            argv: Vec::new(),
            code: 0,
            stdout: format!("before {value} after"),
            stderr: format!("before {value} after"),
            requests: Vec::new(),
            elapsed: Duration::ZERO,
        };
        let fragments = security::collect(&scenario, Some(&invocation))
            .expect("every planted artifact is scannable");
        let found = security::findings(&fragments);
        for plane in security::SecurityPlane::ALL {
            assert!(
                found.iter().any(|finding| finding.contains(plane.name())),
                "planting {name} in {} must be collected and rejected: {found:?}",
                plane.name()
            );
        }
    }
    assert!(
        security::findings(&[security::Fragment {
            plane: security::SecurityPlane::Stdout,
            origin: "a clean fragment".to_string(),
            text: "ordinary operator output".to_string(),
        }])
        .is_empty(),
        "ordinary text must not create a false-positive leak"
    );
}

#[test]
fn the_case_selector_names_one_stable_case_and_refuses_anything_else() {
    assert!(
        selection::selection_from(Err(VarError::NotPresent))
            .expect("an unset selector is not an error")
            .is_none()
    );
    let chosen = &corpus::corpus().cases[corpus::corpus().cases.len() / 2];
    let found = selection::selection_from(Ok(chosen.id.to_string()))
        .expect("a stable identifier selects")
        .expect("and selects something");
    assert_eq!(found.id, chosen.id);
    assert_eq!(found.fingerprint, chosen.fingerprint);
    for bad in [
        "local-9999",
        "local-12",
        "wsl-0001",
        "0007",
        "local-0000",
        "",
    ] {
        assert!(
            selection::selection_from(Ok(bad.to_string())).is_err(),
            "{SELECT_VARIABLE}={bad:?} must be refused, not replay nothing"
        );
    }
    let replay = report::replay_command(&chosen.id.to_string());
    assert!(replay.contains(&format!("{SELECT_VARIABLE}={}", chosen.id)));
    assert!(replay.contains("--ignored"));
}

/// Replays the case [`SELECT_VARIABLE`] names, alone.
///
/// Ignored so that the default run never executes it: the selector can only
/// ever *add* a diagnostic run, never narrow the default one.
#[test]
#[ignore = "local diagnosis: set CLI_CHAINS_CASE=local-NNNN and pass --ignored"]
fn replay_selected_case() {
    let case = selection::selected_case()
        .unwrap_or_else(|problem| panic!("{problem}"))
        .unwrap_or_else(|| {
            panic!(
                "set {SELECT_VARIABLE} to a stable identifier, for example: {}",
                report::replay_command("local-0001")
            )
        });
    let started = std::time::Instant::now();
    let runs = vec![run::execute(case)];
    summarise(&format!("replay of {}", case.id), &runs, started.elapsed());
    assert_all_agree(&runs);
    eprintln!(
        "{} ({}) agreed with the model at all {} steps",
        case.id,
        case.name,
        case.steps.len()
    );
}

// ---------------------------------------------------------------------------
// DoD 2: confinement
// ---------------------------------------------------------------------------

/// The corpus case called `name`; every name used here is a curated journey.
fn case_named(name: &str) -> &'static Case {
    corpus::corpus()
        .cases
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("{name} is a curated journey"))
}

/// The case the confinement and corruption tests drive: from a seeded
/// credential it adds a repository through discovery, configures a host root
/// and a persistent workspace, meets a refusal, and reads back through `list`
/// and `status --json` -- one step on every plane.
fn journey() -> &'static Case {
    case_named("repository-root-refused-where-it-overlaps-the-host-root")
}

#[test]
fn every_process_is_confined_to_its_scenario_and_its_loopback_endpoint() {
    let footprint = StandardFootprint::snapshot();
    let cases = [
        journey(),
        case_named("sign-in-then-resume-without-a-new-code"),
    ];
    let runs = run::execute_all(&cases, 2);
    assert_all_agree(&runs);

    let mut data_roots = BTreeSet::new();
    let mut tags = BTreeSet::new();
    for run in &runs {
        let problems = invocation_problems(run);
        assert!(problems.is_empty(), "{}: {problems:?}", run.case.id);
        assert!(data_roots.insert(run.resolver.data.clone()));
        assert!(tags.insert(run.service_tag.clone()));
        assert!(
            run.resolver.data.starts_with(&run.scenario_root)
                && run.resolver.roots.starts_with(&run.scenario_root),
            "both roots live inside the scenario directory"
        );

        // Positive evidence from the product itself: the secret store it
        // reports is the one rooted in this scenario's data directory, not the
        // developer's.
        for invocation in run.invocations() {
            if invocation.argv.get(2).map(String::as_str) != Some("status") {
                continue;
            }
            let document: serde_json::Value =
                serde_json::from_str(&invocation.stdout).expect("status --json is JSON");
            let location = document["credential"]["store_location"]
                .as_str()
                .expect("status names its secret store");
            let data = run.resolver.data.to_string_lossy();
            assert!(
                location.contains(data.as_ref()),
                "{}: the secret store at {location} is not inside {data}",
                run.case.id
            );
        }

        // Every request any process made reached this case's loopback fixture
        // and was one of the four endpoints the model knows.
        for request in &run.history {
            assert!(
                [
                    "POST /login/device/code",
                    "POST /login/oauth/access_token",
                    "GET /user/installations",
                ]
                .contains(&request.as_str())
                    || (request.starts_with("GET /user/installations/")
                        && request.ends_with("/repositories")),
                "{}: an unexpected request reached the fixture: {request}",
                run.case.id
            );
        }
    }
    assert!(
        runs.iter().any(|run| run.history.len() > 2),
        "at least one case must actually talk to its fake GitHub"
    );
    let appeared = footprint.appeared_since();
    assert!(appeared.is_empty(), "{appeared:?}");
}

// ---------------------------------------------------------------------------
// DoD 3: refused mutations are atomic, observation against observation
// ---------------------------------------------------------------------------

/// Journeys that are mostly refusals, one per area that refuses.
const REFUSAL_JOURNEYS: [&str; 8] = [
    "add-without-a-credential-is-refused-for-both-scopes",
    "duplicate-add-neither-replaces-nor-arms",
    "derived-label-removal-refusal-is-atomic",
    "label-length-and-character-boundaries",
    "host-runner-root-refusals-on-a-fresh-data-root",
    "workspace-argument-and-path-rules",
    "active-attempts-guard-disable-purge-and-the-host-root",
    "malformed-targets-are-refused-before-any-lookup",
];

#[test]
fn refused_mutations_leave_database_and_filesystem_observations_unchanged() {
    let cases: Vec<&Case> = REFUSAL_JOURNEYS
        .iter()
        .map(|name| case_named(name))
        .collect();
    let runs = run::execute_all(&cases, run::default_workers());
    assert_all_agree(&runs);

    let mut refusals = 0;
    let mut first_step_refusals = 0;
    for run in &runs {
        // Each step is compared with the observation before it; for step 1
        // that is the scenario read back before any process ran, so a journey
        // that opens with a refusal is held to the same rule as the rest.
        let mut previous = run.initial.as_ref().expect("a fresh scenario is readable");
        for record in &run.records {
            let after = record.observed.as_ref().expect("readable after");
            let before = std::mem::replace(&mut previous, after);
            let (Step::Run(action), Expected::Action(transition)) =
                (&record.step, &record.expected)
            else {
                continue;
            };
            if action.kind().is_read() || transition.exit.is_success() {
                continue;
            }
            if transition.deviation.is_some() {
                // A named deviation is the product leaving something behind on
                // purpose; the oracle already held it to the permitted delta.
                continue;
            }
            // Counted only once it is actually compared below, so the floor
            // asserted after the loop measures refusals this test checked.
            refusals += 1;
            if record.index == 0 {
                first_step_refusals += 1;
            }
            assert_eq!(
                before.model,
                after.model,
                "{} step {}: a refused {} changed the persisted state",
                run.case.id,
                record.index + 1,
                action.kind()
            );
            assert_eq!(
                before.tree,
                after.tree,
                "{} step {}: a refused {} changed the scenario's files",
                run.case.id,
                record.index + 1,
                action.kind()
            );
            assert!(after.stray.is_empty(), "{:?}", after.stray);
        }
    }
    assert!(
        refusals >= 20,
        "the refusal journeys must actually refuse; only {refusals} refusals ran"
    );
    assert!(
        first_step_refusals > 0,
        "a refusal on a fresh data root, before any other process ran, must be compared"
    );
}

// ---------------------------------------------------------------------------
// DoD 4: every plane can fail, at the step that is wrong
// ---------------------------------------------------------------------------

/// The step index of the first record satisfying `wanted`.
fn step_where(run: &CaseRun<'_>, wanted: impl Fn(&Action, &Transition) -> bool) -> usize {
    run.records
        .iter()
        .find_map(|record| match (&record.step, &record.expected) {
            (Step::Run(action), Expected::Action(transition)) if wanted(action, transition) => {
                Some(record.index)
            }
            _ => None,
        })
        .expect("the journey has such a step")
}

#[test]
fn a_wrong_expectation_on_each_plane_fails_at_the_responsible_action() {
    let case = journey();
    let clean = run::execute(case);
    assert_all_agree(std::slice::from_ref(&clean));
    assert_eq!(
        clean.rejudge(&|_, _| {}),
        None,
        "re-judging unchanged is clean"
    );

    let refusal = step_where(&clean, |action, transition| {
        action.kind().is_mutating() && !transition.exit.is_success()
    });
    let status = step_where(&clean, |action, _| *action == Action::StatusJson);
    let discovery = step_where(&clean, |_, transition| !transition.requests.is_empty());
    let host_root = step_where(&clean, |action, transition| {
        matches!(action, Action::HostSetRuntimeRoot(_)) && transition.exit.is_success()
    });
    let list = step_where(&clean, |action, _| matches!(action, Action::List(_)));

    type Plant = Box<dyn Fn(&mut Transition) + Sync>;
    let plants: Vec<(Plane, usize, Plant)> = vec![
        (
            Plane::Exit,
            refusal,
            Box::new(|transition: &mut Transition| transition.exit = Exit::Success),
        ),
        (
            Plane::Output,
            status,
            Box::new(|transition: &mut Transition| {
                transition
                    .stdout
                    .push("a fragment no command prints".to_string());
            }),
        ),
        (
            Plane::Store,
            host_root,
            Box::new(|transition: &mut Transition| {
                transition.next.credential = !transition.next.credential;
            }),
        ),
        (
            Plane::Filesystem,
            list,
            Box::new(|transition: &mut Transition| {
                if !transition.next.directories.insert(PathValue::Beta) {
                    transition.next.directories.remove(&PathValue::Beta);
                }
            }),
        ),
        (
            Plane::Requests,
            discovery,
            Box::new(|transition: &mut Transition| {
                transition.requests.push(Request::ListInstallations);
            }),
        ),
    ];

    let planted_planes: BTreeSet<Plane> = plants.iter().map(|(plane, _, _)| *plane).collect();
    assert_eq!(
        planted_planes,
        BTreeSet::from(Plane::ALL),
        "every behavioral expectation plane the oracle judges is planted"
    );
    let planted_steps: BTreeSet<usize> = plants.iter().map(|(_, step, _)| *step).collect();
    assert_eq!(
        planted_steps.len(),
        plants.len(),
        "each plane is planted in its own step, so the step a failure names is informative"
    );

    for (plane, step, plant) in &plants {
        let corrupt = |index: usize, transition: &mut Transition| {
            if index == *step {
                plant(transition);
            }
        };
        let (failed_at, mismatches) = clean
            .rejudge(&corrupt)
            .unwrap_or_else(|| panic!("a wrong {plane} expectation at step {} passed", step + 1));
        assert_eq!(
            failed_at,
            *step,
            "a wrong {plane} expectation planted at step {} failed at step {}",
            step + 1,
            failed_at + 1
        );
        let planes: BTreeSet<Plane> = mismatches.iter().map(|mismatch| mismatch.plane).collect();
        assert_eq!(
            planes,
            BTreeSet::from([*plane]),
            "a wrong {plane} expectation must be reported on that plane alone: {mismatches:?}"
        );
    }

    // And live: the runner itself stops at the planted step, runs nothing
    // after it, and reports it with its replay data.
    let (plane, step, plant) = &plants[0];
    let live = run::execute_with(case, &|index, transition| {
        if index == *step {
            plant(transition);
        }
    });
    let divergence = live.divergence().expect("the planted exit fails live");
    assert_eq!(divergence.index, *step);
    assert!(divergence.mismatches.iter().all(|m| m.plane == *plane));
    assert_eq!(
        live.records.len(),
        step + 1,
        "nothing runs after a divergence"
    );
    let text = report::render(&live).expect("a diverging run has a report");
    for section in [
        &format!(
            "CLI chain {} diverged from the model at step {}",
            case.id,
            step + 1
        ),
        &format!("seed {:#018x}", corpus::CORPUS_SEED),
        &format!("version {}", corpus::CORPUS_VERSION),
        "Pre-state",
        "Action prefix",
        "Expected transition",
        "Observed",
        "Fake GitHub call history",
        "GET /user/installations",
        &report::replay_command(&case.id.to_string()),
    ] {
        assert!(
            text.contains(section),
            "the report lacks {section:?}:\n{text}"
        );
    }
}
