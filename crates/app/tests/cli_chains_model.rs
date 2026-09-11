// owner: b1-local-model-corpus
//
// ----------------------------------------------------------------------------
// THE MODEL'S OWN TESTS. NOTHING HERE STARTS THE BINARY.
// ----------------------------------------------------------------------------
// `cli_chains/` is an independent, pure model of the local CLI plus the
// corpus of chains it predicts. Before a runner (task b2) is allowed to judge
// the product against it, the model has to be shown to be worth trusting:
//
// * the inventory holds at least 256 stable, meaningful cases and says why
//   each is there (`b1` Definition of Done 1);
// * every compatible mutating pair has a named witness, and removing one is
//   detected (DoD 2);
// * the pure transitions are right on success, refusal atomicity, idempotent
//   reads, capacity boundaries, label rules, workspace guards and repo/org
//   coexistence (DoD 3);
// * a corrupted expectation fails a self-check that reads no production state
//   (DoD 4).
//
// The checked-in inventory is `cli_chains/local_inventory.txt`. When a change
// to the model or the generator is intended, regenerate it with
// `CLI_CHAINS_BLESS=1 cargo test -p runner-manager --test cli_chains_model`
// and review the diff: renumbered or re-fingerprinted cases are what a replay
// instruction would otherwise silently lose.

mod cli_chains;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use cli_chains::action::{
    Action, ActionKind, AddArgs, AttemptKind, Labels, Seed, Step, Target, TargetKey,
    WorkspaceSetting,
};
use cli_chains::corpus::{self, Case, INVENTORY_FILE, MINIMUM_LOCAL_CASES};
use cli_chains::coverage::{self, Entry};
use cli_chains::ids::{self, CaseId};
use cli_chains::model::{Installation, Mode, Model, PolicyState, Tally};
use cli_chains::transition::{self, Delta, Deviation, Exit, Failure, Reason, Request, Transition};
use cli_chains::values::{
    Capacity, HostLabelValue as H, LabelValue as L, OrgName as O, PathValue as P, RepoName as R,
    Scope, Symbolic, derived_symbol,
};

// ---------------------------------------------------------------------------
// Small builders
// ---------------------------------------------------------------------------

fn repo(name: R) -> Target {
    Target::Repo(name)
}

fn org(name: O) -> Target {
    Target::Org(name)
}

fn key(target: Target) -> TargetKey {
    target.key().expect("a valid target")
}

fn add(target: Target, host: H, max: Option<Capacity>, labels: &[L], enable: bool) -> Action {
    Action::Add(AddArgs {
        target,
        host_label: host,
        max_capacity: max,
        labels: labels.to_vec(),
        enable,
    })
}

fn auto(target: Target) -> Action {
    add(target, H::Home, Some(Capacity::Two), &[L::Gpu], false)
}

fn monitor(target: Target) -> Action {
    add(target, H::Home, None, &[], false)
}

fn signed_in(installation: Installation) -> Model {
    transition::seed(&Model::fresh(installation), &Seed::Credential).expect("fresh")
}

/// Applies an action that must succeed, and returns the transition.
fn ok(model: &Model, action: &Action) -> Transition {
    let result = transition::apply(model, action);
    assert_eq!(
        result.exit,
        Exit::Success,
        "{action:?} must succeed on {model:?}, got {:?} {:?}",
        result.reason,
        result.stderr
    );
    transition::check(model, action, &result).expect("the model's own transition is consistent");
    result
}

/// Applies an action that must be refused for `reason`, and returns it.
fn refused(model: &Model, action: &Action, reason: Reason) -> Transition {
    let result = transition::apply(model, action);
    assert_eq!(
        result.reason,
        Some(reason),
        "{action:?} on {model:?} must be refused as {reason:?}; got {:?}",
        result.exit
    );
    assert_eq!(result.exit, Exit::Refused(reason.failure()));
    transition::check(model, action, &result).expect("the model's own transition is consistent");
    result
}

/// Runs actions that must all succeed.
fn after(mut model: Model, actions: &[Action]) -> Model {
    for action in actions {
        model = ok(&model, action).next;
    }
    model
}

fn seeded(model: &Model, seed: Seed) -> Model {
    transition::seed(model, &seed).expect("a valid seed")
}

fn every_run(case: &Case) -> Vec<(Model, Action, Transition)> {
    case.trace()
        .entries
        .into_iter()
        .filter_map(|entry| match entry {
            Entry::Run {
                action,
                before,
                transition,
            } => Some((before, action, transition)),
            Entry::Seed { .. } => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// DoD 1: the inventory
// ---------------------------------------------------------------------------

#[test]
fn the_inventory_holds_at_least_256_meaningful_local_cases() {
    let corpus = corpus::corpus();
    assert!(
        corpus.cases.len() >= MINIMUM_LOCAL_CASES,
        "the local inventory must hold at least {MINIMUM_LOCAL_CASES} cases; it holds {}",
        corpus.cases.len()
    );
    for case in &corpus.cases {
        assert!(
            !case.contributions.is_empty(),
            "{} ({}) contributes nothing and is padding",
            case.id,
            case.name
        );
        assert!(
            case.steps.len() > case.setup_len,
            "{} has no step under test",
            case.id
        );
        assert!(
            case.steps.iter().any(|step| matches!(step, Step::Run(_))),
            "{} runs no command",
            case.id
        );
    }
    assert!(
        corpus.rejected > 0,
        "the retention rule must actually reject semantically duplicate candidates"
    );
}

#[test]
fn case_identifiers_are_sequential_unique_and_round_trip() {
    let corpus = corpus::corpus();
    let mut fingerprints = BTreeSet::new();
    for (index, case) in corpus.cases.iter().enumerate() {
        let expected = CaseId(u16::try_from(index + 1).unwrap());
        assert_eq!(case.id, expected, "identifiers are positional and gapless");
        let text = case.id.to_string();
        assert!(
            text.starts_with(ids::LOCAL_PREFIX) && text.len() == 10,
            "{text}"
        );
        assert_eq!(CaseId::parse(&text), Some(case.id));
        assert!(
            fingerprints.insert(case.fingerprint),
            "{} has the same fingerprint as an earlier case: its steps are a duplicate",
            case.id
        );
        assert!(std::ptr::eq(corpus.case(case.id).unwrap(), case));
    }
    for rejected in [
        "local-0",
        "local-00001",
        "local-0000",
        "wsl-0001",
        "local-00a1",
        "",
    ] {
        assert_eq!(CaseId::parse(rejected), None, "{rejected:?}");
    }
}

/// The recorded contribution of each case is exactly what it witnessed first,
/// so the inventory's "why" is a fact rather than a label.
#[test]
fn every_case_records_exactly_the_coverage_it_contributes() {
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for case in &corpus::corpus().cases {
        let units = coverage::units(&case.trace());
        let fresh: Vec<String> = units.difference(&covered).cloned().collect();
        assert_eq!(
            fresh, case.contributions,
            "{} ({}) records a contribution it does not make",
            case.id, case.name
        );
        covered.extend(fresh);
    }
}

#[test]
fn every_contribution_category_and_refusal_class_is_represented() {
    let corpus = corpus::corpus();
    let units: BTreeSet<String> = corpus
        .cases
        .iter()
        .flat_map(|case| case.contributions.iter().cloned())
        .collect();
    for category in [
        "pair:",
        "refusal:",
        "boundary:",
        "cross:",
        "invariant:",
        "value:",
        "readback:",
        "deviation:",
    ] {
        let count = units
            .iter()
            .filter(|unit| unit.starts_with(category))
            .count();
        assert!(count > 0, "no case contributes a {category} unit");
    }
    let refusals: BTreeSet<Reason> = corpus
        .cases
        .iter()
        .flat_map(every_run)
        .filter_map(|(_, _, transition)| transition.reason)
        .collect();
    for reason in Reason::ALL {
        assert!(
            refusals.contains(&reason),
            "no case is refused as {reason:?}"
        );
    }
    for (mutation, read) in coverage::readback_universe() {
        let unit = coverage::readback_unit(mutation, read);
        assert!(units.contains(&unit), "{unit} is never witnessed");
    }
}

fn inventory_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(INVENTORY_FILE)
}

#[test]
fn the_checked_in_inventory_matches_the_generator() {
    let rendered = corpus::render_inventory(corpus::corpus());
    let path = inventory_path();
    if std::env::var_os("CLI_CHAINS_BLESS").is_some() {
        std::fs::write(&path, &rendered).expect("the inventory must be writable when blessing");
        return;
    }
    let checked_in = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must exist: {error}", path.display()))
        .replace("\r\n", "\n");
    if checked_in != rendered {
        let first = checked_in
            .lines()
            .zip(rendered.lines())
            .position(|(left, right)| left != right)
            .unwrap_or_else(|| checked_in.lines().count().min(rendered.lines().count()));
        panic!(
            "{} is out of date at line {}:\n  checked in: {:?}\n  generated:  {:?}\n\
             Review the model/generator change, then regenerate with CLI_CHAINS_BLESS=1.",
            path.display(),
            first + 1,
            checked_in.lines().nth(first),
            rendered.lines().nth(first)
        );
    }
}

#[test]
fn generation_is_deterministic() {
    let first = corpus::render_inventory(&corpus::generate());
    let second = corpus::render_inventory(&corpus::generate());
    assert_eq!(first, second);
}

#[test]
fn a_single_case_can_be_selected_for_replay_without_changing_the_corpus() {
    let corpus = corpus::corpus();
    let chosen = &corpus.cases[corpus.cases.len() / 2];
    let selected = corpus
        .case(CaseId::parse(&chosen.id.to_string()).unwrap())
        .unwrap();
    assert_eq!(selected.fingerprint, chosen.fingerprint);
    assert_eq!(ids::SELECT_VARIABLE, "CLI_CHAINS_CASE");
    // Selecting reads nothing back into the corpus: it is the same object.
    assert!(std::ptr::eq(corpus, corpus::corpus()));
}

#[test]
fn only_allowlisted_commands_are_generated() {
    let allowed: BTreeSet<[&str; 2]> = ActionKind::ALL
        .iter()
        .map(|kind| kind.command_path())
        .collect();
    let forbidden = [
        "daemon", "service", "update", "tui", "wsl", "wsl-host", "receive", "--host",
    ];
    for case in &corpus::corpus().cases {
        for step in &case.steps {
            let Step::Run(action) = step else { continue };
            let argv = action.argv(&Symbolic);
            let path = [argv[0].as_str(), argv[1].as_str()];
            assert!(
                allowed.contains(&path),
                "{}: {argv:?} is not allowlisted",
                case.id
            );
            assert_eq!(path, action.kind().command_path());
            for word in &argv {
                assert!(
                    !forbidden.contains(&word.as_str()),
                    "{}: {argv:?} reaches a non-generative command",
                    case.id
                );
            }
        }
    }
}

/// The model is independent of the code it judges: no file under
/// `cli_chains/` names a production crate, the store, or a process.
#[test]
fn the_model_never_imports_production_code_or_spawns_a_process() {
    let sources = [
        ("action.rs", include_str!("cli_chains/action.rs")),
        ("corpus.rs", include_str!("cli_chains/corpus.rs")),
        ("coverage.rs", include_str!("cli_chains/coverage.rs")),
        ("ids.rs", include_str!("cli_chains/ids.rs")),
        ("model.rs", include_str!("cli_chains/model.rs")),
        ("transition.rs", include_str!("cli_chains/transition.rs")),
        ("values.rs", include_str!("cli_chains/values.rs")),
    ];
    for (file, source) in sources {
        for needle in [
            concat!("runner_manager", "_domain"),
            concat!("runner_manager", "_platform"),
            concat!("runner_manager", "_github"),
            concat!("runner_manager", "_agent"),
            concat!("runner_manager", "_testkit"),
            concat!("Sqlite", "Store"),
            concat!("std::", "process"),
            concat!("assert", "_cmd"),
            concat!("cargo", "_bin"),
        ] {
            assert!(
                !source.contains(needle),
                "cli_chains/{file} mentions {needle}; the model must not consult production code \
                 or run anything"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// DoD 2: pairwise witnesses
// ---------------------------------------------------------------------------

#[test]
fn every_compatible_mutating_pair_has_a_named_witness() {
    let corpus = corpus::corpus();
    let traces: Vec<_> = corpus.cases.iter().map(Case::trace).collect();
    let missing = coverage::missing_pairs(&traces);
    assert!(
        missing.is_empty(),
        "unwitnessed compatible pairs: {missing:?}"
    );
    let mutating = ActionKind::mutating().len();
    assert_eq!(
        coverage::compatible_pairs().len() + coverage::incompatible_pairs().len(),
        mutating * mutating
    );
}

#[test]
fn removing_every_witness_of_a_pair_fails_the_completeness_check() {
    let corpus = corpus::corpus();
    let traces: Vec<_> = corpus.cases.iter().map(Case::trace).collect();
    let witnessed: Vec<BTreeSet<_>> = traces.iter().map(coverage::witnessed_pairs).collect();
    let mut sole_witnesses = 0;
    for pair in coverage::compatible_pairs() {
        let witnesses: Vec<usize> = (0..traces.len())
            .filter(|index| witnessed[*index].contains(&pair))
            .collect();
        assert!(!witnesses.is_empty(), "{pair:?} has no witness");
        if witnesses.len() == 1 {
            sole_witnesses += 1;
        }
        let remaining = traces
            .iter()
            .enumerate()
            .filter(|(index, _)| !witnesses.contains(index))
            .map(|(_, trace)| trace);
        let missing = coverage::missing_pairs(remaining);
        assert!(
            missing.contains(&pair),
            "removing {} (the witnesses of {pair:?}) went unnoticed",
            witnesses
                .iter()
                .map(|index| corpus.cases[*index].id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    assert!(
        sole_witnesses > 0,
        "at least one pair must rest on a single named case, or removing one case could never \
         be observed"
    );
}

#[test]
fn incompatible_pairs_cannot_succeed_back_to_back() {
    let seeds = [Seed::Credential];
    let mut starts = Vec::new();
    for installation in [
        Installation::None,
        Installation::Standard,
        Installation::Wide,
    ] {
        starts.push(Model::fresh(installation));
        let mut model = Model::fresh(installation);
        for seed in &seeds {
            model = seeded(&model, *seed);
        }
        starts.push(model.clone());
        if installation != Installation::None {
            starts.push(after(model.clone(), &[auto(repo(R::Widgets))]));
            starts.push(after(model, &[auto(org(O::Acme))]));
        }
    }
    let adds: Vec<Action> = [
        repo(R::Widgets),
        repo(R::Gadgets),
        repo(R::Portal),
        org(O::Acme),
        org(O::Globex),
    ]
    .into_iter()
    .flat_map(|target| {
        [
            auto(target),
            monitor(target),
            add(target, H::Office, Some(Capacity::Max), &[], true),
        ]
    })
    .collect();
    for ((first, second), reason) in coverage::incompatible_pairs() {
        assert!(!reason.is_empty());
        assert_eq!(first, ActionKind::AuthLogout);
        for start in &starts {
            let logout = transition::apply(start, &Action::AuthLogout);
            assert!(logout.exit.is_success());
            for candidate in adds.iter().filter(|action| action.kind() == second) {
                let result = transition::apply(&logout.next, candidate);
                assert!(
                    !result.exit.is_success(),
                    "{candidate:?} succeeded right after a logout, so {first}>{second} is \
                     compatible after all"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The contract every predicted transition obeys
// ---------------------------------------------------------------------------

#[test]
fn every_corpus_transition_satisfies_the_model_contract() {
    for case in &corpus::corpus().cases {
        for (before, action, transition) in every_run(case) {
            transition::check(&before, &action, &transition).unwrap_or_else(|problem| {
                panic!("{} ({}) {action:?}: {problem}", case.id, case.name)
            });
            before.validate().unwrap();
        }
    }
}

#[test]
fn refusals_leave_the_model_unchanged_except_for_named_deviations() {
    let mut seen = BTreeSet::new();
    for case in &corpus::corpus().cases {
        for (before, action, transition) in every_run(case) {
            if transition.exit.is_success() {
                assert_eq!(transition.deviation, None);
                continue;
            }
            match transition.deviation {
                None => assert_eq!(
                    transition.next, before,
                    "{} {action:?}: a refusal changed the model",
                    case.id
                ),
                Some(deviation) => {
                    seen.insert(deviation);
                }
            }
            assert!(
                transition
                    .stderr
                    .iter()
                    .any(|fragment| fragment == "error: "),
                "a refusal names itself on stderr"
            );
        }
    }
    assert_eq!(
        seen,
        BTreeSet::from([
            Deviation::HostMaterializedByRefusal,
            Deviation::PartialCommitOnEnable
        ]),
        "the corpus must exercise exactly the deviations it documents"
    );
}

/// Every model state the corpus reaches, read every way, changes nothing and
/// reads the same twice.
#[test]
fn reads_are_idempotent_and_change_nothing_in_every_reached_state() {
    let reads = [
        Action::StatusJson,
        Action::HostShow,
        Action::List(Scope::Repository),
        Action::List(Scope::Organization),
    ];
    let mut states = 0;
    for case in &corpus::corpus().cases {
        for entry in case.trace().entries {
            let state = entry.after().clone();
            for read in &reads {
                let first = ok(&state, read);
                assert!(first.deltas.is_empty());
                assert_eq!(first.next, state);
                assert_eq!(
                    first.requests,
                    Vec::<Request>::new(),
                    "a read never contacts GitHub"
                );
                assert_eq!(transition::apply(&first.next, read), first);
            }
            states += 1;
        }
    }
    assert!(states > 1_000);
}

// ---------------------------------------------------------------------------
// DoD 4: corrupted expectations are caught without production state
// ---------------------------------------------------------------------------

/// Every way the harness corrupts one delta's payload.
fn corruptions(delta: &Delta) -> Vec<Delta> {
    let mut out = Vec::new();
    match delta {
        Delta::CredentialStored => out.push(Delta::CredentialRemoved),
        Delta::CredentialRemoved => out.push(Delta::CredentialStored),
        Delta::HostMaterialized => out.push(Delta::HostCapacity { from: 1, to: 2 }),
        Delta::HostCapacity { from, to } => {
            out.push(Delta::HostCapacity {
                from: *from,
                to: to.wrapping_add(1).max(1),
            });
            out.push(Delta::HostCapacity {
                from: *to,
                to: *from,
            });
        }
        Delta::HostRunnerRoot { from, to } => {
            out.push(Delta::HostRunnerRoot {
                from: *from,
                to: if *to == Some(P::RootsDir) {
                    Some(P::Beta)
                } else {
                    Some(P::RootsDir)
                },
            });
            out.push(Delta::HostRunnerRoot {
                from: *to,
                to: *from,
            });
        }
        Delta::DirectoryCreated(path) => {
            out.push(Delta::DirectoryCreated(if *path == P::Beta {
                P::Alpha
            } else {
                P::Beta
            }));
        }
        Delta::PolicyAdded { key, policy } => {
            let mut other = policy.clone();
            other.enabled = !other.enabled;
            out.push(Delta::PolicyAdded {
                key: key.clone(),
                policy: other,
            });
            let mut renamed = policy.clone();
            renamed.host_label.push('x');
            out.push(Delta::PolicyAdded {
                key: key.clone(),
                policy: renamed,
            });
        }
        Delta::PolicyRemoved { key, policy } => {
            let mut other = policy.clone();
            other.attempts.cleaned += 1;
            out.push(Delta::PolicyRemoved {
                key: key.clone(),
                policy: other,
            });
        }
        Delta::PolicyMaxCapacity { key, from, to } => out.push(Delta::PolicyMaxCapacity {
            key: key.clone(),
            from: *from,
            to: if *to == u16::MAX { 1 } else { to + 1 },
        }),
        Delta::PolicyLabels {
            key,
            added,
            removed,
        } => {
            let mut more = added.clone();
            more.push("corrupted".to_string());
            out.push(Delta::PolicyLabels {
                key: key.clone(),
                added: more,
                removed: removed.clone(),
            });
            out.push(Delta::PolicyLabels {
                key: key.clone(),
                added: removed.clone(),
                removed: added.clone(),
            });
        }
        Delta::PolicyScale { key, from, to } => {
            out.push(Delta::PolicyScale {
                key: key.clone(),
                from: *from,
                to: (!to.0, to.1),
            });
            out.push(Delta::PolicyScale {
                key: key.clone(),
                from: *from,
                to: (
                    to.0,
                    if to.1 == PolicyState::Disabled {
                        PolicyState::Pending
                    } else {
                        PolicyState::Disabled
                    },
                ),
            });
        }
        Delta::PolicyWorkspace { key, from, to } => out.push(Delta::PolicyWorkspace {
            key: key.clone(),
            from: *from,
            to: if *to == Some(P::Beta) {
                Some(P::Alpha)
            } else {
                Some(P::Beta)
            },
        }),
        Delta::AttemptsRetained { key, tally } => out.push(Delta::AttemptsRetained {
            key: key.clone(),
            tally: tally.plus(Tally {
                active: 1,
                awaiting_cleanup: 0,
                cleaned: 0,
            }),
        }),
        Delta::PackageCachePurged => out.push(Delta::HostMaterialized),
    }
    out
}

#[test]
fn corrupting_any_expected_delta_fails_the_self_check() {
    let mut corrupted = 0;
    for case in &corpus::corpus().cases {
        for (before, action, transition) in every_run(case) {
            for index in 0..transition.deltas.len() {
                let mut dropped = transition.clone();
                dropped.deltas.remove(index);
                assert!(
                    transition::check(&before, &action, &dropped).is_err(),
                    "{} {action:?}: dropping {:?} went unnoticed",
                    case.id,
                    transition.deltas[index]
                );
                let mut doubled = transition.clone();
                doubled
                    .deltas
                    .insert(index, transition.deltas[index].clone());
                assert!(transition::check(&before, &action, &doubled).is_err());
                for replacement in corruptions(&transition.deltas[index]) {
                    let mut altered = transition.clone();
                    altered.deltas[index] = replacement.clone();
                    assert!(
                        transition::check(&before, &action, &altered).is_err(),
                        "{} {action:?}: replacing {:?} with {replacement:?} went unnoticed",
                        case.id,
                        transition.deltas[index]
                    );
                    corrupted += 1;
                }
            }
            // A change smuggled into a transition that declared none.
            if transition.deltas.is_empty() {
                let mut smuggled = transition.clone();
                smuggled.deltas.push(Delta::PackageCachePurged);
                assert!(transition::check(&before, &action, &smuggled).is_err());
            }
        }
    }
    assert!(
        corrupted > 500,
        "the corruption sweep must actually run: {corrupted}"
    );
}

/// Every way the harness corrupts an expected next state.
fn corrupt_state(model: &Model) -> Vec<(&'static str, Model)> {
    let mut out = Vec::new();
    let mut flipped = model.clone();
    flipped.credential = !flipped.credential;
    out.push(("credential", flipped));
    let mut host = model.clone();
    match &mut host.host {
        Some(record) => record.capacity = record.capacity.wrapping_add(1).max(1),
        None => {
            host.host = Some(cli_chains::model::HostModel {
                capacity: 1,
                runner_root: None,
            });
        }
    }
    out.push(("host", host));
    let mut directory = model.clone();
    if !directory.directories.insert(P::Beta) {
        directory.directories.remove(&P::Beta);
    }
    out.push(("directory", directory));
    let mut cache = model.clone();
    cache.package_cache = !cache.package_cache;
    out.push(("package cache", cache));
    let mut retained = model.clone();
    let entry = retained.retained.entry(key(repo(R::Outside))).or_default();
    entry.cleaned += 1;
    out.push(("retained diagnostics", retained));
    if let Some((first_key, _)) = model.policies.iter().next() {
        let mut enabled = model.clone();
        let policy = enabled.policies.get_mut(first_key).unwrap();
        policy.enabled = !policy.enabled;
        out.push(("policy enabled", enabled));
        let mut capacity = model.clone();
        let policy = capacity.policies.get_mut(first_key).unwrap();
        policy.mode = match &policy.mode {
            Mode::MonitorOnly => Mode::Autoscale {
                max_capacity: 3,
                extra_labels: BTreeSet::new(),
            },
            Mode::Autoscale {
                max_capacity,
                extra_labels,
            } => Mode::Autoscale {
                max_capacity: max_capacity.wrapping_add(1).max(1),
                extra_labels: extra_labels.clone(),
            },
        };
        out.push(("policy capacity", capacity));
        let mut attempts = model.clone();
        attempts
            .policies
            .get_mut(first_key)
            .unwrap()
            .attempts
            .active += 1;
        out.push(("policy attempts", attempts));
        let mut gone = model.clone();
        gone.policies.remove(first_key);
        out.push(("policy removed", gone));
    } else {
        let mut extra = model.clone();
        extra.policies.insert(
            key(repo(R::Widgets)),
            cli_chains::model::Policy {
                display: "acme/widgets".to_string(),
                host_label: "home".to_string(),
                mode: Mode::MonitorOnly,
                enabled: false,
                state: PolicyState::Pending,
                workspace: None,
                attempts: Tally::default(),
            },
        );
        out.push(("policy added", extra));
    }
    out
}

#[test]
fn corrupting_the_expected_next_state_fails_the_self_check() {
    let mut corrupted = 0;
    for case in &corpus::corpus().cases {
        for (before, action, transition) in every_run(case) {
            for (what, next) in corrupt_state(&transition.next) {
                let mut altered = transition.clone();
                altered.next = next;
                assert!(
                    transition::check(&before, &action, &altered).is_err(),
                    "{} {action:?}: corrupting the expected {what} went unnoticed",
                    case.id
                );
                corrupted += 1;
            }
        }
    }
    assert!(
        corrupted > 5_000,
        "the corruption sweep must actually run: {corrupted}"
    );
}

#[test]
fn corrupting_the_exit_class_or_request_history_fails_the_self_check() {
    for case in corpus::corpus().cases.iter().take(80) {
        for (before, action, transition) in every_run(case) {
            let mut exit = transition.clone();
            exit.exit = match transition.exit {
                Exit::Success => Exit::Refused(Failure::Conflict),
                Exit::Refused(_) => Exit::Success,
            };
            assert!(transition::check(&before, &action, &exit).is_err());
            let mut reason = transition.clone();
            if let Some(Reason::DuplicateTarget) = transition.reason {
                reason.reason = Some(Reason::MissingPolicy);
            } else if transition.reason.is_some() {
                reason.reason = Some(Reason::DuplicateTarget);
            }
            if reason.reason != transition.reason
                && reason.reason.map(Reason::failure) != transition.reason.map(Reason::failure)
            {
                assert!(transition::check(&before, &action, &reason).is_err());
            }
            let mut write = transition.clone();
            write.requests.push(Request::DeviceCode);
            assert!(
                transition::check(&before, &action, &write).is_err(),
                "{} {action:?}: an unexpected GitHub write went unnoticed",
                case.id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// DoD 3: pure transitions, pinned by hand
// ---------------------------------------------------------------------------

#[test]
fn the_success_path_changes_only_what_each_command_owns() {
    let widgets = repo(R::Widgets);
    let start = signed_in(Installation::Standard);

    let added = ok(&start, &auto(widgets));
    assert!(added.stdout.contains(
        &"Added repo policy for acme/widgets in pending; scaling is disabled.".to_string()
    ));
    assert_eq!(
        added.requests,
        vec![
            Request::ListInstallations,
            Request::ListRepositories(101),
            Request::ListRepositories(202)
        ],
        "add discovers read-only, once per installation"
    );
    let policy = &added.next.policies[&key(widgets)];
    assert_eq!(policy.state, PolicyState::Pending);
    assert!(!policy.enabled, "add never arms (D20)");
    assert_eq!(
        policy.routing_labels().unwrap(),
        vec![derived_symbol("home"), "gpu".to_string()]
    );
    assert_eq!(
        added.next.host.unwrap().capacity,
        1,
        "the first add creates the host at the default"
    );
    assert_eq!(
        added.deltas.len(),
        2,
        "host record and policy: {:?}",
        added.deltas
    );

    let armed = ok(
        &added.next,
        &Action::SetScale {
            target: widgets,
            enabled: true,
        },
    );
    assert_eq!(
        armed.deltas,
        vec![Delta::PolicyScale {
            key: key(widgets),
            from: (false, PolicyState::Pending),
            to: (true, PolicyState::Active),
        }]
    );
    let raised = ok(
        &armed.next,
        &Action::SetCapacity {
            target: widgets,
            max_capacity: Capacity::Five,
        },
    );
    assert!(
        raised
            .stdout
            .contains(&"acme/widgets max capacity is now 5; scaling remains enabled.".to_string())
    );
    let labelled = ok(
        &raised.next,
        &Action::AddLabel {
            target: widgets,
            labels: Labels::of(&[L::SelfHosted]),
        },
    );
    let disabled = ok(
        &labelled.next,
        &Action::SetScale {
            target: widgets,
            enabled: false,
        },
    );
    let final_policy = &disabled.next.policies[&key(widgets)];
    assert_eq!(
        (final_policy.enabled, final_policy.state),
        (false, PolicyState::Disabled)
    );
    assert_eq!(final_policy.max_capacity(), Some(5));
    assert_eq!(
        final_policy.routing_labels().unwrap(),
        vec![
            derived_symbol("home"),
            "gpu".to_string(),
            "self-hosted".to_string()
        ]
    );
    let removed = ok(
        &disabled.next,
        &Action::Remove {
            target: widgets,
            purge: false,
        },
    );
    assert!(removed.next.policies.is_empty());
    assert!(
        removed.next.retained.is_empty(),
        "nothing was journaled, so nothing is retained"
    );
    assert_eq!(
        removed.next.host, added.next.host,
        "removal leaves the host record"
    );
}

#[test]
fn a_refused_mutation_is_atomic_even_after_partial_in_memory_work() {
    let widgets = repo(R::Widgets);
    let start = after(
        signed_in(Installation::Standard),
        &[add(
            widgets,
            H::Home,
            Some(Capacity::Two),
            &[L::Gpu, L::LargeDisk],
            false,
        )],
    );
    // `gpu` is removed in memory before the derived label is refused; nothing
    // may be written.
    let result = refused(
        &start,
        &Action::RemoveLabel {
            target: widgets,
            labels: Labels::of(&[L::Gpu, L::Derived(H::Home)]),
        },
        Reason::DerivedLabelNotRemovable,
    );
    assert_eq!(result.next, start);
    assert!(result.deltas.is_empty());
    assert!(
        result
            .tags
            .contains(&"invariant:multi-label-refusal-is-atomic".to_string())
    );
    let upper = refused(
        &start,
        &Action::RemoveLabel {
            target: widgets,
            labels: Labels::of(&[L::DerivedCase(H::Home)]),
        },
        Reason::DerivedLabelNotRemovable,
    );
    assert_eq!(
        upper.next, start,
        "the derived label folds case, so its upper-case spelling is refused too"
    );

    // A refused add stores nothing and touches no host record.
    let fresh = Model::fresh(Installation::Standard);
    let unauthenticated = refused(&fresh, &auto(widgets), Reason::NotAuthenticated);
    assert!(
        unauthenticated.requests.is_empty(),
        "no credential, no request"
    );
    assert_eq!(unauthenticated.next, fresh);
}

#[test]
fn capacity_boundaries() {
    let fresh = Model::fresh(Installation::Standard);
    let zero = refused(
        &fresh,
        &Action::HostSetCapacity(Capacity::Zero),
        Reason::ZeroHostCapacity,
    );
    assert_eq!(
        zero.next.host, None,
        "a zero is refused before the host record is created"
    );
    let one = ok(&fresh, &Action::HostSetCapacity(Capacity::One));
    assert_eq!(
        one.deltas,
        vec![Delta::HostMaterialized],
        "1 is the default: only the record appears"
    );
    assert!(one.stdout.contains(&"host_capacity: 1 -> 1".to_string()));
    let max = ok(&one.next, &Action::HostSetCapacity(Capacity::Max));
    assert_eq!(max.next.host_capacity(), u16::MAX);
    assert!(
        max.stdout
            .contains(&format!("host_capacity: 1 -> {}", u16::MAX))
    );

    let widgets = repo(R::Widgets);
    let with_policy = after(signed_in(Installation::Standard), &[monitor(widgets)]);
    refused(
        &with_policy,
        &Action::SetCapacity {
            target: widgets,
            max_capacity: Capacity::Zero,
        },
        Reason::ZeroMaxCapacity,
    );
    let missing = refused(
        &with_policy,
        &Action::SetCapacity {
            target: repo(R::Gadgets),
            max_capacity: Capacity::Zero,
        },
        Reason::MissingPolicy,
    );
    assert!(
        missing
            .stderr
            .contains(&"no policy for acme/gadgets exists".to_string())
    );
    let promoted = ok(
        &with_policy,
        &Action::SetCapacity {
            target: widgets,
            max_capacity: Capacity::Max,
        },
    );
    assert_eq!(
        promoted.deltas,
        vec![Delta::PolicyMaxCapacity {
            key: key(widgets),
            from: None,
            to: u16::MAX
        }]
    );
    assert_eq!(
        promoted.next.policies[&key(widgets)]
            .routing_labels()
            .unwrap(),
        vec![derived_symbol("home")],
        "promotion derives the label from the retained host label and adds nothing else"
    );
    refused(
        &signed_in(Installation::Standard),
        &add(widgets, H::Home, Some(Capacity::Zero), &[], false),
        Reason::ZeroMaxCapacity,
    );

    // Host capacity below what is already in use is accepted with a warning.
    let busy = seeded(
        &after(
            signed_in(Installation::Standard),
            &[auto(widgets), auto(org(O::Acme))],
        ),
        Seed::Attempt {
            target: widgets,
            kind: AttemptKind::Active,
        },
    );
    let busy = seeded(
        &busy,
        Seed::Attempt {
            target: org(O::Acme),
            kind: AttemptKind::Active,
        },
    );
    let lowered = ok(&busy, &Action::HostSetCapacity(Capacity::One));
    assert!(
        lowered
            .stdout
            .contains(&"Nothing was terminated".to_string())
    );
    assert_eq!(lowered.next.status().in_use, 2);
    assert_eq!(lowered.next.status().headroom, 0);
}

#[test]
fn the_rest_budget_admits_ten_repositories_and_counts_organizations() {
    let mut model = signed_in(Installation::Wide);
    let mut repositories = vec![R::Widgets, R::Gadgets];
    repositories.extend((1..=9).map(R::Fleet));
    for (index, name) in repositories.iter().enumerate() {
        let result = transition::apply(&model, &monitor(repo(*name)));
        if index < 10 {
            assert!(
                result.exit.is_success(),
                "repository {} of 10 fits",
                index + 1
            );
            model = result.next;
        } else {
            assert_eq!(
                result.reason,
                Some(Reason::BudgetExceeded),
                "the eleventh does not"
            );
            assert_eq!(result.next, model);
        }
    }
    assert_eq!(model.admitted_cost(), 2_400);

    let wide = signed_in(Installation::Wide);
    let organization = ok(&wide, &monitor(org(O::Acme)));
    assert_eq!(
        organization.next.admitted_cost(),
        2_400,
        "1 + 13 * 3 requests, 60 times an hour"
    );
    refused(
        &organization.next,
        &monitor(repo(R::Widgets)),
        Reason::BudgetExceeded,
    );
    let repository = ok(&wide, &monitor(repo(R::Widgets)));
    let refusal = refused(
        &repository.next,
        &monitor(org(O::Acme)),
        Reason::BudgetExceeded,
    );
    assert!(
        refusal
            .tags
            .contains(&"cross:budget-counts-the-other-scope".to_string())
    );

    // The status projection prices every policy at the measured floor.
    let standard = after(
        signed_in(Installation::Standard),
        &[auto(repo(R::Widgets)), auto(org(O::Acme))],
    );
    let projection = standard.status();
    assert_eq!(projection.projected_requests_per_hour, 720);
    assert!(projection.projection_is_floor);
}

#[test]
fn label_rules() {
    let widgets = repo(R::Widgets);
    let start = after(signed_in(Installation::Standard), &[auto(widgets)]);
    let folded = ok(
        &start,
        &Action::AddLabel {
            target: widgets,
            labels: Labels::of(&[L::GpuCase]),
        },
    );
    assert!(folded.deltas.is_empty(), "GPU is gpu");
    assert!(
        folded
            .stdout
            .contains(&"No label changed; acme/widgets already had them that way.".to_string())
    );
    let derived = ok(
        &start,
        &Action::AddLabel {
            target: widgets,
            labels: Labels::of(&[L::Derived(H::Home)]),
        },
    );
    assert!(
        derived.deltas.is_empty(),
        "the derived label is already the host label"
    );
    let several = ok(
        &start,
        &Action::AddLabel {
            target: widgets,
            labels: Labels::of(&[L::SelfHosted, L::LargeDisk, L::SelfHosted]),
        },
    );
    assert_eq!(
        several.deltas,
        vec![Delta::PolicyLabels {
            key: key(widgets),
            added: vec!["self-hosted".to_string(), "large-disk".to_string()],
            removed: vec![],
        }]
    );
    assert_eq!(
        several.next.policies[&key(widgets)]
            .routing_labels()
            .unwrap(),
        vec![
            derived_symbol("home"),
            "gpu".to_string(),
            "large-disk".to_string(),
            "self-hosted".to_string()
        ],
        "host label first, then the optional labels in order"
    );
    let longest = ok(
        &start,
        &Action::AddLabel {
            target: widgets,
            labels: Labels::of(&[L::Max256]),
        },
    );
    assert!(
        longest.next.policies[&key(widgets)]
            .routing_labels()
            .unwrap()
            .contains(&"l".repeat(256))
    );
    for invalid in [L::TooLong257, L::Comma, L::Blank] {
        refused(
            &start,
            &Action::AddLabel {
                target: widgets,
                labels: Labels::of(&[invalid]),
            },
            Reason::InvalidLabel,
        );
        refused(
            &signed_in(Installation::Standard),
            &add(widgets, H::Home, Some(Capacity::Two), &[invalid], false),
            Reason::InvalidLabel,
        );
    }
    let absent = ok(
        &start,
        &Action::RemoveLabel {
            target: widgets,
            labels: Labels::of(&[L::LargeDisk]),
        },
    );
    assert!(
        absent.deltas.is_empty(),
        "removing an absent label is a no-op, not an error"
    );

    let watched = after(signed_in(Installation::Standard), &[monitor(widgets)]);
    refused(
        &watched,
        &Action::AddLabel {
            target: widgets,
            labels: Labels::of(&[L::Gpu]),
        },
        Reason::LabelsOnMonitorOnly,
    );
    refused(
        &signed_in(Installation::Standard),
        &add(widgets, H::Home, None, &[L::Gpu], false),
        Reason::LabelsNeedAutoscale,
    );

    // Host labels: 64 bytes accepted, 65 refused, case folded.
    let long = ok(
        &signed_in(Installation::Standard),
        &add(widgets, H::Max64, Some(Capacity::Two), &[], false),
    );
    assert_eq!(long.next.policies[&key(widgets)].host_label.len(), 64);
    for invalid in [H::TooLong65, H::Space, H::TrailingDash] {
        refused(
            &signed_in(Installation::Standard),
            &add(widgets, invalid, Some(Capacity::Two), &[], false),
            Reason::InvalidHostLabel,
        );
    }
    let cased = ok(
        &signed_in(Installation::Standard),
        &add(
            widgets,
            H::HomeCase,
            Some(Capacity::Two),
            &[L::Derived(H::Home)],
            false,
        ),
    );
    assert_eq!(
        cased.next.policies[&key(widgets)].routing_labels().unwrap(),
        vec![derived_symbol("home")],
        "Home folds to home, and --label with the derived label adds nothing"
    );
}

#[test]
fn workspace_guards() {
    let widgets = repo(R::Widgets);
    let gadgets = repo(R::Gadgets);
    let start = after(
        signed_in(Installation::Standard),
        &[auto(widgets), auto(gadgets)],
    );
    let persistent = |name: R, path: P| Action::SetWorkspace {
        repo: name,
        setting: WorkspaceSetting::Persistent(path),
    };

    refused(
        &start,
        &persistent(R::Widgets, P::Relative),
        Reason::RelativePath,
    );
    refused(
        &start,
        &persistent(R::Widgets, P::InsideAppState),
        Reason::OverlapsApplicationData,
    );
    refused(
        &start,
        &persistent(R::Widgets, P::OccupiedFile),
        Reason::ExistingFile,
    );
    refused(
        &start,
        &persistent(R::Widgets, P::DeepMissing),
        Reason::MissingParents,
    );
    refused(
        &start,
        &persistent(R::Widgets, P::AlphaInner),
        Reason::MissingParents,
    );
    refused(
        &start,
        &Action::SetWorkspace {
            repo: R::Widgets,
            setting: WorkspaceSetting::EphemeralWithPath(P::Alpha),
        },
        Reason::EphemeralRejectsPath,
    );

    let alpha = ok(&start, &persistent(R::Widgets, P::Alpha));
    assert_eq!(
        alpha.deltas[0],
        Delta::DirectoryCreated(P::Alpha),
        "the leaf is created only after every check"
    );
    let same = refused(
        &alpha.next,
        &persistent(R::Gadgets, P::Alpha),
        Reason::OverlapsRepositoryRoot,
    );
    assert!(
        same.stderr
            .contains(&"the persistent workspace root for acme/widgets".to_string())
    );
    refused(
        &alpha.next,
        &persistent(R::Gadgets, P::AlphaInner),
        Reason::OverlapsRepositoryRoot,
    );
    refused(
        &alpha.next,
        &persistent(R::Gadgets, P::RootsDir),
        Reason::OverlapsRepositoryRoot,
    );
    refused(
        &alpha.next,
        &Action::HostSetRuntimeRoot(P::RootsDir),
        Reason::OverlapsRepositoryRoot,
    );
    let resaved = ok(&alpha.next, &persistent(R::Widgets, P::Alpha));
    assert!(
        resaved.deltas.is_empty(),
        "a repository does not overlap its own root"
    );
    let nested = ok(&alpha.next, &persistent(R::Widgets, P::AlphaInner));
    assert_eq!(
        nested.deltas.len(),
        2,
        "creates alpha/inner and moves the root: {:?}",
        nested.deltas
    );

    let host_root = ok(&start, &Action::HostSetRuntimeRoot(P::RootsDir));
    assert_eq!(
        host_root.deltas.len(),
        1,
        "<roots> exists, so nothing is created: {:?}",
        host_root.deltas
    );
    let inside = refused(
        &host_root.next,
        &persistent(R::Widgets, P::Alpha),
        Reason::OverlapsHostRoot,
    );
    assert!(inside.stderr.contains(&"the host runner root".to_string()));

    // Uncleaned attempts guard both settings; cleaned ones do not.
    let blocked = seeded(
        &start,
        Seed::Attempt {
            target: widgets,
            kind: AttemptKind::AwaitingCleanup,
        },
    );
    let refusal = refused(
        &blocked,
        &persistent(R::Widgets, P::Alpha),
        Reason::AttemptsOwnWorkspace,
    );
    assert!(
        refusal
            .stderr
            .contains(&"0 active and 1 awaiting cleanup".to_string())
    );
    ok(&blocked, &persistent(R::Gadgets, P::Alpha));
    refused(
        &blocked,
        &Action::HostSetRuntimeRoot(P::Beta),
        Reason::AttemptsOwnHostRoot,
    );
    let history = seeded(
        &start,
        Seed::Attempt {
            target: widgets,
            kind: AttemptKind::Cleaned,
        },
    );
    ok(&history, &persistent(R::Widgets, P::Alpha));
    ok(&history, &Action::HostSetRuntimeRoot(P::Beta));

    // Organizations have no set-workspace leaf, and a persistent root on one is
    // a shape the model rejects outright.
    let mut corrupt = after(signed_in(Installation::Standard), &[auto(org(O::Acme))]);
    corrupt.directories.insert(P::Alpha);
    corrupt
        .policies
        .get_mut(&key(org(O::Acme)))
        .unwrap()
        .workspace = Some(P::Alpha);
    assert!(corrupt.validate().is_err());
}

#[test]
fn repository_and_organization_policies_coexist_without_overwriting() {
    let widgets = repo(R::Widgets);
    let acme = org(O::Acme);
    let both = after(signed_in(Installation::Standard), &[auto(widgets)]);
    let coexisting = ok(
        &both,
        &add(
            acme,
            H::Office,
            Some(Capacity::Five),
            &[L::SelfHosted],
            true,
        ),
    );
    assert!(
        coexisting
            .tags
            .contains(&"cross:repository-and-organization-policies-coexist".to_string())
    );
    let model = coexisting.next;
    assert_eq!(model.policies.len(), 2);
    assert_eq!(
        model.policies[&key(widgets)],
        both.policies[&key(widgets)],
        "the org add left the repo policy alone"
    );

    let changed = after(
        model.clone(),
        &[
            Action::SetCapacity {
                target: acme,
                max_capacity: Capacity::One,
            },
            Action::AddLabel {
                target: acme,
                labels: Labels::of(&[L::LargeDisk]),
            },
            Action::SetScale {
                target: acme,
                enabled: false,
            },
        ],
    );
    assert_eq!(
        changed.policies[&key(widgets)],
        model.policies[&key(widgets)]
    );
    let removed = ok(
        &changed,
        &Action::Remove {
            target: acme,
            purge: true,
        },
    );
    assert!(
        removed
            .tags
            .contains(&"cross:removal-leaves-the-other-scope-policy".to_string())
    );
    assert_eq!(
        removed.next.policies.keys().collect::<Vec<_>>(),
        vec![&key(widgets)]
    );
    assert_eq!(
        removed.next.list_lines(Scope::Repository),
        vec![
            "acme/widgets\tautoscale\tpending\tenabled=false\tmax=2\tworkspace=ephemeral"
                .to_string()
        ]
    );

    // Case-variant spellings address the same target and keep the typed display.
    let cased = after(
        signed_in(Installation::Standard),
        &[auto(repo(R::WidgetsCase))],
    );
    let duplicate = refused(&cased, &auto(widgets), Reason::DuplicateTarget);
    assert!(
        duplicate
            .stderr
            .contains(&"a policy for acme/widgets already exists".to_string())
    );
    assert_eq!(cased.status().policies[0].target, "Acme/Widgets");
    let armed = refused(
        &cased,
        &add(
            repo(R::WidgetsCase),
            H::Office,
            Some(Capacity::Five),
            &[],
            true,
        ),
        Reason::DuplicateTarget,
    );
    assert_eq!(
        armed.next, cased,
        "a duplicate add neither replaces nor arms"
    );
}

/// `set-scale` over every state a local policy can be in.
#[test]
fn set_scale_state_table() {
    let widgets = repo(R::Widgets);
    let pending = after(signed_in(Installation::Standard), &[auto(widgets)]);
    let active = after(
        pending.clone(),
        &[Action::SetScale {
            target: widgets,
            enabled: true,
        }],
    );
    let disabled = after(
        active.clone(),
        &[Action::SetScale {
            target: widgets,
            enabled: false,
        }],
    );
    let draining = seeded(&active, Seed::Drain(widgets));
    let repair = seeded(&pending, Seed::RepairRequired(widgets));
    let watched = after(signed_in(Installation::Standard), &[monitor(widgets)]);
    let state = |model: &Model| {
        let policy = &model.policies[&key(widgets)];
        (policy.enabled, policy.state)
    };
    let enable = Action::SetScale {
        target: widgets,
        enabled: true,
    };
    let disable = Action::SetScale {
        target: widgets,
        enabled: false,
    };

    assert_eq!(
        state(&ok(&pending, &enable).next),
        (true, PolicyState::Active)
    );
    assert_eq!(
        state(&ok(&active, &enable).next),
        (true, PolicyState::Active)
    );
    assert_eq!(
        state(&ok(&disabled, &enable).next),
        (true, PolicyState::Active)
    );
    refused(&draining, &enable, Reason::IllegalStateTransition);
    refused(&repair, &enable, Reason::IllegalStateTransition);
    refused(&watched, &enable, Reason::EnableMonitorOnly);

    assert_eq!(
        state(&ok(&pending, &disable).next),
        (false, PolicyState::Pending)
    );
    assert_eq!(
        state(&ok(&active, &disable).next),
        (false, PolicyState::Disabled)
    );
    assert_eq!(
        state(&ok(&disabled, &disable).next),
        (false, PolicyState::Disabled)
    );
    assert_eq!(
        state(&ok(&draining, &disable).next),
        (false, PolicyState::Disabled)
    );
    assert_eq!(
        state(&ok(&repair, &disable).next),
        (false, PolicyState::RepairRequired)
    );
    assert_eq!(
        state(&ok(&watched, &disable).next),
        (false, PolicyState::Pending)
    );

    let busy = seeded(
        &active,
        Seed::Attempt {
            target: widgets,
            kind: AttemptKind::Active,
        },
    );
    let unconfirmed = refused(&busy, &disable, Reason::DisableNeedsConfirmation);
    assert!(unconfirmed.stdout.contains(&"Continue? [y/N]".to_string()));
    assert_eq!(state(&ok(&busy, &enable).next), (true, PolicyState::Active));
    refused(
        &signed_in(Installation::Standard),
        &enable,
        Reason::MissingPolicy,
    );
}

#[test]
fn removal_retains_or_purges_diagnostics_and_the_shared_cache() {
    let widgets = repo(R::Widgets);
    let acme = org(O::Acme);
    let start = after(
        signed_in(Installation::Standard),
        &[auto(widgets), auto(acme)],
    );
    let start = seeded(&start, Seed::PackageCache);
    let start = seeded(
        &start,
        Seed::Attempt {
            target: widgets,
            kind: AttemptKind::Cleaned,
        },
    );
    let start = seeded(
        &start,
        Seed::Attempt {
            target: widgets,
            kind: AttemptKind::Active,
        },
    );

    refused(
        &start,
        &Action::Remove {
            target: widgets,
            purge: true,
        },
        Reason::PurgeWithActiveAttempts,
    );
    let kept = ok(
        &start,
        &Action::Remove {
            target: widgets,
            purge: false,
        },
    );
    assert_eq!(
        kept.next.retained[&key(widgets)],
        Tally {
            active: 1,
            awaiting_cleanup: 0,
            cleaned: 1
        },
        "non-purge removal keeps every attempt as diagnostics"
    );
    assert_eq!(
        kept.next.in_use(),
        1,
        "a retained active attempt still counts host-wide"
    );
    refused(
        &kept.next,
        &Action::HostResetRuntimeRoot,
        Reason::AttemptsOwnHostRoot,
    );
    let readded = ok(&kept.next, &auto(widgets));
    assert!(
        readded
            .tags
            .contains(&"invariant:re-added-target-starts-fresh".to_string())
    );
    assert_eq!(
        readded.next.policies[&key(widgets)].attempts,
        Tally::default()
    );

    let quiet = seeded(
        &after(
            signed_in(Installation::Standard),
            &[auto(widgets), auto(acme)],
        ),
        Seed::PackageCache,
    );
    let first = ok(
        &quiet,
        &Action::Remove {
            target: widgets,
            purge: true,
        },
    );
    assert!(
        first.next.package_cache,
        "another policy still uses the cache"
    );
    assert!(
        first
            .stdout
            .contains(&"preserved because another policy still uses it".to_string())
    );
    let last = ok(
        &first.next,
        &Action::Remove {
            target: acme,
            purge: true,
        },
    );
    assert!(!last.next.package_cache, "the last purge purges the cache");
    assert!(last.deltas.contains(&Delta::PackageCachePurged));
}

#[test]
fn documented_deviations_are_predicted_faithfully() {
    // 1. A refused root change on a fresh data root still creates the host.
    let fresh = Model::fresh(Installation::Standard);
    let refusal = refused(
        &fresh,
        &Action::HostSetRuntimeRoot(P::DeepMissing),
        Reason::MissingParents,
    );
    assert_eq!(
        refusal.deviation,
        Some(Deviation::HostMaterializedByRefusal)
    );
    assert_eq!(refusal.deltas, vec![Delta::HostMaterialized]);
    let relative = refused(
        &fresh,
        &Action::HostSetRuntimeRoot(P::Relative),
        Reason::RelativePath,
    );
    assert_eq!(
        relative.deviation, None,
        "a relative path is refused before the host is touched"
    );

    // 2. `add --enable` without a capacity stores, then refuses.
    let partial = refused(
        &signed_in(Installation::Standard),
        &add(repo(R::Widgets), H::Home, None, &[], true),
        Reason::EnableMonitorOnly,
    );
    assert_eq!(partial.deviation, Some(Deviation::PartialCommitOnEnable));
    assert_eq!(
        partial.next.policies[&key(repo(R::Widgets))].state,
        PolicyState::Pending
    );

    // 3. A case-variant spelling does not recognise its own persistent root.
    let persistent_root = after(
        signed_in(Installation::Standard),
        &[
            auto(repo(R::Widgets)),
            Action::SetWorkspace {
                repo: R::Widgets,
                setting: WorkspaceSetting::Persistent(P::Alpha),
            },
        ],
    );
    let owner = refused(
        &persistent_root,
        &Action::SetWorkspace {
            repo: R::WidgetsCase,
            setting: WorkspaceSetting::Persistent(P::Alpha),
        },
        Reason::OverlapsRepositoryRoot,
    );
    assert_eq!(
        owner.deviation,
        Some(Deviation::OwnerComparedCaseSensitively)
    );
    assert_eq!(owner.next, persistent_root);
}

#[test]
fn sign_in_discovery_is_read_only_and_bounded() {
    let fresh = Model::fresh(Installation::Standard);
    let login = ok(&fresh, &Action::AuthLogin);
    assert_eq!(
        login
            .requests
            .iter()
            .map(|request| request.render())
            .collect::<Vec<_>>(),
        vec![
            "POST /login/device/code",
            "POST /login/oauth/access_token",
            "GET /user/installations",
            "GET /user/installations/101/repositories",
            "GET /user/installations/202/repositories",
        ]
    );
    let resumed = ok(&login.next, &Action::AuthLogin);
    assert!(
        resumed.requests.iter().all(|request| request.is_read()),
        "a resumed sign-in asks for no new code"
    );
    assert!(resumed.deltas.is_empty());
    let logout = ok(&resumed.next, &Action::AuthLogout);
    assert!(logout.requests.is_empty());
    assert!(!logout.next.credential);
    let none = signed_in(Installation::None);
    let not_installed = refused(&none, &auto(repo(R::Widgets)), Reason::AppNotInstalled);
    assert_eq!(not_installed.requests, vec![Request::ListInstallations]);
    let elsewhere = refused(
        &signed_in(Installation::Standard),
        &auto(repo(R::Outside)),
        Reason::TargetNotInstalled,
    );
    assert_eq!(elsewhere.requests.len(), 3);
    assert!(
        elsewhere.next.host.is_none(),
        "an unreachable target is refused before the host record"
    );
}

#[test]
fn seeds_describe_only_reachable_states() {
    let widgets = repo(R::Widgets);
    let fresh = Model::fresh(Installation::Standard);
    assert!(
        transition::seed(
            &fresh,
            &Seed::Attempt {
                target: widgets,
                kind: AttemptKind::Active
            }
        )
        .is_err()
    );
    let pending = after(signed_in(Installation::Standard), &[auto(widgets)]);
    assert!(
        transition::seed(&pending, &Seed::Drain(widgets)).is_err(),
        "only an active policy drains"
    );
    let active = after(
        pending.clone(),
        &[Action::SetScale {
            target: widgets,
            enabled: true,
        }],
    );
    assert!(
        transition::seed(&active, &Seed::RepairRequired(widgets)).is_err(),
        "only a pending policy needs repair"
    );
    assert!(transition::seed(&signed_in(Installation::Standard), &Seed::Credential).is_err());
}

#[test]
fn argument_vectors_are_literal_and_symbolic_paths_resolve_through_the_runner() {
    struct Fixed;
    impl cli_chains::values::Resolver for Fixed {
        fn path(&self, value: P) -> String {
            format!(
                "/scenario{}",
                value.symbolic().trim_start_matches('<').replace('>', "")
            )
        }
        fn derived_label(&self, host_label: &str) -> String {
            format!("rm-{host_label}-linux-x64")
        }
    }
    let argv = add(
        repo(R::Widgets),
        H::Home,
        Some(Capacity::Max),
        &[L::Derived(H::Home), L::DerivedCase(H::Home)],
        true,
    )
    .argv(&Fixed);
    assert_eq!(
        argv,
        vec![
            "repo",
            "add",
            "acme/widgets",
            "--host-label=home",
            "--max-capacity=65535",
            "--label=rm-home-linux-x64",
            "--label=RM-HOME-LINUX-X64",
            "--enable",
        ]
    );
    let argv = Action::SetWorkspace {
        repo: R::Widgets,
        setting: WorkspaceSetting::Persistent(P::AlphaInner),
    }
    .argv(&Fixed);
    assert_eq!(argv.last().unwrap(), "--path=/scenarioroots/alpha/inner");
    assert_eq!(Action::StatusJson.argv(&Fixed), vec!["status", "--json"]);
    assert_eq!(
        Action::SetScale {
            target: org(O::AcmeCase),
            enabled: false
        }
        .argv(&Fixed),
        vec!["org", "set-scale", "ACME", "--enabled=false"]
    );
}

#[test]
fn the_status_projection_follows_the_model() {
    let widgets = repo(R::Widgets);
    let model = after(
        signed_in(Installation::Standard),
        &[
            auto(widgets),
            Action::HostSetRuntimeRoot(P::Beta),
            Action::SetWorkspace {
                repo: R::Widgets,
                setting: WorkspaceSetting::Persistent(P::Alpha),
            },
            auto(repo(R::Gadgets)),
        ],
    );
    let status = model.status();
    assert!(status.credential_present && status.host_configured);
    assert_eq!(status.runner_root_source, "configured");
    assert_eq!(status.configured_runner_root, Some(P::Beta));
    let sources: BTreeMap<String, &str> = status
        .policies
        .iter()
        .map(|policy| (policy.target.clone(), policy.workspace_root_source))
        .collect();
    assert_eq!(sources["acme/widgets"], "repository");
    assert_eq!(sources["acme/gadgets"], "configured");
    let reset = ok(&model, &Action::HostResetRuntimeRoot).next.status();
    assert_eq!(reset.runner_root_source, "platform_default");
    assert!(
        reset
            .policies
            .iter()
            .any(|policy| policy.workspace_root_source == "platform_default")
    );
}
