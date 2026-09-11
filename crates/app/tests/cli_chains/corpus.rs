// owner: b1-local-model-corpus
//
//! The deterministic local transition corpus.
//!
//! # How the corpus is built
//!
//! Four sources are offered to one retention rule, in a fixed order:
//!
//! 1. **Curated journeys** — named, hand-written chains for the invariants,
//!    cross-scope interactions and recovery paths `03-coverage-model.md`
//!    lists. Each declares the units it exists for, and generation fails if the
//!    model says the journey does not witness them.
//! 2. **Value probes** — one action per equivalence class, on the smallest
//!    initial state that reaches the value's own check.
//! 3. **Pair chains** — for every compatible mutating pair not yet witnessed,
//!    the smallest baseline on which the model admits both, extended while the
//!    next uncovered pair can follow on.
//! 4. **Readbacks** — a relevant read after each mutation not yet read back in
//!    a fresh process.
//!
//! Curated journeys written after the inventory was first pinned are offered
//! last, so they append cases rather than renumber the ones above.
//!
//! A candidate is kept only if it witnesses a unit no kept case did, and the
//! units it newly witnesses are recorded as its contribution. A candidate that
//! adds nothing is counted as rejected padding and dropped.
//!
//! # Determinism
//!
//! Every choice is a function of [`CORPUS_SEED`] and the fixed candidate
//! order: the seed rotates which equivalent value a pair chain uses, so the
//! corpus exercises more of each class than a fixed first choice would. The
//! generated corpus is pinned by `local_inventory.txt`; changing the seed, the
//! version, the model or a candidate list is a reviewed diff of that file.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use super::action::{
    Action, ActionKind, AddArgs, AttemptKind, Labels, Seed, Step, Target, WorkspaceSetting,
};
use super::coverage::{self, Entry, Trace};
use super::ids::{CaseId, fingerprint};
use super::model::{Installation, Model};
use super::transition;
use super::values::{
    Capacity, HostLabelValue, LabelValue, OrgName, PathValue, RepoName, Resolver, Scope, Symbolic,
};

/// Bumped whenever generation changes in a way that renumbers cases.
pub const CORPUS_VERSION: u32 = 1;

/// The one seed every generated choice derives from.
pub const CORPUS_SEED: u64 = 0x5EED_0C11_C4A1_0001;

/// The inventory must hold at least this many cases (`02-target-architecture.md`).
pub const MINIMUM_LOCAL_CASES: usize = 256;

/// Where a case came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    Curated,
    Value,
    Pair,
    Readback,
}

impl Origin {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Origin::Curated => "curated",
            Origin::Value => "value",
            Origin::Pair => "pair",
            Origin::Readback => "readback",
        }
    }
}

/// One retained case.
#[derive(Debug, Clone)]
pub struct Case {
    pub id: CaseId,
    pub name: String,
    pub origin: Origin,
    pub installation: Installation,
    /// Setup first, then the steps under test.
    pub steps: Vec<Step>,
    /// How many leading steps establish the named initial state.
    pub setup_len: usize,
    /// The units this case witnessed first, which is why it is kept.
    pub contributions: Vec<String>,
    pub fingerprint: u64,
}

impl Case {
    /// Runs the case through the model.
    ///
    /// # Panics
    /// If a seed's precondition fails, which generation already ruled out.
    #[must_use]
    pub fn trace(&self) -> Trace {
        coverage::simulate(self.installation, &self.steps)
            .unwrap_or_else(|problem| panic!("{} ({}): {problem}", self.id, self.name))
    }
}

/// The generated corpus.
#[derive(Debug, Clone)]
pub struct Corpus {
    pub cases: Vec<Case>,
    /// Candidates dropped because they witnessed nothing new.
    pub rejected: usize,
}

impl Corpus {
    /// The case with this identifier.
    #[must_use]
    pub fn case(&self, id: CaseId) -> Option<&Case> {
        self.cases.iter().find(|case| case.id == id)
    }
}

/// The corpus, generated once per test binary.
#[must_use]
pub fn corpus() -> &'static Corpus {
    static CORPUS: OnceLock<Corpus> = OnceLock::new();
    CORPUS.get_or_init(generate)
}

// ---------------------------------------------------------------------------
// Candidates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Candidate {
    name: String,
    origin: Origin,
    installation: Installation,
    setup: Vec<Step>,
    steps: Vec<Step>,
    /// Units a curated journey promises to witness.
    promises: Vec<&'static str>,
}

impl Candidate {
    fn all_steps(&self) -> Vec<Step> {
        let mut steps = self.setup.clone();
        steps.extend(self.steps.iter().cloned());
        steps
    }
}

fn run(action: Action) -> Step {
    Step::Run(action)
}

fn repo(name: RepoName) -> Target {
    Target::Repo(name)
}

fn org(name: OrgName) -> Target {
    Target::Org(name)
}

fn add(
    target: Target,
    host_label: HostLabelValue,
    max: Option<Capacity>,
    labels: &[LabelValue],
    enable: bool,
) -> Action {
    Action::Add(AddArgs {
        target,
        host_label,
        max_capacity: max,
        labels: labels.to_vec(),
        enable,
    })
}

/// The default autoscale policy every baseline uses.
fn auto(target: Target) -> Action {
    add(
        target,
        HostLabelValue::Home,
        Some(Capacity::Two),
        &[LabelValue::Gpu],
        false,
    )
}

fn monitor(target: Target) -> Action {
    add(target, HostLabelValue::Home, None, &[], false)
}

fn set_capacity(target: Target, capacity: Capacity) -> Action {
    Action::SetCapacity {
        target,
        max_capacity: capacity,
    }
}

fn set_scale(target: Target, enabled: bool) -> Action {
    Action::SetScale { target, enabled }
}

fn add_label(target: Target, labels: &[LabelValue]) -> Action {
    Action::AddLabel {
        target,
        labels: Labels::of(labels),
    }
}

fn remove_label(target: Target, labels: &[LabelValue]) -> Action {
    Action::RemoveLabel {
        target,
        labels: Labels::of(labels),
    }
}

fn workspace(repo_name: RepoName, setting: WorkspaceSetting) -> Action {
    Action::SetWorkspace {
        repo: repo_name,
        setting,
    }
}

fn persistent(repo_name: RepoName, path: PathValue) -> Action {
    workspace(repo_name, WorkspaceSetting::Persistent(path))
}

fn remove(target: Target, purge: bool) -> Action {
    Action::Remove { target, purge }
}

fn attempt(target: Target, kind: AttemptKind) -> Step {
    Step::Seed(Seed::Attempt { target, kind })
}

const CREDENTIAL: Step = Step::Seed(Seed::Credential);

fn status() -> Step {
    run(Action::StatusJson)
}

fn repo_list() -> Step {
    run(Action::List(Scope::Repository))
}

fn org_list() -> Step {
    run(Action::List(Scope::Organization))
}

fn host_show() -> Step {
    run(Action::HostShow)
}

use HostLabelValue as H;
use LabelValue as L;
use OrgName as O;
use PathValue as P;
use RepoName as R;

fn curated_case(
    name: &str,
    installation: Installation,
    setup: Vec<Step>,
    steps: Vec<Step>,
    promises: &[&'static str],
) -> Candidate {
    Candidate {
        name: name.to_string(),
        origin: Origin::Curated,
        installation,
        setup,
        steps,
        promises: promises.to_vec(),
    }
}

/// The hand-written journeys.
#[allow(
    clippy::too_many_lines,
    reason = "one list of named journeys reads best whole"
)]
fn curated() -> Vec<Candidate> {
    use Installation::{None as NoApp, Standard, Wide};
    let widgets = repo(R::Widgets);
    let gadgets = repo(R::Gadgets);
    let acme = org(O::Acme);
    vec![
        curated_case(
            "fresh-data-root-reads-are-idempotent",
            Standard,
            vec![],
            vec![
                status(),
                status(),
                host_show(),
                host_show(),
                repo_list(),
                org_list(),
            ],
            &[
                "invariant:idempotent-read:status.json",
                "invariant:idempotent-read:host.show",
            ],
        ),
        curated_case(
            "sign-in-then-resume-without-a-new-code",
            Standard,
            vec![],
            vec![run(Action::AuthLogin), run(Action::AuthLogin), status()],
            &[
                "invariant:login-resumes-without-a-new-code",
                "pair:auth.login>auth.login",
                "readback:auth.login>status.json",
            ],
        ),
        curated_case(
            "logout-leaves-policies-in-place",
            Standard,
            vec![CREDENTIAL, run(auto(widgets))],
            vec![
                run(Action::AuthLogout),
                repo_list(),
                status(),
                run(Action::AuthLogout),
            ],
            &[
                "invariant:logout-leaves-policies",
                "invariant:logout-without-a-credential-is-a-no-op",
            ],
        ),
        curated_case(
            "add-without-a-credential-is-refused-for-both-scopes",
            Standard,
            vec![],
            vec![run(auto(widgets)), run(auto(acme)), status()],
            &[
                "refusal:repo.add:not-authenticated",
                "refusal:org.add:not-authenticated",
            ],
        ),
        curated_case(
            "signed-in-but-app-not-installed",
            NoApp,
            vec![CREDENTIAL],
            vec![
                run(auto(widgets)),
                run(auto(acme)),
                run(Action::AuthLogin),
                status(),
            ],
            &[
                "refusal:repo.add:app-not-installed",
                "refusal:org.add:app-not-installed",
            ],
        ),
        curated_case(
            "targets-outside-every-installation",
            Standard,
            vec![CREDENTIAL],
            vec![
                run(auto(repo(R::Outside))),
                run(auto(org(O::Outside))),
                run(auto(repo(R::Fleet(1)))),
                status(),
            ],
            &[
                "refusal:repo.add:target-not-installed",
                "refusal:org.add:target-not-installed",
            ],
        ),
        curated_case(
            "duplicate-add-neither-replaces-nor-arms",
            Standard,
            vec![CREDENTIAL, run(auto(widgets)), run(auto(acme))],
            vec![
                run(add(
                    repo(R::WidgetsCase),
                    H::Office,
                    Some(Capacity::Five),
                    &[],
                    true,
                )),
                run(add(
                    org(O::AcmeCase),
                    H::Office,
                    Some(Capacity::Five),
                    &[],
                    true,
                )),
                repo_list(),
                org_list(),
            ],
            &[
                "invariant:duplicate-add-keeps-the-existing-policy",
                "refusal:repo.add:duplicate-target",
                "refusal:org.add:duplicate-target",
            ],
        ),
        curated_case(
            "repository-monitor-only-is-promoted-before-labels-or-arming",
            Standard,
            vec![CREDENTIAL, run(monitor(widgets))],
            vec![
                run(add(gadgets, H::Home, None, &[L::Gpu], false)),
                run(add_label(widgets, &[L::Gpu])),
                run(set_scale(widgets, true)),
                run(set_capacity(widgets, Capacity::Five)),
                run(add_label(widgets, &[L::Gpu])),
                repo_list(),
            ],
            &[
                "boundary:monitor-only-promoted",
                "refusal:repo.add:labels-need-autoscale",
                "refusal:repo.add-label:labels-on-monitor-only",
                "refusal:repo.set-scale:enable-monitor-only",
            ],
        ),
        curated_case(
            "organization-monitor-only-is-promoted-before-labels-or-arming",
            Standard,
            vec![CREDENTIAL, run(monitor(acme))],
            vec![
                run(remove_label(acme, &[L::Gpu])),
                run(set_scale(acme, true)),
                run(set_capacity(acme, Capacity::Two)),
                run(set_scale(acme, true)),
                org_list(),
            ],
            &[
                "refusal:org.remove-label:labels-on-monitor-only",
                "refusal:org.set-scale:enable-monitor-only",
            ],
        ),
        curated_case(
            "arming-cycle-through-disabled",
            Standard,
            vec![CREDENTIAL, run(auto(widgets))],
            vec![
                run(set_scale(widgets, false)),
                run(set_scale(widgets, true)),
                run(set_scale(widgets, true)),
                run(set_scale(widgets, false)),
                run(set_scale(widgets, false)),
                run(set_scale(widgets, true)),
                repo_list(),
                status(),
            ],
            &[
                "invariant:repeat-enable-is-idempotent",
                "invariant:disabled-policy-can-be-re-armed",
                "invariant:disabling-an-unarmed-policy-is-a-no-op",
            ],
        ),
        curated_case(
            "derived-label-removal-refusal-is-atomic",
            Standard,
            vec![
                CREDENTIAL,
                run(add(
                    widgets,
                    H::Home,
                    Some(Capacity::Two),
                    &[L::Gpu, L::LargeDisk],
                    false,
                )),
            ],
            vec![
                run(remove_label(widgets, &[L::Gpu, L::Derived(H::Home)])),
                repo_list(),
                status(),
                run(remove_label(widgets, &[L::DerivedCase(H::Home)])),
                status(),
            ],
            &[
                "invariant:multi-label-refusal-is-atomic",
                "refusal:repo.remove-label:derived-label-not-removable",
            ],
        ),
        curated_case(
            "organization-derived-label-removal-refusal-is-atomic",
            Standard,
            vec![
                CREDENTIAL,
                run(add(
                    acme,
                    H::Office,
                    Some(Capacity::Two),
                    &[L::Gpu, L::SelfHosted],
                    false,
                )),
            ],
            vec![
                run(remove_label(acme, &[L::SelfHosted, L::Derived(H::Office)])),
                run(add_label(acme, &[L::GpuCase])),
                org_list(),
                status(),
            ],
            &[
                "refusal:org.remove-label:derived-label-not-removable",
                "invariant:labels-fold-case",
            ],
        ),
        curated_case(
            "labels-fold-case-and-repeat-idempotently",
            Standard,
            vec![CREDENTIAL, run(auto(widgets))],
            vec![
                run(add_label(widgets, &[L::GpuCase])),
                run(add_label(widgets, &[L::Derived(H::Home)])),
                run(add_label(widgets, &[L::LargeDisk, L::SelfHosted])),
                run(remove_label(widgets, &[L::LargeDisk])),
                run(remove_label(widgets, &[L::LargeDisk])),
                status(),
            ],
            &[
                "invariant:labels-fold-case",
                "invariant:label-change-is-idempotent",
                "invariant:derived-label-is-never-duplicated",
            ],
        ),
        curated_case(
            "label-length-and-character-boundaries",
            Standard,
            vec![CREDENTIAL, run(auto(widgets))],
            vec![
                run(add_label(widgets, &[L::Max256])),
                run(add_label(widgets, &[L::TooLong257])),
                run(add_label(widgets, &[L::Comma])),
                run(remove_label(widgets, &[L::Blank])),
                status(),
            ],
            &[
                "boundary:label-256",
                "refusal:repo.add-label:invalid-label",
                "refusal:repo.remove-label:invalid-label",
            ],
        ),
        curated_case(
            "host-label-length-character-and-case-rules",
            Standard,
            vec![CREDENTIAL],
            vec![
                run(add(
                    widgets,
                    H::Max64,
                    Some(Capacity::Two),
                    &[L::Max256],
                    false,
                )),
                run(add(gadgets, H::TooLong65, Some(Capacity::Two), &[], false)),
                run(add(gadgets, H::Space, Some(Capacity::Two), &[], false)),
                run(add(
                    gadgets,
                    H::TrailingDash,
                    Some(Capacity::Two),
                    &[],
                    false,
                )),
                run(add(gadgets, H::HomeCase, Some(Capacity::Two), &[], false)),
                status(),
            ],
            &[
                "boundary:host-label-64",
                "invariant:host-label-folds-case",
                "refusal:repo.add:invalid-host-label",
            ],
        ),
        curated_case(
            "host-capacity-boundaries",
            Standard,
            vec![],
            vec![
                run(Action::HostSetCapacity(Capacity::Zero)),
                host_show(),
                run(Action::HostSetCapacity(Capacity::Max)),
                run(Action::HostSetCapacity(Capacity::One)),
                run(Action::HostSetCapacity(Capacity::One)),
                status(),
            ],
            &[
                "refusal:host.set-capacity:zero-host-capacity",
                "boundary:host-capacity-u16-max",
                "boundary:host-capacity-product-default",
                "invariant:host-capacity-rewrite-is-idempotent",
            ],
        ),
        curated_case(
            "policy-capacity-boundaries",
            Standard,
            vec![CREDENTIAL, run(auto(widgets))],
            vec![
                run(set_capacity(widgets, Capacity::Zero)),
                run(set_capacity(widgets, Capacity::Max)),
                run(set_capacity(widgets, Capacity::One)),
                run(set_capacity(widgets, Capacity::One)),
                run(set_capacity(gadgets, Capacity::Zero)),
                repo_list(),
            ],
            &[
                "refusal:repo.set-capacity:zero-max-capacity",
                "boundary:policy-capacity-u16-max",
                "boundary:policy-capacity-one",
                "invariant:capacity-rewrite-is-idempotent",
                "invariant:missing-target-is-reported-before-a-zero-capacity",
            ],
        ),
        curated_case(
            "repository-and-organization-policies-coexist",
            Standard,
            vec![CREDENTIAL],
            vec![
                run(auto(widgets)),
                run(auto(acme)),
                repo_list(),
                org_list(),
                status(),
                run(remove(acme, false)),
                repo_list(),
                status(),
            ],
            &[
                "cross:repository-and-organization-policies-coexist",
                "cross:removal-leaves-the-other-scope-policy",
            ],
        ),
        curated_case(
            "repository-targets-fill-the-rest-budget",
            Wide,
            vec![CREDENTIAL],
            {
                let mut steps: Vec<Step> = vec![run(monitor(widgets)), run(monitor(gadgets))];
                steps.extend((1..=8).map(|n| run(monitor(repo(R::Fleet(n))))));
                steps.push(run(monitor(repo(R::Fleet(9)))));
                steps.push(status());
                steps.push(host_show());
                steps
            },
            &[
                "boundary:budget-filled",
                "boundary:budget-ceiling",
                "refusal:repo.add:budget-exceeded",
            ],
        ),
        curated_case(
            "the-rest-budget-counts-both-scopes",
            Wide,
            vec![CREDENTIAL],
            vec![
                run(monitor(acme)),
                run(monitor(widgets)),
                run(remove(acme, true)),
                run(monitor(widgets)),
                run(monitor(acme)),
                status(),
            ],
            &[
                "cross:budget-counts-the-other-scope",
                "refusal:org.add:budget-exceeded",
            ],
        ),
        curated_case(
            "purge-keeps-the-package-cache-for-the-other-scope",
            Standard,
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                run(auto(acme)),
                Step::Seed(Seed::PackageCache),
                attempt(widgets, AttemptKind::Cleaned),
            ],
            vec![
                run(remove(widgets, true)),
                status(),
                run(remove(acme, true)),
                status(),
            ],
            &["cross:purge-keeps-the-cache-for-the-other-scope"],
        ),
        curated_case(
            "purge-keeps-a-package-cache-still-in-use",
            Standard,
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                run(auto(gadgets)),
                Step::Seed(Seed::PackageCache),
            ],
            vec![
                run(remove(widgets, true)),
                run(remove(gadgets, true)),
                status(),
            ],
            &["invariant:purge-keeps-a-shared-cache-in-use"],
        ),
        curated_case(
            "non-purge-removal-retains-diagnostics-across-a-re-add",
            Standard,
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                attempt(widgets, AttemptKind::Cleaned),
                attempt(widgets, AttemptKind::AwaitingCleanup),
            ],
            vec![
                run(remove(widgets, false)),
                status(),
                run(auto(widgets)),
                run(persistent(R::Widgets, P::Alpha)),
                run(Action::HostSetRuntimeRoot(P::Beta)),
                status(),
            ],
            &[
                "invariant:non-purge-removal-retains-diagnostics",
                "invariant:re-added-target-starts-fresh",
                "cross:retained-attempts-block-the-host-root",
            ],
        ),
        curated_case(
            "active-attempts-guard-disable-purge-and-the-host-root",
            Standard,
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                run(set_scale(widgets, true)),
                attempt(widgets, AttemptKind::Active),
            ],
            vec![
                run(set_scale(widgets, false)),
                run(remove(widgets, true)),
                run(Action::HostSetCapacity(Capacity::One)),
                run(remove(widgets, false)),
                status(),
                run(Action::HostResetRuntimeRoot),
                host_show(),
            ],
            &[
                "refusal:repo.set-scale:disable-needs-confirmation",
                "refusal:repo.remove:purge-with-active-attempts",
                "cross:removed-policy-attempts-still-count-host-wide",
                "refusal:host.reset-runtime-root:attempts-own-host-root",
            ],
        ),
        curated_case(
            "organization-active-attempts-guard-disable-and-purge",
            Standard,
            vec![
                CREDENTIAL,
                run(add(acme, H::Home, Some(Capacity::Two), &[], true)),
                attempt(acme, AttemptKind::Active),
            ],
            vec![
                run(set_scale(acme, false)),
                run(remove(acme, true)),
                org_list(),
                run(remove(acme, false)),
                status(),
            ],
            &[
                "refusal:org.set-scale:disable-needs-confirmation",
                "refusal:org.remove:purge-with-active-attempts",
            ],
        ),
        curated_case(
            "host-capacity-below-attempts-in-use",
            Standard,
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                run(auto(acme)),
                attempt(widgets, AttemptKind::Active),
                attempt(acme, AttemptKind::Active),
            ],
            vec![
                run(Action::HostSetCapacity(Capacity::One)),
                host_show(),
                status(),
            ],
            &["boundary:host-capacity-below-in-use"],
        ),
        curated_case(
            "repair-required-survives-unrelated-commands",
            Standard,
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                Step::Seed(Seed::RepairRequired(widgets)),
            ],
            vec![
                run(set_scale(widgets, true)),
                run(Action::HostSetCapacity(Capacity::Five)),
                repo_list(),
                run(set_capacity(widgets, Capacity::Five)),
                repo_list(),
                run(remove(widgets, true)),
                status(),
            ],
            &[
                "refusal:repo.set-scale:illegal-state-transition",
                "invariant:repair-required-survives-unrelated-commands",
            ],
        ),
        curated_case(
            "draining-survives-then-a-repeated-disable-completes-it",
            Standard,
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                run(set_scale(widgets, true)),
                Step::Seed(Seed::Drain(widgets)),
            ],
            vec![
                run(auto(acme)),
                run(set_scale(widgets, true)),
                run(set_scale(widgets, false)),
                repo_list(),
                status(),
            ],
            &[
                "invariant:draining-survives-unrelated-commands",
                "invariant:repeated-disable-completes-a-drain",
            ],
        ),
        curated_case(
            "monitor-only-and-enabled-survive-unrelated-commands",
            Standard,
            vec![
                CREDENTIAL,
                run(monitor(widgets)),
                run(auto(acme)),
                run(set_scale(acme, true)),
            ],
            vec![
                run(Action::HostSetCapacity(Capacity::Two)),
                run(auto(gadgets)),
                repo_list(),
                org_list(),
            ],
            &[
                "invariant:monitor-only-survives-unrelated-commands",
                "invariant:enabled-survives-unrelated-commands",
            ],
        ),
        curated_case(
            "host-runner-root-lifecycle",
            Standard,
            vec![],
            vec![
                run(Action::HostSetRuntimeRoot(P::Alpha)),
                host_show(),
                run(Action::HostSetRuntimeRoot(P::Alpha)),
                run(Action::HostResetRuntimeRoot),
                run(Action::HostResetRuntimeRoot),
                run(Action::HostSetRuntimeRoot(P::Alpha)),
                run(Action::HostSetRuntimeRoot(P::AlphaInner)),
                status(),
            ],
            &[
                "invariant:host-root-change-leaves-the-old-directory",
                "invariant:host-root-rewrite-is-idempotent",
            ],
        ),
        curated_case(
            "host-runner-root-refusals-on-a-fresh-data-root",
            Standard,
            vec![],
            vec![
                run(Action::HostSetRuntimeRoot(P::Relative)),
                status(),
                run(Action::HostSetRuntimeRoot(P::DeepMissing)),
                run(Action::HostSetRuntimeRoot(P::OccupiedFile)),
                run(Action::HostSetRuntimeRoot(P::InsideAppState)),
                run(Action::HostSetRuntimeRoot(P::AlphaInner)),
                host_show(),
                status(),
            ],
            &[
                "deviation:host-materialized-by-refusal",
                "refusal:host.set-runtime-root:relative-path",
                "refusal:host.set-runtime-root:missing-parents",
                "refusal:host.set-runtime-root:existing-file",
                "refusal:host.set-runtime-root:overlaps-application-data",
                "invariant:refused-path-creates-nothing",
            ],
        ),
        curated_case(
            "host-runner-root-reset-on-a-fresh-data-root",
            Standard,
            vec![],
            vec![run(Action::HostResetRuntimeRoot), host_show(), status()],
            &["readback:host.reset-runtime-root>host.show"],
        ),
        curated_case(
            "host-root-refused-where-it-overlaps-a-repository-root",
            Standard,
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                run(persistent(R::Widgets, P::Alpha)),
            ],
            vec![
                run(Action::HostSetRuntimeRoot(P::RootsDir)),
                run(Action::HostSetRuntimeRoot(P::Alpha)),
                run(Action::HostSetRuntimeRoot(P::AlphaInner)),
                run(Action::HostSetRuntimeRoot(P::Beta)),
                status(),
            ],
            &[
                "cross:host-root-overlaps-a-repository-root",
                "refusal:host.set-runtime-root:overlaps-repository-root",
            ],
        ),
        curated_case(
            "repository-root-refused-where-it-overlaps-the-host-root",
            Standard,
            vec![CREDENTIAL, run(auto(widgets))],
            vec![
                run(Action::HostSetRuntimeRoot(P::RootsDir)),
                run(persistent(R::Widgets, P::Alpha)),
                run(Action::HostSetRuntimeRoot(P::Beta)),
                run(persistent(R::Widgets, P::Alpha)),
                repo_list(),
                status(),
            ],
            &[
                "cross:repository-root-overlaps-the-host-root",
                "refusal:repo.set-workspace:overlaps-host-root",
            ],
        ),
        curated_case(
            "repository-roots-never-overlap-and-changes-leave-directories",
            Standard,
            vec![CREDENTIAL, run(auto(widgets)), run(auto(gadgets))],
            vec![
                run(persistent(R::Widgets, P::Alpha)),
                run(persistent(R::Gadgets, P::Alpha)),
                run(persistent(R::Gadgets, P::AlphaInner)),
                run(persistent(R::Gadgets, P::Beta)),
                run(persistent(R::Widgets, P::Alpha)),
                run(workspace(R::Widgets, WorkspaceSetting::Ephemeral)),
                run(persistent(R::Gadgets, P::Alpha)),
                status(),
            ],
            &[
                "invariant:repository-roots-never-overlap",
                "invariant:workspace-rewrite-is-idempotent",
                "invariant:workspace-change-leaves-the-old-root",
            ],
        ),
        curated_case(
            "uncleaned-attempts-guard-workspace-and-host-root",
            Standard,
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                attempt(widgets, AttemptKind::AwaitingCleanup),
            ],
            vec![
                run(persistent(R::Widgets, P::Alpha)),
                run(workspace(R::Widgets, WorkspaceSetting::Ephemeral)),
                run(Action::HostSetRuntimeRoot(P::Beta)),
                repo_list(),
                status(),
            ],
            &[
                "refusal:repo.set-workspace:attempts-own-workspace",
                "refusal:host.set-runtime-root:attempts-own-host-root",
            ],
        ),
        curated_case(
            "workspace-argument-and-path-rules",
            Standard,
            vec![CREDENTIAL, run(auto(widgets))],
            vec![
                run(workspace(
                    R::Widgets,
                    WorkspaceSetting::EphemeralWithPath(P::Alpha),
                )),
                run(persistent(R::Widgets, P::Relative)),
                run(persistent(R::Gadgets, P::Alpha)),
                run(persistent(R::Malformed, P::Alpha)),
                run(persistent(R::Widgets, P::OccupiedFile)),
                run(persistent(R::Widgets, P::DeepMissing)),
                run(persistent(R::Widgets, P::InsideAppState)),
                run(persistent(R::Widgets, P::AlphaInner)),
                status(),
            ],
            &[
                "refusal:repo.set-workspace:ephemeral-rejects-path",
                "refusal:repo.set-workspace:relative-path",
                "refusal:repo.set-workspace:missing-policy",
                "refusal:repo.set-workspace:invalid-target",
                "refusal:repo.set-workspace:existing-file",
                "refusal:repo.set-workspace:missing-parents",
                "refusal:repo.set-workspace:overlaps-application-data",
            ],
        ),
        curated_case(
            "add-and-enable-in-one-command",
            Standard,
            vec![CREDENTIAL],
            vec![
                run(add(
                    widgets,
                    H::Home,
                    Some(Capacity::Two),
                    &[L::SelfHosted],
                    true,
                )),
                run(add(acme, H::Office, Some(Capacity::Max), &[], true)),
                status(),
                repo_list(),
                org_list(),
            ],
            &["value:repo.add:enable=true", "value:org.add:enable=true"],
        ),
        curated_case(
            "add-enable-on-monitor-only-stores-then-refuses",
            Standard,
            vec![CREDENTIAL],
            vec![
                run(add(widgets, H::Home, None, &[], true)),
                repo_list(),
                status(),
                run(auto(widgets)),
            ],
            &[
                "deviation:partial-commit-on-enable",
                "refusal:repo.add:enable-monitor-only",
            ],
        ),
        curated_case(
            "malformed-targets-are-refused-before-any-lookup",
            Standard,
            vec![CREDENTIAL],
            vec![
                run(auto(repo(R::Malformed))),
                run(auto(repo(R::IllegalChar))),
                run(auto(org(O::TrailingDash))),
                run(set_capacity(repo(R::Malformed), Capacity::Two)),
                run(remove(org(O::TrailingDash), true)),
                run(set_scale(repo(R::IllegalChar), true)),
                status(),
            ],
            &[
                "refusal:repo.add:invalid-target",
                "refusal:org.add:invalid-target",
                "refusal:repo.set-capacity:invalid-target",
                "refusal:org.remove:invalid-target",
                "refusal:repo.set-scale:invalid-target",
            ],
        ),
        curated_case(
            "commands-on-missing-policies-are-not-found",
            Standard,
            vec![CREDENTIAL, run(auto(widgets))],
            vec![
                run(set_scale(gadgets, true)),
                run(remove(gadgets, false)),
                run(set_capacity(acme, Capacity::Two)),
                run(add_label(acme, &[L::Gpu])),
                run(remove_label(acme, &[L::Gpu])),
                run(remove_label(gadgets, &[L::Gpu])),
                run(add_label(gadgets, &[L::Gpu])),
                run(set_scale(acme, false)),
                run(remove(acme, true)),
                status(),
            ],
            &[
                "refusal:repo.set-scale:missing-policy",
                "refusal:repo.remove:missing-policy",
                "refusal:org.set-capacity:missing-policy",
                "refusal:org.add-label:missing-policy",
                "refusal:org.remove-label:missing-policy",
                "refusal:org.set-scale:missing-policy",
                "refusal:org.remove:missing-policy",
            ],
        ),
        curated_case(
            "targets-are-case-insensitive-and-keep-their-spelling",
            Standard,
            vec![CREDENTIAL],
            vec![
                run(auto(repo(R::WidgetsCase))),
                run(set_capacity(widgets, Capacity::Five)),
                run(add_label(repo(R::WidgetsCase), &[L::LargeDisk])),
                repo_list(),
                run(auto(org(O::AcmeCase))),
                run(set_scale(acme, true)),
                org_list(),
                status(),
            ],
            &[
                "value:repo.add:target=case-variant",
                "value:org.add:target=case-variant",
            ],
        ),
        curated_case(
            "removal-then-re-add-starts-a-fresh-policy",
            Standard,
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                run(persistent(R::Widgets, P::Alpha)),
            ],
            vec![
                run(remove(widgets, false)),
                run(monitor(widgets)),
                repo_list(),
                run(persistent(R::Widgets, P::Alpha)),
                status(),
            ],
            &["pair:repo.remove>repo.add"],
        ),
        curated_case(
            "sign-out-then-sign-in-restores-add",
            Standard,
            vec![CREDENTIAL],
            vec![
                run(Action::AuthLogout),
                run(auto(widgets)),
                run(Action::AuthLogin),
                run(auto(widgets)),
                status(),
            ],
            &["pair:auth.login>repo.add"],
        ),
    ]
}

/// Hand-written journeys added after the corpus was first pinned.
///
/// Offered after every other source, so adding one appends a case to the
/// inventory instead of renumbering every case generated after the curated
/// block.
fn appended_curated() -> Vec<Candidate> {
    vec![curated_case(
        "case-variant-owner-meets-its-own-persistent-root",
        Installation::Standard,
        vec![
            CREDENTIAL,
            run(auto(repo(R::Widgets))),
            run(persistent(R::Widgets, P::Alpha)),
        ],
        vec![
            run(persistent(R::WidgetsCase, P::Alpha)),
            repo_list(),
            status(),
        ],
        &["deviation:owner-compared-case-sensitively"],
    )]
}

// ---------------------------------------------------------------------------
// Value probes
// ---------------------------------------------------------------------------

fn probe(name: String, setup: Vec<Step>, action: Action) -> Candidate {
    Candidate {
        name,
        origin: Origin::Value,
        installation: Installation::Standard,
        setup,
        steps: vec![run(action)],
        promises: Vec::new(),
    }
}

/// One action per equivalence class, each on the smallest state that reaches
/// the check the class exists for.
#[allow(clippy::too_many_lines, reason = "one flat list of probes per leaf")]
fn value_probes() -> Vec<Candidate> {
    let mut probes = Vec::new();
    let signed_in = || vec![CREDENTIAL];
    let with_repo = || vec![CREDENTIAL, run(auto(repo(R::Widgets)))];
    let with_org = || vec![CREDENTIAL, run(auto(org(O::Acme)))];
    let repo_names = [
        R::Widgets,
        R::Gadgets,
        R::Portal,
        R::WidgetsCase,
        R::Fleet(1),
        R::Outside,
        R::Malformed,
        R::IllegalChar,
    ];
    let org_names = [O::Acme, O::Globex, O::AcmeCase, O::Outside, O::TrailingDash];
    let host_labels = [
        H::Home,
        H::Office,
        H::HomeCase,
        H::Max64,
        H::TooLong65,
        H::Space,
        H::TrailingDash,
    ];
    let labels = [
        L::Gpu,
        L::GpuCase,
        L::LargeDisk,
        L::SelfHosted,
        L::Max256,
        L::TooLong257,
        L::Comma,
        L::Blank,
        L::Derived(H::Home),
        L::DerivedCase(H::Home),
    ];

    for capacity in Capacity::ALL {
        probes.push(probe(
            format!("host-capacity-{}", capacity.class()),
            vec![],
            Action::HostSetCapacity(capacity),
        ));
    }
    for path in PathValue::ALL {
        probes.push(probe(
            format!("host-runner-root-{}", path.class()),
            vec![],
            Action::HostSetRuntimeRoot(path),
        ));
    }

    for (scope, targets, setup) in [
        (
            "repo",
            repo_names
                .iter()
                .map(|name| repo(*name))
                .collect::<Vec<_>>(),
            with_repo as fn() -> Vec<Step>,
        ),
        (
            "org",
            org_names.iter().map(|name| org(*name)).collect::<Vec<_>>(),
            with_org as fn() -> Vec<Step>,
        ),
    ] {
        let home = targets[0];
        for target in &targets {
            probes.push(probe(
                format!("{scope}-add-target-{}", target.class()),
                signed_in(),
                auto(*target),
            ));
        }
        for host_label in host_labels {
            probes.push(probe(
                format!("{scope}-add-host-label-{}", host_label.class()),
                signed_in(),
                add(home, host_label, Some(Capacity::Two), &[], false),
            ));
        }
        probes.push(probe(
            format!("{scope}-add-monitor-only"),
            signed_in(),
            monitor(home),
        ));
        for capacity in Capacity::ALL {
            probes.push(probe(
                format!("{scope}-add-max-capacity-{}", capacity.class()),
                signed_in(),
                add(home, H::Home, Some(capacity), &[], false),
            ));
        }
        for label in labels {
            probes.push(probe(
                format!("{scope}-add-with-label-{}", label.class()),
                signed_in(),
                add(home, H::Home, Some(Capacity::Two), &[label], false),
            ));
        }
        probes.push(probe(
            format!("{scope}-add-enabled"),
            signed_in(),
            add(home, H::Home, Some(Capacity::Two), &[], true),
        ));
        for capacity in Capacity::ALL {
            probes.push(probe(
                format!("{scope}-set-capacity-{}", capacity.class()),
                setup(),
                set_capacity(home, capacity),
            ));
        }
        for target in &targets {
            probes.push(probe(
                format!("{scope}-set-capacity-target-{}", target.class()),
                setup(),
                set_capacity(*target, Capacity::Five),
            ));
        }
        for enabled in [true, false] {
            probes.push(probe(
                format!("{scope}-set-scale-{enabled}"),
                setup(),
                set_scale(home, enabled),
            ));
        }
        for target in &targets {
            probes.push(probe(
                format!("{scope}-set-scale-target-{}", target.class()),
                setup(),
                set_scale(*target, true),
            ));
        }
        for label in labels {
            probes.push(probe(
                format!("{scope}-add-label-{}", label.class()),
                setup(),
                add_label(home, &[label]),
            ));
            probes.push(probe(
                format!("{scope}-remove-label-{}", label.class()),
                setup(),
                remove_label(home, &[label]),
            ));
        }
        probes.push(probe(
            format!("{scope}-add-several-labels"),
            setup(),
            add_label(home, &[L::LargeDisk, L::SelfHosted]),
        ));
        probes.push(probe(
            format!("{scope}-remove-several-labels"),
            setup(),
            remove_label(home, &[L::Gpu, L::SelfHosted]),
        ));
        for target in &targets {
            probes.push(probe(
                format!("{scope}-add-label-target-{}", target.class()),
                setup(),
                add_label(*target, &[L::LargeDisk]),
            ));
            probes.push(probe(
                format!("{scope}-remove-label-target-{}", target.class()),
                setup(),
                remove_label(*target, &[L::Gpu]),
            ));
            probes.push(probe(
                format!("{scope}-remove-target-{}", target.class()),
                setup(),
                remove(*target, false),
            ));
        }
        for purge in [true, false] {
            probes.push(probe(
                format!("{scope}-remove-purge-{purge}"),
                setup(),
                remove(home, purge),
            ));
        }
    }

    probes.push(probe(
        "repo-set-workspace-ephemeral".to_string(),
        with_repo(),
        workspace(R::Widgets, WorkspaceSetting::Ephemeral),
    ));
    probes.push(probe(
        "repo-set-workspace-ephemeral-with-path".to_string(),
        with_repo(),
        workspace(R::Widgets, WorkspaceSetting::EphemeralWithPath(P::Beta)),
    ));
    for path in PathValue::ALL {
        probes.push(probe(
            format!("repo-set-workspace-persistent-{}", path.class()),
            with_repo(),
            persistent(R::Widgets, path),
        ));
    }
    for name in repo_names {
        probes.push(probe(
            format!("repo-set-workspace-target-{}", name.class()),
            with_repo(),
            persistent(name, P::Beta),
        ));
    }
    probes
}

// ---------------------------------------------------------------------------
// Pair chains
// ---------------------------------------------------------------------------

/// SplitMix64: a tiny, well-distributed, dependency-free generator. Only its
/// determinism matters here.
#[derive(Debug, Clone)]
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Rotates a list by a seeded offset.
    fn rotate<T: Clone>(&mut self, items: &[T]) -> Vec<T> {
        if items.is_empty() {
            return Vec::new();
        }
        let offset = usize::try_from(self.next() % items.len() as u64).unwrap_or(0);
        let mut rotated = items[offset..].to_vec();
        rotated.extend_from_slice(&items[..offset]);
        rotated
    }
}

/// The initial states pair chains are built on, smallest first.
fn baselines() -> Vec<(&'static str, Vec<Step>)> {
    let widgets = repo(R::Widgets);
    let gadgets = repo(R::Gadgets);
    let acme = org(O::Acme);
    let globex = org(O::Globex);
    vec![
        ("fresh", vec![]),
        ("signed-in", vec![CREDENTIAL]),
        ("one-repository", vec![CREDENTIAL, run(auto(widgets))]),
        ("one-organization", vec![CREDENTIAL, run(auto(acme))]),
        (
            "repository-and-organization",
            vec![CREDENTIAL, run(auto(widgets)), run(auto(acme))],
        ),
        (
            "two-repositories",
            vec![CREDENTIAL, run(auto(widgets)), run(auto(gadgets))],
        ),
        (
            "two-organizations",
            vec![CREDENTIAL, run(auto(acme)), run(auto(globex))],
        ),
        (
            "two-of-each",
            vec![
                CREDENTIAL,
                run(auto(widgets)),
                run(auto(gadgets)),
                run(auto(acme)),
                run(auto(globex)),
            ],
        ),
    ]
}

/// Parameterisations of one leaf worth trying, in a seeded order.
fn action_candidates(kind: ActionKind, rng: &mut Rng) -> Vec<Action> {
    let repos = [R::Widgets, R::Gadgets, R::Portal];
    let orgs = [O::Acme, O::Globex];
    let scoped: Vec<Target> = if matches!(
        kind,
        ActionKind::OrgAdd
            | ActionKind::OrgSetCapacity
            | ActionKind::OrgSetScale
            | ActionKind::OrgAddLabel
            | ActionKind::OrgRemoveLabel
            | ActionKind::OrgRemove
    ) {
        orgs.iter().map(|name| org(*name)).collect()
    } else {
        repos.iter().map(|name| repo(*name)).collect()
    };
    let capacities = rng.rotate(&[Capacity::Five, Capacity::Two, Capacity::Max, Capacity::One]);
    let extra_labels = rng.rotate(&[L::LargeDisk, L::SelfHosted, L::Max256]);
    let mut actions = Vec::new();
    match kind {
        ActionKind::AuthLogin => actions.push(Action::AuthLogin),
        ActionKind::AuthLogout => actions.push(Action::AuthLogout),
        ActionKind::HostSetCapacity => {
            actions.extend(
                capacities
                    .iter()
                    .map(|capacity| Action::HostSetCapacity(*capacity)),
            );
        }
        ActionKind::HostSetRuntimeRoot => {
            let paths = rng.rotate(&[P::Beta, P::Alpha, P::RootsDir]);
            actions.extend(paths.iter().map(|path| Action::HostSetRuntimeRoot(*path)));
            actions.push(Action::HostSetRuntimeRoot(P::AlphaInner));
        }
        ActionKind::HostResetRuntimeRoot => actions.push(Action::HostResetRuntimeRoot),
        ActionKind::HostShow => actions.push(Action::HostShow),
        ActionKind::RepoList => actions.push(Action::List(Scope::Repository)),
        ActionKind::OrgList => actions.push(Action::List(Scope::Organization)),
        ActionKind::StatusJson => actions.push(Action::StatusJson),
        ActionKind::RepoAdd | ActionKind::OrgAdd => {
            let host_labels = rng.rotate(&[H::Home, H::Office]);
            for target in &scoped {
                actions.push(add(
                    *target,
                    host_labels[0],
                    Some(capacities[0]),
                    &[L::Gpu],
                    false,
                ));
                actions.push(monitor(*target));
                actions.push(add(
                    *target,
                    host_labels[1],
                    Some(Capacity::One),
                    &[extra_labels[0]],
                    true,
                ));
            }
        }
        ActionKind::RepoSetCapacity | ActionKind::OrgSetCapacity => {
            for target in &scoped {
                actions.extend(
                    capacities
                        .iter()
                        .map(|capacity| set_capacity(*target, *capacity)),
                );
            }
        }
        ActionKind::RepoSetScale | ActionKind::OrgSetScale => {
            for target in &scoped {
                actions.push(set_scale(*target, true));
                actions.push(set_scale(*target, false));
            }
        }
        ActionKind::RepoAddLabel | ActionKind::OrgAddLabel => {
            for target in &scoped {
                actions.extend(
                    extra_labels
                        .iter()
                        .map(|label| add_label(*target, &[*label])),
                );
                actions.push(add_label(*target, &[L::Gpu]));
            }
        }
        ActionKind::RepoRemoveLabel | ActionKind::OrgRemoveLabel => {
            for target in &scoped {
                actions.push(remove_label(*target, &[L::Gpu]));
                actions.extend(
                    extra_labels
                        .iter()
                        .map(|label| remove_label(*target, &[*label])),
                );
            }
        }
        ActionKind::RepoSetWorkspace => {
            let paths = rng.rotate(&[P::Alpha, P::Beta]);
            for name in repos {
                for path in &paths {
                    actions.push(persistent(name, *path));
                }
                actions.push(workspace(name, WorkspaceSetting::Ephemeral));
            }
        }
        ActionKind::RepoRemove | ActionKind::OrgRemove => {
            for target in &scoped {
                actions.push(remove(*target, true));
                actions.push(remove(*target, false));
            }
        }
    }
    actions
}

/// The one spelling of a read leaf. Goes through [`action_candidates`] so the
/// seeded generator advances exactly as it would for any other leaf.
fn read_action(read: ActionKind, rng: &mut Rng) -> Action {
    action_candidates(read, rng)
        .into_iter()
        .next()
        .expect("every read has one spelling")
}

/// A successful action on `model`, preferring one that addresses `anchor` and
/// one that changes something.
fn best_success(
    model: &Model,
    kind: ActionKind,
    anchor: Option<Target>,
    rng: &mut Rng,
) -> Option<(Action, Model)> {
    let mut best: Option<(u8, Action, Model)> = None;
    for action in action_candidates(kind, rng) {
        let result = transition::apply(model, &action);
        if !result.exit.is_success() {
            continue;
        }
        let same_target = anchor.is_some()
            && action.target().and_then(|t| t.key()) == anchor.and_then(|t| t.key());
        let score = u8::from(same_target) * 2 + u8::from(!result.deltas.is_empty());
        if best.as_ref().is_none_or(|(current, _, _)| score > *current) {
            best = Some((score, action, result.next));
        }
    }
    best.map(|(_, action, next)| (action, next))
}

fn model_after(installation: Installation, steps: &[Step]) -> Model {
    coverage::simulate(installation, steps)
        .expect("baselines are valid")
        .last()
        .clone()
}

/// A chain of mutations witnessing `first>second`, extended while the next
/// uncovered pair can follow on, on the smallest baseline that admits it.
fn pair_chain(
    first: ActionKind,
    second: ActionKind,
    covered: &BTreeSet<String>,
    rng: &mut Rng,
) -> Option<Candidate> {
    for (baseline, setup) in baselines() {
        let start = model_after(Installation::Standard, &setup);
        let Some((a, after_a)) = best_success(&start, first, None, rng) else {
            continue;
        };
        let Some((b, after_b)) = best_success(&after_a, second, a.target(), rng) else {
            continue;
        };
        let mut steps = vec![run(a), run(b.clone())];
        let mut chain = vec![first, second];
        let mut claimed: BTreeSet<String> = BTreeSet::new();
        claimed.insert(coverage::pair_unit(first, second));
        let (mut current_kind, mut current_action, mut current) = (second, b, after_b);
        while chain.len() < 4 {
            let mut extended = false;
            for next_kind in ActionKind::mutating() {
                let unit = coverage::pair_unit(current_kind, next_kind);
                if covered.contains(&unit) || claimed.contains(&unit) {
                    continue;
                }
                if let Some((c, after_c)) =
                    best_success(&current, next_kind, current_action.target(), rng)
                {
                    steps.push(run(c.clone()));
                    chain.push(next_kind);
                    claimed.insert(unit);
                    (current_kind, current_action, current) = (next_kind, c, after_c);
                    extended = true;
                    break;
                }
            }
            if !extended {
                break;
            }
        }
        // One read of the last mutation, when that readback is still open.
        if let Some(read) = ActionKind::reads().into_iter().find(|read| {
            coverage::readback_relevant(current_kind, *read)
                && !covered.contains(&coverage::readback_unit(current_kind, *read))
        }) {
            steps.push(run(read_action(read, rng)));
        }
        let names: Vec<&str> = chain.iter().map(|kind| kind.name()).collect();
        return Some(Candidate {
            name: format!("chain {} from {baseline}", names.join(" > ")),
            origin: Origin::Pair,
            installation: Installation::Standard,
            setup,
            steps,
            promises: Vec::new(),
        });
    }
    None
}

/// A mutation followed by a relevant read, on the smallest baseline where the
/// mutation succeeds.
fn readback_case(mutation: ActionKind, read: ActionKind, rng: &mut Rng) -> Option<Candidate> {
    for (baseline, setup) in baselines() {
        let start = model_after(Installation::Standard, &setup);
        let Some((action, _)) = best_success(&start, mutation, None, rng) else {
            continue;
        };
        let reader = read_action(read, rng);
        return Some(Candidate {
            name: format!("readback {mutation} then {read} from {baseline}"),
            origin: Origin::Readback,
            installation: Installation::Standard,
            setup,
            steps: vec![run(action), run(reader)],
            promises: Vec::new(),
        });
    }
    None
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Offers a candidate to the retention rule.
fn offer(
    candidate: Candidate,
    covered: &mut BTreeSet<String>,
    kept: &mut Vec<(Candidate, Vec<String>)>,
    rejected: &mut usize,
) {
    let trace = coverage::simulate(candidate.installation, &candidate.all_steps())
        .unwrap_or_else(|problem| panic!("candidate {:?}: {problem}", candidate.name));
    let units = coverage::units(&trace);
    for promise in &candidate.promises {
        assert!(
            units.contains(*promise),
            "curated journey {:?} promises {promise:?}, but the model says it witnesses only \
             {units:?}",
            candidate.name
        );
    }
    let fresh: Vec<String> = units.difference(covered).cloned().collect();
    if fresh.is_empty() {
        *rejected += 1;
        return;
    }
    covered.extend(fresh.iter().cloned());
    kept.push((candidate, fresh));
}

/// Builds the corpus. Deterministic: two calls produce identical corpora.
///
/// # Panics
/// If a compatible pair has no construction, or a curated journey does not
/// witness what it promises — both are defects in this generator.
#[must_use]
pub fn generate() -> Corpus {
    let mut rng = Rng(CORPUS_SEED ^ u64::from(CORPUS_VERSION));
    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut kept: Vec<(Candidate, Vec<String>)> = Vec::new();
    let mut rejected = 0;

    for candidate in curated() {
        offer(candidate, &mut covered, &mut kept, &mut rejected);
    }
    for candidate in value_probes() {
        offer(candidate, &mut covered, &mut kept, &mut rejected);
    }
    for (first, second) in coverage::compatible_pairs() {
        if covered.contains(&coverage::pair_unit(first, second)) {
            continue;
        }
        let candidate = pair_chain(first, second, &covered, &mut rng).unwrap_or_else(|| {
            panic!(
                "no baseline admits {first} then {second}; declare it incompatible or fix the model"
            )
        });
        offer(candidate, &mut covered, &mut kept, &mut rejected);
    }
    for (mutation, read) in coverage::readback_universe() {
        if covered.contains(&coverage::readback_unit(mutation, read)) {
            continue;
        }
        if let Some(candidate) = readback_case(mutation, read, &mut rng) {
            offer(candidate, &mut covered, &mut kept, &mut rejected);
        }
    }
    for candidate in appended_curated() {
        offer(candidate, &mut covered, &mut kept, &mut rejected);
    }

    let cases = kept
        .into_iter()
        .enumerate()
        .map(|(index, (candidate, contributions))| {
            let id = CaseId(u16::try_from(index + 1).expect("fewer than 65 536 cases"));
            let steps = candidate.all_steps();
            let rendered: Vec<String> = steps.iter().map(|step| step.describe(&Symbolic)).collect();
            let print = fingerprint(&format!(
                "{}\n{}",
                candidate.installation.name(),
                rendered.join("\n")
            ));
            Case {
                id,
                name: candidate.name,
                origin: candidate.origin,
                installation: candidate.installation,
                setup_len: candidate.setup.len(),
                steps,
                contributions,
                fingerprint: print,
            }
        })
        .collect();
    Corpus { cases, rejected }
}

// ---------------------------------------------------------------------------
// The inventory
// ---------------------------------------------------------------------------

/// The checked-in inventory's path, relative to this crate.
pub const INVENTORY_FILE: &str = "tests/cli_chains/local_inventory.txt";

/// Renders the inventory: every case, why it is kept, and each step with the
/// exit class the model expects.
#[must_use]
pub fn render_inventory(corpus: &Corpus) -> String {
    let resolver: &dyn Resolver = &Symbolic;
    let mut text = String::new();
    text.push_str("# Local CLI chain inventory -- GENERATED, DO NOT EDIT BY HAND.\n");
    text.push_str(&format!(
        "# corpus version {CORPUS_VERSION}, seed {CORPUS_SEED:#018x}, {} cases, {} rejected candidates\n",
        corpus.cases.len(),
        corpus.rejected
    ));
    text.push_str(
        "# Regenerate: CLI_CHAINS_BLESS=1 cargo test -p runner-manager --test cli_chains_model\n",
    );
    text.push_str(
        "# Paths are relative to the scenario's <roots> and <data>; rm-<host>-<os>-<arch> is the derived label.\n",
    );
    for case in &corpus.cases {
        let trace = case.trace();
        text.push('\n');
        text.push_str(&format!(
            "{} fp={:016x} origin={} fixture={}\n",
            case.id,
            case.fingerprint,
            case.origin.name(),
            case.installation.name()
        ));
        text.push_str(&format!("  name: {}\n", case.name));
        text.push_str(&format!(
            "  contributes: {}\n",
            case.contributions.join(", ")
        ));
        for (index, (step, entry)) in case.steps.iter().zip(&trace.entries).enumerate() {
            let marker = if index < case.setup_len { "setup " } else { "" };
            let outcome = match entry {
                Entry::Seed { .. } => String::new(),
                Entry::Run { transition, .. } => {
                    let mut outcome = format!(" => {}", transition.exit.describe());
                    if let Some(reason) = transition.reason {
                        outcome.push_str(&format!(" {}", reason.slug()));
                    }
                    if let Some(deviation) = transition.deviation {
                        outcome.push_str(&format!(" [deviation: {}]", deviation.slug()));
                    }
                    outcome
                }
            };
            text.push_str(&format!(
                "  {:>2}. {marker}{}{outcome}\n",
                index + 1,
                step.describe(resolver)
            ));
        }
    }
    text
}
