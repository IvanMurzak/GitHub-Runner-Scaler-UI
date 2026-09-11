// owner: a1-command-accountability
//
// ----------------------------------------------------------------------------
// EVERY PUBLISHED COMMAND LEAF IS ACCOUNTED FOR, OR THE BUILD IS RED.
// ----------------------------------------------------------------------------
// `.taskflow/2026-09-10-cli-chains-acceptance/02-target-architecture.md` ¶4:
// the combinatorial chain generator deliberately does NOT execute `daemon run`,
// `service install`/`uninstall`, `update`, `tui`, hidden commands, or real WSL
// operations. That is only safe if the leaves it skips are skipped on purpose
// and are covered somewhere else, so this manifest maps every published leaf to
// exactly one of five coverage classes and names the tests that carry it.
//
// The manifest is not a second copy of clap's tree. The leaf inventory it is
// checked against is derived from `SURFACE` in `cli_command_surface.rs`, which
// that file already pins against the real `--help` in both directions, and
// `cli_command_surface.rs` also re-walks the live `--help` tree against this
// manifest. So a new clap leaf fails the surface tests; a new `SURFACE` entry
// fails here until somebody reviews it and writes its row.
//
// ----------------------------------------------------------------------------
// WHAT A ROW HAS TO PROVE.
// ----------------------------------------------------------------------------
// 1. Its leaf is published (not stale, not hidden) and appears once.
// 2. Every piece of evidence is a real `#[test]` function at a repository path,
//    found by reading the file rather than trusted from the row.
// 3. A row outside `Generated` names a typed safety boundary and a concrete
//    reason. "Not modelled" alone is not one (`03-coverage-model.md`,
//    "Command accountability").
// 4. A `Privileged` row cites an `#[ignore]`d test that a workflow runs by name
//    with `--ignored`; every other row cites at least one test that runs,
//    unconditionally, in the default `cargo nextest run --workspace`.
//
// ----------------------------------------------------------------------------
// FINAL CROSS-TRACK EVIDENCE.
// ----------------------------------------------------------------------------
// Every `Generated` row cites the default 256+ case real-process run plus the
// checked-in inventory and pairwise-witness contracts. Every `Scripted` row
// cites the default 32+ case WSL run plus its inventory contract. These shared
// constants keep a leaf from quietly retaining pre-corpus evidence after the
// corpus or its authoritative test is renamed.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

/// Where a leaf's behaviour is proved, one class per published leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// Modelled local chain: executed by the black-box chain generator against
    /// an isolated data root, through real `runner-manager` processes.
    Generated,
    /// Scripted WSL chain: driven through the private `Workstation` harness in
    /// `crates/app/src/cli/wsl_acceptance.rs` over `ScriptedRunner`.
    Scripted,
    /// An existing dedicated acceptance test outside the generator.
    Dedicated,
    /// A privileged CI test: `#[ignore]`d locally, run by name in a workflow.
    Privileged,
    /// An intentionally non-executable surface check (`--help`/parse only).
    SurfaceOnly,
}

impl Coverage {
    /// Whether the combinatorial local-chain generator executes this leaf.
    /// Every other class is an exclusion and must say why.
    pub const fn is_generated(self) -> bool {
        matches!(self, Self::Generated)
    }
}

/// The reason a leaf is kept out of generated execution. Typed on purpose: the
/// set is reviewed here, and "not modelled" cannot be spelled as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    NonTerminating,
    HostServiceManager,
    SelfReplacingDownload,
    TerminalOwnership,
    WslPlatform,
    LivePermissionProbe,
}

impl Boundary {
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NonTerminating => {
                "runs until it is signalled, so a chain would never reach its next action"
            }
            Self::HostServiceManager => {
                "reads or changes the machine-wide service manager, outside every \
                 scenario's temporary roots"
            }
            Self::SelfReplacingDownload => {
                "downloads a release and replaces the executable under test"
            }
            Self::TerminalOwnership => {
                "takes over the controlling terminal and waits for operator input"
            }
            Self::WslPlatform => {
                "addresses real wsl.exe, distribution, and Task Scheduler state unless \
                 driven through the scripted WSL seam"
            }
            Self::LivePermissionProbe => {
                "queries live GitHub permission state rather than only local persisted state"
            }
        }
    }
}

/// Why a leaf is excluded from generated execution.
#[derive(Clone, Copy, Debug)]
pub struct Exclusion {
    pub boundary: Boundary,
    /// The leaf-specific consequence of the boundary, in a sentence a reviewer
    /// can check against the code.
    pub reason: &'static str,
}

/// One test function, by repository-relative path and name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub file: &'static str,
    pub test: &'static str,
}

/// One published leaf's reviewed classification.
#[derive(Clone, Copy, Debug)]
pub struct Classification {
    /// `family` or `family subcommand`, exactly as `--help` spells it.
    pub leaf: &'static str,
    pub coverage: Coverage,
    pub evidence: &'static [Evidence],
    /// Required for every class except [`Coverage::Generated`], forbidden for it.
    pub exclusion: Option<Exclusion>,
}

const fn at(file: &'static str, test: &'static str) -> Evidence {
    Evidence { file, test }
}

const AUTH_STATES: &str = "crates/app/tests/auth_states.rs";
const LOCAL_CHAIN_ACCEPTANCE: &str = "crates/app/tests/cli_chains_acceptance.rs";
const LOCAL_CHAIN_MODEL: &str = "crates/app/tests/cli_chains_model.rs";
const SURFACE_TESTS: &str = "crates/app/tests/cli_command_surface.rs";
const DAEMON_UNIT: &str = "crates/app/src/cli/daemon.rs";
const SERVICE_UNIT: &str = "crates/app/src/cli/service.rs";
const PRIVILEGED_SERVICE: &str = "crates/platform/tests/privileged_service_installer.rs";
const PRIVILEGED_WSL: &str = "crates/platform/tests/privileged_wsl_lifecycle.rs";
const TUI_SHELL: &str = "crates/app/src/tui/shell.rs";
const UPDATE: &str = "crates/app/tests/update_command.rs";
const WSL_ACCEPTANCE: &str = "crates/app/src/cli/wsl_acceptance.rs";

pub const LOCAL_CHAIN_EVIDENCE: &[Evidence] = &[
    at(
        LOCAL_CHAIN_ACCEPTANCE,
        "the_complete_local_corpus_agrees_with_the_model_through_real_processes",
    ),
    at(
        LOCAL_CHAIN_MODEL,
        "the_inventory_holds_at_least_256_meaningful_local_cases",
    ),
    at(
        LOCAL_CHAIN_MODEL,
        "case_identifiers_are_sequential_unique_and_round_trip",
    ),
    at(
        LOCAL_CHAIN_MODEL,
        "every_compatible_mutating_pair_has_a_named_witness",
    ),
];

pub const WSL_CHAIN_EVIDENCE: &[Evidence] = &[
    at(
        WSL_ACCEPTANCE,
        "the_inventory_holds_at_least_32_distinct_named_cases_covering_every_state",
    ),
    at(
        WSL_ACCEPTANCE,
        "every_case_in_the_inventory_runs_exactly_once_and_matches_its_transitions",
    ),
];

const fn generated(leaf: &'static str) -> Classification {
    Classification {
        leaf,
        coverage: Coverage::Generated,
        evidence: LOCAL_CHAIN_EVIDENCE,
        exclusion: None,
    }
}

const fn scripted(leaf: &'static str) -> Classification {
    Classification {
        leaf,
        coverage: Coverage::Scripted,
        evidence: WSL_CHAIN_EVIDENCE,
        exclusion: Some(Exclusion {
            boundary: Boundary::WslPlatform,
            reason: WSL_REASON,
        }),
    }
}

const WSL_REASON: &str = "Every `wsl` leaf drives `wsl.exe` on the host (and `install` also \
     Task Scheduler and a credential device flow). Ordinary CI legs have no provisioned \
     distribution, so these run only through the scripted `Workstation` seam, never as \
     real processes in a local chain.";

/// The reviewed classification of every published leaf.
pub const MANIFEST: &[Classification] = &[
    // -- auth: sign-in state is modelled as credential presence -------------
    generated("auth login"),
    Classification {
        leaf: "auth status",
        coverage: Coverage::Dedicated,
        evidence: &[
            at(
                AUTH_STATES,
                "a_machine_with_no_credential_reports_not_authenticated",
            ),
            at(
                AUTH_STATES,
                "an_accepted_credential_reports_what_it_can_reach",
            ),
        ],
        exclusion: Some(Exclusion {
            boundary: Boundary::LivePermissionProbe,
            reason: "Unlike the local model's credential-presence setup, `auth status` performs \
                     live GitHub permission probes. Its dedicated loopback tests exercise those \
                     responses without making the generated local corpus depend on GitHub.",
        }),
    },
    generated("auth logout"),
    // -- host ----------------------------------------------------------------
    generated("host set-capacity"),
    generated("host set-runtime-root"),
    generated("host reset-runtime-root"),
    generated("host show"),
    // -- repo ----------------------------------------------------------------
    generated("repo add"),
    generated("repo list"),
    generated("repo set-capacity"),
    generated("repo set-scale"),
    generated("repo add-label"),
    generated("repo remove-label"),
    generated("repo set-workspace"),
    generated("repo remove"),
    // -- org -----------------------------------------------------------------
    generated("org add"),
    generated("org list"),
    generated("org set-capacity"),
    generated("org set-scale"),
    generated("org add-label"),
    generated("org remove-label"),
    generated("org remove"),
    // -- daemon --------------------------------------------------------------
    Classification {
        leaf: "daemon run",
        coverage: Coverage::Dedicated,
        evidence: &[
            at(
                SURFACE_TESTS,
                "daemon_run_refuses_a_second_instance_without_prompting",
            ),
            at(
                DAEMON_UNIT,
                "shutdown_loop_supervises_a_busy_child_to_completion_without_terminating_it",
            ),
            at(
                PRIVILEGED_SERVICE,
                "production_daemon_entrypoint_reaches_running_and_handles_scm_stop",
            ),
        ],
        exclusion: Some(Exclusion {
            boundary: Boundary::NonTerminating,
            reason: "`daemon run` is the long-lived host agent: it takes the single-instance \
                     lock and supervises runners until a stop signal arrives, so it cannot be \
                     one step of a chain. Its supervision loop is tested in-process and its \
                     lock refusal through the real binary.",
        }),
    },
    // -- service -------------------------------------------------------------
    Classification {
        leaf: "service install",
        coverage: Coverage::Privileged,
        evidence: &[
            at(
                PRIVILEGED_SERVICE,
                "install_status_and_uninstall_round_trip_against_the_real_service_manager",
            ),
            at(
                SERVICE_UNIT,
                "the_service_binary_is_a_copy_this_product_owns_and_reinstalling_replaces_it",
            ),
        ],
        exclusion: Some(Exclusion {
            boundary: Boundary::HostServiceManager,
            reason: "Registers the product with the machine's real service manager and copies \
                     the binary to an owned location; a generated run would leave a machine-wide \
                     registration behind. Only the Windows privileged job performs it, under \
                     fixture names with a leak check.",
        }),
    },
    Classification {
        leaf: "service uninstall",
        coverage: Coverage::Privileged,
        evidence: &[
            at(
                PRIVILEGED_SERVICE,
                "uninstall_leaves_configuration_sqlite_secrets_and_cache_byte_for_byte",
            ),
            at(
                PRIVILEGED_SERVICE,
                "install_status_and_uninstall_round_trip_against_the_real_service_manager",
            ),
        ],
        exclusion: Some(Exclusion {
            boundary: Boundary::HostServiceManager,
            reason: "Removes a machine-wide service registration; under a generator it could \
                     remove the operator's own installation. It runs only against fixture \
                     registrations in the privileged job.",
        }),
    },
    Classification {
        leaf: "service status",
        coverage: Coverage::Dedicated,
        evidence: &[
            at(
                SURFACE_TESTS,
                "service_status_runs_unattended_and_reports_offline_honestly",
            ),
            at(
                SURFACE_TESTS,
                "the_suite_asks_about_a_disposable_registration_and_says_which_one",
            ),
            at(
                SERVICE_UNIT,
                "stale_binary_status_prints_the_diagnosis_and_returns_an_error",
            ),
        ],
        exclusion: Some(Exclusion {
            boundary: Boundary::HostServiceManager,
            reason: "Queries the host's service manager, which `--data-dir` does not move, so \
                     its answer depends on what is installed on the machine. Its dedicated \
                     tests pin the fixture service-name tag that isolates it.",
        }),
    },
    // -- tui -----------------------------------------------------------------
    Classification {
        leaf: "tui",
        coverage: Coverage::Dedicated,
        evidence: &[
            at(
                TUI_SHELL,
                "tui_refuses_captured_or_redirected_stdio_instead_of_waiting_for_events",
            ),
            at(
                TUI_SHELL,
                "production_shell_routes_navigation_filter_activation_and_render_to_screen_model",
            ),
        ],
        exclusion: Some(Exclusion {
            boundary: Boundary::TerminalOwnership,
            reason: "Enters raw mode and the alternate screen and runs an event loop until the \
                     operator quits; with captured stdio it refuses instead. Its reducer, input \
                     and render paths are tested in-process against recorded sessions.",
        }),
    },
    // -- status: the modelled readback ---------------------------------------
    generated("status"),
    // -- update --------------------------------------------------------------
    Classification {
        leaf: "update",
        coverage: Coverage::Dedicated,
        evidence: &[
            at(UPDATE, "a_newer_release_replaces_the_running_binary"),
            at(UPDATE, "check_reports_the_new_version_and_changes_nothing"),
            at(
                UPDATE,
                "a_substituted_archive_is_refused_and_nothing_is_installed",
            ),
        ],
        exclusion: Some(Exclusion {
            boundary: Boundary::SelfReplacingDownload,
            reason: "Without `--check` it downloads a release archive and replaces the running \
                     executable; even `--check` resolves a release channel. The dedicated suite \
                     drives it against a loopback asset source and a disposable binary copy.",
        }),
    },
    // -- wsl: the scripted seam ----------------------------------------------
    scripted("wsl list"),
    Classification {
        leaf: "wsl install",
        coverage: Coverage::Scripted,
        evidence: &[
            at(
                WSL_ACCEPTANCE,
                "the_inventory_holds_at_least_32_distinct_named_cases_covering_every_state",
            ),
            at(
                WSL_ACCEPTANCE,
                "every_case_in_the_inventory_runs_exactly_once_and_matches_its_transitions",
            ),
            at(
                PRIVILEGED_WSL,
                "the_rendered_task_is_one_task_scheduler_accepts_reads_back_and_removes",
            ),
        ],
        exclusion: Some(Exclusion {
            boundary: Boundary::WslPlatform,
            reason: WSL_REASON,
        }),
    },
    scripted("wsl status"),
    scripted("wsl detach"),
];

/// The surface test that proves the hidden bridges stay reachable and hidden.
/// Hidden commands are kept out of [`MANIFEST`]; this is what covers them.
pub const HIDDEN_BRIDGE_EVIDENCE: Evidence = at(
    SURFACE_TESTS,
    "every_hidden_bridge_still_parses_and_is_still_absent_from_help",
);

/// The leaves `02-target-architecture.md` ¶4 names as never executed by the
/// generator, transcribed by hand like `SURFACE` and for the same reason: a row
/// flipped to `Generated` must contradict the design, not quietly redefine it.
pub const NEVER_GENERATED: [&str; 9] = [
    "daemon run",
    "service install",
    "service uninstall",
    "update",
    "tui",
    "wsl list",
    "wsl install",
    "wsl status",
    "wsl detach",
];

// ---------------------------------------------------------------------------
// Defects
// ---------------------------------------------------------------------------

/// One way the manifest can be wrong. Checks collect every defect rather than
/// stopping at the first, so one run shows a reviewer the whole correction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Defect {
    /// A published leaf with no row.
    Unclassified { leaf: String },
    /// A row whose leaf is not published.
    Stale { leaf: String },
    /// A leaf with more than one row.
    Duplicate { leaf: String, rows: usize },
    /// A row for a command that is deliberately hidden.
    HiddenLeafClassified { leaf: String },
    /// A row that cites no evidence at all.
    NoEvidence { leaf: String },
    /// A cited test that does not exist as a test.
    MissingEvidence {
        leaf: String,
        evidence: Evidence,
        why: String,
    },
    /// An exclusion from generated execution with no stated boundary.
    UnjustifiedExclusion { leaf: String, coverage: Coverage },
    /// An exclusion whose reason says nothing concrete.
    VagueExclusion {
        leaf: String,
        boundary: Boundary,
        reason: String,
    },
    /// A generated leaf that also claims a safety exclusion.
    GeneratedLeafExcluded { leaf: String },
    /// A leaf the architecture keeps out of the generator, classified into it.
    GeneratedAgainstArchitecture { leaf: String },
    /// A non-privileged row with no test that runs by default on every OS.
    NoDefaultRunEvidence { leaf: String },
    /// A privileged row with no `#[ignore]`d test that a workflow runs.
    NoPrivilegedEvidence { leaf: String },
    /// An `#[ignore]`d test no workflow runs by name, so it runs nowhere.
    IgnoredEvidenceNotWired { leaf: String, evidence: Evidence },
}

impl fmt::Display for Defect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unclassified { leaf } => write!(
                f,
                "`{leaf}` is published but has no classification; add a reviewed row to \
                 MANIFEST"
            ),
            Self::Stale { leaf } => write!(
                f,
                "`{leaf}` is classified but is not a published leaf; remove or rename the row"
            ),
            Self::Duplicate { leaf, rows } => {
                write!(f, "`{leaf}` has {rows} rows; a leaf has exactly one")
            }
            Self::HiddenLeafClassified { leaf } => write!(
                f,
                "`{leaf}` is a hidden command and must stay out of the public inventory"
            ),
            Self::NoEvidence { leaf } => write!(f, "`{leaf}` cites no evidence"),
            Self::MissingEvidence {
                leaf,
                evidence,
                why,
            } => write!(
                f,
                "`{leaf}` cites `{}::{}`, which is not existing evidence: {why}",
                evidence.file, evidence.test
            ),
            Self::UnjustifiedExclusion { leaf, coverage } => write!(
                f,
                "`{leaf}` is {coverage:?}, which excludes it from generated execution, but \
                 states no safety boundary"
            ),
            Self::VagueExclusion {
                leaf,
                boundary,
                reason,
            } => write!(
                f,
                "`{leaf}` is excluded because it {}, but its reason does not say what that \
                 means for this leaf: {reason:?}",
                boundary.describe()
            ),
            Self::GeneratedLeafExcluded { leaf } => write!(
                f,
                "`{leaf}` is Generated but also claims a safety exclusion; it is one or the other"
            ),
            Self::GeneratedAgainstArchitecture { leaf } => write!(
                f,
                "`{leaf}` is Generated, but `02-target-architecture.md` ¶4 keeps it out of \
                 the generator as long-lived, terminal-owning, self-replacing or host-mutating"
            ),
            Self::NoDefaultRunEvidence { leaf } => write!(
                f,
                "`{leaf}` cites no test that runs unconditionally in the default workspace \
                 test run"
            ),
            Self::NoPrivilegedEvidence { leaf } => write!(
                f,
                "`{leaf}` is Privileged but cites no `#[ignore]`d test that a workflow runs \
                 with `--ignored`"
            ),
            Self::IgnoredEvidenceNotWired { leaf, evidence } => write!(
                f,
                "`{leaf}` cites `{}::{}`, which is `#[ignore]`d and run by no workflow, so it \
                 verifies nothing",
                evidence.file, evidence.test
            ),
        }
    }
}

/// Renders a defect list for an assertion message.
pub fn report(defects: &[Defect]) -> String {
    defects
        .iter()
        .map(|defect| format!("  - {defect}"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// The inventory check: missing, stale, duplicate, hidden
// ---------------------------------------------------------------------------

/// Compares the rows with the published and hidden leaf sets.
pub fn inventory_defects(
    published: &[String],
    hidden: &[String],
    manifest: &[Classification],
) -> Vec<Defect> {
    let mut rows: BTreeMap<&str, usize> = BTreeMap::new();
    for row in manifest {
        *rows.entry(row.leaf).or_default() += 1;
    }

    let mut defects = Vec::new();
    for leaf in published {
        if !rows.contains_key(leaf.as_str()) {
            defects.push(Defect::Unclassified { leaf: leaf.clone() });
        }
    }
    for (leaf, count) in &rows {
        if hidden.iter().any(|hidden| hidden == leaf) {
            defects.push(Defect::HiddenLeafClassified {
                leaf: (*leaf).to_string(),
            });
        } else if !published.iter().any(|published| published == leaf) {
            defects.push(Defect::Stale {
                leaf: (*leaf).to_string(),
            });
        }
        if *count > 1 {
            defects.push(Defect::Duplicate {
                leaf: (*leaf).to_string(),
                rows: *count,
            });
        }
    }
    defects
}

/// Rows that classify a [`NEVER_GENERATED`] leaf as `Generated`. Such a row can
/// pass both other checks -- flipping the class and dropping the exclusion
/// leaves real evidence behind -- so the design's boundary is checked on its own.
pub fn architecture_defects(manifest: &[Classification]) -> Vec<Defect> {
    manifest
        .iter()
        .filter(|row| row.coverage.is_generated() && NEVER_GENERATED.contains(&row.leaf))
        .map(|row| Defect::GeneratedAgainstArchitecture {
            leaf: row.leaf.to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The justification check: evidence exists, exclusions are concrete
// ---------------------------------------------------------------------------

/// What the justification check reads. The repository in the real test; a
/// table of synthetic files in the controls that prove the check can fail.
pub trait EvidenceSource {
    /// A repository-relative file's text, or `None` when there is no such file.
    fn source(&self, file: &str) -> Option<String>;
    /// Every workflow under `.github/workflows/`, concatenated.
    fn workflows(&self) -> String;
}

/// The real repository, rooted at its top-level directory.
pub struct Repository {
    pub root: PathBuf,
}

impl EvidenceSource for Repository {
    fn source(&self, file: &str) -> Option<String> {
        std::fs::read_to_string(self.root.join(file))
            .ok()
            .map(|text| text.replace("\r\n", "\n"))
    }

    fn workflows(&self) -> String {
        let directory = self.root.join(".github").join("workflows");
        let Ok(entries) = std::fs::read_dir(&directory) else {
            return String::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "yml" || extension == "yaml")
            })
            .collect();
        paths.sort();
        paths
            .iter()
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .map(|text| text.replace("\r\n", "\n"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// What the attributes above a test function say about when it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TestFunction {
    /// `#[ignore]`, or an `ignore` inside `cfg_attr`.
    pub ignored: bool,
    /// `#[cfg(...)]` or `cfg_attr(...)` on the function: it may not run on
    /// every CI leg.
    pub conditional: bool,
}

/// Finds `fn name(` in `source` and reads the attribute block above it.
///
/// The block is every contiguous line above the signature that is a comment or
/// an attribute (including the inside of a multi-line attribute); it ends at a
/// blank line or at a line that closes code (`}`, `;`, `{`). A function without
/// `#[test]` or `#[tokio::test]` in its block is not evidence, however its name
/// reads.
pub fn find_test(source: &str, name: &str) -> Result<TestFunction, String> {
    let lines: Vec<&str> = source.lines().collect();
    let signature = format!("fn {name}(");
    let mut found_a_function = false;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let item = trimmed
            .strip_prefix("pub ")
            .unwrap_or(trimmed)
            .trim_start_matches("async ");
        if !item.starts_with(&signature) {
            continue;
        }
        found_a_function = true;

        let mut attributes: Vec<&str> = Vec::new();
        for above in lines[..index].iter().rev() {
            let above = above.trim();
            if above.starts_with("//") {
                continue;
            }
            if above.is_empty()
                || above.ends_with('}')
                || above.ends_with(';')
                || above.ends_with('{')
            {
                break;
            }
            attributes.push(above);
        }
        let is_test = attributes.iter().any(|attribute| {
            attribute.starts_with("#[test]") || attribute.starts_with("#[tokio::test")
        });
        if !is_test {
            continue;
        }
        let block = attributes.join(" ");
        return Ok(TestFunction {
            ignored: block.contains("#[ignore")
                || (block.contains("cfg_attr") && block.contains("ignore")),
            conditional: block.contains("#[cfg(") || block.contains("cfg_attr("),
        });
    }
    Err(if found_a_function {
        format!("`fn {name}` exists but carries no `#[test]` attribute")
    } else {
        format!("no `fn {name}` in the file")
    })
}

/// A path the manifest may cite: repository-relative, `/`-separated, `.rs`.
fn check_path(file: &str) -> Result<(), String> {
    let absolute = file.starts_with('/') || file.contains(':');
    let escapes = file
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..");
    if file.contains('\\') || absolute || escapes {
        return Err("the path must be repository-relative and `/`-separated".to_string());
    }
    if !file.ends_with(".rs") {
        return Err("evidence must be a Rust test source".to_string());
    }
    Ok(())
}

/// Resolves one piece of evidence to the test it names.
///
/// A file-level `#![cfg(...)]` (the privileged suites carry `#![cfg(windows)]`)
/// makes every test in it conditional, whatever its own attributes say. A
/// `#[cfg]` on an enclosing inline `mod` is not seen; no cited test sits in
/// one, and a reviewer adding such a citation has the attribute in view.
pub fn check_evidence(
    evidence: &Evidence,
    source: &dyn EvidenceSource,
) -> Result<TestFunction, String> {
    check_path(evidence.file)?;
    let text = source
        .source(evidence.file)
        .ok_or_else(|| "the file does not exist".to_string())?;
    let mut test = find_test(&text, evidence.test)?;
    test.conditional |= text
        .lines()
        .any(|line| line.trim_start().starts_with("#![cfg("));
    Ok(test)
}

/// Whether some workflow runs this integration-test target by name with
/// `--ignored` on the same command line.
///
/// Comments and step names are not command lines: a `- name:` that mentions
/// `--ignored` over a step that no longer passes it must not count as wiring.
/// Nor does a line whose libtest filters leave this test out: a positional
/// filter or `--skip` after ` -- ` narrows the run by name.
pub fn is_wired(evidence: &Evidence, workflows: &str) -> bool {
    if !evidence.file.contains("/tests/") {
        // Only an integration-test target can be selected with `--test`.
        return false;
    }
    let stem = evidence
        .file
        .rsplit('/')
        .next()
        .and_then(|name| name.strip_suffix(".rs"))
        .unwrap_or_default();
    let flag = format!("--test {stem}");
    workflows.lines().any(|line| {
        let trimmed = line.trim_start().trim_start_matches("- ");
        if trimmed.starts_with('#') || trimmed.starts_with("name:") {
            return false;
        }
        line.contains("--ignored")
            && line.match_indices(&flag).any(|(offset, _)| {
                !line[offset + flag.len()..]
                    .starts_with(|next: char| next.is_ascii_alphanumeric() || next == '_')
            })
            && harness_selects(line, evidence.test)
    })
}

/// Whether the libtest arguments after ` -- ` on `line` keep `test` in the
/// run. A positional filter keeps only names containing it, `--skip` drops
/// names containing its value, and `--exact` makes both whole-name matches.
fn harness_selects(line: &str, test: &str) -> bool {
    let Some((_, harness)) = line.split_once(" -- ") else {
        return true;
    };
    let mut tokens = harness
        .split_whitespace()
        .take_while(|token| !matches!(*token, "&&" | "||" | ";" | "|"));
    let mut filters = Vec::new();
    let mut skips = Vec::new();
    let mut exact = false;
    while let Some(token) = tokens.next() {
        match token {
            "--exact" => exact = true,
            "--skip" => skips.extend(tokens.next()),
            // libtest options that take their value as the next word.
            "--test-threads" | "--logfile" | "--color" | "--format" | "--shuffle-seed" | "-Z" => {
                tokens.next();
            }
            "\\" => {}
            option if option.starts_with('-') => {}
            filter => filters.push(filter),
        }
    }
    let matches = |pattern: &&str| {
        let pattern = pattern.trim_matches(['\'', '"']);
        if exact {
            test == pattern
        } else {
            test.contains(pattern)
        }
    };
    (filters.is_empty() || filters.iter().any(matches)) && !skips.iter().any(matches)
}

/// Phrases that restate "not covered" rather than naming a boundary.
const NON_REASONS: [&str; 7] = [
    "not modelled",
    "not modeled",
    "unmodelled",
    "out of scope",
    "todo",
    "tbd",
    "n/a",
];

/// The shortest reason that can name a consequence rather than a label.
const MINIMUM_REASON: usize = 40;

/// Checks every row's exclusion and evidence against `source`.
pub fn justification_defects(
    manifest: &[Classification],
    source: &dyn EvidenceSource,
) -> Vec<Defect> {
    let workflows = source.workflows();
    let mut defects = Vec::new();
    for row in manifest {
        let leaf = row.leaf.to_string();

        match (row.coverage.is_generated(), row.exclusion) {
            (true, Some(_)) => defects.push(Defect::GeneratedLeafExcluded { leaf: leaf.clone() }),
            (false, None) => defects.push(Defect::UnjustifiedExclusion {
                leaf: leaf.clone(),
                coverage: row.coverage,
            }),
            (false, Some(exclusion)) => {
                let reason = exclusion.reason.trim();
                let lowered = reason.to_lowercase();
                let restates = NON_REASONS.iter().any(|phrase| lowered.contains(phrase));
                if reason.chars().count() < MINIMUM_REASON || restates {
                    defects.push(Defect::VagueExclusion {
                        leaf: leaf.clone(),
                        boundary: exclusion.boundary,
                        reason: reason.to_string(),
                    });
                }
            }
            (true, None) => {}
        }

        if row.evidence.is_empty() {
            defects.push(Defect::NoEvidence { leaf: leaf.clone() });
            continue;
        }

        let mut runs_by_default = false;
        let mut runs_privileged = false;
        for evidence in row.evidence {
            match check_evidence(evidence, source) {
                Err(why) => defects.push(Defect::MissingEvidence {
                    leaf: leaf.clone(),
                    evidence: *evidence,
                    why,
                }),
                Ok(test) if test.ignored => {
                    if is_wired(evidence, &workflows) {
                        runs_privileged = true;
                    } else {
                        defects.push(Defect::IgnoredEvidenceNotWired {
                            leaf: leaf.clone(),
                            evidence: *evidence,
                        });
                    }
                }
                Ok(test) => runs_by_default |= !test.conditional,
            }
        }

        if row.coverage == Coverage::Privileged {
            if !runs_privileged {
                defects.push(Defect::NoPrivilegedEvidence { leaf });
            }
        } else if !runs_by_default {
            defects.push(Defect::NoDefaultRunEvidence { leaf });
        }
    }
    defects
}

// ---------------------------------------------------------------------------
// Controls: the justification check fails on every defect it names
// ---------------------------------------------------------------------------
// The real manifest passes, so on its own it proves nothing about the check.
// These rows run against a synthetic repository, where each defect can be
// planted without touching a real test file, and the first control shows the
// well-formed version of every class passing.

mod controls {
    use super::*;

    const FIXTURE: &str = "crates/app/tests/fixture.rs";
    const GATED_FILE: &str = "crates/platform/tests/gated.rs";
    const UNIT: &str = "crates/app/src/cli/fixture.rs";

    const FIXTURE_SOURCE: &str = r#"
use std::path::Path;

/// Runs on every leg.
#[test]
fn runs_everywhere() {}

#[test]
#[cfg(windows)]
fn runs_on_windows_only() {}

#[cfg_attr(
    not(windows),
    ignore = "needs the service manager"
)]
#[test]
fn ignored_off_windows() {}

#[test]
#[ignore = "privileged: run by name in CI"]
fn privileged_case() {}

fn helper_named_like_a_test(path: &Path) -> bool {
    path.exists()
}

#[tokio::test(flavor = "current_thread")]
async fn runs_everywhere_async() {}
"#;

    const GATED_SOURCE: &str = r#"
#![cfg(windows)]

#[test]
fn looks_unconditional() {}
"#;

    const WIRED: &str = r#"
      - name: privileged suite
        run: |
          cargo test -p runner-manager \
            --test fixture -- --ignored --test-threads=1
"#;

    struct Table {
        workflows: &'static str,
    }

    impl EvidenceSource for Table {
        fn source(&self, file: &str) -> Option<String> {
            match file {
                FIXTURE | UNIT => Some(FIXTURE_SOURCE.to_string()),
                GATED_FILE => Some(GATED_SOURCE.to_string()),
                _ => None,
            }
        }

        fn workflows(&self) -> String {
            self.workflows.to_string()
        }
    }

    const WIRED_REPOSITORY: Table = Table { workflows: WIRED };

    const CONCRETE: &str = "Takes the single-instance lock and never exits on its own, so a \
                            chain would block on it forever.";

    const LEAF: &str = "host show";

    /// A row for [`LEAF`]. Rows in `MANIFEST` borrow `'static` evidence, so a
    /// control's evidence is leaked; a test process's lifetime is the point.
    fn row(
        coverage: Coverage,
        evidence: &[Evidence],
        exclusion: Option<Exclusion>,
    ) -> Classification {
        Classification {
            leaf: LEAF,
            coverage,
            evidence: Box::leak(evidence.to_vec().into_boxed_slice()),
            exclusion,
        }
    }

    fn excluded(boundary: Boundary, reason: &'static str) -> Option<Exclusion> {
        Some(Exclusion { boundary, reason })
    }

    fn defects_of(row: Classification, source: &dyn EvidenceSource) -> Vec<Defect> {
        justification_defects(&[row], source)
    }

    #[test]
    fn a_well_formed_row_of_every_class_is_accepted() {
        let rows = [
            row(Coverage::Generated, &[at(FIXTURE, "runs_everywhere")], None),
            row(
                Coverage::Scripted,
                &[at(UNIT, "runs_everywhere_async")],
                excluded(Boundary::WslPlatform, CONCRETE),
            ),
            row(
                Coverage::Dedicated,
                &[
                    at(FIXTURE, "runs_on_windows_only"),
                    at(FIXTURE, "runs_everywhere"),
                ],
                excluded(Boundary::NonTerminating, CONCRETE),
            ),
            row(
                Coverage::Privileged,
                &[at(FIXTURE, "privileged_case")],
                excluded(Boundary::HostServiceManager, CONCRETE),
            ),
            row(
                Coverage::SurfaceOnly,
                &[at(FIXTURE, "runs_everywhere")],
                excluded(Boundary::TerminalOwnership, CONCRETE),
            ),
        ];
        for row in rows {
            let defects = defects_of(row, &WIRED_REPOSITORY);
            assert!(
                defects.is_empty(),
                "a well-formed {:?} row must pass, or every rejection below is \
                 meaningless:\n{}",
                row.coverage,
                report(&defects)
            );
        }
    }

    #[test]
    fn evidence_that_names_no_real_test_is_rejected() {
        let cases = [
            (
                at("crates/app/tests/absent.rs", "runs_everywhere"),
                "does not exist",
            ),
            (at(FIXTURE, "renamed_away"), "no `fn renamed_away`"),
            (at(FIXTURE, "helper_named_like_a_test"), "no `#[test]`"),
            (at(FIXTURE, "runs_everywhere_async_"), "no `fn"),
            (
                at("/crates/app/tests/fixture.rs", "runs_everywhere"),
                "repository-relative",
            ),
            (
                at("crates\\app\\tests\\fixture.rs", "runs_everywhere"),
                "repository-relative",
            ),
            (
                at("crates/app/../app/tests/fixture.rs", "runs_everywhere"),
                "repository-relative",
            ),
            (
                at("crates/app/tests/fixture.md", "runs_everywhere"),
                "Rust test source",
            ),
        ];
        for (evidence, why) in cases {
            let defects = defects_of(
                row(Coverage::Generated, &[evidence], None),
                &WIRED_REPOSITORY,
            );
            assert!(
                defects.iter().any(|defect| matches!(
                    defect,
                    Defect::MissingEvidence { why: reason, .. } if reason.contains(why)
                )),
                "{evidence:?} must be rejected as missing evidence ({why}); got:\n{}",
                report(&defects)
            );
        }

        let defects = defects_of(row(Coverage::Generated, &[], None), &WIRED_REPOSITORY);
        assert_eq!(
            defects,
            [Defect::NoEvidence {
                leaf: LEAF.to_string()
            }],
            "a row with no evidence at all must be rejected"
        );
    }

    #[test]
    fn an_exclusion_must_name_a_concrete_boundary_and_a_generated_row_none() {
        let evidence = &[at(FIXTURE, "runs_everywhere")];

        for coverage in [
            Coverage::Scripted,
            Coverage::Dedicated,
            Coverage::Privileged,
            Coverage::SurfaceOnly,
        ] {
            let defects = defects_of(row(coverage, evidence, None), &WIRED_REPOSITORY);
            assert!(
                defects.contains(&Defect::UnjustifiedExclusion {
                    leaf: LEAF.to_string(),
                    coverage,
                }),
                "{coverage:?} without a boundary must be rejected; got:\n{}",
                report(&defects)
            );
        }

        for reason in [
            "Not modelled.",
            "Not modelled by the generator yet; revisit this row after the corpus lands.",
            "Out of scope for the local chain generator and its reference model.",
            "TODO: explain why this leaf is kept out of generated execution.",
            "   ",
            "Long-running.",
        ] {
            let defects = defects_of(
                row(
                    Coverage::Dedicated,
                    evidence,
                    excluded(Boundary::NonTerminating, reason),
                ),
                &WIRED_REPOSITORY,
            );
            assert!(
                defects
                    .iter()
                    .any(|defect| matches!(defect, Defect::VagueExclusion { .. })),
                "{reason:?} is not a concrete safety boundary; got:\n{}",
                report(&defects)
            );
        }

        let defects = defects_of(
            row(
                Coverage::Generated,
                evidence,
                excluded(Boundary::NonTerminating, CONCRETE),
            ),
            &WIRED_REPOSITORY,
        );
        assert_eq!(
            defects,
            [Defect::GeneratedLeafExcluded {
                leaf: LEAF.to_string()
            }],
            "a generated row that also claims an exclusion must be rejected"
        );
    }

    #[test]
    fn only_an_unconditional_test_counts_as_default_run_evidence() {
        for evidence in [
            at(FIXTURE, "runs_on_windows_only"),
            at(FIXTURE, "ignored_off_windows"),
            at(FIXTURE, "privileged_case"),
            at(GATED_FILE, "looks_unconditional"),
        ] {
            for (coverage, exclusion) in [
                (Coverage::Generated, None),
                (
                    Coverage::Dedicated,
                    excluded(Boundary::NonTerminating, CONCRETE),
                ),
            ] {
                let defects = defects_of(row(coverage, &[evidence], exclusion), &WIRED_REPOSITORY);
                assert!(
                    defects.contains(&Defect::NoDefaultRunEvidence {
                        leaf: LEAF.to_string()
                    }),
                    "{coverage:?} citing only {evidence:?} has nothing that runs on every \
                     leg of the default test run; got:\n{}",
                    report(&defects)
                );
            }
        }
    }

    #[test]
    fn privileged_evidence_must_be_run_by_name_by_a_workflow() {
        let privileged = &[at(FIXTURE, "privileged_case")];
        let exclusion = excluded(Boundary::HostServiceManager, CONCRETE);

        for workflows in [
            // No workflow at all.
            "",
            // The target runs, but not its ignored tests.
            "        run: cargo test -p runner-manager --test fixture\n",
            // Only a step name or a comment still mentions it.
            "      - name: cargo test --test fixture -- --ignored\n        run: cargo test\n",
            "        # cargo test --test fixture -- --ignored\n",
            // A different target whose name merely starts with this one.
            "        run: cargo test --test fixture_other -- --ignored\n",
            // The target runs, but a libtest filter leaves this test out.
            "        run: cargo test --test fixture -- --ignored another_case\n",
            "        run: cargo test --test fixture -- --ignored --skip privileged\n",
            "        run: cargo test --test fixture -- --ignored --exact privileged\n",
        ] {
            let defects = defects_of(
                row(Coverage::Privileged, privileged, exclusion),
                &Table { workflows },
            );
            assert_eq!(
                defects,
                [
                    Defect::IgnoredEvidenceNotWired {
                        leaf: LEAF.to_string(),
                        evidence: privileged[0],
                    },
                    Defect::NoPrivilegedEvidence {
                        leaf: LEAF.to_string()
                    },
                ],
                "with workflows {workflows:?} the privileged test runs nowhere"
            );
        }

        // Filters that keep the test in the run are still wiring.
        for workflows in [
            "        run: cargo test --test fixture -- --ignored privileged\n",
            "        run: cargo test --test fixture -- --ignored --exact privileged_case --test-threads 1\n",
            "        run: cargo test --test fixture -- --ignored --skip another_case\n",
        ] {
            let defects = defects_of(
                row(Coverage::Privileged, privileged, exclusion),
                &Table { workflows },
            );
            assert!(
                defects.is_empty(),
                "with workflows {workflows:?} the privileged test runs; got:\n{}",
                report(&defects)
            );
        }

        // A privileged row whose only evidence runs by default is not privileged,
        // and a unit test inside `src/` cannot be selected with `--test` at all.
        for evidence in [at(FIXTURE, "runs_everywhere"), at(UNIT, "privileged_case")] {
            let defects = defects_of(
                row(Coverage::Privileged, &[evidence], exclusion),
                &WIRED_REPOSITORY,
            );
            assert!(
                defects.contains(&Defect::NoPrivilegedEvidence {
                    leaf: LEAF.to_string()
                }),
                "a Privileged row citing only {evidence:?} is run by no privileged job; \
                 got:\n{}",
                report(&defects)
            );
        }
    }

    #[test]
    fn every_boundary_describes_a_consequence() {
        for boundary in [
            Boundary::NonTerminating,
            Boundary::HostServiceManager,
            Boundary::SelfReplacingDownload,
            Boundary::TerminalOwnership,
            Boundary::WslPlatform,
        ] {
            assert!(
                boundary.describe().chars().count() >= MINIMUM_REASON,
                "{boundary:?} must describe what it does to a chain, not name itself"
            );
        }
    }
}
