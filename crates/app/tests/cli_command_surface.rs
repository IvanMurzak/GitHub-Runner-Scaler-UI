// owner: f1-cli-auth-host-status
//
// ----------------------------------------------------------------------------
// THE COMMAND LIST IS A CONTRACT, AND `02-target-architecture.md` SAYS SO.
// ----------------------------------------------------------------------------
// "The single binary has these commands. This list is exhaustive."
//
// So this file measures the surface in both directions. A command in the design
// and missing from `--help` is an unfinished build; a command in `--help` and
// not in the design is scope somebody added without a decision. Only checking
// the first direction would let the second happen silently, which is exactly
// what `f1`'s Definition of Done rules out with the words "and nothing beyond
// it".
//
// The list below is transcribed from the design document by hand, on purpose.
// Deriving it from the clap tree would make this test agree with whatever the
// tree says, which is the one thing it must not do.

mod support;

use support::{run, runner_manager};

/// The exhaustive surface, transcribed from `02-target-architecture.md`.
///
/// Top-level commands, and for each family the subcommands under it.
const SURFACE: [(&str, &[&str]); 8] = [
    ("auth", &["login", "status", "logout"]),
    (
        "host",
        &[
            "set-capacity",
            "set-runtime-root",
            "reset-runtime-root",
            "show",
        ],
    ),
    (
        "repo",
        &[
            "add",
            "list",
            "set-capacity",
            "set-scale",
            "add-label",
            "remove-label",
            "set-workspace",
            "remove",
        ],
    ),
    (
        "org",
        &[
            "add",
            "list",
            "set-capacity",
            "set-scale",
            "add-label",
            "remove-label",
            "remove",
        ],
    ),
    ("daemon", &["run"]),
    ("service", &["install", "uninstall", "status"]),
    ("tui", &[]),
    ("status", &[]),
];

/// The command names clap lists under `Commands:` in a help page.
///
/// clap indents each entry by two spaces and puts the name first, so the name
/// is the first whitespace-delimited token of an indented line inside that
/// section. Options are in their own section and are skipped by construction.
fn commands_in(help: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut inside = false;
    for line in help.lines() {
        if line.trim_end() == "Commands:" {
            inside = true;
            continue;
        }
        if inside {
            if line.trim().is_empty() {
                break;
            }
            if !line.starts_with("  ") {
                break;
            }
            let Some(name) = line.split_whitespace().next() else {
                continue;
            };
            // clap renders aliases as `name, alias`; take the primary name.
            names.push(name.trim_end_matches(',').to_string());
        }
    }
    names
}

fn help_for(path: &[&str]) -> String {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let mut command = runner_manager(temporary.path());
    for segment in path {
        command.arg(segment);
    }
    command.arg("--help");
    let outcome = run(command);
    assert_eq!(
        outcome.code,
        0,
        "`{} --help` must succeed; stderr was: {}",
        path.join(" "),
        outcome.stderr
    );
    outcome.stdout
}

#[test]
fn version_reports_the_package_version() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let outcome = run({
        let mut command = runner_manager(temporary.path());
        command.arg("--version");
        command
    });
    assert_eq!(outcome.code, 0, "stderr: {}", outcome.stderr);
    assert_eq!(
        outcome.stdout.trim(),
        format!("runner-manager {}", env!("CARGO_PKG_VERSION")),
        "Journey 0 step 2 is `runner-manager --version` to confirm the install, so the \
         output has to name the product and its version and nothing else"
    );
}

/// Both directions at once: the design's list and `--help`'s list must be the
/// same set.
#[test]
fn the_help_text_lists_the_documented_surface_and_nothing_beyond_it() {
    let mut listed = commands_in(&help_for(&[]));
    listed.sort();
    listed.dedup();

    let mut documented: Vec<String> = SURFACE
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect();
    documented.sort();

    assert!(
        !listed.is_empty(),
        "no commands were parsed out of `--help`. Every assertion below would then be \
         vacuous, so this is a failure and not a clean result."
    );
    assert_eq!(
        listed, documented,
        "`--help` and `02-target-architecture.md` must list the same commands. \
         `02-target-architecture.md` says of its list: \"This list is exhaustive.\""
    );
}

#[test]
fn every_documented_family_lists_exactly_its_documented_subcommands() {
    for (family, subcommands) in SURFACE {
        if subcommands.is_empty() {
            continue;
        }
        let mut listed = commands_in(&help_for(&[family]));
        listed.sort();
        let mut documented: Vec<String> = subcommands.iter().map(|s| (*s).to_string()).collect();
        documented.sort();

        assert!(
            !listed.is_empty(),
            "no subcommands were parsed out of `{family} --help`"
        );
        assert_eq!(
            listed, documented,
            "`{family}`'s subcommands must be exactly the documented ones"
        );
    }
}

/// The parser is what makes the two assertions above meaningful, so it is shown
/// to reject a help page that does not carry the section at all.
#[test]
fn the_help_parser_finds_nothing_in_a_page_without_a_commands_section() {
    assert!(
        commands_in("Usage: runner-manager [OPTIONS]\n\nOptions:\n  -h, --help\n").is_empty(),
        "a page with no `Commands:` section must parse to nothing, so that a help page \
         that stopped listing commands fails the surface test instead of passing it"
    );
    assert_eq!(
        commands_in("Commands:\n  auth  Sign in\n  host  Capacity\n\nOptions:\n  -h\n"),
        ["auth", "host"],
        "and a page that does carry one must parse to its entries, or the test above \
         would pass for the wrong reason"
    );
}

/// Every documented command must at least *parse*. A family declared with the
/// wrong argument shape would otherwise only be found by `f2` or `f3`.
#[test]
fn every_documented_command_is_reachable() {
    for (family, subcommands) in SURFACE {
        let mut paths: Vec<Vec<&str>> = Vec::new();
        if subcommands.is_empty() {
            paths.push(vec![family]);
        } else {
            for subcommand in subcommands {
                paths.push(vec![family, subcommand]);
            }
        }
        for path in paths {
            let help = help_for(&path);
            assert!(
                help.contains("Usage:"),
                "`{}` must have a usage line",
                path.join(" ")
            );
        }
    }
}

/// A command the design does not list must be a usage error, not a surprise.
#[test]
fn an_undocumented_command_is_refused() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let outcome = run({
        let mut command = runner_manager(temporary.path());
        command.arg("teleport");
        command
    });
    assert_eq!(
        outcome.code, 2,
        "clap owns exit code 2 for a usage error, which is why no runtime failure class \
         uses it; got stderr: {}",
        outcome.stderr
    );
}

#[test]
fn service_set_start_mode_is_neither_listed_nor_accepted() {
    let help = help_for(&["service"]);
    assert!(
        !commands_in(&help)
            .iter()
            .any(|name| name == "set-start-mode"),
        "the immutable service surface must not advertise set-start-mode: {help}"
    );

    let temporary = tempfile::tempdir().expect("a temporary directory");
    let outcome = run({
        let mut command = runner_manager(temporary.path());
        command.args(["service", "set-start-mode", "login"]);
        command
    });
    assert_eq!(
        outcome.code, 2,
        "set-start-mode is not an F3 CLI command; stderr: {}",
        outcome.stderr
    );
}

/// `daemon run` is noninteractive: when another instance owns the host it
/// returns immediately with the conflict class and names that holder.
#[test]
fn daemon_run_refuses_a_second_instance_without_prompting() {
    use runner_manager_platform::lock::{HostLock, LockKind};
    use runner_manager_platform::paths::AppPaths;

    let temporary = tempfile::tempdir().expect("a temporary directory");
    let paths = AppPaths::rooted_at(temporary.path());
    paths.create_all().unwrap();
    let _held = HostLock::try_acquire(&paths, LockKind::SingleInstance).unwrap();
    let outcome = run({
        let mut command = runner_manager(temporary.path());
        command.args(["daemon", "run"]);
        command
    });
    assert_eq!(
        outcome.code, 11,
        "the conflict class; stderr: {}",
        outcome.stderr
    );
    assert_ne!(outcome.code, 2, "and it must not be clap's usage code");
    assert!(
        outcome.stderr.contains(&std::process::id().to_string()),
        "the message must name the holder and return without reading stdin: {}",
        outcome.stderr
    );
}

#[test]
fn service_status_runs_unattended_and_reports_offline_honestly() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let outcome = run({
        let mut command = runner_manager(temporary.path());
        command.args(["service", "status"]);
        command
    });
    assert_eq!(outcome.code, 0, "stderr: {}", outcome.stderr);
    assert!(outcome.stdout.contains("offline"), "{}", outcome.stdout);
    assert!(
        outcome.stdout.contains("no successful contact"),
        "{}",
        outcome.stdout
    );
}

/// The one variable that could send a credential somewhere other than GitHub is
/// refused for anything but a loopback origin — checked against the real binary,
/// because the unit test proves only that the predicate is right.
#[test]
fn a_non_loopback_github_override_is_refused_by_the_binary() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let outcome = run({
        let mut command = runner_manager(temporary.path());
        command
            .env("RUNNER_MANAGER_GITHUB_BASE_URL", "https://evil.example/")
            .args(["auth", "status"]);
        command
    });
    assert_eq!(
        outcome.code, 9,
        "the invalid-argument class; stderr: {}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("loopback"),
        "the refusal must say why: {}",
        outcome.stderr
    );
}

// ----------------------------------------------------------------------------
// THE SUITE MUST NOT MEET THE SERVICE THIS DEVELOPER ACTUALLY INSTALLED.
// ----------------------------------------------------------------------------
// `--data-dir` moves the directories. It does not move the service manager,
// which holds one registration per machine under one constant name. So every
// test that ran `service status` against a temporary directory was really
// asking about this machine's own installation, and got a true answer that the
// test did not expect: a registration with no install record behind it.
//
// `service_status_runs_unattended_and_reports_offline_honestly` and three tests
// in `no_secret_reaches_command_output` failed that way -- on `main`, for
// anybody who had ever run `service install`, and for nobody who had not. This
// pins the isolation that fixed them, because a harness change is exactly the
// kind of thing that comes back silently.

/// The isolation is real, and it says so rather than quietly describing a
/// service the operator never installed.
#[test]
fn the_suite_asks_about_a_disposable_registration_and_says_which_one() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let outcome = run({
        let mut command = runner_manager(temporary.path());
        command.args(["service", "status"]);
        command
    });

    assert_eq!(outcome.code, 0, "stderr: {}", outcome.stderr);
    assert!(
        outcome.stdout.contains("runner-manager-selftest-"),
        "the name asked about must be a fixture, which cannot collide with the product's: {}",
        outcome.stdout
    );
    assert!(
        outcome
            .stdout
            .contains("RUNNER_MANAGER_SERVICE_NAME_TAG is set"),
        "a report about a registration nobody installed must say that is what it is: {}",
        outcome.stdout
    );
}

/// The other half: with no tag, the product's own name is what is reported.
///
/// Without this, a harness that stopped setting the variable would leave the
/// test above passing against the wrong thing.
#[test]
fn without_the_tag_the_product_registration_is_the_one_reported() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let outcome = run({
        let mut command = runner_manager(temporary.path());
        command.env_remove("RUNNER_MANAGER_SERVICE_NAME_TAG");
        command.args(["service", "status"]);
        command
    });

    assert!(
        outcome.stdout.contains("Service: runner-manager\n"),
        "the shipped default is the product registration: {}",
        outcome.stdout
    );
    assert!(
        !outcome
            .stdout
            .contains("RUNNER_MANAGER_SERVICE_NAME_TAG is set"),
        "and it does not claim to be a fixture: {}",
        outcome.stdout
    );
    // Deliberately no assertion on the exit code. Whether this machine has the
    // product installed is not this suite's business, and asserting either way
    // is what made four tests depend on it.
}

// ----------------------------------------------------------------------------
// THE README'S `## Commands` BLOCK IS PART OF THE SURFACE, NOT A DESCRIPTION OF
// IT.
// ----------------------------------------------------------------------------
// The block is what a user copies. Every line in it is therefore a claim that
// the binary accepts those arguments, and a claim nothing checked until this
// existed: `--data-dir` moved, `set-runtime-root` arrived, `set-workspace`
// arrived, and the README could have documented any spelling of any of them
// without a single test noticing.
//
// So each documented line is fed to the REAL parser, and the set of families
// and subcommands it names is compared against clap's own `--help` in both
// directions. A command in the README and not in `--help` is a promise the
// binary does not keep; a command in `--help` and not in the README is a
// feature nobody can find.

fn repository_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository root must exist")
}

/// The README, with line endings normalised.
///
/// The repository does not pin `*.md` to LF, so a Windows checkout with
/// `core.autocrlf=true` delivers CRLF and every offset below would be measured
/// against a different string than CI on Linux sees.
fn readme() -> String {
    let path = repository_root().join("README.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
        .replace("\r\n", "\n")
}

/// Every command line inside the README's `## Commands` fenced block, with
/// backslash continuations joined and trailing `# comments` removed.
fn documented_command_lines(source: &str) -> Vec<String> {
    const HEADING: &str = "\n## Commands\n";
    let heading = source.find(HEADING).unwrap_or_else(|| {
        panic!("README.md must carry a `## Commands` section listing the surface")
    });
    let rest = &source[heading + HEADING.len()..];
    let fence = rest
        .find("```bash\n")
        .expect("the `## Commands` section must open a ```bash block");
    let body = &rest[fence + "```bash\n".len()..];
    let close = body
        .find("\n```")
        .expect("the ```bash block under `## Commands` must be closed");
    let body = &body[..close];

    let mut lines: Vec<String> = Vec::new();
    let mut pending = String::new();
    for raw in body.lines() {
        // The comment is documentation about the command, not part of it, and
        // it is stripped before the continuation is joined so that a comment
        // on a continued line cannot swallow the rest of it.
        let code = match raw.find(" #") {
            Some(offset) => &raw[..offset],
            None => raw,
        }
        .trim();
        if code.is_empty() {
            continue;
        }
        if let Some(head) = code.strip_suffix('\\') {
            pending.push_str(head.trim_end());
            pending.push(' ');
            continue;
        }
        pending.push_str(code);
        lines.push(std::mem::take(&mut pending).trim().to_string());
    }
    assert!(
        pending.is_empty(),
        "a documented command ends with a `\\` continuation and no following \
         line: {pending}"
    );
    lines
}

/// One documented line turned into arguments the parser can be given.
///
/// `[...]` marks an OPTIONAL part, and the optional parts are kept rather than
/// dropped: an optional flag the binary no longer accepts is exactly the kind
/// of stale documentation this test is for. `a|b` is a choice, and the first
/// alternative stands for it. Everything else that is a metavariable becomes a
/// value of the right shape, because `host set-capacity N` has to reach the
/// parser as a number or it would fail here for a reason the README did not
/// cause.
fn arguments_for(line: &str, path_value: &str) -> Vec<String> {
    line.split_whitespace()
        .map(|token| token.replace(['[', ']'], ""))
        .filter(|token| !token.is_empty())
        .map(|token| {
            let chosen = token.split('|').next().unwrap_or_default().to_string();
            match chosen.as_str() {
                "OWNER/REPO" => "owner/repo".to_string(),
                "ORG" => "acme".to_string(),
                "HOST" => "home".to_string(),
                "LABEL" => "gpu".to_string(),
                "BOOL" => "true".to_string(),
                "N" => "1".to_string(),
                "PATH" | "DIR" => path_value.to_string(),
                _ => chosen,
            }
        })
        .collect()
}

/// `--help` is appended rather than running the command for real, because
/// `auth login`, `daemon run`, `service install` and `tui` all *do* something.
///
/// It is not a weaker check than it looks. clap resolves the subcommand path,
/// rejects an unknown flag and rejects a value outside a `ValueEnum` even when
/// `--help` is present -- `an_undocumented_flag_is_still_refused_with_help`
/// below pins exactly that, so a run of this suite cannot pass because the
/// parser stopped looking.
#[test]
fn every_command_the_readme_documents_is_accepted_by_the_real_parser() {
    let source = readme();
    let lines = documented_command_lines(&source);
    assert!(
        !lines.is_empty(),
        "no commands were parsed out of the README's `## Commands` block, \
         which would make every assertion below vacuous"
    );

    // One disposable root for the whole loop: `--help` short-circuits before the
    // binary reads or creates anything under it, so a directory per documented
    // line would buy nothing and cost two dozen filesystem round trips.
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let path_value = temporary.path().join("root").display().to_string();

    for line in &lines {
        let arguments = arguments_for(line, &path_value);
        let (binary, arguments) = arguments
            .split_first()
            .expect("a documented line has at least one token");
        assert_eq!(
            binary, "runner-manager",
            "every line in the `## Commands` block must invoke the product: {line}"
        );

        let mut command = runner_manager(temporary.path());
        command.args(arguments);
        command.arg("--help");
        let outcome = run(command);
        assert_eq!(
            outcome.code, 0,
            "the README documents `{line}`, and the real parser refuses it \
             (exit {}):\n{}\nThe `## Commands` block is copied by users; a \
             line in it that the binary does not accept is a defect in the \
             product, not in its documentation.",
            outcome.code, outcome.stderr
        );
    }
}

/// The negative control for the test above: `--help` does not make clap accept
/// anything at all.
#[test]
fn an_undocumented_flag_is_still_refused_with_help() {
    for arguments in [
        // A plausible misspelling of the flag `host set-runtime-root` takes.
        vec!["host", "set-runtime-root", "--root", "C:/rman", "--help"],
        // A value outside `WorkspaceMode`.
        vec![
            "repo",
            "set-workspace",
            "owner/repo",
            "--mode",
            "shared",
            "--help",
        ],
    ] {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let outcome = run({
            let mut command = runner_manager(temporary.path());
            command.args(&arguments);
            command
        });
        assert_eq!(
            outcome.code,
            2,
            "`{}` must be clap's usage error. If it is not, appending \
             `--help` short-circuits parsing and \
             `every_command_the_readme_documents_is_accepted_by_the_real_parser` \
             proves nothing; stderr: {}",
            arguments.join(" "),
            outcome.stderr
        );
    }
}

/// Both directions between the README and clap's own `--help`.
#[test]
fn the_readme_documents_exactly_the_commands_the_help_text_lists() {
    let source = readme();
    let lines = documented_command_lines(&source);

    // clap's own answer, read once per family: this suite already spawns the
    // binary a few dozen times and re-reading a help page per documented line
    // would multiply that for no extra signal.
    let families: Vec<(String, Vec<String>)> = commands_in(&help_for(&[]))
        .into_iter()
        .map(|family| {
            let subcommands = commands_in(&help_for(&[family.as_str()]));
            (family, subcommands)
        })
        .collect();

    // What the README names, as `family` or `family subcommand`.
    let mut documented: Vec<String> = Vec::new();
    for line in &lines {
        let tokens: Vec<&str> = line.split_whitespace().skip(1).collect();
        let Some(family) = tokens.first().copied() else {
            panic!("a documented line names no command: {line}");
        };
        let subcommands = families
            .iter()
            .find(|(name, _)| name == family)
            .map(|(_, subcommands)| subcommands.as_slice())
            .unwrap_or_default();
        let named = match tokens.get(1).copied() {
            Some(second) if subcommands.iter().any(|name| name == second) => {
                format!("{family} {second}")
            }
            _ => family.to_string(),
        };
        documented.push(named);
    }
    documented.sort();
    documented.dedup();

    // What `--help` lists, in the same spelling.
    let mut listed: Vec<String> = Vec::new();
    for (family, subcommands) in &families {
        if subcommands.is_empty() {
            listed.push(family.clone());
        } else {
            listed.extend(
                subcommands
                    .iter()
                    .map(|subcommand| format!("{family} {subcommand}")),
            );
        }
    }
    listed.sort();
    listed.dedup();

    assert!(
        !listed.is_empty(),
        "no commands were parsed out of `--help`, so this comparison would be \
         vacuous"
    );
    assert_eq!(
        documented, listed,
        "the README's `## Commands` block and `--help` must name the same \
         commands. A command only in `--help` is one no user can discover; a \
         command only in the README is a promise the binary does not keep."
    );
}
