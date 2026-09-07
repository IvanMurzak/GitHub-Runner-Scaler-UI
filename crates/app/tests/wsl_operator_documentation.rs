// owner: b3-acceptance-docs
//
// ----------------------------------------------------------------------------
// THE OPERATOR DOCUMENTATION IS THE FEATURE'S FIRST DEFINITION-OF-DONE ITEM.
// ----------------------------------------------------------------------------
// `b3-acceptance-docs`:
//
//   "A new operator can configure a second Linux host without any undocumented
//    staging directory, PowerShell token extraction, manual systemd unit or
//    manual scheduled task."
//   "Documentation says clearly that each host needs an independent sign-in and
//    why refresh-token sharing fails."
//
// Neither is checkable by reading the code, and both stop being true the moment
// somebody edits a section without reading it. So they are checked here, the
// way `readme_disclosure.rs` checks the permission disclosure: every scan is
// paired with a positive assertion that the thing being scanned was found at
// all, because an absence read out of a section this test failed to locate is
// not evidence of anything.
//
// ----------------------------------------------------------------------------
// AND EVERY COMMAND THE SECTION PRINTS IS FED TO THE REAL PARSER.
// ----------------------------------------------------------------------------
// `cli_command_surface.rs` does this for the README's `## Commands` block. That
// block is one fenced list; this section is a procedure, with the commands an
// operator actually copies spread through it, and until this existed a
// mistyped `--distribution` or a renamed flag in any of them would have shipped
// unnoticed.

mod support;

use std::path::{Path, PathBuf};

use support::{run, runner_manager};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository root must exist")
}

/// A repository markdown file, with line endings normalised.
///
/// The repository does not pin `*.md` to LF, so a Windows checkout with
/// `core.autocrlf=true` delivers CRLF and every offset below would be measured
/// against a different string than CI on Linux sees.
fn document(name: &str) -> String {
    let path = repository_root().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

/// The heading that opens the managed WSL host procedure.
const WSL_HEADING: &str = "\n## Run Linux jobs too: manage a WSL2 distribution\n";

/// The section's text, from its heading to the next `## `.
///
/// `### ` subsections belong to it and must not end it: the whole procedure is
/// written as subsections, so a range that stopped at the first one would make
/// every assertion below vacuous.
fn wsl_section(source: &str) -> &str {
    let start = source.find(WSL_HEADING).unwrap_or_else(|| {
        panic!(
            "README.md must carry a `## Run Linux jobs too: manage a WSL2 distribution` \
             section. It is the procedure `b3-acceptance-docs`'s first Definition-of-Done \
             item is about, and without it a new operator has nothing to follow."
        )
    });
    let after = start + WSL_HEADING.len();
    let end = source[after..]
        .find("\n## ")
        .map_or(source.len(), |offset| after + offset);
    let section = &source[after..end];
    assert!(
        section.len() > 2_000,
        "the WSL section is {} bytes, which is too short to be the procedure this test \
         reads. Either the section was gutted or the range above stopped early.",
        section.len()
    );
    section
}

// ---------------------------------------------------------------------------
// Definition of Done 1: nothing is left to the operator to invent
// ---------------------------------------------------------------------------

#[test]
fn the_procedure_states_every_prerequisite_a_new_operator_has_to_meet() {
    let section = document("README.md");
    let section = wsl_section(&section);

    for (needle, why) in [
        (
            "WSL2",
            "the distribution has to be WSL2, and WSL1 is refused",
        ),
        (
            "systemd=true",
            "systemd is a hard prerequisite and `/etc/wsl.conf` is where an operator \
             enables it",
        ),
        (
            "/etc/wsl.conf",
            "naming the setting without naming the file leaves the operator searching",
        ),
        (
            "wsl --terminate",
            "the wsl.conf change takes effect on the next start, and nothing else in the \
             procedure restarts the distribution",
        ),
        (
            "root",
            "the provider installs a system service and needs root",
        ),
        (
            "ARM",
            "the published Linux architectures are a prerequisite, not a detail",
        ),
        (
            "browser",
            "the one interactive step is the sign-in, and it happens on Windows",
        ),
        (
            "Windows",
            "the whole family refuses on anything else, and that has to be stated first",
        ),
    ] {
        assert!(
            section.contains(needle),
            "the prerequisites must name {needle:?}: {why}"
        );
    }
}

/// The Definition-of-Done item, stated as a scan for the four things the
/// feature exists to remove.
#[test]
fn the_procedure_promises_the_four_manual_steps_this_feature_removes() {
    let source = document("README.md");
    let section = wsl_section(&source);

    // The promise, in the README's own words.
    for named in [
        "staging folder",
        "systemd unit",
        "scheduled task",
        "credential store",
    ] {
        assert!(
            section.contains(named),
            "the section must say plainly that {named:?} is not something the operator \
             creates or copies from. `b3-acceptance-docs`: a new operator configures a \
             second Linux host \"without any undocumented staging directory, PowerShell \
             token extraction, manual systemd unit or manual scheduled task\"."
        );
    }
    assert!(
        section.contains("it is a defect in the product"),
        "and it must say what to conclude if a step ever does ask for one, or the \
         paragraph is a description rather than a promise"
    );

    // And the negative half: the procedure never actually tells the operator to
    // perform one of them. A promise a later edit quietly contradicts two
    // subsections down is worth nothing.
    for forbidden in [
        "schtasks",
        "New-ScheduledTask",
        "systemctl enable",
        "systemctl daemon-reload",
        "Get-Credential",
        "CryptUnprotectData",
    ] {
        assert!(
            !section.contains(forbidden),
            "the procedure asks the operator to run {forbidden:?}, which is exactly one of \
             the manual steps this feature exists to remove"
        );
    }
}

// ---------------------------------------------------------------------------
// Definition of Done 2: independent sign-in, and why sharing cannot work
// ---------------------------------------------------------------------------

#[test]
fn the_procedure_says_each_host_signs_in_separately_and_why_sharing_fails() {
    let source = document("README.md");
    let section = wsl_section(&source);

    assert!(
        section.contains("Each host signs in separately")
            || section.contains("Each host needs its own sign-in"),
        "the section must state the rule as a rule, not leave it to be inferred from an \
         example"
    );
    assert!(
        section.contains("renew"),
        "and it must give the reason: GitHub invalidates both halves of a token pair when \
         either half is renewed. Without the mechanism, \"sign in twice\" reads like \
         bureaucracy and the first operator to hit a rate limit will try copying the \
         credential."
    );
    for consequence in ["logging each other out", "does not work"] {
        assert!(
            section.contains(consequence),
            "the consequence must be stated too: {consequence:?} is what an operator needs \
             to know before deciding to copy a token"
        );
    }
    assert!(
        section.contains("never written down on Windows")
            || section.contains("is never written down on the"),
        "and the guarantee the design makes in return: the issued credential does not touch \
         this machine's disk"
    );
}

// ---------------------------------------------------------------------------
// The rest of the scope: policy, capacity, status, detach, availability,
// Docker, recovery
// ---------------------------------------------------------------------------

#[test]
fn the_procedure_covers_every_topic_the_task_lists() {
    let source = document("README.md");
    let section = wsl_section(&source);

    for (topic, needle) in [
        ("fresh install", "wsl install --distribution Ubuntu"),
        ("adoption", "adopted rather than reinstalled"),
        ("policy setup through --host", "--host wsl:Ubuntu repo add"),
        ("capacity", "host set-capacity"),
        ("status", "wsl status --distribution Ubuntu"),
        ("the JSON document", "--json"),
        ("detach", "wsl detach --distribution Ubuntu"),
        ("login availability", "after that user logs on"),
        ("docker diagnostics", "Docker is diagnosed, not installed"),
        ("recovery", "run `wsl install` again"),
    ] {
        assert!(
            section.contains(needle),
            "the section must cover {topic}, and the text that would show it does \
             ({needle:?}) is absent"
        );
    }

    // Two claims the product makes structurally, which the documentation has to
    // make in the same terms or an operator will read a refusal as a bug.
    assert!(
        section.contains("A preflight failure changed nothing at all"),
        "recovery starts with knowing whether anything was changed"
    );
    assert!(
        section.contains("deliberately not called `uninstall`"),
        "`detach`'s name is a decision the 2026-09-06 review made on purpose, and the \
         section is where an operator learns it deletes no Linux data"
    );
}

// ---------------------------------------------------------------------------
// Every command the section prints is one the binary accepts
// ---------------------------------------------------------------------------

/// Every `runner-manager …` line in the section, with trailing `# comments`
/// removed.
fn documented_commands(section: &str) -> Vec<String> {
    section
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("runner-manager "))
        .map(|line| match line.find(" #") {
            Some(offset) => line[..offset].trim().to_string(),
            None => line.to_string(),
        })
        .collect()
}

/// One documented line turned into arguments the parser can be given.
///
/// The same substitutions `cli_command_surface.rs` makes, for the same reason:
/// `repo add OWNER/REPO` has to reach the parser as something shaped like a
/// repository or it would fail here for a reason the README did not cause.
fn arguments_for(line: &str) -> Vec<String> {
    line.split_whitespace()
        .map(|token| match token {
            "OWNER/REPO" => "owner/repo",
            "NAME" => "Ubuntu",
            "N" => "1",
            other => other,
        })
        .map(str::to_string)
        .collect()
}

#[test]
fn every_command_the_procedure_prints_is_accepted_by_the_real_parser() {
    let source = document("README.md");
    let section = wsl_section(&source);
    let commands = documented_commands(section);
    assert!(
        commands.len() >= 10,
        "only {} commands were parsed out of the WSL section, which means this scan is \
         broken rather than that the procedure has almost none: {commands:?}",
        commands.len()
    );

    // `--help` rather than a real run: `wsl install` provisions a host and
    // `auth login` opens a browser. clap still resolves the whole subcommand
    // path and still rejects an unknown flag, which is the half that matters --
    // `an_undocumented_flag_is_still_refused_with_help` in
    // `cli_command_surface.rs` pins exactly that.
    let temporary = tempfile::tempdir().expect("a temporary directory");
    for line in &commands {
        let arguments = arguments_for(line);
        let (binary, arguments) = arguments
            .split_first()
            .expect("a documented line has at least one token");
        assert_eq!(
            binary, "runner-manager",
            "every command line in this section must invoke the product: {line}"
        );

        let mut command = runner_manager(temporary.path());
        command.args(arguments);
        command.arg("--help");
        let outcome = run(command);
        assert_eq!(
            outcome.code, 0,
            "the README documents `{line}`, and the real parser refuses it (exit {}):\n{}\n\
             An operator copies these lines; one the binary does not accept is a defect in \
             the product, not in its documentation.",
            outcome.code, outcome.stderr
        );
    }
}

// ---------------------------------------------------------------------------
// The release note
// ---------------------------------------------------------------------------

/// The heading of the newest entry, and its `X.Y.Z` parts.
fn newest_entry(changelog: &str) -> (String, (u64, u64, u64)) {
    let heading = changelog
        .lines()
        .find_map(|line| line.strip_prefix("## "))
        .expect("CHANGELOG.md must carry at least one `## <version>` entry")
        .trim()
        .to_string();
    let parts: Vec<u64> = heading
        .split('.')
        .map(|part| {
            part.parse::<u64>().unwrap_or_else(|_| {
                panic!(
                    "the newest changelog entry is headed {heading:?}, which is not the \
                     strict `X.Y.Z` the release workflow accepts. `release.sh` refuses a \
                     pre-release or build-metadata suffix, so a heading it would refuse \
                     names no release this repository can publish."
                )
            })
        })
        .collect();
    assert_eq!(
        parts.len(),
        3,
        "the newest changelog entry must be headed with an `X.Y.Z` version, not {heading:?}"
    );
    (heading, (parts[0], parts[1], parts[2]))
}

/// The version `[workspace.package]` currently pins.
fn workspace_version() -> (u64, u64, u64) {
    let manifest = document("Cargo.toml");
    let line = manifest
        .lines()
        .skip_while(|line| line.trim() != "[workspace.package]")
        .find_map(|line| line.trim().strip_prefix("version = "))
        .expect("the root manifest must carry a `[workspace.package]` version");
    let text = line.trim().trim_matches('"');
    let parts: Vec<u64> = text
        .split('.')
        .map(|part| part.parse().expect("the manifest version is X.Y.Z"))
        .collect();
    (parts[0], parts[1], parts[2])
}

#[test]
fn the_changelog_documents_this_feature_under_a_version_the_release_can_publish() {
    let changelog = document("CHANGELOG.md");
    let (heading, newest) = newest_entry(&changelog);

    assert!(
        newest >= workspace_version(),
        "the newest changelog entry is {heading}, which is older than the version the \
         workspace pins. The release workflow sets the version at release time, so the top \
         entry names the release being prepared and can never fall behind the manifest."
    );

    // The entry is about this feature, and names the whole surface it added.
    let entry = changelog
        .split("\n## ")
        .nth(1)
        .expect("the newest entry has a body");
    for named in [
        "wsl list",
        "wsl install",
        "wsl status",
        "wsl detach",
        "--host local|wsl:NAME",
    ] {
        assert!(
            entry.contains(named),
            "the {heading} entry must name `{named}`. An operator reads a release note to \
             decide whether to upgrade, and a new command surface that is not in it is one \
             nobody upgrading will look for."
        );
    }
    for promise in [
        "own GitHub credential",
        "convergent",
        "after that user logs on",
        "no workload dependency",
        "unchanged",
    ] {
        assert!(
            entry.to_lowercase().contains(&promise.to_lowercase()),
            "the {heading} entry must state {promise:?}: it is one of the promises \
             `03-security-and-lifecycle.md` makes, and a release note that omits it \
             describes a different release"
        );
    }
}

/// The same prose convention the README is held to.
#[test]
fn the_changelog_uses_no_em_dash() {
    let changelog = document("CHANGELOG.md");
    let offenders: Vec<&str> = changelog
        .lines()
        .filter(|line| line.contains('\u{2014}'))
        .collect();
    assert!(
        offenders.is_empty(),
        "CHANGELOG.md contains the em dash character on {} line(s). It is user-facing \
         markdown and is held to `the_readme_uses_no_em_dash`'s convention:\n{}",
        offenders.len(),
        offenders.join("\n")
    );
}
