// owner: a3-distribution-and-readme
//
// ----------------------------------------------------------------------------
// THE README IS A PRODUCT REQUIREMENT WITH A GATE, NOT PROSE.
// ----------------------------------------------------------------------------
// `07-security.md` records the published App's permission set as a one-time,
// product-wide decision that every future user inherits, and converts the cost
// into an obligation:
//
//   "it must be stated prominently wherever the App is offered -- not left for
//    GitHub's installation screen to disclose"
//
// with a named release gate: "the `Administration: Read and write` disclosure
// appears in the README before the install commands". D21 adds that it binds
// monitor-only users too.
//
// Prose drifts. Somebody tightens the opening, moves the install block up so
// the "getting started" section is nearer the top, and the disclosure is now
// AFTER the command people copy -- which is the exact failure the requirement
// names, and it looks like an improvement in the diff. This file is what makes
// that a red test instead of a judgement call at review time.
//
// ----------------------------------------------------------------------------
// WHAT "BEFORE" IS MEASURED AS.
// ----------------------------------------------------------------------------
// Not "the word Administration appears somewhere above". The WHOLE disclosure
// section has to end before the FIRST install command begins, measured as byte
// offsets in the rendered source. A reader who stops at the first thing they
// can copy must have already passed all of it.
//
// Every scan below is paired with a positive assertion that the thing being
// scanned was found at all, because an absence read out of a file this test
// failed to parse is not evidence of anything.

use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository root must exist")
}

/// The README with line endings normalised.
///
/// The repository does not pin `*.md` to LF, so a Windows checkout with
/// `core.autocrlf=true` -- Git for Windows' default -- delivers this file with
/// CRLF. Every offset and substring below would then be measured against a
/// different string than the one CI on Linux sees.
fn readme() -> String {
    let path = repository_root().join("README.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
        .replace("\r\n", "\n")
}

/// The heading that opens the disclosure, and the one that ends it.
const DISCLOSURE_HEADING: &str = "\n## What you are granting\n";

/// Byte range of the disclosure section: from its heading to the next `## `.
fn disclosure_section(source: &str) -> (usize, usize) {
    let start = source.find(DISCLOSURE_HEADING).unwrap_or_else(|| {
        panic!(
            "README.md must carry a `## What you are granting` section. It is \
             the section `07-security.md` requires, and `#what-you-are-granting` \
             is the anchor the Homebrew formula's caveats and npm/README.md \
             both link to."
        )
    });

    // The next top-level heading after it. `### ` subsections belong to this
    // section and must not end it.
    let after = start + DISCLOSURE_HEADING.len();
    let end = source[after..]
        .find("\n## ")
        .map(|offset| after + offset)
        .unwrap_or(source.len());

    (start, end)
}

/// The install commands the README advertises, in the order D11 lists them.
///
/// These are matched as literal command text rather than as headings, because
/// what a reader copies is the command. A heading renamed from "Install script"
/// to "Quick install" must not silently take the ordering assertion with it.
const INSTALL_COMMANDS: [(&str, &str); 5] = [
    (
        "curl -fsSL https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.sh | sh",
        "the install script, macOS and Linux",
    ),
    (
        "irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 | iex",
        "the install script, Windows -- the path a clean Windows host with no \
         Node installed depends on",
    ),
    (
        "npm i -g @ivan-murzak/runner-manager",
        "the npm wrapper -- SCOPED, because the unscoped `runner-manager` on \
         npmjs.com is an unrelated project and installing it puts a different \
         tool on PATH under this one's name",
    ),
    (
        "brew install IvanMurzak/tap/runner-manager",
        "the Homebrew tap",
    ),
    ("cargo install runner-manager", "cargo install"),
];

fn first_install_command_offset(source: &str) -> (usize, &'static str) {
    let mut earliest: Option<(usize, &'static str)> = None;
    for (command, what) in INSTALL_COMMANDS {
        if let Some(offset) = source.find(command)
            && earliest.is_none_or(|(best, _)| offset < best)
        {
            earliest = Some((offset, what));
        }
    }
    earliest.expect(
        "README.md advertises none of the four documented install channels. \
         Every ordering assertion in this file would then be vacuous, so this \
         is a failure and not a clean result.",
    )
}

#[test]
fn every_documented_channel_appears_in_the_readme() {
    // The positive half, and it comes first: the ordering test below is only
    // meaningful if there is something to order.
    let source = readme();

    for (command, what) in INSTALL_COMMANDS {
        assert!(
            source.contains(command),
            "README.md does not carry the install command for {what}:\n  {command}\n\
             D11 lists four channels plus `cargo install`, and the README is \
             where each of them is offered."
        );
    }

    // ------------------------------------------------------------------------
    // THE ORDER IS THE OWNER'S; THE CAVEAT TRAVELLING WITH npm IS NOT.
    // ------------------------------------------------------------------------
    // This used to require the install script to be the FIRST channel offered,
    // because it is the only one whose install location does not move when a
    // toolchain moves -- and `service install` records an ABSOLUTE binary path
    // (`05-infrastructure.md`). The owner has since put the short commands, npm
    // among them, at the top of the section, which is a presentation decision
    // and is theirs to make.
    //
    // What is NOT theirs to lose is the sentence that makes the first command
    // safe to take: an `npm i -g` binary lives under the ACTIVE Node prefix, a
    // Node upgrade moves it, and the installed service then points at a path
    // that no longer exists. So the rule now binds the hazard to the offer --
    // the npm command must be followed by the caveat and by the command that
    // reports it -- rather than binding the order.
    let npm = source
        .find(INSTALL_COMMANDS[2].0)
        .expect("checked above: the npm command is present");
    for (needle, why) in [
        (
            "stale",
            "the word `service status` prints for a recorded path whose binary \
             has moved",
        ),
        (
            "service status",
            "the command that reports it, rather than the service quietly \
             appearing healthy until the next unattended boot",
        ),
    ] {
        // Searched from the npm command onwards, not from the top of the file:
        // `service status` also appears in the command reference far above the
        // install section, and a mention there is not the caveat this is about.
        assert!(
            source[npm..].contains(needle),
            "README.md offers `npm i -g` at byte {npm} and never mentions \
             `{needle}` after it. A reader who takes the first command in the \
             section must still meet the caveat that makes it safe: {why}."
        );
    }
}

#[test]
fn the_permission_disclosure_precedes_every_install_command() {
    let source = readme();
    let (start, end) = disclosure_section(&source);
    let (first_command, what) = first_install_command_offset(&source);

    assert!(
        start < first_command,
        "README.md's `What you are granting` section begins at byte {start}, \
         after the first install command ({what}) at byte {first_command}."
    );

    // The whole section, not just its heading. A disclosure that starts above
    // the install block and continues below it is one a reader can act before
    // finishing -- and the sentence they would skip is the one about deleting
    // repositories.
    assert!(
        end <= first_command,
        "README.md's `What you are granting` section runs to byte {end}, past \
         the first install command ({what}) at byte {first_command}. \
         `07-security.md` requires the disclosure BEFORE the install commands: \
         a reader who stops at the first thing they can copy must already have \
         passed all of it."
    );
}

#[test]
fn the_disclosure_states_the_whole_permission_set() {
    let source = readme();
    let (start, end) = disclosure_section(&source);
    let section = &source[start..end];

    // The four rows of the table in `07-security.md`. Matched inside the
    // disclosure section rather than anywhere in the file, so a permission
    // mentioned in passing further down does not satisfy this.
    for (permission, level) in [
        ("Repository → Administration", "Read and write"),
        ("Repository → Actions", "Read"),
        ("Repository → Metadata", "Read"),
        ("Organization → Self-hosted runners", "Read and write"),
    ] {
        assert!(
            section.contains(permission),
            "the disclosure section does not name `{permission}`. The published \
             App declares one permission set for every user, and the README is \
             where it is published."
        );
        let row = section
            .lines()
            .find(|line| line.contains(permission))
            .expect("just asserted the permission appears");
        assert!(
            row.contains(level),
            "`{permission}` is listed without its level `{level}`:\n  {row}"
        );
    }
}

#[test]
fn the_disclosure_says_what_administration_write_actually_permits() {
    let source = readme();
    let (start, end) = disclosure_section(&source);
    let section = &source[start..end];

    // ------------------------------------------------------------------------
    // THE THREE VERBS ARE THE WHOLE POINT.
    // ------------------------------------------------------------------------
    // "Administration: Read and write" on a consent screen reads like a runner
    // permission. `07-security.md` says in as many words that it is not, and
    // names what else it authorises. A README that lists the permission and
    // stops has disclosed the string and not the cost.
    for verb in ["deleting", "renaming", "transferring"] {
        assert!(
            section.contains(verb),
            "the disclosure section never says that `Administration: Read and \
             write` permits {verb} the repository. `07-security.md`: \"The same \
             grant permits deleting, renaming, and transferring the repository \
             and adding or removing collaborators.\""
        );
    }
    assert!(
        section.contains("collaborators"),
        "the disclosure section does not mention adding or removing \
         collaborators, which the same grant also permits"
    );

    // D21: a monitor-only user grants exactly the same thing, and that is the
    // case a reader is least likely to expect a write grant in.
    assert!(
        section.contains("dashboard") || section.contains("monitor"),
        "the disclosure section does not say that the grant binds a user who \
         only ever watches. D21 accepted that cost explicitly, which is what \
         makes stating it a requirement rather than a courtesy."
    );
    assert!(
        section.contains("same permissions") || section.contains("same permission set"),
        "the disclosure section does not say that monitor-only mode grants the \
         SAME permissions. A GitHub App grants its whole declared set on \
         installation; there is no per-installation subset."
    );

    // The organization-scope half, which is the actionable advice in all of
    // this: it is narrower, it is verified, and the design says to prefer it.
    assert!(
        section.contains("Organization") && section.contains("narrow"),
        "the disclosure section does not tell the reader that organization \
         scope is the narrower grant. `09-release-distribution.md` and \
         `07-security.md` both say the UI and the docs should; the org-scope \
         registration was verified against \
         `organization_self_hosted_runners` alone, with no \
         `organization_administration` (docs/spikes/d18-org-jit-verification.md)."
    );
}

#[test]
fn the_readme_advertises_no_download_that_is_not_a_terminal_command() {
    let source = readme();

    // ------------------------------------------------------------------------
    // D12 DEPENDS ON THIS, WHICH IS WHY IT IS A TEST AND NOT A STYLE NOTE.
    // ------------------------------------------------------------------------
    // "No paid code signing" is only safe because every advertised path is a
    // terminal path: Gatekeeper and SmartScreen act on the quarantine flags a
    // BROWSER sets, and curl/irm/tar/brew/npm/cargo do not set them. A single
    // "Download for Windows" button reintroduces the prompt this project buys
    // no certificate to avoid -- and it would be added by someone trying to be
    // helpful, in a commit that mentions none of this.
    // ------------------------------------------------------------------------
    // NARROWED TO IMAGES THAT ARE DOWNLOADS, NOT TO EVERY IMAGE.
    // ------------------------------------------------------------------------
    // This used to forbid `![` outright. That also forbids a CI badge, a
    // screenshot of the TUI, and a diagram -- none of which sets a quarantine
    // flag on anything -- and the message a contributor would have got for
    // adding one talks about code-signing certificates, which is not a sentence
    // anybody can act on.
    //
    // What D14 removed is the download IMAGE: a "Download for Windows" button,
    // which is an image whose LINK TARGET is an archive or a release download.
    // That is the shape to forbid, and forbidding it precisely is what keeps
    // the rule from being deleted the first time somebody wants a badge.
    for line in source.lines() {
        if !line.contains("![") {
            continue;
        }
        for target in link_targets(line) {
            assert!(
                !is_download_target(&target),
                "README.md embeds an image whose link target is a download \
                 ({target}):\n  {line}\nD14 removed download images and \
                 buttons; every advertised path must be a terminal command, \
                 which is the whole reason no code-signing certificate is \
                 needed (D12)."
            );
        }
    }
    assert!(
        !source.contains("<img"),
        "README.md embeds a raw <img> tag; see above"
    );
    assert!(
        !source.to_lowercase().contains("<a href"),
        "README.md contains a raw anchor tag, which is how a download BUTTON \
         gets styled into a README. Links are markdown links; downloads are \
         terminal commands."
    );

    // A markdown link whose target is a download is a download link however it
    // is labelled and whether or not it wears an image.
    //
    // ------------------------------------------------------------------------
    // `line.find(opener)` WAS THE FIRST MATCH PER LINE, AND ONE LINE HOLDS TWO.
    // ------------------------------------------------------------------------
    // A download button is `[![label](image)](target)`: two `](` on one line,
    // and it is the SECOND that downloads. `find` returned the first, so the
    // shape this whole test exists to forbid was the shape it read past --
    // while `link_targets` beside it already walked every one of them. Reusing
    // it is not tidying; it is the difference between checking the image URL
    // and checking the download.
    for line in source.lines() {
        for target in link_targets(line) {
            assert!(
                !is_download_target(&target),
                "README.md links directly to a download ({target}):\n  {line}\n\
                 Release archives and installers stay published and linkable, \
                 but the README does not present them as the way in (D14): a \
                 browser download carries the quarantine flag that every \
                 terminal path avoids."
            );
        }
    }
}

/// Whether a link target is something a BROWSER downloads rather than something
/// it displays.
///
/// ----------------------------------------------------------------------------
/// THE INSTALLER EXTENSIONS ARE THE POINT, NOT THE ARCHIVES.
/// ----------------------------------------------------------------------------
/// This began as `.zip`, `.tar.gz` and the two release-download paths, which
/// covers the archives this project publishes and misses the shape that would
/// actually hurt. D12 -- "no paid code signing" -- is safe only while every
/// advertised path is a terminal path, and the download that trips SmartScreen
/// hardest is not an archive: it is a `.exe` or an `.msi`, the two things a
/// "Download for Windows" button would point at, and precisely the two D12
/// depends on nobody adding. `.pkg` and `.dmg` are the macOS half of the same
/// statement, where Gatekeeper is the prompt in question.
///
/// So the set is the installer extensions plus the archives, and adding one
/// here is cheaper than the release where somebody discovers the button was
/// never forbidden.
fn is_download_target(target: &str) -> bool {
    const DOWNLOAD_EXTENSIONS: [&str; 7] =
        [".zip", ".tar.gz", ".7z", ".exe", ".msi", ".pkg", ".dmg"];
    DOWNLOAD_EXTENSIONS
        .iter()
        .any(|extension| target.ends_with(extension))
        || target.contains("/releases/download/")
        || target.contains("/releases/latest/download/")
}

/// Every markdown link target on one line.
///
/// A download button is written `[![label](image)](target)`, so both targets on
/// the line matter and taking only the first would miss the one that does the
/// downloading.
fn link_targets(line: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut rest = line;
    while let Some(offset) = rest.find("](") {
        let after = &rest[offset + 2..];
        let target = after.split(')').next().unwrap_or(after);
        targets.push(target.trim().to_string());
        rest = after;
    }
    targets
}

#[test]
fn the_readme_advertises_neither_winget_nor_scoop() {
    let source = readme().to_lowercase();

    // D11 is explicit that neither is a product channel: on Windows, npm serves
    // anyone with Node and `irm ... | iex` serves everyone else, so a third
    // Windows channel adds a manifest to keep in sync every release without
    // reaching a user the first two miss -- and `microsoft/winget-pkgs` would
    // put an external reviewer on the critical path of every release.
    //
    // Asserted on the README because that is where a channel becomes real: a
    // manifest nobody documents installs nobody, and a channel documented here
    // is one users will expect to keep working.
    for absent in ["winget", "scoop"] {
        assert!(
            !source.contains(absent),
            "README.md mentions `{absent}`. D11 rules it out as a product \
             channel; advertising it here is what would make it one."
        );
    }
}

#[test]
fn the_install_instructions_state_the_properties_the_scripts_actually_have() {
    let source = readme();

    // Each of these is a Definition-of-Done item that the README is the user's
    // only notice of. They are asserted here so that a rewrite of the install
    // section cannot quietly drop the sentence that tells a user the checksum
    // is verified, or the one that warns an npm install moves with Node.
    for (needle, why) in [
        (
            "SHA256SUMS",
            "the scripts verify the archive against the release's published \
             checksums; a user who does not know that cannot know what an abort \
             means",
        ),
        (
            "abort",
            "the scripts abort without installing anything on a checksum \
             mismatch (`07-security.md`, artifact-tampering control)",
        ),
        (
            "--version 1.2.3",
            "a pinned install is a documented capability, and the piped form \
             needs `sh -s --` for it, which is the part users get wrong",
        ),
        (
            "service status",
            "an npm-installed binary moves with the Node prefix and \
             `service status` is what reports the resulting stale path \
             (`05-infrastructure.md`, service behaviour 6)",
        ),
        (
            "Gatekeeper",
            "why no install path triggers a security prompt, and why no \
             certificate is bought (D12)",
        ),
        ("SmartScreen", "the Windows half of the same statement"),
    ] {
        assert!(
            source.contains(needle),
            "README.md never mentions `{needle}`: {why}"
        );
    }

    // The two-step form, for operators who will not pipe a remote script into a
    // shell -- and it must come AFTER the one-line form, because it is the
    // alternative rather than the recommendation.
    let piped = source
        .find(INSTALL_COMMANDS[0].0)
        .expect("the piped install command must be present");
    let two_step = source.find("-o install.sh").unwrap_or_else(|| {
        panic!(
            "README.md must show the two-step download-read-run form for \
             operators who will not pipe a remote script into a shell \
             (`09-release-distribution.md`)."
        )
    });
    assert!(
        piped < two_step,
        "the two-step form appears before the piped one. It is the alternative, \
         not the recommendation: put the one-line command first."
    );
    assert!(
        source.contains("less install.sh") || source.contains("cat install.sh"),
        "the two-step form must actually show the READ step. `download then \
         run` with no reading in between is the piped form with extra typing."
    );
}
