// owner: a3-distribution-and-readme
//
// ----------------------------------------------------------------------------
// STEP 8 IS THE ONE STEP THAT RUNS AFTER SOMETHING IRREVERSIBLE SUCCEEDED.
// ----------------------------------------------------------------------------
// Steps 1 to 7 can all be made safe by refusing early: a bad version never
// tags, a red test never builds, a missing asset never publishes. Step 8 runs
// after the GitHub Release exists, and it writes to two systems this repository
// does not own -- the npm registry and a Homebrew tap. Neither can be undone by
// re-dispatching: `npm unpublish` is restricted and time-limited, and a tap
// commit is somebody else's history.
//
// So the decisions it makes are extracted into `.github/scripts/channels.sh`
// and driven here, on every pull request, against a synthetic release: which
// digest belongs to which asset, what the formula and the manifests say, and
// whether an archive may be unpacked into a package at all. Nothing is
// published and no credential is needed.
//
// ----------------------------------------------------------------------------
// THE ONE CLAIM THIS FILE EXISTS FOR.
// ----------------------------------------------------------------------------
// "The Homebrew formula and npm package resolve to the same checksums the
// release published."
//
// That is not one property, it is two, and only the second is hard:
//
//   * the formula and the manifests COPY a digest out of SHA256SUMS -- checked
//     below by reading both documents and comparing;
//   * the binary inside a published npm package came from the archive that
//     digest describes -- which no amount of comparing documents establishes.
//     `npm-stage` re-hashes each archive before unpacking it, and
//     `npm_stage_refuses_an_archive_whose_digest_does_not_match` is what proves
//     that check is load-bearing rather than decorative.
//
// ----------------------------------------------------------------------------
// WHAT THIS FILE CANNOT REACH.
// ----------------------------------------------------------------------------
// The real `npm publish`, the real tap push, and `gh release download` all need
// a credential and a network. What is asserted about them is their SHAPE in
// release.yml -- that the job exists, sits after publication, re-downloads what
// was published rather than reusing the build artifacts, and forces nothing.
// Whether npmjs.com accepts the package is not knowable from here.

mod common;

use common::{
    FixtureRelease, TARGETS, build_release, channels_script, posix, repository_root, run_bash,
    substitute_payload,
};

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn run_channels(arguments: &[&str]) -> (bool, String) {
    run_bash(&channels_script(), arguments, &[])
}

fn channels_stdout(arguments: &[&str]) -> String {
    let (ok, output) = run_channels(arguments);
    assert!(
        ok,
        "channels.sh {arguments:?} was expected to succeed:\n{output}"
    );
    output.trim().to_string()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
        .replace("\r\n", "\n")
}

/// `SHA256SUMS` as a map from asset name to digest.
fn published_digests(sums: &Path) -> BTreeMap<String, String> {
    let text = read(sums);
    let mut map = BTreeMap::new();
    for line in text.lines() {
        if let Some((hash, name)) = line.split_once("  ") {
            map.insert(name.trim().to_string(), hash.trim().to_string());
        }
    }
    assert_eq!(
        map.len(),
        TARGETS.len(),
        "the fixture SHA256SUMS did not parse into one entry per target; every \
         comparison below would be against the wrong thing:\n{text}"
    );
    map
}

// ----------------------------------------------------------------------------
// Looking a digest up.
// ----------------------------------------------------------------------------

#[test]
fn the_checksum_lookup_matches_the_whole_asset_name() {
    // ------------------------------------------------------------------------
    // A SUBSTRING MATCH HERE PINS A FORMULA TO THE WRONG FILE'S DIGEST.
    // ------------------------------------------------------------------------
    // Today's release publishes one file per target and a substring search
    // would happen to work. It stops working the first time anything is
    // published beside an archive -- a `.sig`, a `.intoto.jsonl`, a `.minisig`
    // -- and the failure is a formula whose `sha256` describes a signature
    // file. Homebrew then reports a checksum mismatch on a perfectly good
    // download and the release looks corrupted.
    let temporary = TempDir::new().expect("a temporary directory");
    let sums = temporary.path().join("SHA256SUMS");
    let wanted = "a".repeat(64);
    let decoy = "b".repeat(64);
    let suffix = "c".repeat(64);
    std::fs::write(
        &sums,
        format!(
            "{wanted}  runner-manager-1.2.3-x86_64-apple-darwin.tar.gz\n\
             {decoy}  vendored-runner-manager-1.2.3-x86_64-apple-darwin.tar.gz\n\
             {suffix}  runner-manager-1.2.3-x86_64-apple-darwin.tar.gz.sig\n"
        ),
    )
    .expect("a SHA256SUMS fixture");

    let found = channels_stdout(&[
        "checksum",
        &posix(&sums),
        "runner-manager-1.2.3-x86_64-apple-darwin.tar.gz",
    ]);
    assert_eq!(
        found, wanted,
        "the lookup matched a neighbouring asset rather than the one asked for"
    );

    // Absent must be a failure, never an empty string. An empty digest rendered
    // into a formula is a formula that installs whatever it is handed.
    let (ok, output) = run_channels(&[
        "checksum",
        &posix(&sums),
        "runner-manager-1.2.3-nope.tar.gz",
    ]);
    assert!(
        !ok,
        "the lookup returned something for an absent asset:\n{output}"
    );
    assert!(
        output.contains("records no digest"),
        "the failure must say the digest is missing, not fail obscurely:\n{output}"
    );

    // Two lines for one name is a malformed release, and choosing either is
    // choosing at random.
    let duplicated = temporary.path().join("DUPES");
    std::fs::write(
        &duplicated,
        format!(
            "{wanted}  runner-manager-1.2.3-x86_64-apple-darwin.tar.gz\n\
             {decoy}  runner-manager-1.2.3-x86_64-apple-darwin.tar.gz\n"
        ),
    )
    .expect("a duplicate fixture");
    let (ok, output) = run_channels(&[
        "checksum",
        &posix(&duplicated),
        "runner-manager-1.2.3-x86_64-apple-darwin.tar.gz",
    ]);
    assert!(
        !ok,
        "the lookup picked one of two conflicting digests:\n{output}"
    );
    assert!(
        output.contains("refusing to guess"),
        "the failure must say why it refused:\n{output}"
    );
}

#[test]
fn the_checksum_lookup_reads_both_forms_sha256sum_writes() {
    // ------------------------------------------------------------------------
    // SHA256SUMS IS A PARSED INTERFACE, AND IT HAS TWO SPELLINGS.
    // ------------------------------------------------------------------------
    // `sha256sum -c` verifies both `<hash>  <name>` (text mode) and
    // `<hash> *<name>` (binary mode -- what `-b` writes everywhere and what GNU
    // sha256sum writes on Windows by DEFAULT). `release.sh sha256` normalises
    // to the first, so a release this repository published only ever carries
    // that one; but this subcommand is also pointed at files this repository
    // did not write -- a re-run over a hand-assembled directory, a mirror --
    // and refusing those is refusing what the README's own manual check
    // accepts.
    let temporary = TempDir::new().expect("a temporary directory");
    let wanted = "a".repeat(64);

    let binary_mode = temporary.path().join("SHA256SUMS.binary");
    std::fs::write(
        &binary_mode,
        format!("{wanted} *runner-manager-1.2.3-x86_64-apple-darwin.tar.gz\n"),
    )
    .expect("a binary-mode fixture");

    let found = channels_stdout(&[
        "checksum",
        &posix(&binary_mode),
        "runner-manager-1.2.3-x86_64-apple-darwin.tar.gz",
    ]);
    assert_eq!(
        found, wanted,
        "channels.sh refused the binary-mode form that `sha256sum -b` writes \
         and `sha256sum -c` verifies"
    );

    // And a file nothing could be read out of gets its OWN sentence. A
    // truncated download and a release that never published an asset are
    // different failures with different fixes, and reporting the first as the
    // second sends whoever reads it hunting for a missing build.
    let unreadable = temporary.path().join("NOT-A-CHECKSUM-FILE");
    std::fs::write(
        &unreadable,
        "<html><head><title>404 Not Found</title></head></html>\n",
    )
    .expect("an unreadable fixture");

    let (ok, output) = run_channels(&[
        "checksum",
        &posix(&unreadable),
        "runner-manager-1.2.3-x86_64-apple-darwin.tar.gz",
    ]);
    assert!(
        !ok,
        "the lookup returned something from a file it could not parse:\n{output}"
    );
    assert!(
        output.contains("no line in the form"),
        "an unparseable checksum file must be reported as one:\n{output}"
    );
    assert!(
        !output.contains("records no digest"),
        "channels.sh reported a file it could not parse at all as a release \
         missing one asset. Those have different causes and different \
         fixes:\n{output}"
    );
}

// ----------------------------------------------------------------------------
// The Homebrew formula.
// ----------------------------------------------------------------------------

/// The `url`/`sha256` pairs a formula declares, in file order.
fn formula_pairs(formula: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut pending: Option<String> = None;
    for line in formula.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("url \"") {
            pending = rest.strip_suffix('"').map(str::to_string);
        } else if let Some(rest) = line.strip_prefix("sha256 \"")
            && let Some(url) = pending.take()
        {
            pairs.push((url, rest.strip_suffix('"').unwrap_or(rest).to_string()));
        }
    }
    pairs
}

#[test]
fn the_brew_formula_pins_every_platform_to_the_published_digest() {
    let temporary = TempDir::new().expect("a temporary directory");
    let release = build_release(temporary.path(), "1.2.3");
    let digests = published_digests(&release.sums());

    let output_path = temporary.path().join("Formula").join("runner-manager.rb");
    let report = channels_stdout(&[
        "brew-formula",
        "1.2.3",
        &posix(&release.sums()),
        "IvanMurzak/GitHub-Runner-Scaler-UI",
        &posix(&output_path),
    ]);
    assert!(
        report.contains("4 platforms"),
        "unexpected report:\n{report}"
    );

    let formula = read(&output_path);
    let pairs = formula_pairs(&formula);

    // Homebrew has no Windows, so four of the five targets. Named explicitly so
    // that quietly dropping a platform still fails.
    assert_eq!(
        pairs.len(),
        4,
        "the formula must declare a url/sha256 pair for each of macOS arm64, \
         macOS x64, Linux arm64 and Linux x64:\n{formula}"
    );

    for target in [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-gnu",
    ] {
        let asset = format!("runner-manager-1.2.3-{target}.tar.gz");
        let (url, sha) = pairs
            .iter()
            .find(|(url, _)| url.ends_with(&asset))
            .unwrap_or_else(|| panic!("the formula declares no url for {target}:\n{formula}"));

        assert_eq!(
            sha,
            digests
                .get(&asset)
                .expect("the fixture publishes this asset"),
            "the formula pins {target} to a digest SHA256SUMS does not record \
             for it. That is the exact failure the Definition of Done names: \
             `brew install` would report a checksum mismatch on a download that \
             is perfectly good."
        );

        // ----------------------------------------------------------------
        // PINNED TO download/v1.2.3/, NEVER TO latest/download/.
        // ----------------------------------------------------------------
        // Homebrew caches a download by its url. A `latest` url would serve
        // one release's bytes under the next release's cache key, and the
        // sha256 beside it would then be wrong for everyone whose cache was
        // warm -- a failure that reproduces for nobody who cleared it.
        assert!(
            url.contains("/releases/download/v1.2.3/"),
            "the formula's url for {target} is not pinned to this version's \
             tag: {url}"
        );
        assert!(
            !url.contains("latest/download"),
            "the formula's url for {target} points at `latest`: {url}"
        );
    }

    // The version has to be stated, not inferred: Homebrew's inference reads
    // `-1.2.3-` out of a file name only for a small set of shapes.
    assert!(
        formula.contains("version \"1.2.3\""),
        "the formula must state its version explicitly:\n{formula}"
    );
    // And the disclosure follows the product into the channel: `brew install`
    // is a path to using this tool that never passes through the README.
    assert!(
        formula.contains("Administration") && formula.contains("deleting"),
        "the formula's caveats must repeat the `Administration: Read and write` \
         disclosure. `brew install` reaches a user who may never open the \
         README, and `07-security.md` requires the statement wherever the App \
         is offered.\n{formula}"
    );
}

#[test]
fn the_brew_formula_desc_fits_what_brew_audit_accepts() {
    // ------------------------------------------------------------------------
    // `brew audit` FAILS A `desc` OF 80 CHARACTERS OR MORE.
    // ------------------------------------------------------------------------
    // The npm description is the right length for an npm package page, where it
    // is most of what a reader sees before deciding. Reused verbatim as the
    // formula's `desc` it is about 110 characters, and `brew audit` rejects
    // that -- which nobody discovers until the audit runs, which is after the
    // tap commit, which is after `npm publish`, which is the one action in step
    // 8 that cannot be undone.
    //
    // So there are two strings rather than one truncated at render time: a
    // truncation cuts mid-word at whatever length the description happens to
    // be, and silently.
    let temporary = TempDir::new().expect("a temporary directory");
    let release = build_release(temporary.path(), "1.2.3");
    let output_path = temporary.path().join("Formula").join("runner-manager.rb");
    channels_stdout(&[
        "brew-formula",
        "1.2.3",
        &posix(&release.sums()),
        "IvanMurzak/GitHub-Runner-Scaler-UI",
        &posix(&output_path),
    ]);

    let formula = read(&output_path);
    let description = formula
        .lines()
        .find_map(|line| line.trim().strip_prefix("desc \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or_else(|| panic!("the rendered formula declares no `desc`:\n{formula}"));

    assert!(
        !description.trim().is_empty(),
        "the formula's `desc` is empty; `brew audit` requires one:\n{formula}"
    );
    assert!(
        description.chars().count() < 80,
        "the formula's `desc` is {} characters. `brew audit` accepts fewer \
         than 80, and it is run by anyone who taps this formula as well as by \
         Homebrew itself:\n  {description}",
        description.chars().count()
    );
    // Homebrew also rejects a description that opens with an article or with
    // the formula's own name.
    for opener in ["A ", "An ", "The ", "runner-manager"] {
        assert!(
            !description.starts_with(opener),
            "`brew audit` rejects a `desc` starting with `{opener}`:\n  {description}"
        );
    }
}

#[test]
fn the_brew_formula_refuses_to_render_when_a_digest_is_missing() {
    // Fails closed, and writes NOTHING. A formula rendered with an empty
    // `sha256 ""` is worse than no formula: Homebrew treats an empty checksum
    // on a stable url as a hard error only sometimes, and a partial file left
    // on disk is a file the next step will happily copy into the tap.
    let temporary = TempDir::new().expect("a temporary directory");
    let release = build_release(temporary.path(), "1.2.3");

    let text = read(&release.sums());
    let thinned: String = text
        .lines()
        .filter(|line| !line.contains("aarch64-apple-darwin"))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_eq!(
        thinned.lines().count(),
        TARGETS.len() - 1,
        "the fixture did not lose exactly one line, so this test would not be \
         testing what it says"
    );
    std::fs::write(release.sums(), thinned).expect("rewriting SHA256SUMS");

    let output_path = temporary.path().join("Formula").join("runner-manager.rb");
    let (ok, output) = run_channels(&[
        "brew-formula",
        "1.2.3",
        &posix(&release.sums()),
        "IvanMurzak/GitHub-Runner-Scaler-UI",
        &posix(&output_path),
    ]);
    assert!(
        !ok,
        "the formula was rendered with a digest missing:\n{output}"
    );
    assert!(
        output.contains("aarch64-apple-darwin"),
        "the failure must name the asset it could not pin:\n{output}"
    );
    assert!(
        !output_path.exists(),
        "a partially rendered formula was left at {}. The next step copies this \
         file into the tap without reading it.",
        output_path.display()
    );
}

// ----------------------------------------------------------------------------
// The npm manifests.
// ----------------------------------------------------------------------------

fn json(path: &Path) -> serde_json::Value {
    let text = read(path);
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("{} is not valid JSON: {err}\n{text}", path.display()))
}

/// The npm platform package name for a target, as channels.sh computes it.
fn package_name(target: &str) -> String {
    channels_stdout(&["npm-package-name", target])
}

#[test]
fn the_npm_manifests_pin_every_platform_package_and_its_published_digest() {
    let temporary = TempDir::new().expect("a temporary directory");
    let release = build_release(temporary.path(), "1.2.3");
    let digests = published_digests(&release.sums());
    let out = temporary.path().join("npm");

    channels_stdout(&[
        "npm-manifests",
        "1.2.3",
        &posix(&release.sums()),
        &posix(&out),
    ]);

    let root = json(&out.join("runner-manager").join("package.json"));
    assert_eq!(root["name"], "runner-manager");
    assert_eq!(root["version"], "1.2.3");
    assert_eq!(
        root["bin"]["runner-manager"], "bin/runner-manager.cjs",
        "the root package must point npm at the shim"
    );

    let optional = root["optionalDependencies"]
        .as_object()
        .expect("the root package must declare optionalDependencies");
    assert_eq!(
        optional.len(),
        TARGETS.len(),
        "every published platform needs a package, or npm silently installs a \
         wrapper with no binary on the platform that was left out: {optional:?}"
    );

    for (target, _, binary) in TARGETS {
        let name = package_name(target);
        assert_eq!(
            optional.get(&name).and_then(|value| value.as_str()),
            Some("1.2.3"),
            "the root package must depend on {name} at the exact version being \
             published. A range would let npm resolve a platform binary from a \
             different release than the wrapper."
        );

        let manifest = json(&out.join(&name).join("package.json"));
        // ----------------------------------------------------------------
        // `os` AND `cpu` ARE WHAT MAKE optionalDependencies WORK AT ALL.
        // ----------------------------------------------------------------
        // npm skips an optional package whose os/cpu do not match. Get one
        // wrong and either nobody installs that platform's binary, or
        // everybody installs it -- five binaries on every machine, four of
        // them unusable.
        let (expected_os, expected_cpu) = match target {
            "x86_64-pc-windows-msvc" => ("win32", "x64"),
            "aarch64-apple-darwin" => ("darwin", "arm64"),
            "x86_64-apple-darwin" => ("darwin", "x64"),
            "x86_64-unknown-linux-gnu" => ("linux", "x64"),
            "aarch64-unknown-linux-gnu" => ("linux", "arm64"),
            other => panic!("the fixture grew a target this test does not map: {other}"),
        };
        assert_eq!(
            manifest["os"][0], expected_os,
            "{name} declares the wrong `os`"
        );
        assert_eq!(
            manifest["cpu"][0], expected_cpu,
            "{name} declares the wrong `cpu`"
        );
        assert_eq!(
            manifest["runnerManager"]["binary"], binary,
            "{name} names the wrong binary file"
        );

        let asset = manifest["runnerManager"]["asset"]
            .as_str()
            .expect("each platform manifest records the asset it came from")
            .to_string();
        assert_eq!(
            manifest["runnerManager"]["sha256"].as_str(),
            digests.get(&asset).map(String::as_str),
            "{name} records a digest for {asset} that SHA256SUMS does not. \
             This field is the only record anyone can check the published \
             package against after the fact."
        );
    }
}

#[test]
fn the_npm_manifests_refuse_to_render_when_a_digest_is_missing() {
    let temporary = TempDir::new().expect("a temporary directory");
    let release = build_release(temporary.path(), "1.2.3");

    let text = read(&release.sums());
    let thinned: String = text
        .lines()
        .filter(|line| !line.contains("x86_64-pc-windows-msvc"))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_eq!(thinned.lines().count(), TARGETS.len() - 1);
    std::fs::write(release.sums(), thinned).expect("rewriting SHA256SUMS");

    let out = temporary.path().join("npm");
    let (ok, output) = run_channels(&[
        "npm-manifests",
        "1.2.3",
        &posix(&release.sums()),
        &posix(&out),
    ]);
    assert!(
        !ok,
        "manifests were rendered with a digest missing:\n{output}"
    );
    assert!(
        !out.exists(),
        "a partial staging directory was left behind; the publish step walks it"
    );
}

// ----------------------------------------------------------------------------
// Staging the publishable tree.
// ----------------------------------------------------------------------------

fn stage(release: &FixtureRelease, out: &Path) -> (bool, String) {
    run_channels(&[
        "npm-stage",
        &release.version,
        &posix(&release.sums()),
        &posix(&release.assets),
        &posix(out),
    ])
}

#[test]
fn npm_stage_puts_the_verified_binary_in_every_platform_package() {
    let temporary = TempDir::new().expect("a temporary directory");
    let release = build_release(temporary.path(), "1.2.3");
    let out = temporary.path().join("dist-npm");

    let (ok, output) = stage(&release, &out);
    assert!(ok, "npm-stage failed on a good release:\n{output}");

    for (target, _, binary) in TARGETS {
        let name = package_name(target);
        let staged = out.join(&name).join("bin").join(binary);
        assert!(
            staged.is_file(),
            "{name} was published without the binary it exists to carry: {}",
            staged.display()
        );
        let expected = temporary
            .path()
            .join("stage")
            .join(format!("runner-manager-1.2.3-{target}"))
            .join(binary);
        assert_eq!(
            std::fs::read(&staged).expect("the staged binary"),
            std::fs::read(&expected).expect("the archived binary"),
            "the binary in {name} is not the one the archive carried"
        );
        assert!(
            out.join(&name).join("README.md").is_file(),
            "{name} ships without a README; npmjs.com renders the package page \
             from it, and it is where the npm-prefix warning lives"
        );
        assert!(
            out.join(&name).join("LICENSE").is_file(),
            "{name} declares `\"license\": \"MIT\"` and ships no licence text. \
             A package that claims a licence nobody can read is a package \
             nobody can comply with."
        );
    }

    // The root package carries the shim and nothing platform-specific.
    let root = out.join("runner-manager");
    assert!(
        root.join("bin").join("runner-manager.cjs").is_file(),
        "the root package is missing the shim npm's `bin` entry points at"
    );
    assert!(
        root.join("LICENSE").is_file(),
        "the root package declares MIT and ships no licence text"
    );

    // ------------------------------------------------------------------------
    // PUBLISH ORDER IS RECORDED, NOT LEFT TO A DIRECTORY LISTING.
    // ------------------------------------------------------------------------
    // The root package depends on all five platform packages at an exact
    // version. Published first, it is installable for the minutes before its
    // dependencies exist -- and every install in that window fails when npm
    // resolves them. A `for d in dist-npm/*` loop would publish in whatever
    // order the filesystem returns, which on a sorted listing puts
    // `runner-manager` before `runner-manager-darwin-arm64`.
    let order = read(&out.join("PUBLISH_ORDER"));
    let lines: Vec<&str> = order.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(
        lines.len(),
        TARGETS.len() + 1,
        "PUBLISH_ORDER must name all five platform packages and the root:\n{order}"
    );
    assert_eq!(
        lines.last(),
        Some(&"runner-manager"),
        "the root package must be published LAST:\n{order}"
    );
    for (target, _, _) in TARGETS {
        let name = package_name(target);
        assert!(
            lines.contains(&name.as_str()),
            "PUBLISH_ORDER omits {name}, so it would never be published and the \
             root package would be uninstallable on that platform:\n{order}"
        );
    }
}

#[test]
fn npm_stage_refuses_an_archive_whose_digest_does_not_match() {
    // ------------------------------------------------------------------------
    // THIS IS THE ASSERTION THE DoD CLAIM ACTUALLY RESTS ON.
    // ------------------------------------------------------------------------
    // Copying a digest from SHA256SUMS into a manifest proves the two documents
    // agree. It says nothing about the bytes going INTO the package -- and the
    // package is what users get. Corrupting an archive that SHA256SUMS still
    // describes correctly is the one input that tells those two properties
    // apart: a stage that only copied digests would sail through this and
    // publish the tampered binary with a correct-looking checksum beside it.
    let temporary = TempDir::new().expect("a temporary directory");
    let release = build_release(temporary.path(), "1.2.3");
    substitute_payload(&release, "aarch64-unknown-linux-gnu");

    let out = temporary.path().join("dist-npm");
    let (ok, output) = stage(&release, &out);
    assert!(
        !ok,
        "npm-stage unpacked an archive that does not match its published \
         digest:\n{output}"
    );
    assert!(
        output.contains("DIGEST MISMATCH"),
        "the refusal must name what went wrong:\n{output}"
    );
    assert!(
        !out.join("PUBLISH_ORDER").exists(),
        "PUBLISH_ORDER was written even though staging failed. The publish step \
         reads that file, so writing it is what turns an aborted stage into a \
         published package."
    );
    assert!(
        !out.join(package_name("aarch64-unknown-linux-gnu"))
            .join("bin")
            .exists(),
        "the tampered archive's binary was staged anyway"
    );
}

// ----------------------------------------------------------------------------
// The three lists of platforms that must not drift apart.
// ----------------------------------------------------------------------------

/// `env.RELEASE_TARGETS` from release.yml.
fn release_targets() -> BTreeSet<String> {
    let source = read(
        &repository_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    );
    let mut lines = source.lines();
    let key_indent = loop {
        match lines.next() {
            Some(line) if line.trim_start().starts_with("RELEASE_TARGETS:") => {
                break line.trim_end().len() - line.trim().len();
            }
            Some(_) => continue,
            None => panic!("release.yml must declare `env.RELEASE_TARGETS`"),
        }
    };
    let mut targets = BTreeSet::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.trim_end().len() - trimmed.len();
        if indent <= key_indent {
            break;
        }
        targets.extend(trimmed.split_whitespace().map(String::from));
    }
    targets
}

/// `PUBLISHED_TARGETS` from channels.sh, as target names.
fn channel_targets() -> BTreeSet<String> {
    let source = read(&channels_script());
    let start = source
        .find("readonly PUBLISHED_TARGETS='")
        .expect("channels.sh must declare PUBLISHED_TARGETS");
    let body = &source[start + "readonly PUBLISHED_TARGETS='".len()..];
    let end = body.find('\'').expect("PUBLISHED_TARGETS must be closed");
    body[..end]
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.split('|')
                .next()
                .expect("a row has at least one field")
                .trim()
                .to_string()
        })
        .collect()
}

#[test]
fn the_channel_matrix_names_exactly_the_published_targets() {
    // ------------------------------------------------------------------------
    // TWO LISTS, AND THEY CANNOT BE ONE.
    // ------------------------------------------------------------------------
    // `RELEASE_TARGETS` is a workflow `env` value; `PUBLISHED_TARGETS` is a
    // shell constant in a script the workflow calls. Neither can read the
    // other. A target added to the build matrix but not here is a platform that
    // gets built, published, and then silently omitted from npm and Homebrew --
    // and the only symptom is a user on that platform being told there is no
    // binary for them, one release later.
    let published = release_targets();
    let channels = channel_targets();

    assert_eq!(
        published.len(),
        5,
        "expected five targets in release.yml's RELEASE_TARGETS, parsed: {published:?}"
    );
    assert_eq!(
        channels, published,
        "channels.sh's PUBLISHED_TARGETS and release.yml's RELEASE_TARGETS name \
         different platforms. Whichever list is short is the channel that ships \
         a release missing a platform."
    );

    // And the fixture's own copy, so a green run of this whole file cannot mean
    // "all three lists were changed to the same wrong thing".
    let fixture: BTreeSet<String> = TARGETS
        .iter()
        .map(|(target, _, _)| (*target).to_string())
        .collect();
    assert_eq!(
        fixture, published,
        "the test fixture builds a different set of archives than the release \
         publishes"
    );
}

// ----------------------------------------------------------------------------
// The npm wrapper's entry point.
// ----------------------------------------------------------------------------

fn shim_path() -> PathBuf {
    let path = repository_root()
        .join("npm")
        .join("bin")
        .join("runner-manager.cjs");
    assert!(path.is_file(), "{} must exist", path.display());
    path
}

/// The shim's `PLATFORMS` table, as `"<platform> <arch>" -> (package, binary)`.
fn shim_platforms() -> BTreeMap<String, (String, String)> {
    let source = read(&shim_path());
    let start = source
        .find("const PLATFORMS = {")
        .expect("the shim must declare a PLATFORMS table");
    let body = &source[start..];
    let end = body.find("\n};").expect("PLATFORMS must be closed");

    let mut table = BTreeMap::new();
    for line in body[..end].lines() {
        let line = line.trim();
        let Some((key, rest)) = line.split_once(": [") else {
            continue;
        };
        let key = key.trim().trim_matches('"').to_string();
        let values: Vec<String> = rest
            .trim_end_matches(&[',', ']'][..])
            .trim_end_matches(']')
            .split(',')
            .map(|value| value.trim().trim_matches(&['"', ']'][..]).to_string())
            .filter(|value| !value.is_empty())
            .collect();
        if values.len() == 2 {
            table.insert(key, (values[0].clone(), values[1].clone()));
        }
    }
    table
}

#[test]
fn the_shim_resolves_the_same_packages_the_generator_publishes() {
    // The shim is committed; the manifests are generated at release time. They
    // are two hand-written lists of the same five platforms, in two languages,
    // in two files -- so a package renamed on one side and not the other
    // produces a wrapper that installs cleanly and then cannot find its own
    // binary. That failure reaches the user, not CI, unless this compares them.
    let table = shim_platforms();
    assert_eq!(
        table.len(),
        TARGETS.len(),
        "the shim's PLATFORMS table did not parse into five entries, so the \
         comparison below would be vacuous: {table:?}"
    );

    for (target, _, binary) in TARGETS {
        let (node_platform, node_arch) = match target {
            "x86_64-pc-windows-msvc" => ("win32", "x64"),
            "aarch64-apple-darwin" => ("darwin", "arm64"),
            "x86_64-apple-darwin" => ("darwin", "x64"),
            "x86_64-unknown-linux-gnu" => ("linux", "x64"),
            "aarch64-unknown-linux-gnu" => ("linux", "arm64"),
            other => panic!("unmapped target {other}"),
        };
        let key = format!("{node_platform} {node_arch}");
        let entry = table
            .get(&key)
            .unwrap_or_else(|| panic!("the shim has no entry for `{key}` ({target}): {table:?}"));
        assert_eq!(
            entry.0,
            package_name(target),
            "the shim resolves `{key}` to a package channels.sh does not \
             publish under that name"
        );
        assert_eq!(
            entry.1, binary,
            "the shim expects the wrong binary file name for `{key}`"
        );
    }
}

#[test]
fn the_npm_readme_warns_that_a_global_npm_prefix_moves() {
    // ------------------------------------------------------------------------
    // THIS README IS SHIPPED, AND IT IS THE ONLY WARNING THE npm USER GETS.
    // ------------------------------------------------------------------------
    // `05-infrastructure.md` (service behaviour 6) and
    // `09-release-distribution.md` both single out one failure mode of this
    // channel: `npm i -g` installs into the ACTIVE Node version's global
    // prefix, `service install` records the binary's absolute path, and
    // switching Node versions leaves the installed service pointing at a path
    // that no longer exists. Nothing fails at the time; it fails at the next
    // unattended boot.
    //
    // The task spec makes documenting it part of the deliverable. It is
    // asserted here, and not just in the repository README, because `npm-stage`
    // copies this file into all six published packages -- so it is what a user
    // who arrived through npmjs.com reads, and they may never see the
    // repository at all.
    let readme = read(&repository_root().join("npm").join("README.md"));
    assert!(
        readme.len() > 500,
        "npm/README.md is too short to be the package page it is published as"
    );

    for (needle, why) in [
        (
            "global prefix",
            "the mechanism: an `npm i -g` binary lives under the active Node \
             installation's global prefix",
        ),
        (
            "service install",
            "the command that records the absolute path, and the one to re-run \
             after a Node upgrade",
        ),
        (
            "service status",
            "what reports the resulting stale path as an error rather than \
             appearing healthy",
        ),
        (
            "stale",
            "the word `service status` actually uses, so a user can match what \
             they read here to what they see there",
        ),
        (
            "install.sh",
            "the channel with no such failure mode, which is why the README \
             recommends it for a boot-start service",
        ),
        (
            "Administration",
            "the permission disclosure follows the product into the channel: \
             an npm user may never open the repository README \
             (`07-security.md`)",
        ),
    ] {
        assert!(
            readme.contains(needle),
            "npm/README.md never mentions `{needle}`: {why}"
        );
    }

    // The disclosure has to be more than the permission's name here too.
    assert!(
        readme.contains("deleting")
            && readme.contains("renaming")
            && readme.contains("transferring"),
        "npm/README.md names `Administration: Read and write` without saying \
         what it permits. The string is not the disclosure."
    );

    // ------------------------------------------------------------------------
    // AND IT COMES BEFORE THE INSTALL COMMAND, FOR THE SAME REASON IT DOES IN
    // THE REPOSITORY README.
    // ------------------------------------------------------------------------
    // The task's Definition of Done binds only the repository README, so this
    // is not a contract violation -- it is the same requirement arriving by its
    // own logic. `07-security.md` asks for the disclosure "stated prominently
    // wherever the App is offered", the npmjs.com package page IS where the App
    // is offered to npm users, and the comment above this test already argues
    // that those users "may never see the repository at all". A disclosure
    // seventy lines below the command they came to copy is not prominent.
    let install = readme.find("npm i -g runner-manager").unwrap_or_else(|| {
        panic!("npm/README.md must carry the install command it exists to serve")
    });
    let disclosure = readme
        .find("Administration")
        .unwrap_or_else(|| panic!("checked above: the permission is named somewhere in this file"));
    assert!(
        disclosure < install,
        "npm/README.md puts `npm i -g runner-manager` at byte {install} and the \
         first mention of `Administration` at byte {disclosure}. A reader who \
         stops at the first thing they can copy must already have passed the \
         sentence about deleting their repositories."
    );
}

/// The `node` that runs the shim, or `None` with a reason printed.
fn node_or_skip() -> Option<PathBuf> {
    for candidate in ["node", "node.exe"] {
        if let Some(path) = std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|directory| directory.join(candidate))
                .find(|candidate| candidate.is_file())
        }) {
            return Some(path);
        }
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "no `node` on PATH in CI. Node is preinstalled on all three GitHub \
         runner images; if that stops being true, install it in the workflow \
         rather than letting the npm wrapper go untested."
    );
    eprintln!("SKIPPED: no `node` on PATH. The npm wrapper is exercised in CI.");
    None
}

/// Lays out `<root>/node_modules/...` the way `npm i -g` would.
fn install_wrapper(node: &Path, root: &Path, with_platform_package: bool) -> PathBuf {
    let modules = root.join("node_modules");
    let wrapper = modules.join("runner-manager").join("bin");
    std::fs::create_dir_all(&wrapper).expect("the wrapper directory");
    std::fs::copy(shim_path(), wrapper.join("runner-manager.cjs")).expect("copying the shim");

    if with_platform_package {
        let (platform, arch) = (std::env::consts::OS, std::env::consts::ARCH);
        let package = match (platform, arch) {
            ("windows", "x86_64") => "runner-manager-win32-x64",
            ("macos", "aarch64") => "runner-manager-darwin-arm64",
            ("macos", "x86_64") => "runner-manager-darwin-x64",
            ("linux", "x86_64") => "runner-manager-linux-x64",
            ("linux", "aarch64") => "runner-manager-linux-arm64",
            other => panic!("this host ({other:?}) is not one the wrapper publishes for"),
        };
        let binary_name = if cfg!(windows) {
            "runner-manager.exe"
        } else {
            "runner-manager"
        };
        let bin = modules.join(package).join("bin");
        std::fs::create_dir_all(&bin).expect("the platform package");
        std::fs::write(
            modules.join(package).join("package.json"),
            format!("{{ \"name\": \"{package}\", \"version\": \"1.2.3\" }}\n"),
        )
        .expect("the platform manifest");

        // ----------------------------------------------------------------
        // THE STAND-IN BINARY IS `node` ITSELF.
        // ----------------------------------------------------------------
        // The shim's job is to pass argv through and hand back the child's
        // exit code, and proving that needs a child that can be TOLD what to
        // print and what to exit with. A shell script cannot be that on
        // Windows -- `spawnSync` will not start a `.exe` that is really a
        // batch file -- and a real runner-manager binary is not built by this
        // test. Copying node makes one executable serve every platform:
        // invoked as `runner-manager -e "<script>"` it is a programmable
        // child.
        let destination = bin.join(binary_name);
        if std::fs::hard_link(node, &destination).is_err() {
            std::fs::copy(node, &destination).expect("copying node as the stand-in binary");
        }
    }

    wrapper.join("runner-manager.cjs")
}

#[test]
fn the_shim_passes_arguments_through_and_returns_the_binarys_exit_code() {
    let Some(node) = node_or_skip() else {
        return;
    };
    let temporary = TempDir::new().expect("a temporary directory");
    let shim = install_wrapper(&node, temporary.path(), true);

    // ------------------------------------------------------------------------
    // A WRAPPER THAT ALWAYS EXITS 0 IS WORSE THAN NO WRAPPER.
    // ------------------------------------------------------------------------
    // `service install` registers this binary, a service manager restarts it on
    // failure, and CI steps branch on its status. A shim that swallowed the
    // child's exit code would make every one of those read success -- including
    // the boot-start service, which would stop restarting an agent that keeps
    // dying.
    let output = Command::new(&node)
        .arg(&shim)
        .arg("-e")
        .arg("process.stdout.write('passed:' + process.argv.length); process.exit(7)")
        .output()
        .expect("cannot run the shim");

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("passed:"),
        "the shim did not reach the platform binary at all:\n{text}"
    );
    assert_eq!(
        output.status.code(),
        Some(7),
        "the shim did not propagate the binary's exit code:\n{text}"
    );
}

#[test]
fn the_shim_explains_a_platform_package_npm_skipped() {
    let Some(node) = node_or_skip() else {
        return;
    };
    let temporary = TempDir::new().expect("a temporary directory");
    let shim = install_wrapper(&node, temporary.path(), false);

    // The cost of `optionalDependencies`: npm skips a platform package
    // SILENTLY, and does it for three unrelated reasons -- `--omit=optional`, a
    // lockfile built on another OS, an unreachable registry. The install looks
    // clean and the binary is simply absent. A bare "MODULE_NOT_FOUND" leaves a
    // user with no idea which of the three happened.
    let output = Command::new(&node)
        .arg(&shim)
        .arg("--version")
        .output()
        .expect("cannot run the shim");

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "the shim reported success with no binary to run:\n{text}"
    );
    assert!(
        text.contains("is not installed"),
        "the shim must say plainly that the platform package is missing:\n{text}"
    );
    assert!(
        text.contains("--omit=optional"),
        "the shim must name the likeliest cause; `optionalDependencies` is why \
         npm skipped it without saying so:\n{text}"
    );
    assert!(
        text.contains("npm install -g runner-manager"),
        "the shim must give the command that fixes it:\n{text}"
    );
}

// ----------------------------------------------------------------------------
// Step 8's shape in release.yml.
// ----------------------------------------------------------------------------

/// The raw text of one job block from release.yml.
fn job_block(job: &str) -> String {
    let source = read(
        &repository_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    );
    let mut inside_jobs = false;
    let mut collecting = false;
    let mut block = String::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            if collecting {
                block.push_str(line);
                block.push('\n');
            }
            continue;
        }
        let indent = line.trim_end().len() - trimmed.len();
        if indent == 0 {
            inside_jobs = trimmed.starts_with("jobs:");
            if collecting {
                break;
            }
            continue;
        }
        if !inside_jobs {
            continue;
        }
        if indent == 2 {
            if collecting {
                break;
            }
            collecting = trimmed.starts_with(&format!("{job}:"));
            if collecting {
                block.push_str(line);
                block.push('\n');
            }
            continue;
        }
        if collecting {
            block.push_str(line);
            block.push('\n');
        }
    }

    block
}

/// Every `run:` body inside a job block -- executable text only.
fn run_bodies(block: &str) -> Vec<String> {
    let lines: Vec<&str> = block.lines().collect();
    let mut bodies = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            index += 1;
            continue;
        }
        let indent = lines[index].trim_end().len() - trimmed.len();
        let Some(rest) = trimmed.strip_prefix("run:") else {
            index += 1;
            continue;
        };
        let rest = rest.trim();
        index += 1;
        if !rest.starts_with('|') && !rest.starts_with('>') {
            bodies.push(rest.to_string());
            continue;
        }
        let mut body = String::new();
        while index < lines.len() {
            let raw = lines[index];
            if raw.trim().is_empty() {
                index += 1;
                continue;
            }
            let line_indent = raw.trim_end().len() - raw.trim().len();
            if line_indent <= indent {
                break;
            }
            // Comments inside a `run:` body are shell comments, and they are
            // still not executed. Dropping them is what lets this job document
            // "no --clobber" in the very step the scan below checks.
            if !raw.trim().starts_with('#') {
                body.push_str(raw);
                body.push('\n');
            }
            index += 1;
        }
        bodies.push(body);
    }

    bodies
}

#[test]
fn step_eight_pins_the_channels_to_what_was_actually_published() {
    let block = job_block("channels");
    assert!(
        block.contains("runs-on:"),
        "release.yml must declare a `channels` job -- step 8 of \
         `09-release-distribution.md`. Parsed block:\n{block}"
    );

    // It has to come after publication, or "the checksums this run published"
    // names something that does not exist yet.
    assert!(
        block.contains("needs: [validate, tag, publish]"),
        "the channels job must wait on `publish`:\n{block}"
    );

    // A leg that wedges here holds a release whose channels are half updated.
    let timeout = block
        .lines()
        .find_map(|line| line.trim().strip_prefix("timeout-minutes:"))
        .expect("the channels job must declare timeout-minutes")
        .trim()
        .parse::<u32>()
        .expect("timeout-minutes must be a number");
    assert!(
        (1..=60).contains(&timeout),
        "the channels job allows {timeout} minutes; the point of the value is \
         to be far below GitHub's 360-minute default"
    );

    let executable = run_bodies(&block).join("\n");
    assert!(
        !executable.is_empty(),
        "no `run:` bodies parsed out of the channels job; every assertion below \
         would be vacuous:\n{block}"
    );

    for (required, why) in [
        (
            "gh release download",
            "the digests every channel pins must be taken from what the RELEASE \
             serves, not from this run's build artifacts. Reusing the artifacts \
             would make them self-consistent and prove nothing about the \
             release page.",
        ),
        (
            "sha256sum -c SHA256SUMS",
            "and those downloads must be checked against the published checksum \
             file before a single manifest is rendered",
        ),
        (
            "channels.sh npm-stage",
            "the npm packages must be assembled by the subcommand that \
             re-hashes each archive before unpacking it",
        ),
        (
            "channels.sh brew-formula",
            "the tap formula must be rendered by the generator that fails \
             closed on a missing digest",
        ),
        (
            "install/install.sh install/install.ps1",
            "the install scripts must be attached to the release, or \
             `releases/latest/download/install.sh` -- the address the README \
             documents -- is a 404",
        ),
        (
            "PUBLISH_ORDER",
            "the publish loop must read the recorded order, not a directory \
             listing: the root package has to go last",
        ),
    ] {
        assert!(
            executable.contains(required),
            "no `run:` body in the channels job executes `{required}`. {why}\n\
             Parsed executable text:\n{executable}"
        );
    }

    for (forbidden, why) in [
        (
            "--clobber",
            "`gh release upload --clobber` replaces an asset that is already \
             published. This workflow never replaces what it published; a \
             re-run reports the refusal and moves on.",
        ),
        (
            "--provenance",
            "npm provenance is signed with an OIDC token, which needs \
             `id-token: write` -- a permission `workflow_triggers.rs` refuses \
             for this workflow because it would let the one workflow holding a \
             publishing credential mint more.",
        ),
        (
            "npm unpublish",
            "unpublishing is not a recovery path; it breaks every install that \
             already resolved the version",
        ),
        (
            "git push --force",
            "the tap is somebody else's history; a non-fast-forward must fail \
             the job, not overwrite",
        ),
        (
            "--force-with-lease",
            "still a force push, and still drops whatever else was on the tap",
        ),
    ] {
        assert!(
            !executable.contains(forbidden),
            "a `run:` body in the channels job executes `{forbidden}`. {why}"
        );
    }
}

#[test]
fn step_eight_proves_both_install_scripts_reached_the_release() {
    // ------------------------------------------------------------------------
    // A REFUSAL AND A FAILURE EXIT THE SAME WAY.
    // ------------------------------------------------------------------------
    // `gh release upload` returns non-zero when an asset is already attached --
    // which on a re-run is expected and fine -- and ALSO for a 5xx, an expired
    // or under-scoped token, a rate limit, a file that is not there, and a
    // PARTIAL upload where install.sh conflicted and install.ps1 never went up
    // at all. An `if/else` on that exit status cannot tell them apart, so
    // reading every one of them as "already attached" and then announcing the
    // address is live produces a GREEN release whose
    // `releases/latest/download/install.sh` is a 404.
    //
    // That address is the FIRST install command in the README, so the failure
    // reaches every new user and nobody else. The only thing that settles it is
    // the release itself: `gh release view` is read-only, uploads nothing, and
    // replaces nothing -- which is why this can be asserted without reaching
    // for the `--clobber` the job forbids.
    let block = job_block("channels");
    let bodies = run_bodies(&block);
    assert!(!bodies.is_empty(), "no run bodies parsed:\n{block}");

    let upload = bodies
        .iter()
        .find(|body| body.contains("gh release upload"))
        .expect(
            "the channels job must attach install.sh and install.ps1 to the \
             release; without them the README's documented address is a 404",
        );

    for (required, why) in [
        (
            "gh release view",
            "the step must ask the RELEASE what it carries rather than infer it \
             from an exit status that means five different things",
        ),
        (
            "--json assets",
            "and it must read the asset list, which is the only thing that \
             answers the question",
        ),
        (
            "grep -qxF",
            "matched whole AND literal. `-x` is what stops `install.sh` \
             matching as a substring of `install.sh.sig`; `-F` is what stops \
             its `.` being read as a regex any-char, which would let \
             `installXsh` satisfy a check whose entire job is exactness. The \
             comment beside it claims a literal whole-line match, so `-F` is \
             the spelling that makes the claim true",
        ),
        (
            "exit 1",
            "a missing asset must FAIL the job. Reporting it and continuing is \
             what the branch above already did",
        ),
    ] {
        assert!(
            upload.contains(required),
            "the install-script upload step does not execute `{required}`. \
             {why}\nParsed step:\n{upload}"
        );
    }

    // Both scripts, not one. The partial upload -- install.sh conflicts,
    // install.ps1 never goes up -- is the case the old branch handled worst,
    // and it is the case a single check would still miss.
    for script in ["install.sh", "install.ps1"] {
        assert!(
            upload.matches(script).count() >= 2,
            "`{script}` appears only once in the upload step, so it is uploaded \
             and never checked. A partial upload attaches one of the two and \
             exits non-zero, which is indistinguishable from a \
             refusal:\n{upload}"
        );
    }
}

#[test]
fn step_eight_refuses_to_start_without_the_credentials_it_needs() {
    // ------------------------------------------------------------------------
    // A SKIPPED CHANNEL LOOKS EXACTLY LIKE AN UPDATED ONE.
    // ------------------------------------------------------------------------
    // `if: env.NPM_TOKEN != ''` is the obvious way to write this and it is the
    // wrong one: a release with no npm secret would go green having published
    // nothing to npm, and the first symptom is a user installing a version
    // behind with no way to tell why. The check is also FIRST, before anything
    // is uploaded or pushed, so a missing secret costs no partial update.
    let block = job_block("channels");
    let bodies = run_bodies(&block);
    assert!(!bodies.is_empty(), "no run bodies parsed:\n{block}");

    let guard = bodies
        .iter()
        .position(|body| body.contains("NPM_TOKEN") && body.contains("HOMEBREW_TAP_TOKEN"))
        .expect(
            "the channels job must check both channel secrets in one step \
             before it does anything else",
        );
    assert_eq!(
        guard, 0,
        "the credential check must be the first `run:` step in the job. It ran \
         at position {guard}, which means something else already wrote to the \
         release or the tap before the job discovered it could not finish."
    );
    assert!(
        bodies[guard].contains("exit 1"),
        "the credential check must FAIL the run when a secret is missing, not \
         warn and continue:\n{}",
        bodies[guard]
    );

    // ------------------------------------------------------------------------
    // PRESENT IS NOT THE SAME AS WORKING, AND THE TAP IS TOUCHED LAST.
    // ------------------------------------------------------------------------
    // The order of this job is download, upload scripts, stage npm, render the
    // formula, `npm publish`, THEN clone the tap. A HOMEBREW_TAP_TOKEN that is
    // set but carries no access, or a TAP_REPOSITORY that was renamed or never
    // created, therefore fails AFTER the one action here nothing can undo --
    // `npm unpublish` is restricted and time-limited. A pre-flight that checks
    // a secret is non-empty and stops there has moved no failure at all.
    assert!(
        bodies[guard].contains("git ls-remote"),
        "the pre-flight validates the SECRETS but not the TAP. One read-only \
         `git ls-remote` moves a bad token or a missing repository from after \
         `npm publish` to before it, and it needs exactly the access the clone \
         at the end of the job needs:\n{}",
        bodies[guard]
    );

    // ------------------------------------------------------------------------
    // AND `ls-remote` PROVES A READ, WHILE WHAT LANDS LAST IS A WRITE.
    // ------------------------------------------------------------------------
    // `git ls-remote` speaks git-upload-pack, so it passes for a token that can
    // read the tap and not write it -- which is the exact shape a
    // `HOMEBREW_TAP_TOKEN` takes when somebody grants it `contents: read`. That
    // token then fails on the `git push` at the END of this job, after
    // `npm publish`, and `npm unpublish` is restricted and time-limited.
    //
    // `git push --dry-run` performs the git-receive-pack advertisement, which
    // is the request GitHub refuses with 403 for a read-only token, and it
    // creates nothing: measured, a dry run to a new branch prints
    // `* [new branch]`, exits 0, and leaves the remote without that ref.
    assert!(
        bodies[guard].contains("git push --dry-run"),
        "the pre-flight proves the tap is READABLE and stops there. \
         `git ls-remote` is git-upload-pack; the action this job actually ends \
         with is a PUSH, and a token with read but no write passes the check \
         above and fails after `npm publish`. `git push --dry-run` does the \
         receive-pack advertisement -- the request that 403s for a read-only \
         token -- and writes nothing:\n{}",
        bodies[guard]
    );

    // ------------------------------------------------------------------------
    // THE README HARDCODES THE TAP AND THIS JOB TAKES IT FROM A VARIABLE.
    // ------------------------------------------------------------------------
    // Setting `vars.RUNNER_MANAGER_TAP_REPOSITORY` without editing the README
    // leaves every reader copying `brew install <owner>/<tap>/runner-manager`
    // for a tap this release no longer writes to. It surfaces as
    // `No available formula`, which reads like a broken release rather than a
    // stale document -- and nothing else in this repository would notice.
    assert!(
        bodies[guard].contains("README.md"),
        "the pre-flight must check that README.md documents the tap this job \
         actually publishes to. The tap is a workflow variable and the README's \
         `brew install` line is not:\n{}",
        bodies[guard]
    );
}

/// The tap `release.yml` falls back to when no repository variable is set.
///
/// ----------------------------------------------------------------------------
/// EVERY OCCURRENCE, NOT THE FIRST ONE.
/// ----------------------------------------------------------------------------
/// The default is spelled once per step that needs it -- the pre-flight, the
/// tap update, and the summary -- because a `run:` step only sees the `env:`
/// declared on it. Reading `source.find(MARKER)` took the FIRST of those and
/// compared only that one against the README, so a tap update pointed at a
/// different repository than the pre-flight validated would have gone green:
/// the README agreement would still hold against a spelling no longer used by
/// the step that does the writing.
///
/// So all of them are collected and they must agree. That is what makes the
/// single value this returns meaningful enough to compare with anything --
/// and it fails naming both spellings, because "they disagree" without saying
/// how is a finding somebody has to redo.
fn workflow_default_tap() -> String {
    let source = read(
        &repository_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    );
    const MARKER: &str = "vars.RUNNER_MANAGER_TAP_REPOSITORY || '";

    let mut spellings: Vec<String> = Vec::new();
    let mut rest = source.as_str();
    while let Some(offset) = rest.find(MARKER) {
        let after = &rest[offset + MARKER.len()..];
        spellings.push(
            after
                .split('\'')
                .next()
                .expect("a quoted default")
                .to_string(),
        );
        rest = after;
    }

    let first = spellings.first().cloned().unwrap_or_else(|| {
        panic!(
            "release.yml no longer names a default for \
             `vars.RUNNER_MANAGER_TAP_REPOSITORY`. The assertion below compares \
             that default with the README and would be checking nothing."
        )
    });

    for (index, spelling) in spellings.iter().enumerate() {
        assert_eq!(
            spelling,
            &first,
            "release.yml spells the default tap {} times and occurrence {} is \
             `{spelling}` while the first is `{first}`. Each `run:` step carries \
             its own `env:`, so a job whose pre-flight validates one repository \
             and whose push targets another is a release that checks the wrong \
             thing and then writes to the wrong place. All spellings: \
             {spellings:?}",
            spellings.len(),
            index + 1,
        );
    }

    first
}

#[test]
fn the_readme_and_the_workflow_name_the_same_homebrew_tap() {
    // Homebrew's shorthand drops the `homebrew-` prefix, so the repository
    // `IvanMurzak/homebrew-tap` is tapped as `IvanMurzak/tap`. Two spellings of
    // one thing, in two files, is exactly the shape that drifts -- and the
    // symptom lands on a user, not on this repository.
    let tap = workflow_default_tap();
    let (owner, repository) = tap
        .split_once('/')
        .unwrap_or_else(|| panic!("release.yml's default tap `{tap}` is not `owner/repository`"));
    let shorthand = repository.strip_prefix("homebrew-").unwrap_or(repository);
    let documented = format!("brew install {owner}/{shorthand}/runner-manager");

    let readme = read(&repository_root().join("README.md"));
    assert!(
        readme.contains(&documented),
        "release.yml publishes the formula to `{tap}`, which is tapped as \
         `{owner}/{shorthand}`, and README.md does not document \
         `{documented}`. Every reader who copies the README's line would get \
         `No available formula`."
    );
}
