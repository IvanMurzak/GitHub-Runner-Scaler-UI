// owner: a3-distribution-and-readme
//
// Shared fixtures for `install_scripts.rs` and `release_channels.rs`.
//
// ----------------------------------------------------------------------------
// WHY THESE TWO SHARE A MODULE WHEN a2's TWO FILES DELIBERATELY DO NOT.
// ----------------------------------------------------------------------------
// `release_workflow.rs` and `workflow_triggers.rs` duplicate a small YAML
// scanner on purpose: they belong to different tasks, and teaching one file new
// tricks for the other's benefit makes it fail for reasons its owner does not
// own. Both files here belong to a3, and what they share is not a few lines of
// parsing -- it is a whole synthetic GitHub Release: five archives, one of them
// a zip written byte by byte, and a `SHA256SUMS` produced by the same code the
// real release uses. Building that twice would give the two files two
// definitions of what a release looks like, which is precisely the drift the
// fixtures exist to catch.
//
// ----------------------------------------------------------------------------
// THE FIXTURE'S CHECKSUMS COME FROM `release.sh sha256`, NOT FROM A CRATE.
// ----------------------------------------------------------------------------
// Two reasons, and the second is the real one. First, `crates/app` has no
// hashing crate available to it and this task may not edit a manifest. Second,
// and more usefully: the format of `SHA256SUMS` is a2's contract -- a bare
// asset name behind exactly two spaces -- and every consumer written here reads
// it. Generating the fixture with the same subcommand the release workflow
// calls means these tests consume the real format rather than one written from
// a reading of it.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

// ----------------------------------------------------------------------------
// Locating things.
// ----------------------------------------------------------------------------

pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository root must exist")
}

/// A path in the form `bash` accepts on every platform.
///
/// Git Bash is an MSYS program: it understands `C:/dir/file`, but a Windows
/// path spelled with backslashes reaches the script with its separators read as
/// escape characters.
pub fn posix(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

/// The `bash` that runs the shell scripts under test.
///
/// ----------------------------------------------------------------------------
/// ON WINDOWS THIS MUST NOT BE `bash` FROM `PATH`.
/// ----------------------------------------------------------------------------
/// `C:\Windows\System32\bash.exe` exists on stock Windows and on GitHub's
/// windows runner image, and it is not a shell: it is the WSL launcher. Where
/// no distribution is installed it fails with
/// `execvpe(/bin/bash) failed: No such file or directory`. Git for Windows
/// ships the real thing, and anyone who cloned this repository has Git, so
/// resolution goes through `git`.
///
/// This panics rather than skipping. ci.yml already depends on bash existing on
/// all three runner images, so "no usable bash" is a broken environment and a
/// test that quietly passed in one would be worth nothing. Same reasoning, and
/// the same resolution order, as `release_workflow.rs`.
pub fn bash_program() -> PathBuf {
    if let Some(explicit) = std::env::var_os("RUNNER_MANAGER_BASH") {
        return PathBuf::from(explicit);
    }
    if !cfg!(windows) {
        return PathBuf::from("bash");
    }

    let mut tried: Vec<PathBuf> = Vec::new();
    if let Some(git) = find_on_path("git.exe")
        && let Some(root) = git.parent().and_then(Path::parent)
    {
        let candidate = root.join("bin").join("bash.exe");
        if candidate.is_file() {
            return candidate;
        }
        tried.push(candidate);
    }
    let standard = PathBuf::from(r"C:\Program Files\Git\bin\bash.exe");
    if standard.is_file() {
        return standard;
    }
    tried.push(standard);

    panic!(
        "no usable bash found on Windows. Tried, in order: {tried:?}. `bash` on \
         PATH is deliberately NOT a fallback: there it resolves to the WSL \
         launcher, a different program that fails outright when no distribution \
         is installed. Install Git for Windows, or set RUNNER_MANAGER_BASH."
    );
}

/// Runs a bash script and returns (success, merged stdout+stderr).
pub fn run_bash(script: &Path, arguments: &[&str], envs: &[(&str, &str)]) -> (bool, String) {
    let mut command = Command::new(bash_program());
    command.arg(posix(script));
    command.args(arguments);
    command.current_dir(repository_root());
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
        .output()
        .unwrap_or_else(|err| panic!("cannot run {}: {err}", posix(script)));
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

pub fn release_script() -> PathBuf {
    let path = repository_root()
        .join(".github")
        .join("scripts")
        .join("release.sh");
    assert!(path.is_file(), "{} must exist", path.display());
    path
}

pub fn channels_script() -> PathBuf {
    let path = repository_root()
        .join(".github")
        .join("scripts")
        .join("channels.sh");
    assert!(
        path.is_file(),
        "{} must exist: it is where step 8's decisions live",
        path.display()
    );
    path
}

pub fn install_script(name: &str) -> PathBuf {
    let path = repository_root().join("install").join(name);
    assert!(
        path.is_file(),
        "{} must exist: it is a published release asset",
        path.display()
    );
    path
}

/// `<hash>  <bare name>` for one file, produced by the release's own code.
pub fn checksum_line(file: &Path) -> String {
    let (ok, output) = run_bash(&release_script(), &["sha256", &posix(file)], &[]);
    assert!(
        ok,
        "release.sh sha256 failed for {}:\n{output}",
        file.display()
    );
    output.trim().to_string()
}

// ----------------------------------------------------------------------------
// A synthetic release.
// ----------------------------------------------------------------------------

/// The five published targets, as `(target, archive extension, binary name)`.
///
/// Kept in this order so a failure message reads in the same order as
/// `RELEASE_TARGETS` in release.yml and `PUBLISHED_TARGETS` in channels.sh.
/// Those two lists being the same set is asserted in `release_channels.rs`;
/// this one is the fixture's own copy, and it being wrong shows up as an
/// archive the scripts under test cannot find.
pub const TARGETS: [(&str, &str, &str); 5] = [
    ("x86_64-pc-windows-msvc", "zip", "runner-manager.exe"),
    ("aarch64-apple-darwin", "tar.gz", "runner-manager"),
    ("x86_64-apple-darwin", "tar.gz", "runner-manager"),
    ("x86_64-unknown-linux-gnu", "tar.gz", "runner-manager"),
    ("aarch64-unknown-linux-gnu", "tar.gz", "runner-manager"),
];

pub struct FixtureRelease {
    pub root: PathBuf,
    pub assets: PathBuf,
    pub version: String,
}

impl FixtureRelease {
    pub fn sums(&self) -> PathBuf {
        self.assets.join("SHA256SUMS")
    }

    /// The staged payload directory an archive was packed from.
    pub fn staged(&self, target: &str) -> PathBuf {
        self.root
            .join("stage")
            .join(format!("runner-manager-{}-{target}", self.version))
    }

    pub fn archive(&self, target: &str) -> PathBuf {
        let (_, extension, _) = TARGETS
            .iter()
            .find(|(name, _, _)| *name == target)
            .unwrap_or_else(|| panic!("unknown target {target}"));
        self.assets.join(format!(
            "runner-manager-{}-{target}.{extension}",
            self.version
        ))
    }

    /// What the fake binary for `target` prints when run.
    pub fn expected_output(&self, target: &str) -> String {
        format!("runner-manager {} ({target})", self.version)
    }
}

/// Builds a directory that looks exactly like a published release: five
/// archives laid out the way the real ones are, plus a `SHA256SUMS` in the
/// format `release.sh sha256` produces.
///
/// The stand-in binary is a `/bin/sh` script that echoes its version, so the
/// install-script tests can prove the file they installed still RUNS rather
/// than only that a file of the right name appeared.
pub fn build_release(root: &Path, version: &str) -> FixtureRelease {
    let stage = root.join("stage");
    let assets = root.join("assets");
    std::fs::create_dir_all(&stage).expect("fixture stage");
    std::fs::create_dir_all(&assets).expect("fixture assets");

    let mut sums = String::new();

    for (target, extension, binary) in TARGETS {
        let stem = format!("runner-manager-{version}-{target}");
        let payload = stage.join(&stem);
        std::fs::create_dir_all(&payload).expect("fixture payload directory");

        let body = format!("#!/bin/sh\necho \"runner-manager {version} ({target})\"\n");
        std::fs::write(payload.join(binary), body.as_bytes()).expect("fixture binary");
        std::fs::write(payload.join("LICENSE"), b"MIT\n").expect("fixture licence");

        let archive = assets.join(format!("{stem}.{extension}"));
        pack(&stage, &stem, binary, extension, &archive, body.as_bytes());

        sums.push_str(&checksum_line(&archive));
        sums.push('\n');
    }

    // Sorted by asset name, byte-for-byte the way `publish` assembles it.
    let mut lines: Vec<&str> = sums.lines().collect();
    lines.sort_by_key(|line| line.split_once("  ").map(|(_, name)| name).unwrap_or(line));
    std::fs::write(assets.join("SHA256SUMS"), format!("{}\n", lines.join("\n")))
        .expect("fixture SHA256SUMS");

    FixtureRelease {
        root: root.to_path_buf(),
        assets,
        version: version.to_string(),
    }
}

/// `tar -czf <archive> -C <stage> <stem>`, spelled so it works on Windows.
///
/// ----------------------------------------------------------------------------
/// THE ARCHIVE PATH IS RELATIVE, AND IT HAS TO BE.
/// ----------------------------------------------------------------------------
/// GNU tar reads an archive name containing a colon before the first slash as
/// `host:path` and tries to reach a remote tape drive -- so a perfectly good
/// Windows path becomes `tar (child): Cannot connect to C: resolve failed`.
/// `--force-local` fixes that on GNU tar and does not exist on the bsdtar macOS
/// ships, so the portable spelling is to run from the staging directory and
/// name the archive relatively. `assets/` is a sibling of `stage/`, which is
/// what makes `../assets/...` correct.
fn run_tar(stage: &Path, stem: &str, archive: &Path) -> (bool, String) {
    let name = archive
        .file_name()
        .expect("an archive file name")
        .to_string_lossy();
    let mut command = Command::new(bash_program());
    command.arg("-c");
    command.arg(format!(
        "cd '{}' && tar -czf '../assets/{}' '{}'",
        posix(stage),
        name,
        stem
    ));
    let output = command.output().expect("cannot run tar through bash");
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

// ----------------------------------------------------------------------------
// A zip writer, because `zip` is not a tool this project may assume.
// ----------------------------------------------------------------------------
// `tar` is on every runner image and release.yml already calls it. `zip` is
// not: release.yml packages the Windows artifact with PowerShell's
// `Compress-Archive` precisely because Git Bash has no `zip` and the Windows
// image does not ship one. Reaching for PowerShell here would tie the fixture
// -- which every platform's test run needs -- to a shell only one of them is
// guaranteed to have.
//
// So the archive is written directly. Entries are STORED (method 0), which
// needs no compressor: the format is a header, the bytes, and a CRC-32. Both
// readers that matter, `Expand-Archive` and `unzip`, handle stored entries and
// create the intermediate directories from the entry path.

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (index, slot) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 != 0 {
                0xEDB8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
        }
        *slot = value;
    }

    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc = table[((crc ^ u32::from(*byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

pub fn write_stored_zip(path: &Path, entries: &[(String, &[u8])]) {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();

    // 1980-01-01, the zero point of the MS-DOS date field. A literal zero is
    // not a valid date and some readers complain about it.
    const DOS_TIME: u16 = 0;
    const DOS_DATE: u16 = 0x0021;

    for (name, data) in entries {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let size = data.len() as u32;
        let name_bytes = name.as_bytes();

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // local header
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&DOS_TIME.to_le_bytes());
        out.extend_from_slice(&DOS_DATE.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // central header
        central.extend_from_slice(&0x031Eu16.to_le_bytes()); // made by: unix
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        central.extend_from_slice(&DOS_TIME.to_le_bytes());
        central.extend_from_slice(&DOS_DATE.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        // External attributes: unix mode 0755 in the high 16 bits, so an
        // extractor that honours them produces an executable file.
        central.extend_from_slice(&0x81ED_0000u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }

    let central_offset = out.len() as u32;
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);

    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // end of central dir
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("zip parent directory");
    }
    std::fs::write(path, &out)
        .unwrap_or_else(|err| panic!("cannot write {}: {err}", path.display()));
}

/// Packs one staged payload directory into the archive shape its target uses.
fn pack(stage: &Path, stem: &str, binary: &str, extension: &str, archive: &Path, body: &[u8]) {
    match extension {
        "tar.gz" => {
            // Shelled out rather than written by hand: `tar` is on all three
            // runner images -- release.yml's own packaging step calls it -- and
            // a hand-rolled tar writer would be fixture code with its own bugs.
            // The zip has no such luxury; see write_stored_zip.
            let (ok, output) = run_tar(stage, stem, archive);
            assert!(ok, "packing {stem}.{extension} failed:\n{output}");
        }
        "zip" => write_stored_zip(archive, &[(format!("{stem}/{binary}"), body)]),
        other => panic!("unknown archive extension {other}"),
    }
}

/// Replaces one target's archive with a **valid** archive carrying different
/// bytes, leaving `SHA256SUMS` describing the archive that used to be there.
///
/// ----------------------------------------------------------------------------
/// SUBSTITUTED, NOT DAMAGED, AND THE DIFFERENCE IS THE WHOLE TEST.
/// ----------------------------------------------------------------------------
/// The obvious way to write this is to append a few bytes to the file. It
/// looks equivalent and it is not: GNU tar rejects trailing garbage on its own,
/// so a script that never checked a digest would ALSO fail -- and the test
/// would pass while proving nothing about the checksum. Measured, not assumed:
/// with the digest comparison deliberately disabled, the appended-bytes version
/// of this failed with `tar: could not unpack` rather than with a mismatch.
///
/// What `07-security.md` actually names as the threat is "a published release
/// artifact is tampered with in transit" -- a substitution, which unpacks
/// perfectly and runs whatever the attacker put in it. So the archive rebuilt
/// here is well-formed in every way except that it is not the one whose digest
/// was published. Nothing but the SHA-256 comparison can tell.
pub fn substitute_payload(release: &FixtureRelease, target: &str) {
    let (_, extension, binary) = TARGETS
        .iter()
        .find(|(name, _, _)| *name == target)
        .unwrap_or_else(|| panic!("unknown target {target}"));

    let stem = format!("runner-manager-{}-{target}", release.version);
    let body = format!("#!/bin/sh\necho \"substituted payload for {target}\"\n");
    let staged = release.staged(target);
    std::fs::write(staged.join(binary), body.as_bytes()).expect("the substituted binary");

    let archive = release.archive(target);
    std::fs::remove_file(&archive).expect("removing the original archive");
    pack(
        &release.root.join("stage"),
        &stem,
        binary,
        extension,
        &archive,
        body.as_bytes(),
    );

    assert!(
        archive.is_file(),
        "the substituted archive was not written for {target}"
    );
}
