// owner: a1-wsl-platform-adapter

//! Choosing the one published Linux archive that matches, proving it is the
//! one that was published, and putting the binary inside it at
//! `/usr/local/bin/runner-manager` without a moment in which that path holds
//! half a file.
//!
//! # There is no download here, and that is the point
//!
//! `crates/app/src/cli/update.rs` already fetches release assets, and it does
//! so under two controls worth keeping: the origin is either GitHub or a
//! loopback/local mirror, and `SHA256SUMS` is checked before anything is
//! installed. Re-implementing the fetch in this crate would mean a second
//! origin policy to keep in step with the first — which is the shape of an
//! unverified download path even when the first version of it is careful.
//!
//! So this module takes an archive a caller *already has* plus the checksum
//! document that describes it, and refuses to do anything with the archive
//! until its SHA-256 matches. The orchestration layer supplies both from the
//! existing update path. What is genuinely new here — and could not be
//! borrowed — is everything after the digest matches, because the destination
//! is inside another operating system.
//!
//! # Exact version, not newest
//!
//! [`select_exact_release`] differs from `update`'s selection in exactly one
//! way, and it is the important one: `update` looks for the *newest* published
//! archive, and this looks for the archive whose version is *exactly* the one
//! asked for. `02-target-architecture.md` step 2 requires "the Linux release
//! artifact whose semantic version exactly matches the controlling Windows
//! binary", because a WSL host running a different build from the Windows host
//! that manages it is a support matrix nobody wants and a bug report nobody
//! can read.
//!
//! # Atomicity is a rename inside the distribution
//!
//! Windows cannot atomically replace a file that lives in ext4 inside a WSL
//! virtual disk, so the whole install happens there:
//!
//! 1. the archive's SHA-256 is verified **on the Windows side**, before a byte
//!    of it is piped anywhere;
//! 2. a `0700` staging directory is created *beside the destination*, so the
//!    final step is a rename within one filesystem and is therefore atomic;
//! 3. the archive is streamed into `tar` on the child's stdin and the one
//!    wanted member is extracted;
//! 4. the extracted binary is made executable and asked its own `--version`,
//!    which must be exactly the version selected;
//! 5. only then is it renamed onto the destination.
//!
//! Every failure before step 5 leaves the destination exactly as it was —
//! `03-security-and-lifecycle.md`'s "old binary remains executable" row — and
//! the staging directory is removed on the way out either way.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use runner_manager_domain::model::Arch;
use sha2::{Digest, Sha256};

use super::WslError;
use super::exec::{ChildInput, PipedInput};
use super::probe::{LinuxCommand, WslInvoker};

/// Where the Linux binary lives, which is what `install.sh` and the Linux
/// service registration already assume.
pub const DEFAULT_LINUX_DESTINATION: &str = "/usr/local/bin/runner-manager";

/// The largest archive this will pipe into a distribution.
///
/// The published Linux archive is tens of megabytes; a quarter of a gigabyte
/// is far above anything the release workflow can produce and far below
/// anything that would matter to a workstation. The bound exists so that a
/// wrong path — a caller handing over a disk image by mistake — fails with a
/// sentence instead of with an allocation.
pub const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

/// How long the extraction is given. Longer than a probe: it is the one step
/// that moves real data across the boundary.
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Which archive
// ---------------------------------------------------------------------------

/// The published artifact for one operating system and architecture.
///
/// The two rows named here must stay equal to the Linux rows of
/// `crates/app/src/cli/update.rs`'s `host_target`, to `PUBLISHED_TARGETS` in
/// `.github/scripts/channels.sh` and to `RELEASE_TARGETS` in `release.yml`.
/// `linux_release_targets_match_the_published_matrix` below is the test that
/// says so; without it, a target this module asks for and the release does not
/// publish would be reported to an operator as "your architecture was dropped"
/// about a release that is perfectly fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseTarget {
    triple: &'static str,
    extension: &'static str,
    binary: &'static str,
}

impl ReleaseTarget {
    /// The Rust target triple the archive is named after.
    #[must_use]
    pub fn triple(&self) -> &'static str {
        self.triple
    }

    /// The archive's extension, without the dot.
    #[must_use]
    pub fn extension(&self) -> &'static str {
        self.extension
    }

    /// The executable's name inside the archive.
    #[must_use]
    pub fn binary(&self) -> &'static str {
        self.binary
    }

    /// The asset name a given version is published under.
    #[must_use]
    pub fn asset_for(&self, version: &str) -> String {
        format!(
            "runner-manager-{version}-{}.{}",
            self.triple, self.extension
        )
    }
}

/// The published Linux archive for an architecture.
///
/// # Errors
///
/// [`WslError::UnsupportedArchitecture`]. 32-bit ARM is refused here rather
/// than left to fail at download: the release publishes no
/// `armv7-unknown-linux-gnueabihf` archive, so there is nothing to select.
pub fn linux_target(distribution: &str, arch: Arch) -> Result<ReleaseTarget, WslError> {
    match arch {
        Arch::X64 => Ok(ReleaseTarget {
            triple: "x86_64-unknown-linux-gnu",
            extension: "tar.gz",
            binary: "runner-manager",
        }),
        Arch::Arm64 => Ok(ReleaseTarget {
            triple: "aarch64-unknown-linux-gnu",
            extension: "tar.gz",
            binary: "runner-manager",
        }),
        Arch::Arm32 => Err(WslError::UnsupportedArchitecture {
            distribution: distribution.to_string(),
            reported: "32-bit ARM".to_string(),
        }),
    }
}

/// One release artifact: what it is called and what it must hash to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedArtifact {
    version: String,
    asset: String,
    digest: String,
}

impl PublishedArtifact {
    /// The exact semantic version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The published asset name.
    #[must_use]
    pub fn asset(&self) -> &str {
        &self.asset
    }

    /// The published SHA-256, lower-case hex.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// `X.Y.Z`, as three numbers.
///
/// Pre-release and build metadata are rejected rather than ignored, for the
/// reason `update.rs` gives: the release workflow refuses to publish them, so
/// a tag carrying one is not a release anything here should follow.
#[must_use]
pub fn parse_semantic_version(raw: &str) -> Option<(u64, u64, u64)> {
    let mut parts = raw.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// The version in `runner-manager-<X.Y.Z>-<target>.<extension>`, when the name
/// is exactly that and nothing else.
///
/// Matched whole rather than by prefix: `…-linux-gnu.tar.gz` is a prefix of
/// `…-linux-gnu.tar.gz.sig`, and a signature file is not an archive.
#[must_use]
pub fn version_of_asset(name: &str, target: &ReleaseTarget) -> Option<String> {
    let rest = name.strip_prefix("runner-manager-")?;
    let rest = rest.strip_suffix(&format!(".{}", target.extension))?;
    let version = rest.strip_suffix(&format!("-{}", target.triple))?;
    parse_semantic_version(version).map(|_| version.to_string())
}

/// Finds the archive for `target` whose version is exactly `version`.
///
/// Both checksum-line forms `sha256sum -c` accepts are accepted here —
/// `<hash>  <name>` and `<hash> *<name>` — for the reason `update.rs` gives:
/// a parser stricter than the tool the README tells an operator to verify with
/// would refuse a release that command is happy with.
///
/// # Errors
///
/// [`WslError::UnreadableChecksums`] when nothing in the document parses as a
/// checksum line at all — a truncated download or a proxy error page;
/// [`WslError::NoSuchArtifact`] when the document is fine and simply does not
/// publish this version for this architecture;
/// [`WslError::AmbiguousArtifact`] when two lines claim it, which is a release
/// to refuse rather than to guess about.
pub fn select_exact_release(
    document: &str,
    target: &ReleaseTarget,
    version: &str,
) -> Result<PublishedArtifact, WslError> {
    if parse_semantic_version(version).is_none() {
        return Err(WslError::UnreadableChecksums {
            detail: format!(
                "`{version}` is not an exact `X.Y.Z` version, and this install selects an \
                 exact one rather than the newest"
            ),
        });
    }
    let mut usable = 0_usize;
    let mut matched: Vec<PublishedArtifact> = Vec::new();
    for line in document.lines() {
        let fields: Vec<&str> = line.trim_end_matches('\r').split_whitespace().collect();
        let [digest, name] = fields[..] else { continue };
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        usable += 1;
        let name = name.strip_prefix('*').unwrap_or(name);
        let Some(found) = version_of_asset(name, target) else {
            continue;
        };
        if found != version {
            continue;
        }
        matched.push(PublishedArtifact {
            version: found,
            asset: name.to_string(),
            digest: digest.to_ascii_lowercase(),
        });
    }

    if usable == 0 {
        return Err(WslError::UnreadableChecksums {
            detail: "the checksum document has no line that reads as \
                     '<64 hex digits><spaces><asset name>'; it is empty, truncated, or not a \
                     SHA256SUMS file at all"
                .to_string(),
        });
    }
    match matched.len() {
        1 => Ok(matched.remove(0)),
        0 => Err(WslError::NoSuchArtifact {
            version: version.to_string(),
            triple: target.triple.to_string(),
            published: usable,
        }),
        count => Err(WslError::AmbiguousArtifact {
            version: version.to_string(),
            triple: target.triple.to_string(),
            count,
        }),
    }
}

// ---------------------------------------------------------------------------
// Proving the archive is the published one
// ---------------------------------------------------------------------------

/// The SHA-256 of a file, lower-case hex.
///
/// Read in chunks, which keeps the peak cost of an install to one buffer
/// rather than to a copy of the archive.
///
/// # Errors
///
/// [`WslError::UnreadableArchive`].
pub fn sha256_of_file(path: &Path) -> Result<String, WslError> {
    let unreadable = |error: std::io::Error| WslError::UnreadableArchive {
        path: path.to_path_buf(),
        detail: error.to_string(),
    };
    let mut file = std::fs::File::open(path).map_err(unreadable)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(unreadable)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Reads an archive into memory once its digest matches the published one.
///
/// The order is the whole control: the file is hashed, the hash is compared,
/// and only then are the bytes loaded to be piped. A mismatch returns before
/// anything has been sent anywhere.
///
/// # Errors
///
/// [`WslError::UnreadableArchive`] when the file cannot be read or is larger
/// than [`MAX_ARCHIVE_BYTES`]; [`WslError::DigestMismatch`] when it is not the
/// published archive.
pub fn read_verified_archive(
    path: &Path,
    artifact: &PublishedArtifact,
) -> Result<Vec<u8>, WslError> {
    let metadata = std::fs::metadata(path).map_err(|error| WslError::UnreadableArchive {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    if metadata.len() > MAX_ARCHIVE_BYTES {
        return Err(WslError::UnreadableArchive {
            path: path.to_path_buf(),
            detail: format!(
                "it is {} bytes, and this refuses to pipe anything larger than {MAX_ARCHIVE_BYTES}",
                metadata.len()
            ),
        });
    }
    let actual = sha256_of_file(path)?;
    if actual != artifact.digest {
        return Err(WslError::DigestMismatch {
            path: path.to_path_buf(),
            expected: artifact.digest.clone(),
            actual,
        });
    }
    std::fs::read(path).map_err(|error| WslError::UnreadableArchive {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Where it goes
// ---------------------------------------------------------------------------

/// An absolute Linux path to a file, split into the parts the install needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBinaryPath {
    directory: String,
    file_name: String,
}

impl LinuxBinaryPath {
    /// Parses and checks an absolute Linux path.
    ///
    /// # Errors
    ///
    /// [`WslError::InvalidDestination`] when it is relative, ends in `/`,
    /// contains a `.` or `..` component, an empty component, or a control
    /// character. Each of those would make the staging directory this module
    /// creates land somewhere other than beside the destination, and the
    /// atomic rename depends on it landing beside it.
    pub fn parse(path: &str) -> Result<Self, WslError> {
        let refuse = |reason: &str| {
            Err(WslError::InvalidDestination {
                path: path.to_string(),
                reason: reason.to_string(),
            })
        };
        if !path.starts_with('/') {
            return refuse("it is not an absolute Linux path");
        }
        if path.chars().any(char::is_control) {
            return refuse("it contains a control character");
        }
        let components: Vec<&str> = path.split('/').skip(1).collect();
        if components.iter().any(|component| component.is_empty()) {
            return refuse("it has an empty path component, or a trailing slash");
        }
        if components
            .iter()
            .any(|component| *component == "." || *component == "..")
        {
            return refuse("it contains a `.` or `..` component, which is not resolved here");
        }
        let Some((file_name, directory_parts)) = components.split_last() else {
            return refuse("it names the root directory rather than a file");
        };
        Ok(Self {
            directory: format!("/{}", directory_parts.join("/")),
            file_name: (*file_name).to_string(),
        })
    }

    /// The directory the binary lives in, and the staging directory is created
    /// in.
    #[must_use]
    pub fn directory(&self) -> &str {
        &self.directory
    }

    /// The file's own name.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// The whole path.
    #[must_use]
    pub fn as_path(&self) -> String {
        if self.directory == "/" {
            format!("/{}", self.file_name)
        } else {
            format!("{}/{}", self.directory, self.file_name)
        }
    }
}

impl Default for LinuxBinaryPath {
    fn default() -> Self {
        Self::parse(DEFAULT_LINUX_DESTINATION)
            .expect("the product's own default destination is a valid absolute path")
    }
}

// ---------------------------------------------------------------------------
// The install
// ---------------------------------------------------------------------------

/// What was installed, once the rename succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledBinary {
    destination: String,
    version: String,
    asset: String,
}

impl InstalledBinary {
    /// Where it now is, inside the distribution.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The version it reported about itself after being installed.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The published asset it came out of.
    #[must_use]
    pub fn asset(&self) -> &str {
        &self.asset
    }
}

/// Stages and installs one release binary inside a distribution.
#[derive(Debug)]
pub struct BinaryInstaller<'invoker> {
    invoker: &'invoker WslInvoker<'invoker>,
    distribution: String,
    destination: LinuxBinaryPath,
    staging_token: String,
}

impl<'invoker> BinaryInstaller<'invoker> {
    /// Installs into `destination` in `distribution`.
    #[must_use]
    pub fn new(
        invoker: &'invoker WslInvoker<'invoker>,
        distribution: impl Into<String>,
        destination: LinuxBinaryPath,
    ) -> Self {
        Self {
            invoker,
            distribution: distribution.into(),
            destination,
            staging_token: uuid::Uuid::new_v4().simple().to_string(),
        }
    }

    /// Fixes the random part of the staging directory's name.
    ///
    /// Only a test needs this. It exists so that the argument vectors this
    /// module builds can be asserted exactly, rather than matched with a
    /// pattern that would also match a mistake.
    #[must_use]
    pub fn with_staging_token(mut self, token: impl Into<String>) -> Self {
        self.staging_token = token.into();
        self
    }

    /// Where the archive is unpacked: beside the destination, so that the
    /// final rename cannot cross a filesystem.
    #[must_use]
    pub fn staging_directory(&self) -> String {
        let directory = self.destination.directory();
        let separator = if directory.ends_with('/') { "" } else { "/" };
        format!(
            "{directory}{separator}.runner-manager-install-{}",
            self.staging_token
        )
    }

    /// Verifies the archive, unpacks it, checks the version, and renames it
    /// into place.
    ///
    /// # Errors
    ///
    /// [`WslError::DigestMismatch`] or [`WslError::UnreadableArchive`] before
    /// anything is sent; [`WslError::CommandFailed`] from any Linux step; and
    /// [`WslError::VersionMismatch`] when the archive turned out to hold a
    /// different build. In every one of those cases the destination is
    /// untouched and the staging directory has been removed.
    pub fn install(
        &self,
        archive: &Path,
        artifact: &PublishedArtifact,
        target: &ReleaseTarget,
    ) -> Result<InstalledBinary, WslError> {
        // Nothing crosses the boundary until the digest matches.
        let bytes = read_verified_archive(archive, artifact)?;

        let staging = self.staging_directory();
        // `mkdir` without `-p`: it must *create* the directory, so a name that
        // somehow already exists is a failure rather than a directory whose
        // contents this then trusts.
        self.invoker.exec_ok(
            "create a staging directory inside the distribution",
            self.command("mkdir").args(["-m", "0700", staging.as_str()]),
        )?;

        let installed = self.stage_and_rename(&staging, bytes, artifact, target);
        // Best-effort, and after both outcomes: on success it removes an empty
        // directory, on failure it removes the partial extraction. A failure
        // to clean up must not mask the real error, so its result is dropped.
        drop(
            self.invoker
                .exec(self.command("rm").args(["-rf", staging.as_str()])),
        );
        installed
    }

    /// Everything between "the staging directory exists" and "the rename
    /// happened", so that the caller can clean up on either outcome.
    fn stage_and_rename(
        &self,
        staging: &str,
        bytes: Vec<u8>,
        artifact: &PublishedArtifact,
        target: &ReleaseTarget,
    ) -> Result<InstalledBinary, WslError> {
        let staged = format!("{staging}/{}", target.binary());

        // `--no-same-owner` because the archive's recorded ownership is the
        // release runner's, not this distribution's, and root would otherwise
        // honour it. `-` is stdin: the archive is streamed rather than written
        // to a file inside the distribution, so no temporary copy of it exists
        // there to be left behind.
        self.invoker.exec_ok(
            "unpack the release archive inside the distribution",
            self.command("tar")
                .args([
                    "-xzf",
                    "-",
                    "-C",
                    staging,
                    "--no-same-owner",
                    target.binary(),
                ])
                .with_input(ChildInput::Piped(PipedInput::from_bytes(bytes)))
                .with_timeout(EXTRACT_TIMEOUT),
        )?;

        self.invoker.exec_ok(
            "make the unpacked binary executable",
            self.command("chmod").args(["0755", staged.as_str()]),
        )?;

        // The archive said which version it was; this asks the binary. They
        // have to agree before it replaces a binary a service is running.
        let reported = self.invoker.exec_ok(
            "read the unpacked binary's version",
            self.command(staged.as_str()).args(["--version"]),
        )?;
        let reported = reported.stdout_text();
        if !reports_version(&reported, artifact.version()) {
            return Err(WslError::VersionMismatch {
                expected: artifact.version().to_string(),
                reported,
            });
        }

        // The atomic step. `-T` so that a destination which is unexpectedly a
        // directory is a refusal rather than a binary placed *inside* it.
        let destination = self.destination.as_path();
        self.invoker.exec_ok(
            "put the new binary in place",
            self.command("mv")
                .args(["-T", staged.as_str(), destination.as_str()]),
        )?;

        Ok(InstalledBinary {
            destination,
            version: artifact.version().to_string(),
            asset: artifact.asset().to_string(),
        })
    }

    fn command(&self, program: &str) -> LinuxCommand {
        LinuxCommand::new(self.distribution.clone(), program)
    }
}

/// Whether `--version` output names exactly this version.
///
/// Compared as a whole whitespace-separated token, so that `0.4.0` does not
/// match a binary that reports `0.4.10`.
#[must_use]
fn reports_version(output: &str, version: &str) -> bool {
    output
        .split_whitespace()
        .any(|token| token.trim_start_matches('v') == version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::wsl::exec::{CommandOutput, ScriptedRunner};
    use crate::wsl::probe::WslExecutable;

    const DIGEST_X64: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const DIGEST_ARM: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn sums() -> String {
        format!(
            concat!(
                "{x64}  runner-manager-0.4.0-x86_64-unknown-linux-gnu.tar.gz\n",
                "{arm} *runner-manager-0.4.0-aarch64-unknown-linux-gnu.tar.gz\n",
                "3333333333333333333333333333333333333333333333333333333333333333  \
                 runner-manager-0.4.0-x86_64-pc-windows-msvc.zip\n",
                "4444444444444444444444444444444444444444444444444444444444444444  \
                 runner-manager-0.3.2-x86_64-unknown-linux-gnu.tar.gz\n",
                "5555555555555555555555555555555555555555555555555555555555555555  \
                 runner-manager-0.4.0-x86_64-unknown-linux-gnu.tar.gz.sig\n",
            ),
            x64 = DIGEST_X64,
            arm = DIGEST_ARM,
        )
    }

    fn x64() -> ReleaseTarget {
        linux_target("Ubuntu", Arch::X64).expect("x64 is published")
    }

    // -- Selection -----------------------------------------------------------

    #[test]
    fn linux_release_targets_match_the_published_matrix() {
        // The two Linux rows of `crates/app/src/cli/update.rs`'s `host_target`,
        // written out independently. Asserting the table against itself would
        // prove nothing; this is the copy that goes red when the release drops
        // or renames an architecture.
        assert_eq!(x64().triple(), "x86_64-unknown-linux-gnu");
        assert_eq!(x64().extension(), "tar.gz");
        assert_eq!(x64().binary(), "runner-manager");
        let arm = linux_target("Ubuntu", Arch::Arm64).expect("arm64 is published");
        assert_eq!(arm.triple(), "aarch64-unknown-linux-gnu");
        assert_eq!(
            x64().asset_for("0.4.0"),
            "runner-manager-0.4.0-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[test]
    fn thirty_two_bit_arm_has_no_artifact_and_is_refused_rather_than_guessed() {
        let error = linux_target("Ubuntu", Arch::Arm32).expect_err("nothing is published");
        assert!(
            matches!(error, WslError::UnsupportedArchitecture { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn the_exact_version_and_architecture_are_selected_out_of_a_real_document() {
        let artifact = select_exact_release(&sums(), &x64(), "0.4.0").expect("published");
        assert_eq!(artifact.version(), "0.4.0");
        assert_eq!(
            artifact.asset(),
            "runner-manager-0.4.0-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(artifact.digest(), DIGEST_X64);
    }

    #[test]
    fn the_star_form_of_a_checksum_line_is_accepted_as_sha256sum_accepts_it() {
        let arm = linux_target("Ubuntu", Arch::Arm64).expect("published");
        let artifact = select_exact_release(&sums(), &arm, "0.4.0").expect("published");
        assert_eq!(artifact.digest(), DIGEST_ARM);
        assert!(
            !artifact.asset().starts_with('*'),
            "the `*` marks a binary read, and is not part of the name"
        );
    }

    #[test]
    fn a_signature_file_is_not_an_archive() {
        // `…tar.gz.sig` has `…tar.gz` as a prefix, which is why the suffix is
        // matched whole.
        assert_eq!(
            version_of_asset(
                "runner-manager-0.4.0-x86_64-unknown-linux-gnu.tar.gz.sig",
                &x64()
            ),
            None
        );
    }

    #[test]
    fn a_newer_published_version_is_not_accepted_when_an_exact_one_was_asked_for() {
        // The difference from `update`, stated as a test: `update` would take
        // 0.4.0 here; this must take 0.3.2 and nothing else.
        let artifact = select_exact_release(&sums(), &x64(), "0.3.2").expect("published");
        assert_eq!(artifact.version(), "0.3.2");
    }

    #[test]
    fn a_version_the_release_does_not_publish_says_how_many_assets_it_has() {
        let error = select_exact_release(&sums(), &x64(), "9.9.9").expect_err("not published");
        let WslError::NoSuchArtifact {
            version,
            triple,
            published,
        } = &error
        else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(version, "9.9.9");
        assert_eq!(triple, "x86_64-unknown-linux-gnu");
        assert_eq!(*published, 5);
    }

    #[test]
    fn two_archives_for_one_target_refuse_rather_than_guess() {
        let document = format!(
            "{DIGEST_X64}  runner-manager-0.4.0-x86_64-unknown-linux-gnu.tar.gz\n\
             {DIGEST_ARM}  runner-manager-0.4.0-x86_64-unknown-linux-gnu.tar.gz\n"
        );
        let error = select_exact_release(&document, &x64(), "0.4.0").expect_err("ambiguous");
        assert!(
            matches!(error, WslError::AmbiguousArtifact { count: 2, .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_document_that_is_not_a_checksum_file_is_told_apart_from_a_missing_row() {
        let error = select_exact_release("<html>404</html>", &x64(), "0.4.0")
            .expect_err("not a checksum document");
        assert!(
            matches!(error, WslError::UnreadableChecksums { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn an_inexact_version_is_refused_before_the_document_is_read() {
        // "newest", "the 0.4 line" and a pre-release are all things an exact
        // match cannot mean, and each of them would otherwise install a build
        // that does not match the Windows binary managing it.
        for version in ["0.4", "0.4.0-rc.1", "latest", "v0.4.0", "0.4.0+build", ""] {
            let error = select_exact_release(&sums(), &x64(), version)
                .expect_err("an inexact version must be refused");
            assert!(
                matches!(error, WslError::UnreadableChecksums { .. }),
                "{version:?} produced the wrong refusal: {error:?}"
            );
        }
        // And the one exact spelling is still accepted, so the loop above is
        // not passing because everything is refused.
        assert_eq!(
            select_exact_release(&sums(), &x64(), "0.4.0")
                .expect("0.4.0 is published")
                .version(),
            "0.4.0"
        );
    }

    // -- Digest --------------------------------------------------------------

    fn write_archive(directory: &Path, bytes: &[u8]) -> (PathBuf, String) {
        let path = directory.join("archive.tar.gz");
        std::fs::write(&path, bytes).expect("write the archive");
        let digest = sha256_of_file(&path).expect("hash it");
        (path, digest)
    }

    #[test]
    fn the_digest_is_the_one_sha256sum_would_print() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let (_, digest) = write_archive(directory.path(), b"");
        // The SHA-256 of the empty input, which is a constant anybody can check.
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn an_archive_whose_digest_does_not_match_is_never_read_into_memory() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let (path, _) = write_archive(directory.path(), b"not the published bytes");
        let artifact = PublishedArtifact {
            version: "0.4.0".to_string(),
            asset: "runner-manager-0.4.0-x86_64-unknown-linux-gnu.tar.gz".to_string(),
            digest: DIGEST_X64.to_string(),
        };
        let error = read_verified_archive(&path, &artifact).expect_err("mismatch");
        let WslError::DigestMismatch {
            expected, actual, ..
        } = &error
        else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(expected, DIGEST_X64);
        assert_ne!(actual, DIGEST_X64);
    }

    // -- Destination ---------------------------------------------------------

    #[test]
    fn the_default_destination_is_the_one_the_linux_service_already_assumes() {
        let destination = LinuxBinaryPath::default();
        assert_eq!(destination.as_path(), DEFAULT_LINUX_DESTINATION);
        assert_eq!(destination.directory(), "/usr/local/bin");
        assert_eq!(destination.file_name(), "runner-manager");
    }

    #[test]
    fn a_destination_that_would_move_the_staging_directory_elsewhere_is_refused() {
        for path in [
            "usr/local/bin/runner-manager",
            "/usr/local/bin/",
            "/usr/local//bin/runner-manager",
            "/usr/local/bin/../../tmp/runner-manager",
            "/usr/local/bin/./runner-manager",
            "/",
            "/usr/local/bin/runner\nmanager",
        ] {
            assert!(
                LinuxBinaryPath::parse(path).is_err(),
                "{path:?} should be refused"
            );
        }
    }

    #[test]
    fn a_destination_at_the_root_still_stages_beside_itself() {
        let destination = LinuxBinaryPath::parse("/runner-manager").expect("valid");
        assert_eq!(destination.directory(), "/");
        assert_eq!(destination.as_path(), "/runner-manager");
        let runner = ScriptedRunner::new();
        let executable = WslExecutable::at("wsl.exe");
        let invoker = WslInvoker::new(&runner, &executable);
        let installer =
            BinaryInstaller::new(&invoker, "Ubuntu", destination).with_staging_token("token");
        assert_eq!(
            installer.staging_directory(),
            "/.runner-manager-install-token"
        );
    }

    // -- The install ---------------------------------------------------------

    struct Fixture {
        directory: tempfile::TempDir,
        archive: PathBuf,
        artifact: PublishedArtifact,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let (archive, digest) = write_archive(directory.path(), b"pretend this is a tar.gz");
        let artifact = PublishedArtifact {
            version: "0.4.0".to_string(),
            asset: "runner-manager-0.4.0-x86_64-unknown-linux-gnu.tar.gz".to_string(),
            digest,
        };
        Fixture {
            directory,
            archive,
            artifact,
        }
    }

    fn healthy_runner() -> ScriptedRunner {
        ScriptedRunner::new().always(
            "--version",
            CommandOutput::exited(0, "runner-manager 0.4.0\n", ""),
        )
    }

    #[test]
    fn a_successful_install_runs_exactly_the_expected_argument_vectors_in_order() {
        let fixture = fixture();
        let runner = healthy_runner();
        let executable = WslExecutable::at("wsl.exe");
        let invoker = WslInvoker::new(&runner, &executable);
        let installed = BinaryInstaller::new(&invoker, "Ubuntu", LinuxBinaryPath::default())
            .with_staging_token("token")
            .install(&fixture.archive, &fixture.artifact, &x64())
            .expect("the scripted distribution accepts every step");

        assert_eq!(installed.destination(), DEFAULT_LINUX_DESTINATION);
        assert_eq!(installed.version(), "0.4.0");

        let staging = "/usr/local/bin/.runner-manager-install-token";
        let expected: Vec<Vec<String>> = vec![
            vec!["mkdir", "-m", "0700", staging],
            vec![
                "tar",
                "-xzf",
                "-",
                "-C",
                staging,
                "--no-same-owner",
                "runner-manager",
            ],
            vec![
                "chmod",
                "0755",
                "/usr/local/bin/.runner-manager-install-token/runner-manager",
            ],
            vec![
                "/usr/local/bin/.runner-manager-install-token/runner-manager",
                "--version",
            ],
            vec![
                "mv",
                "-T",
                "/usr/local/bin/.runner-manager-install-token/runner-manager",
                DEFAULT_LINUX_DESTINATION,
            ],
            vec!["rm", "-rf", staging],
        ]
        .into_iter()
        .map(|step| {
            let mut argv = vec![
                "--distribution".to_string(),
                "Ubuntu".to_string(),
                "--user".to_string(),
                "root".to_string(),
                "--exec".to_string(),
            ];
            argv.extend(step.into_iter().map(str::to_string));
            argv
        })
        .collect();

        let actual: Vec<Vec<String>> = runner
            .recorded()
            .into_iter()
            .map(|request| request.arguments)
            .collect();
        assert_eq!(actual, expected);
        drop(fixture.directory);
    }

    #[test]
    fn the_staging_directory_is_beside_the_destination_so_the_rename_is_atomic() {
        // The property the whole failure model rests on: `mv` between two
        // paths in one directory is `rename(2)`, and `rename(2)` either
        // replaced the file or did not.
        let runner = healthy_runner();
        let executable = WslExecutable::at("wsl.exe");
        let invoker = WslInvoker::new(&runner, &executable);
        let installer = BinaryInstaller::new(&invoker, "Ubuntu", LinuxBinaryPath::default())
            .with_staging_token("token");
        let staging = installer.staging_directory();
        assert!(staging.starts_with("/usr/local/bin/"));
        assert_eq!(
            staging.rfind('/'),
            Some("/usr/local/bin".len()),
            "the staging directory must be a direct child of the destination's directory: \
             {staging}"
        );
    }

    #[test]
    fn a_digest_mismatch_never_reaches_the_distribution_at_all() {
        let fixture = fixture();
        let mut wrong = fixture.artifact.clone();
        wrong.digest = DIGEST_X64.to_string();
        let runner = healthy_runner();
        let executable = WslExecutable::at("wsl.exe");
        let invoker = WslInvoker::new(&runner, &executable);
        let error = BinaryInstaller::new(&invoker, "Ubuntu", LinuxBinaryPath::default())
            .install(&fixture.archive, &wrong, &x64())
            .expect_err("the archive is not the published one");
        assert!(
            matches!(error, WslError::DigestMismatch { .. }),
            "{error:?}"
        );
        assert_eq!(
            runner.call_count(),
            0,
            "nothing may run in the distribution: {:?}",
            runner.command_lines()
        );
    }

    #[test]
    fn a_failed_extraction_preserves_the_destination_and_removes_the_staging_directory() {
        let fixture = fixture();
        let runner = healthy_runner().always(
            "--exec tar",
            CommandOutput::exited(2, "", "gzip: stdin: not in gzip format\n"),
        );
        let executable = WslExecutable::at("wsl.exe");
        let invoker = WslInvoker::new(&runner, &executable);
        let error = BinaryInstaller::new(&invoker, "Ubuntu", LinuxBinaryPath::default())
            .with_staging_token("token")
            .install(&fixture.archive, &fixture.artifact, &x64())
            .expect_err("tar refused");
        assert!(error.to_string().contains("not in gzip format"), "{error}");

        let lines = runner.command_lines();
        assert!(
            lines.iter().all(|line| !line.contains("--exec mv")),
            "the destination must not be touched: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line
                    .contains("--exec rm -rf /usr/local/bin/.runner-manager-install-token")),
            "the staging directory must be removed: {lines:?}"
        );
    }

    #[test]
    fn a_binary_reporting_a_different_version_is_never_renamed_into_place() {
        let fixture = fixture();
        let runner = ScriptedRunner::new().always(
            "--version",
            CommandOutput::exited(0, "runner-manager 0.4.10\n", ""),
        );
        let executable = WslExecutable::at("wsl.exe");
        let invoker = WslInvoker::new(&runner, &executable);
        let error = BinaryInstaller::new(&invoker, "Ubuntu", LinuxBinaryPath::default())
            .install(&fixture.archive, &fixture.artifact, &x64())
            .expect_err("0.4.10 is not 0.4.0");
        let WslError::VersionMismatch { expected, reported } = &error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(expected, "0.4.0");
        assert!(reported.contains("0.4.10"));
        assert!(
            runner
                .command_lines()
                .iter()
                .all(|line| !line.contains("--exec mv")),
            "the destination must not be touched"
        );
    }

    #[test]
    fn a_version_check_matches_whole_tokens_rather_than_prefixes() {
        assert!(reports_version("runner-manager 0.4.0", "0.4.0"));
        assert!(reports_version("runner-manager v0.4.0", "0.4.0"));
        assert!(!reports_version("runner-manager 0.4.10", "0.4.0"));
        assert!(!reports_version("runner-manager 10.4.0", "0.4.0"));
        assert!(!reports_version("", "0.4.0"));
    }

    #[test]
    fn the_archive_is_piped_rather_than_written_into_the_distribution() {
        // `03-security-and-lifecycle.md` wants no temporary copy left inside
        // the distribution on a failure. The control is that no step ever
        // names a file to write the archive to: it goes to `tar` on stdin.
        let fixture = fixture();
        let runner = healthy_runner();
        let executable = WslExecutable::at("wsl.exe");
        let invoker = WslInvoker::new(&runner, &executable);
        BinaryInstaller::new(&invoker, "Ubuntu", LinuxBinaryPath::default())
            .with_staging_token("token")
            .install(&fixture.archive, &fixture.artifact, &x64())
            .expect("installed");

        let piped = runner.piped_input();
        assert_eq!(
            piped,
            std::fs::read(&fixture.archive).expect("the archive is readable"),
            "the whole archive should have gone through the pipe"
        );
        for request in runner.recorded() {
            assert!(
                !request
                    .arguments
                    .iter()
                    .any(|argument| argument.contains(".tar.gz")),
                "no step may name an archive file inside the distribution: {:?}",
                request.arguments
            );
        }
    }
}
