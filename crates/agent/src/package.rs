// owner: e2-runner-package-cache
//
// `e1` owns `reconcile` and the crate root, `e3` owns `lifecycle`. Nothing in
// this file edits either: the attempt vocabulary this module reasons about —
// `RunnerAttempt`, `AttemptId`, `AttemptState::is_terminal` — is `b1`'s and is
// consumed, never restated.

//! The cached, checksum-verified GitHub runner package.
//!
//! Two failure modes drive this module, and every decision below is one of them
//! being closed:
//!
//! * **A tampered package executes arbitrary code on the operator's machine.**
//!   Download metadata comes from GitHub and nowhere else, the published
//!   SHA-256 is verified *before* extraction, and an absent published checksum
//!   fails closed rather than degrading into "skip the check"
//!   (`07-security.md`, `05-infrastructure.md`).
//! * **A stale package makes every job start failing for a reason nobody will
//!   guess.** GitHub rejects runners more than 30 days behind the latest
//!   release (`01-current-architecture.md`, edge case 7), so the published
//!   version is re-checked on a bounded interval and a superseded cache entry
//!   is refreshed before a cold start.
//!
//! # The shape of the cache
//!
//! Under [`AppPaths::state_dir`], which `05-infrastructure.md` names as the home
//! of "the retained runner package cache":
//!
//! ```text
//! state/
//!   packages/
//!     2.330.0/                     one immutable entry, never mutated after it lands
//!       .runner-package.json       its manifest, written before the entry lands
//!       run.sh, bin/, externals/   GitHub's archive, extracted
//!     .staging/                    transient; a partial install is only ever here
//!     .leases/                     <attempt-uuid>.lease, the prune guard's evidence
//!   tool-cache/                    approved tool caches, retained beside the binaries
//! runtime/                         per-attempt job workspaces — NOT under packages/
//! ```
//!
//! **A cache entry is created by exactly one filesystem operation.** Extraction
//! writes into `.staging/<uuid>/`, the manifest is written *inside* that
//! staging directory, and the directory is then renamed to `packages/<version>/`.
//! The rename is the single commit point: an entry that exists is an entry that
//! is complete, and a crash at any earlier moment leaves nothing but staging
//! litter. That is also what makes "a second install of the same version is a
//! no-op" true rather than aspirational — the entry is found and returned before
//! anything is fetched.
//!
//! # The seam `e3` consumes, stated deliberately
//!
//! `e3` creates each JIT runtime as "a copy or link from that cache plus a
//! unique workspace" (`05-infrastructure.md`). Three contracts hold that seam
//! together, and they are stated here because an unstated port contract becomes
//! a defect in the consumer:
//!
//! 1. [`InstalledPackage::root`] is **read-only to the caller**. It is the
//!    shared, immutable source that every runtime is copied or linked from.
//!    Writing into it corrupts every future runtime, and nothing in this module
//!    can detect it after the fact.
//! 2. [`PackageCache::lease`] must be called for the version a runtime was
//!    created from, and [`PackageCache::release`] when that runtime is removed.
//!    **The prune guard is only as truthful as those calls**: a version with no
//!    lease is a version this module believes nothing references. The guard is
//!    fail-closed in the other direction — see [`PackageCache::prune`] — so a
//!    lease that is never released costs disk, while a lease that is never taken
//!    costs a running runner its binaries.
//! 3. Job workspaces live under [`AppPaths::runtime_dir`] and never under the
//!    package cache. [`PackageCache::lease`] **enforces** this rather than
//!    documenting it: a lease whose attempt's runtime path resolves inside the
//!    cache root is refused.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use runner_manager_domain::attempt::{FailureReason, RunnerAttempt};
use runner_manager_domain::model::{Arch, AttemptId, Clock, Elapsed, Os, Timestamp};
use runner_manager_github::rest::{RunnerDownload, RunnerDownloads};
use runner_manager_platform::os::{self as host_os, UnsupportedHost};
use runner_manager_platform::paths::AppPaths;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// The cache root, under [`AppPaths::state_dir`].
const PACKAGES_DIR: &str = "packages";
/// Approved tool caches, retained beside the runner binaries and deliberately
/// **not** inside [`PACKAGES_DIR`]: a version entry is immutable, and a tool
/// cache is by definition written to.
const TOOL_CACHE_DIR: &str = "tool-cache";
/// Transient extraction area. Everything here is litter from an interrupted
/// install and may be removed at any time.
const STAGING_DIR: &str = ".staging";
/// One file per attempt that holds a version.
const LEASES_DIR: &str = ".leases";
const LEASE_EXTENSION: &str = "lease";
/// The manifest, written inside the staging directory before the entry lands.
const MANIFEST_FILE: &str = ".runner-package.json";

/// How far behind the latest release a cached package may be before it is
/// refreshed. GitHub rejects runners past this and plans to block them at
/// registration (`01-current-architecture.md`, edge case 7).
pub const FRESHNESS_WINDOW_DAYS: i64 = 30;

/// How often the published version is re-checked. "A bounded interval"
/// (`05-infrastructure.md`); six hours keeps the check far cheaper than the
/// demand poll while still catching a release the same day it ships.
pub const CHECK_INTERVAL_HOURS: i64 = 6;

/// How many times a *retryable* failure is retried before the install is
/// abandoned. A terminal failure consumes none of this budget.
pub const RETRY_BUDGET: u32 = 3;

// ---------------------------------------------------------------------------
// RunnerVersion
// ---------------------------------------------------------------------------

/// A runner package version, such as `2.330.0`.
///
/// # Why this is parsed rather than carried as a string
///
/// The version becomes a **directory name** under the cache root, and it is
/// derived from a filename GitHub sends over the wire. A string taken on trust
/// there is a path component taken on trust: `..`, `foo/bar`, `C:\x` and an
/// empty segment are all things a hostile or merely broken response could
/// supply. [`RunnerVersion::parse`] admits only two to four dot-separated runs
/// of ASCII digits, which cannot spell any of them.
///
/// Ordering is numeric per component, so `2.9.0 < 2.10.0`. Nothing in this
/// module makes a *safety* decision from that ordering — freshness is decided
/// from install time, not from version order — but a deterministic order makes
/// [`PackageCache::installed`] stable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RunnerVersion {
    /// Numeric components, compared first so `2.10.0` sorts above `2.9.0`.
    parts: Vec<u64>,
    raw: String,
}

impl RunnerVersion {
    /// The longest version string accepted. Generous for `MAJOR.MINOR.PATCH`
    /// and still far short of anything that could exhaust a path.
    const MAX_LEN: usize = 64;
    const MIN_PARTS: usize = 2;
    const MAX_PARTS: usize = 4;

    /// # Errors
    /// [`PackageError::UnrecognisedVersion`] when `raw` is not two to four
    /// dot-separated runs of ASCII digits.
    pub fn parse(raw: &str) -> Result<Self, PackageError> {
        let unrecognised = || PackageError::UnrecognisedVersion {
            raw: raw.to_string(),
        };
        if raw.is_empty() || raw.len() > Self::MAX_LEN {
            return Err(unrecognised());
        }
        let mut parts = Vec::new();
        for segment in raw.split('.') {
            if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_digit()) {
                return Err(unrecognised());
            }
            parts.push(segment.parse::<u64>().map_err(|_| unrecognised())?);
        }
        if parts.len() < Self::MIN_PARTS || parts.len() > Self::MAX_PARTS {
            return Err(unrecognised());
        }
        Ok(Self {
            parts,
            raw: raw.to_string(),
        })
    }

    /// The version embedded in a published filename such as
    /// `actions-runner-win-x64-2.330.0.zip`.
    ///
    /// GitHub's runner-downloads response carries no version field — the only
    /// version signal it publishes is inside the filename and the URL — so this
    /// is where the cache's directory names come from.
    ///
    /// # Errors
    /// [`PackageError::UnsupportedArchive`] when the extension is neither
    /// `.zip` nor `.tar.gz`/`.tgz`, and [`PackageError::UnrecognisedVersion`]
    /// when the trailing segment is not a version.
    pub fn from_filename(filename: &str) -> Result<Self, PackageError> {
        let (stem, _) = ArchiveKind::split(filename)?;
        let last = stem
            .rsplit('-')
            .next()
            .ok_or_else(|| PackageError::UnrecognisedVersion {
                raw: filename.to_string(),
            })?;
        Self::parse(last)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for RunnerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl TryFrom<String> for RunnerVersion {
    type Error = PackageError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<RunnerVersion> for String {
    fn from(value: RunnerVersion) -> Self {
        value.raw
    }
}

// ---------------------------------------------------------------------------
// Sha256Hex
// ---------------------------------------------------------------------------

/// A SHA-256 digest, normalised to 64 lowercase hex characters.
///
/// Parsed rather than compared as a raw string so that a malformed published
/// value — the wrong length, a non-hex character, an `sha256:` prefix — is a
/// *refusal* rather than a comparison that quietly never matches. A digest
/// check that can never succeed and a digest check that can never fail are the
/// same defect wearing different clothes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Hex(String);

impl Sha256Hex {
    const LEN: usize = 64;

    /// # Errors
    /// [`PackageError::MalformedDigest`] when `raw` is not 64 hex characters.
    pub fn parse(raw: &str) -> Result<Self, PackageError> {
        let trimmed = raw.trim();
        if trimmed.len() != Self::LEN || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PackageError::MalformedDigest {
                raw: trimmed.to_string(),
            });
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Sha256Hex {
    type Error = PackageError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Sha256Hex> for String {
    fn from(value: Sha256Hex) -> Self {
        value.0
    }
}

/// Digests an already-downloaded file without holding it in memory.
///
/// The runner package is 150-300 MB; the whole reason `reqwest`'s `stream`
/// feature is enabled for this crate is that neither the download nor this pass
/// buffers it.
fn sha256_file(path: &Path) -> Result<Sha256Hex, PackageError> {
    let mut file = fs::File::open(path).map_err(|source| PackageError::Io {
        what: "open the downloaded package for verification",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| PackageError::Io {
            what: "read the downloaded package for verification",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Sha256Hex::parse(&hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Archive kind
// ---------------------------------------------------------------------------

/// The two shapes GitHub publishes the runner in.
///
/// **Derived from the filename, never from the host OS.** They agree in
/// practice — `.zip` for Windows, `.tar.gz` elsewhere — but the filename is what
/// actually arrived, and deriving the format from an assumption about the host
/// is how a correct download gets fed to the wrong extractor. It also lets both
/// extraction paths be exercised on all three CI legs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    Zip,
    TarGz,
}

impl ArchiveKind {
    /// Splits a published filename into its stem and its archive kind.
    fn split(filename: &str) -> Result<(&str, Self), PackageError> {
        let lower = filename.to_ascii_lowercase();
        for (extension, kind) in [
            (".tar.gz", Self::TarGz),
            (".tgz", Self::TarGz),
            (".zip", Self::Zip),
        ] {
            if lower.ends_with(extension) {
                return Ok((&filename[..filename.len() - extension.len()], kind));
            }
        }
        Err(PackageError::UnsupportedArchive {
            filename: filename.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can stop a package reaching the cache.
///
/// # Terminal versus retryable is not a style choice here
///
/// `03-control-flows.md` flow 2 fixes the split, and it is narrower than it
/// looks: *"a JIT request, download checksum, process start, or runner exit
/// before job acceptance is retried with bounded exponential backoff … A runner
/// version rejection and an absent published checksum are terminal,
/// operator-actionable conditions, not retryable errors."*
///
/// So a checksum **mismatch** is retryable — the usual cause is a truncated or
/// corrupted transfer, and the next attempt gets clean bytes — while an
/// **absent** checksum is terminal, because retrying cannot make GitHub publish
/// one. Getting this backwards in either direction is a real outage: retrying a
/// version rejection turns a fixable condition into a silent loop, and treating
/// a mismatch as terminal fails a cold start on a dropped packet.
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// This OS and architecture pair is not one the product documents. Refused
    /// before any request is made, let alone any download.
    #[error("{0}")]
    UnsupportedHost(#[from] UnsupportedHost),

    /// GitHub publishes no package for this host. **Never a reason to fall back
    /// to a hardcoded URL** — that is the substitution `07-security.md` exists
    /// to prevent.
    #[error("GitHub publishes no runner package for {os}/{arch}")]
    NoPackagePublished { os: Os, arch: Arch },

    /// GitHub published no usable `sha256_checksum` and no operator-pinned
    /// digest is configured. Terminal: the agent fails closed
    /// (`05-infrastructure.md`).
    ///
    /// `empty` distinguishes a field GitHub omitted from one it sent as `""`.
    /// Both are unusable, but they are different facts about the response and
    /// `c3` deliberately keeps them apart.
    #[error(
        "GitHub published {} for runner package {version} ({os}/{arch}), so it \
         cannot be verified and will not be installed. Pin the digest you have \
         independently confirmed for {version} and retry.",
        if *empty { "an empty sha256_checksum" } else { "no sha256_checksum" }
    )]
    ChecksumAbsent {
        version: RunnerVersion,
        os: Os,
        arch: Arch,
        empty: bool,
    },

    /// The bytes on disk are not the bytes GitHub published. The partial file
    /// is removed before this is returned, and nothing is extracted.
    #[error(
        "runner package {version} does not match its published SHA-256 \
         (published {expected}, downloaded {actual}); the partial download was \
         discarded and nothing was extracted"
    )]
    ChecksumMismatch {
        version: RunnerVersion,
        expected: Sha256Hex,
        actual: Sha256Hex,
    },

    /// A digest — published or pinned — that is not 64 hex characters.
    #[error("`{raw}` is not a SHA-256 digest; a digest is 64 hexadecimal characters")]
    MalformedDigest { raw: String },

    /// GitHub refused this runner on version grounds. Terminal and
    /// operator-actionable; see [`DownloadCatalog`] for who reports it.
    #[error(
        "GitHub rejected the runner version{}{}. Runners more than \
         {FRESHNESS_WINDOW_DAYS} days behind the latest release are refused. \
         Install the current package and start a new attempt; retrying this one \
         cannot succeed.",
        version.as_ref().map(|v| format!(" {v}")).unwrap_or_default(),
        detail.as_ref().map(|d| format!(": {d}")).unwrap_or_default()
    )]
    VersionRejected {
        version: Option<RunnerVersion>,
        detail: Option<String>,
    },

    /// The download metadata could not be read. Retryable.
    #[error("the runner download metadata could not be read: {detail}")]
    CatalogUnavailable { detail: String },

    /// The package bytes could not be fetched. Retryable.
    #[error("the runner package could not be downloaded: {detail}")]
    Download { detail: String },

    /// A filename whose trailing segment is not a version.
    #[error("`{raw}` is not a runner version")]
    UnrecognisedVersion { raw: String },

    /// A published filename that is neither a `.zip` nor a `.tar.gz`.
    #[error("`{filename}` is not a runner package archive this agent can extract")]
    UnsupportedArchive { filename: String },

    /// An archive entry whose path escapes the directory being extracted into.
    ///
    /// Verification runs before extraction, so these bytes are the bytes GitHub
    /// published and this should be unreachable. It is refused anyway: the cost
    /// is a path comparison, and the thing it prevents is an archive writing
    /// outside the cache root.
    #[error("runner package entry `{entry}` escapes the directory it is extracted into")]
    UnsafeArchiveEntry { entry: String },

    /// The archive could not be read or unpacked.
    #[error("the runner package archive could not be extracted: {detail}")]
    Extract { detail: String },

    /// A prune was refused because a live attempt still holds the version.
    #[error(
        "runner package {version} is still held by attempt {attempt}, which is \
         `{state}` and not terminal; it will be prunable once that attempt \
         concludes"
    )]
    VersionInUse {
        version: RunnerVersion,
        attempt: AttemptId,
        state: &'static str,
    },

    /// A prune was refused because a lease names an attempt the caller did not
    /// report. See [`PackageCache::prune`] for why this fails closed.
    #[error(
        "runner package {version} is held by attempt {attempt}, which is not in \
         the attempt set supplied; refusing to prune a version whose holder \
         cannot be shown to be terminal. Release the lease explicitly if that \
         attempt is known to be gone."
    )]
    VersionHeldByUnknownAttempt {
        version: RunnerVersion,
        attempt: AttemptId,
    },

    /// A lease was refused because the attempt's workspace is inside the cache.
    #[error(
        "attempt {attempt} has its runtime at `{}`, which is inside the runner \
         package cache. Job workspaces are disposable and the cache is \
         immutable; a workspace here would be destroyed by a prune and would \
         mutate an entry that every other runtime is copied from.",
        path.display()
    )]
    WorkspaceInsideCache { attempt: AttemptId, path: PathBuf },

    /// A lease or prune named a version that is not in the cache.
    #[error("runner package {version} is not installed")]
    NotInstalled { version: RunnerVersion },

    #[error("cannot {what} at `{}`: {source}", path.display())]
    Io {
        what: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// Every retry was spent on retryable failures.
    #[error("giving up after {attempts} attempts: {source}")]
    Exhausted {
        attempts: u32,
        #[source]
        source: Box<PackageError>,
    },
}

impl PackageError {
    /// Whether this condition is terminal and operator-actionable rather than
    /// something a retry can clear.
    ///
    /// Read the type-level documentation before changing any arm: the split is
    /// fixed by `03-control-flows.md`, not by taste.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            // Retrying cannot make GitHub publish a checksum, support an
            // undocumented platform, publish a package it does not publish,
            // accept a rejected version, or turn a malformed value well-formed.
            Self::UnsupportedHost(_)
            | Self::NoPackagePublished { .. }
            | Self::ChecksumAbsent { .. }
            | Self::MalformedDigest { .. }
            | Self::VersionRejected { .. }
            | Self::UnrecognisedVersion { .. }
            | Self::UnsupportedArchive { .. }
            | Self::UnsafeArchiveEntry { .. }
            | Self::VersionInUse { .. }
            | Self::VersionHeldByUnknownAttempt { .. }
            | Self::WorkspaceInsideCache { .. }
            | Self::NotInstalled { .. } => true,
            // A truncated transfer, a 5xx, a rate limit, a locked file: the next
            // attempt can differ.
            Self::ChecksumMismatch { .. }
            | Self::CatalogUnavailable { .. }
            | Self::Download { .. }
            | Self::Extract { .. }
            | Self::Io { .. } => false,
            // The budget is spent; whatever it was spent on, this is the end.
            Self::Exhausted { .. } => true,
        }
    }

    /// The domain reason to journal, when this failure concludes an attempt.
    ///
    /// `b1` owns [`FailureReason`] and already names both of this module's
    /// terminal security conditions. Nothing here invents a second vocabulary
    /// for them.
    #[must_use]
    pub fn failure_reason(&self) -> Option<FailureReason> {
        match self {
            Self::ChecksumAbsent { .. }
            | Self::ChecksumMismatch { .. }
            | Self::MalformedDigest { .. }
            | Self::UnsafeArchiveEntry { .. } => Some(FailureReason::RunnerPackageUnverified),
            Self::VersionRejected { .. } => Some(FailureReason::RunnerVersionRejected),
            Self::Exhausted { source, .. } => source.failure_reason(),
            _ => None,
        }
    }

    /// What the operator has to do. Every terminal condition has one; a
    /// retryable one has none, because the answer is "wait".
    #[must_use]
    pub fn operator_action(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedHost(_) => Some(
                "run the agent on a documented operating system and architecture, \
                 or add this host to the supported matrix",
            ),
            Self::NoPackagePublished { .. } => Some(
                "check that GitHub publishes a runner package for this host's \
                 operating system and architecture",
            ),
            Self::ChecksumAbsent { .. } => Some(
                "confirm the package digest independently and pin it, or wait \
                 for GitHub to publish a checksum; the package will not be \
                 installed unverified",
            ),
            Self::MalformedDigest { .. } => {
                Some("correct the pinned digest to 64 hexadecimal characters")
            }
            Self::VersionRejected { .. } => Some(
                "install the current runner package and start a new attempt; \
                 this one cannot be retried into success",
            ),
            Self::UnsupportedArchive { .. } | Self::UnrecognisedVersion { .. } => Some(
                "GitHub's runner download metadata is not in a shape this agent \
                 recognises; report it rather than working around it",
            ),
            Self::UnsafeArchiveEntry { .. } => Some(
                "the runner package archive contains an entry that writes \
                 outside the cache; do not install it and report it",
            ),
            Self::VersionInUse { .. } => {
                Some("wait for the attempt holding this version to conclude")
            }
            Self::VersionHeldByUnknownAttempt { .. } => Some(
                "release the lease for the attempt named above if it is known to \
                 be gone, then prune again",
            ),
            Self::WorkspaceInsideCache { .. } => {
                Some("place job workspaces under the runtime directory")
            }
            Self::NotInstalled { .. } => Some("install the version before referencing it"),
            Self::Exhausted { source, .. } => source.operator_action(),
            Self::ChecksumMismatch { .. }
            | Self::CatalogUnavailable { .. }
            | Self::Download { .. }
            | Self::Extract { .. }
            | Self::Io { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// Where the published runner-download metadata comes from.
///
/// Deliberately narrower than `c3`'s `InventoryGateway`: this module needs one
/// answer, and a port with one method is a port a test can substitute without
/// standing up a whole gateway. [`GatewayCatalog`] adapts the real one.
///
/// # Reporting a version rejection through this port
///
/// GitHub's runner-downloads endpoint does not itself reject a version — the
/// rejection lands at *registration*, which is `e3`'s path. This port carries
/// [`PackageError::VersionRejected`] anyway so that a rejection observed
/// anywhere in the agent reaches the one place that can act on it: the cache,
/// whose fix is a newer package.
///
/// **An implementation that answers `VersionRejected` is promising that
/// retrying is pointless.** [`PackageCache`] honours that literally — it makes
/// no further attempt and spends none of its retry budget — so an
/// implementation that returns it for a transient condition converts a blip
/// into a stopped host. When in doubt, answer
/// [`PackageError::CatalogUnavailable`], which is retryable.
#[async_trait::async_trait]
pub trait DownloadCatalog: fmt::Debug + Send + Sync {
    /// The runner packages GitHub currently publishes.
    ///
    /// # Errors
    /// [`PackageError::CatalogUnavailable`] for anything a retry could clear,
    /// [`PackageError::VersionRejected`] for a version refusal.
    async fn published(&self) -> Result<RunnerDownloads, PackageError>;
}

/// Streams a published package onto disk.
///
/// # Contract
///
/// * The bytes are written to `destination` and nowhere else.
/// * **The implementation does not remove `destination` on failure.** A partial
///   file is the caller's to discard, and [`PackageCache`] discards it — see
///   [`PackageCache::prune`]'s neighbour, `download_and_verify`. Having the
///   fetcher clean up would hide a partial download from the very test that
///   proves it is removed.
/// * Nothing is verified here. Verification is the cache's, and it happens
///   before extraction.
#[async_trait::async_trait]
pub trait PackageFetcher: fmt::Debug + Send + Sync {
    /// Stream `url` into `destination`, answering how many bytes were written.
    ///
    /// # Errors
    /// [`PackageError::Download`] for a transport or status failure,
    /// [`PackageError::Io`] for a write failure.
    async fn fetch(&self, url: &str, destination: &Path) -> Result<u64, PackageError>;
}

/// How long to wait between retries of a retryable failure.
#[async_trait::async_trait]
pub trait Backoff: fmt::Debug + Send + Sync {
    /// Called after attempt `attempt` (1-based) failed retryably.
    async fn wait(&self, attempt: u32);
}

/// Bounded exponential backoff, as `03-control-flows.md` requires.
#[derive(Debug, Clone, Copy)]
pub struct ExponentialBackoff {
    base: std::time::Duration,
    cap: std::time::Duration,
}

impl ExponentialBackoff {
    #[must_use]
    pub const fn new(base: std::time::Duration, cap: std::time::Duration) -> Self {
        Self { base, cap }
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new(
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(30),
        )
    }
}

#[async_trait::async_trait]
impl Backoff for ExponentialBackoff {
    async fn wait(&self, attempt: u32) {
        let factor = 1_u32 << attempt.min(16);
        let delay = self.base.saturating_mul(factor).min(self.cap);
        tokio::time::sleep(delay).await;
    }
}

/// No delay at all. For tests, and for a caller that supplies its own pacing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBackoff;

#[async_trait::async_trait]
impl Backoff for NoBackoff {
    async fn wait(&self, _attempt: u32) {}
}

// ---------------------------------------------------------------------------
// Production adapters
// ---------------------------------------------------------------------------

/// Adapts `c3`'s `InventoryGateway` to [`DownloadCatalog`].
///
/// Every `InventoryError` maps to [`PackageError::CatalogUnavailable`], which
/// is retryable, because the downloads endpoint has no version-rejection
/// response: a rate limit, a cancellation and a transport failure are all
/// conditions a later attempt can clear.
#[derive(Debug)]
pub struct GatewayCatalog<G> {
    gateway: G,
    target: runner_manager_domain::model::ScaleTarget,
}

impl<G> GatewayCatalog<G> {
    #[must_use]
    pub const fn new(gateway: G, target: runner_manager_domain::model::ScaleTarget) -> Self {
        Self { gateway, target }
    }
}

#[async_trait::async_trait]
impl<G> DownloadCatalog for GatewayCatalog<G>
where
    G: runner_manager_github::rest::InventoryGateway,
{
    async fn published(&self) -> Result<RunnerDownloads, PackageError> {
        let cancel = runner_manager_github::rest::CancelToken::new();
        self.gateway
            .runner_downloads(&self.target, &cancel)
            .await
            .map_err(|error| PackageError::CatalogUnavailable {
                detail: error.to_string(),
            })
    }
}

/// Streams the package with `reqwest`, one chunk at a time.
///
/// The `stream` feature exists in this workspace for exactly this: the package
/// is 150-300 MB, and buffering it in memory on a home host is not an option —
/// nor would it leave a partial file on disk for the mismatch path to remove.
#[derive(Debug, Clone)]
pub struct HttpFetcher {
    client: reqwest::Client,
}

impl HttpFetcher {
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new(reqwest::Client::new())
    }
}

#[async_trait::async_trait]
impl PackageFetcher for HttpFetcher {
    async fn fetch(&self, url: &str, destination: &Path) -> Result<u64, PackageError> {
        use futures::StreamExt as _;
        use tokio::io::AsyncWriteExt as _;

        let response = self
            .client
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| PackageError::Download {
                detail: error.to_string(),
            })?;

        let mut file = tokio::fs::File::create(destination)
            .await
            .map_err(|source| PackageError::Io {
                what: "create the package download file",
                path: destination.to_path_buf(),
                source,
            })?;

        let mut stream = response.bytes_stream();
        let mut written = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| PackageError::Download {
                detail: error.to_string(),
            })?;
            written += chunk.len() as u64;
            file.write_all(&chunk)
                .await
                .map_err(|source| PackageError::Io {
                    what: "write the package download file",
                    path: destination.to_path_buf(),
                    source,
                })?;
        }
        file.flush().await.map_err(|source| PackageError::Io {
            what: "flush the package download file",
            path: destination.to_path_buf(),
            source,
        })?;
        file.sync_all().await.map_err(|source| PackageError::Io {
            what: "sync the package download file",
            path: destination.to_path_buf(),
            source,
        })?;
        Ok(written)
    }
}

// ---------------------------------------------------------------------------
// Pinned digests
// ---------------------------------------------------------------------------

/// Digests the operator has independently confirmed, keyed by version.
///
/// This is the *only* way a package with no published checksum is ever
/// installed. It is a deliberate, named, per-version act by an operator — not a
/// switch that turns verification off — which is the difference
/// `05-infrastructure.md` draws between "require an operator-pinned digest" and
/// "skip the check".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinnedDigests(BTreeMap<RunnerVersion, Sha256Hex>);

impl PinnedDigests {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin `digest` for `version`.
    ///
    /// # Errors
    /// [`PackageError::UnrecognisedVersion`] or
    /// [`PackageError::MalformedDigest`] when either value is not well formed.
    pub fn pin(mut self, version: &str, digest: &str) -> Result<Self, PackageError> {
        self.0
            .insert(RunnerVersion::parse(version)?, Sha256Hex::parse(digest)?);
        Ok(self)
    }

    #[must_use]
    pub fn get(&self, version: &RunnerVersion) -> Option<&Sha256Hex> {
        self.0.get(version)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Freshness
// ---------------------------------------------------------------------------

/// When a cached package stops being good enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Freshness {
    /// How far behind the latest release a cached entry may fall.
    pub window: Elapsed,
    /// How often the published version is re-checked.
    pub check_interval: Elapsed,
}

impl Default for Freshness {
    fn default() -> Self {
        Self {
            window: Elapsed::days(FRESHNESS_WINDOW_DAYS),
            check_interval: Elapsed::hours(CHECK_INTERVAL_HOURS),
        }
    }
}

// ---------------------------------------------------------------------------
// InstalledPackage
// ---------------------------------------------------------------------------

/// One immutable entry in the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    version: RunnerVersion,
    root: PathBuf,
    installed_at: Timestamp,
    digest: Sha256Hex,
}

impl InstalledPackage {
    #[must_use]
    pub fn version(&self) -> &RunnerVersion {
        &self.version
    }

    /// The extracted package directory.
    ///
    /// **Read-only to the caller.** Every JIT runtime is a copy or a link from
    /// here (`05-infrastructure.md`), so a write into this directory reaches
    /// every runtime created afterwards. Nothing in this module can detect such
    /// a write after the fact; see the module documentation's seam contract.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// When this entry landed. The freshness deadline runs from here — see
    /// [`PackageCache::is_stale`] for why install time is the honest proxy for
    /// the moment the version was superseded.
    #[must_use]
    pub const fn installed_at(&self) -> Timestamp {
        self.installed_at
    }

    /// The digest that was verified before extraction.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Hex {
        &self.digest
    }
}

/// The on-disk manifest, written inside the staging directory so that it lands
/// with the entry in one rename.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    version: RunnerVersion,
    digest: Sha256Hex,
    installed_at: Timestamp,
    /// The published filename the entry was built from. Diagnostic only.
    filename: String,
}

// ---------------------------------------------------------------------------
// PackageCache
// ---------------------------------------------------------------------------

/// The ports [`PackageCache`] reaches the world through.
pub struct CachePorts {
    pub catalog: Arc<dyn DownloadCatalog>,
    pub fetcher: Arc<dyn PackageFetcher>,
    pub backoff: Arc<dyn Backoff>,
    pub clock: Arc<dyn Clock>,
}

impl fmt::Debug for CachePorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachePorts")
            .field("catalog", &self.catalog)
            .field("fetcher", &self.fetcher)
            .field("backoff", &self.backoff)
            .field("clock", &self.clock)
            .finish()
    }
}

/// The versioned, immutable, checksum-verified runner package cache.
#[derive(Debug)]
pub struct PackageCache {
    root: PathBuf,
    tool_cache: PathBuf,
    os: Os,
    arch: Arch,
    ports: CachePorts,
    pins: PinnedDigests,
    freshness: Freshness,
    retry_budget: u32,
    /// When the published version was last resolved successfully.
    ///
    /// Held in memory rather than on disk on purpose: a restart forcing a
    /// re-check is the *correct* behaviour — the agent has no idea how long it
    /// was down — so persisting this would only buy the ability to skip a check
    /// that should not be skipped.
    last_check: Mutex<Option<Timestamp>>,
}

impl PackageCache {
    /// Build a cache rooted under `paths`, for a host running `os`/`arch`.
    ///
    /// `os` and `arch` are parameters rather than probed here, following
    /// `d1`'s pattern: `runner_manager_platform::os::detect_host` is called once
    /// at the composition edge, and everything below takes the pair as a value.
    /// That is the whole injection seam — there is no host-probe trait — and it
    /// is what lets a Linux CI leg exercise the Windows selection path.
    #[must_use]
    pub fn new(paths: &AppPaths, os: Os, arch: Arch, ports: CachePorts) -> Self {
        Self {
            root: paths.state_dir().join(PACKAGES_DIR),
            tool_cache: paths.state_dir().join(TOOL_CACHE_DIR),
            os,
            arch,
            ports,
            pins: PinnedDigests::new(),
            freshness: Freshness::default(),
            retry_budget: RETRY_BUDGET,
            last_check: Mutex::new(None),
        }
    }

    #[must_use]
    pub fn with_pins(mut self, pins: PinnedDigests) -> Self {
        self.pins = pins;
        self
    }

    #[must_use]
    pub const fn with_freshness(mut self, freshness: Freshness) -> Self {
        self.freshness = freshness;
        self
    }

    /// Override the retry budget. Zero is rejected in favour of one attempt,
    /// because a cache that never attempts anything is not a cache.
    #[must_use]
    pub const fn with_retry_budget(mut self, budget: u32) -> Self {
        self.retry_budget = if budget == 0 { 1 } else { budget };
        self
    }

    /// The cache root. Nothing outside this module writes here.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where approved tool caches are retained.
    ///
    /// A sibling of the package entries, not a child: an entry is immutable and
    /// a tool cache is by definition written to. Both are retained across
    /// attempts, and both are outside [`AppPaths::runtime_dir`], which is where
    /// disposable job workspaces live — that is the separation
    /// `05-infrastructure.md` asks for.
    #[must_use]
    pub fn tool_cache_dir(&self) -> &Path {
        &self.tool_cache
    }

    // -- installation ------------------------------------------------------

    /// Make a verified runner package available, and answer which one.
    ///
    /// **This is the cold-start path.** It decides three things in order:
    ///
    /// 1. Is this host one the product documents? An undocumented pair is
    ///    refused here, before the catalog is consulted and long before
    ///    anything is downloaded.
    /// 2. Is a check due? The published version is re-checked on
    ///    [`Freshness::check_interval`], and always when the cache is empty. A
    ///    cold start inside that interval reuses what a previous one resolved,
    ///    which is what "a bounded interval" buys.
    /// 3. Is what we hold still good enough? See [`Self::is_stale`].
    ///
    /// # Errors
    /// Any [`PackageError`]. A terminal one is returned on the spot and spends
    /// none of the retry budget; a retryable one is retried up to
    /// [`Self::with_retry_budget`] times and then wrapped in
    /// [`PackageError::Exhausted`].
    pub async fn ensure_installed(&self) -> Result<InstalledPackage, PackageError> {
        // Before the catalog, before the fetcher, before anything touches the
        // network: an unsupported pair has no package and never will.
        host_os::validate(self.os, self.arch)?;

        let now = self.ports.clock.now();
        if !self.check_is_due(now)?
            && let Some(entry) = self.newest_installed()?
        {
            return Ok(entry);
        }

        let mut last: Option<PackageError> = None;
        for attempt in 1..=self.retry_budget {
            match self.install_once().await {
                Ok(package) => {
                    *self
                        .last_check
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(self.ports.clock.now());
                    return Ok(package);
                }
                Err(error) if error.is_terminal() => return Err(error),
                Err(error) => {
                    last = Some(error);
                    if attempt < self.retry_budget {
                        self.ports.backoff.wait(attempt).await;
                    }
                }
            }
        }
        Err(PackageError::Exhausted {
            attempts: self.retry_budget,
            source: Box::new(last.expect("a spent budget leaves a failure behind")),
        })
    }

    /// Whether a cached entry has fallen outside the freshness window.
    ///
    /// # Why install time, and why this is the fail-closed direction
    ///
    /// GitHub's rule is about the *release*: a runner more than
    /// [`FRESHNESS_WINDOW_DAYS`] days behind the latest one is refused. The
    /// agent cannot see release dates — GitHub's runner-downloads response
    /// carries no version field, let alone a publication timestamp — so the
    /// supersession moment has to be bounded rather than read.
    ///
    /// It can be bounded exactly. This cache only ever installs the version
    /// GitHub was publishing at the time, so an entry installed at `T` *was*
    /// the latest release at `T`. Whatever superseded it did so at some
    /// `R >= T`, hence `now - R <= now - T`. So:
    ///
    /// * `now - T <= window` proves `now - R <= window`: the entry cannot be
    ///   past the deadline, and reusing it is safe.
    /// * `now - T > window` proves nothing either way, so the entry is treated
    ///   as stale and refreshed.
    ///
    /// The error is therefore always toward refreshing early, never toward
    /// running a package GitHub will refuse. Refreshing early costs a download;
    /// refreshing late costs every job on the host, for a reason the operator
    /// has no way to guess.
    #[must_use]
    pub fn is_stale(&self, package: &InstalledPackage, now: Timestamp) -> bool {
        now.signed_duration_since(package.installed_at) > self.freshness.window
    }

    /// Whether the published version is due to be re-checked.
    fn check_is_due(&self, now: Timestamp) -> Result<bool, PackageError> {
        if self.newest_installed()?.is_none() {
            return Ok(true);
        }
        let last = *self
            .last_check
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(match last {
            None => true,
            Some(at) => now.signed_duration_since(at) >= self.freshness.check_interval,
        })
    }

    /// One attempt: resolve, decide, and install if a download is warranted.
    async fn install_once(&self) -> Result<InstalledPackage, PackageError> {
        let published = self.ports.catalog.published().await?;

        // Selection: this host's OS and architecture, from GitHub's metadata.
        // `select` answering `None` is refused rather than fallen back from —
        // a hardcoded URL is the substitution `07-security.md` names as the
        // threat.
        let download = published.select(self.os, self.arch).ok_or(
            PackageError::NoPackagePublished {
                os: self.os,
                arch: self.arch,
            },
        )?;
        let version = RunnerVersion::from_filename(&download.filename)?;

        // Already held: no fetch, no extraction, no rewrite.
        if let Some(entry) = self.entry(&version)? {
            return Ok(entry);
        }

        // A different version is published. Whether that warrants 150-300 MB is
        // the freshness question, and only that question.
        let now = self.ports.clock.now();
        if let Some(newest) = self.newest_installed()?
            && !self.is_stale(&newest, now)
        {
            return Ok(newest);
        }

        let digest = self.required_digest(download, &version)?;
        self.download_verify_and_install(download, &version, &digest, now)
            .await
    }

    /// The digest that must match, or a refusal.
    ///
    /// This is the fail-closed gate. `sha256_checksum` is optional in GitHub's
    /// schema, and the only two acceptable outcomes when it is unusable are an
    /// operator-pinned digest or a refusal to install. There is no third.
    fn required_digest(
        &self,
        download: &RunnerDownload,
        version: &RunnerVersion,
    ) -> Result<Sha256Hex, PackageError> {
        match download.sha256_checksum() {
            Some(raw) if !raw.trim().is_empty() => Sha256Hex::parse(raw),
            published => match self.pins.get(version) {
                Some(pinned) => Ok(pinned.clone()),
                None => Err(PackageError::ChecksumAbsent {
                    version: version.clone(),
                    os: self.os,
                    arch: self.arch,
                    // `c3` keeps "absent" and "empty" apart deliberately; both
                    // are unusable, but they are different facts about the
                    // response and the operator is owed the one that happened.
                    empty: published.is_some(),
                }),
            },
        }
    }

    /// Fetch, verify, extract, commit. In that order, without exception.
    async fn download_verify_and_install(
        &self,
        download: &RunnerDownload,
        version: &RunnerVersion,
        expected: &Sha256Hex,
        now: Timestamp,
    ) -> Result<InstalledPackage, PackageError> {
        let (_, kind) = ArchiveKind::split(&download.filename)?;
        let staging = self.new_staging_dir()?;
        let guard = StagingGuard::new(staging.clone());
        let archive = staging.join("package.archive");

        self.ports
            .fetcher
            .fetch(&download.download_url, &archive)
            .await?;

        // Verification, before extraction. The whole module exists for this
        // ordering.
        let archive_for_hash = archive.clone();
        let actual = tokio::task::spawn_blocking(move || sha256_file(&archive_for_hash))
            .await
            .map_err(|error| PackageError::Extract {
                detail: format!("the verification task failed: {error}"),
            })??;

        if actual != *expected {
            // The partial (or substituted) file is removed here rather than left
            // for the staging sweep, because "the partially downloaded file is
            // removed" is a property this module owes on the mismatch path
            // specifically, not a side effect of tidying up later.
            if let Err(source) = fs::remove_file(&archive)
                && source.kind() != io::ErrorKind::NotFound
            {
                return Err(PackageError::Io {
                    what: "remove the unverified package download",
                    path: archive.clone(),
                    source,
                });
            }
            return Err(PackageError::ChecksumMismatch {
                version: version.clone(),
                expected: expected.clone(),
                actual,
            });
        }

        let extracted = staging.join("root");
        let archive_for_extract = archive.clone();
        let extracted_for_task = extracted.clone();
        tokio::task::spawn_blocking(move || {
            extract(&archive_for_extract, kind, &extracted_for_task)
        })
        .await
        .map_err(|error| PackageError::Extract {
            detail: format!("the extraction task failed: {error}"),
        })??;

        // The archive has served its purpose; it is not part of the entry.
        let _ = fs::remove_file(&archive);

        let manifest = Manifest {
            version: version.clone(),
            digest: expected.clone(),
            installed_at: now,
            filename: download.filename.clone(),
        };
        write_json(&extracted.join(MANIFEST_FILE), &manifest)?;

        let target = self.version_dir(version);
        create_dir_all(&self.root)?;

        // The single commit point. `rename` onto an existing directory fails on
        // Windows and replaces nothing on Unix, and either way the answer is the
        // same: someone already installed this version, and an installed entry
        // is never overwritten.
        match fs::rename(&extracted, &target) {
            Ok(()) => {}
            Err(source) => {
                if let Some(entry) = self.entry(version)? {
                    guard.disarm_into_sweep();
                    return Ok(entry);
                }
                return Err(PackageError::Io {
                    what: "commit the extracted runner package",
                    path: target,
                    source,
                });
            }
        }
        guard.disarm_into_sweep();

        Ok(InstalledPackage {
            version: version.clone(),
            root: target,
            installed_at: now,
            digest: expected.clone(),
        })
    }

    // -- reading the cache -------------------------------------------------

    fn version_dir(&self, version: &RunnerVersion) -> PathBuf {
        self.root.join(version.as_str())
    }

    /// One entry, if it is installed and complete.
    ///
    /// A directory with no readable manifest is *not* an entry: the manifest
    /// lands with the directory in a single rename, so its absence means the
    /// directory was not produced by this module and nothing may be assumed
    /// about its contents.
    ///
    /// # Errors
    /// [`PackageError::Io`] when the cache cannot be read.
    pub fn entry(&self, version: &RunnerVersion) -> Result<Option<InstalledPackage>, PackageError> {
        let root = self.version_dir(version);
        if !root.is_dir() {
            return Ok(None);
        }
        let Some(manifest) = read_json::<Manifest>(&root.join(MANIFEST_FILE))? else {
            return Ok(None);
        };
        Ok(Some(InstalledPackage {
            version: manifest.version,
            root,
            installed_at: manifest.installed_at,
            digest: manifest.digest,
        }))
    }

    /// Every complete entry, oldest version first.
    ///
    /// # Errors
    /// [`PackageError::Io`] when the cache directory cannot be read.
    pub fn installed(&self) -> Result<Vec<InstalledPackage>, PackageError> {
        let mut found = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(found),
            Err(source) => {
                return Err(PackageError::Io {
                    what: "read the runner package cache",
                    path: self.root.clone(),
                    source,
                });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|source| PackageError::Io {
                what: "read the runner package cache",
                path: self.root.clone(),
                source,
            })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // `.staging` and `.leases` are not versions, and `RunnerVersion`
            // could not parse them anyway; skipping them explicitly keeps the
            // intent visible.
            if name.starts_with('.') {
                continue;
            }
            let Ok(version) = RunnerVersion::parse(name) else {
                continue;
            };
            if let Some(package) = self.entry(&version)? {
                found.push(package);
            }
        }
        found.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(found)
    }

    /// The most recently installed entry, which is the one a cold start reuses.
    fn newest_installed(&self) -> Result<Option<InstalledPackage>, PackageError> {
        Ok(self
            .installed()?
            .into_iter()
            .max_by_key(|package| package.installed_at))
    }

    // -- leases and pruning ------------------------------------------------

    fn leases_dir(&self) -> PathBuf {
        self.root.join(LEASES_DIR)
    }

    fn lease_path(&self, attempt: AttemptId) -> PathBuf {
        self.leases_dir()
            .join(format!("{attempt}.{LEASE_EXTENSION}"))
    }

    /// Record that `attempt` holds `version`, so a prune cannot remove it.
    ///
    /// Two refusals, both structural:
    ///
    /// * A version that is not installed cannot be held.
    /// * An attempt whose runtime directory is **inside the cache root** is
    ///   refused outright. Job workspaces are disposable and per-attempt; a
    ///   package entry is shared and immutable. A workspace nested in one would
    ///   be destroyed the moment that version was pruned, and would mutate an
    ///   entry that every other runtime is copied from. This is checked rather
    ///   than documented because a documented invariant with no enforcement is
    ///   how the property silently stops holding.
    ///
    /// The lease survives a restart — it is a file, not a field — which is what
    /// makes the guard meaningful across the agent's own lifetime.
    ///
    /// # Errors
    /// [`PackageError::NotInstalled`], [`PackageError::WorkspaceInsideCache`],
    /// or [`PackageError::Io`].
    pub fn lease(
        &self,
        attempt: &RunnerAttempt,
        version: &RunnerVersion,
    ) -> Result<(), PackageError> {
        if self.entry(version)?.is_none() {
            return Err(PackageError::NotInstalled {
                version: version.clone(),
            });
        }
        let runtime = attempt.runtime_path();
        if is_inside(&self.root, runtime) {
            return Err(PackageError::WorkspaceInsideCache {
                attempt: attempt.id,
                path: runtime.to_path_buf(),
            });
        }
        create_dir_all(&self.leases_dir())?;
        write_json(
            &self.lease_path(attempt.id),
            &Lease {
                version: version.clone(),
            },
        )
    }

    /// Drop `attempt`'s hold, whatever it was holding.
    ///
    /// Idempotent: releasing a lease that was never taken is not an error, so a
    /// cleanup path may call it unconditionally.
    ///
    /// # Errors
    /// [`PackageError::Io`] when the lease file cannot be removed.
    pub fn release(&self, attempt: AttemptId) -> Result<(), PackageError> {
        let path = self.lease_path(attempt);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(PackageError::Io {
                what: "release a runner package lease",
                path,
                source,
            }),
        }
    }

    /// Every attempt currently holding `version`.
    ///
    /// # Errors
    /// [`PackageError::Io`] when the lease directory cannot be read.
    pub fn holders(&self, version: &RunnerVersion) -> Result<Vec<AttemptId>, PackageError> {
        let mut holders = Vec::new();
        let dir = self.leases_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(holders),
            Err(source) => {
                return Err(PackageError::Io {
                    what: "read the runner package leases",
                    path: dir,
                    source,
                });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|source| PackageError::Io {
                what: "read the runner package leases",
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(LEASE_EXTENSION) {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(uuid) = uuid::Uuid::parse_str(stem) else {
                continue;
            };
            let Some(lease) = read_json::<Lease>(&path)? else {
                continue;
            };
            if lease.version == *version {
                holders.push(AttemptId::from_uuid(uuid));
            }
        }
        holders.sort_unstable();
        Ok(holders)
    }

    /// Remove a cached version, if nothing active still references it.
    ///
    /// `attempts` is the host's attempt set — the same set
    /// `RunnerLauncher::attempts` answers, terminal entries included, because
    /// both questions are asked of one set. Each lease on `version` is resolved
    /// against it:
    ///
    /// | Lease's attempt | Outcome |
    /// |---|---|
    /// | present and non-terminal | **refused** — [`PackageError::VersionInUse`] |
    /// | present and terminal | released, and the prune proceeds |
    /// | absent from the set | **refused** — [`PackageError::VersionHeldByUnknownAttempt`] |
    ///
    /// # Why an absent attempt refuses rather than releases
    ///
    /// It would be tidier to read "not in the set" as "gone", and it would be
    /// wrong. `e1` documents that a launcher's newly created attempt may not be
    /// visible to `attempts()` yet — a journal write that has not landed, an
    /// asynchronous store, a cache — and that lag is exactly the window in
    /// which a just-leased version would look unreferenced. Deleting a package
    /// out from under a starting runner is not a condition the runner can
    /// report intelligibly, so the ambiguous case fails closed. The cost is a
    /// version that stays on disk until [`Self::release`] is called for a lease
    /// nobody will ever release; the error names that remedy.
    ///
    /// **The guard is only as truthful as the caller's leases.** This function
    /// can refuse to prune something it knows is held; it cannot discover a
    /// reference nobody recorded. See the module documentation's seam contract.
    ///
    /// # Errors
    /// [`PackageError::VersionInUse`],
    /// [`PackageError::VersionHeldByUnknownAttempt`],
    /// [`PackageError::NotInstalled`], or [`PackageError::Io`].
    pub fn prune(
        &self,
        version: &RunnerVersion,
        attempts: &[RunnerAttempt],
    ) -> Result<(), PackageError> {
        if self.entry(version)?.is_none() {
            return Err(PackageError::NotInstalled {
                version: version.clone(),
            });
        }
        let holders = self.holders(version)?;
        for holder in &holders {
            match attempts.iter().find(|attempt| attempt.id == *holder) {
                Some(attempt) if !attempt.is_terminal() => {
                    return Err(PackageError::VersionInUse {
                        version: version.clone(),
                        attempt: *holder,
                        state: state_name(attempt),
                    });
                }
                Some(_) => {}
                None => {
                    return Err(PackageError::VersionHeldByUnknownAttempt {
                        version: version.clone(),
                        attempt: *holder,
                    });
                }
            }
        }

        let dir = self.version_dir(version);
        fs::remove_dir_all(&dir).map_err(|source| PackageError::Io {
            what: "remove a cached runner package",
            path: dir,
            source,
        })?;
        // The holders were all terminal, so their leases are spent.
        for holder in holders {
            self.release(holder)?;
        }
        Ok(())
    }

    // -- staging -----------------------------------------------------------

    fn staging_root(&self) -> PathBuf {
        self.root.join(STAGING_DIR)
    }

    fn new_staging_dir(&self) -> Result<PathBuf, PackageError> {
        let dir = self.staging_root().join(uuid::Uuid::new_v4().to_string());
        create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Remove staging litter left by an interrupted install.
    ///
    /// Nothing under `.staging/` is ever part of an entry, so this is always
    /// safe to call. It is separate from installing because a sweep that ran
    /// automatically would race a concurrent install's staging directory.
    ///
    /// # Errors
    /// [`PackageError::Io`] when the staging root cannot be read.
    pub fn sweep_staging(&self) -> Result<usize, PackageError> {
        let root = self.staging_root();
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(source) => {
                return Err(PackageError::Io {
                    what: "read the runner package staging area",
                    path: root,
                    source,
                });
            }
        };
        let mut swept = 0;
        for entry in entries.flatten() {
            if fs::remove_dir_all(entry.path()).is_ok() {
                swept += 1;
            }
        }
        Ok(swept)
    }
}

/// One attempt's hold on one version.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Lease {
    version: RunnerVersion,
}

/// A stable name for an attempt's state, for an error message.
fn state_name(attempt: &RunnerAttempt) -> &'static str {
    use runner_manager_domain::attempt::AttemptState as S;
    match attempt.state() {
        S::Allocated => "allocated",
        S::JitReceived => "jit_received",
        S::Starting => "starting",
        S::Idle => "idle",
        S::Busy => "busy",
        S::Finished => "finished",
        S::Failed => "failed",
        S::Orphaned => "orphaned",
        S::Cleaned => "cleaned",
    }
}

/// Removes a staging directory unless the install committed it.
struct StagingGuard {
    dir: Option<PathBuf>,
}

impl StagingGuard {
    fn new(dir: PathBuf) -> Self {
        Self { dir: Some(dir) }
    }

    /// The entry landed (or was already there); the staging directory is now
    /// ordinary litter and is removed on the spot rather than on unwind.
    fn disarm_into_sweep(mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

/// Extract a verified archive into a fresh directory.
///
/// The digest has already matched by the time this runs, so these are the bytes
/// GitHub published. The containment checks below are defence in depth, not the
/// primary control — but they are cheap, and what they prevent is an archive
/// writing outside the directory it was given.
fn extract(archive: &Path, kind: ArchiveKind, into: &Path) -> Result<(), PackageError> {
    create_dir_all(into)?;
    match kind {
        ArchiveKind::Zip => extract_zip(archive, into),
        ArchiveKind::TarGz => extract_tar_gz(archive, into),
    }
}

fn extract_zip(archive: &Path, into: &Path) -> Result<(), PackageError> {
    let file = fs::File::open(archive).map_err(|source| PackageError::Io {
        what: "open the runner package archive",
        path: archive.to_path_buf(),
        source,
    })?;
    let mut zip = zip::ZipArchive::new(file).map_err(|error| PackageError::Extract {
        detail: error.to_string(),
    })?;

    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(|error| PackageError::Extract {
            detail: error.to_string(),
        })?;
        let raw_name = entry.name().to_string();
        // `enclosed_name` answers `None` for an absolute path, a drive prefix,
        // or any `..` component. Our own containment check follows it because
        // the two disagree on nothing and agreeing twice is the point.
        let relative = entry
            .enclosed_name()
            .ok_or_else(|| PackageError::UnsafeArchiveEntry {
                entry: raw_name.clone(),
            })?;
        let destination = resolve_inside(into, &relative, &raw_name)?;

        if entry.is_dir() {
            create_dir_all(&destination)?;
            continue;
        }
        if entry.is_symlink() {
            // Windows packages are the `.zip` ones and contain no symlinks. A
            // link here would be a shape this agent has never seen from GitHub,
            // and creating it needs a privilege the agent should not want.
            return Err(PackageError::UnsafeArchiveEntry { entry: raw_name });
        }
        if let Some(parent) = destination.parent() {
            create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&destination).map_err(|source| PackageError::Io {
            what: "create an extracted runner package file",
            path: destination.clone(),
            source,
        })?;
        io::copy(&mut entry, &mut out).map_err(|source| PackageError::Io {
            what: "write an extracted runner package file",
            path: destination.clone(),
            source,
        })?;
        set_executable(&destination, entry.unix_mode())?;
    }
    Ok(())
}

fn extract_tar_gz(archive: &Path, into: &Path) -> Result<(), PackageError> {
    let file = fs::File::open(archive).map_err(|source| PackageError::Io {
        what: "open the runner package archive",
        path: archive.to_path_buf(),
        source,
    })?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let entries = tar.entries().map_err(|source| PackageError::Extract {
        detail: source.to_string(),
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|source| PackageError::Extract {
            detail: source.to_string(),
        })?;
        let path = entry.path().map_err(|source| PackageError::Extract {
            detail: source.to_string(),
        })?;
        let display = path.display().to_string();
        // Our own containment check, before `tar`'s. It costs a path walk and
        // it means the refusal is this module's behaviour rather than a
        // dependency's default that a version bump could change.
        resolve_inside(into, path.as_ref(), &display)?;
        // The runner's `run.sh`, `config.sh` and `bin/*` are useless without
        // their mode bits.
        entry.set_preserve_permissions(true);
        let unpacked = entry
            .unpack_in(into)
            .map_err(|source| PackageError::Extract {
                detail: source.to_string(),
            })?;
        if !unpacked {
            return Err(PackageError::UnsafeArchiveEntry { entry: display });
        }
    }
    Ok(())
}

/// Join `relative` onto `root` and prove the result stays inside it.
fn resolve_inside(root: &Path, relative: &Path, raw: &str) -> Result<PathBuf, PackageError> {
    let unsafe_entry = || PackageError::UnsafeArchiveEntry {
        entry: raw.to_string(),
    };
    if relative.is_absolute() {
        return Err(unsafe_entry());
    }
    let mut resolved = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            // `.` is harmless but carries no information; everything else —
            // `..`, a root, a drive prefix — is an escape attempt or a shape
            // this module refuses to guess about.
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(unsafe_entry());
            }
        }
    }
    if !is_inside(root, &resolved) {
        return Err(unsafe_entry());
    }
    Ok(resolved)
}

/// Whether `candidate` is `root` itself or lies beneath it, lexically.
///
/// Lexical on purpose: it must answer for paths that do not exist yet — an
/// archive entry's destination, an attempt's runtime directory before `e3`
/// creates it — and `canonicalize` cannot.
fn is_inside(root: &Path, candidate: &Path) -> bool {
    let normalise = |path: &Path| -> Vec<std::ffi::OsString> {
        path.components()
            .filter_map(|component| match component {
                Component::Normal(part) => Some(part.to_os_string()),
                Component::RootDir => Some(std::ffi::OsString::from("/")),
                Component::Prefix(prefix) => Some(prefix.as_os_str().to_os_string()),
                Component::CurDir | Component::ParentDir => None,
            })
            .collect()
    };
    // A `..` anywhere in the candidate means the lexical answer is not
    // trustworthy, so refuse to claim containment.
    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return false;
    }
    let root = normalise(root);
    let candidate = normalise(candidate);
    candidate.len() >= root.len() && candidate[..root.len()] == root[..]
}

#[cfg(unix)]
fn set_executable(path: &Path, mode: Option<u32>) -> Result<(), PackageError> {
    use std::os::unix::fs::PermissionsExt as _;
    let Some(mode) = mode else { return Ok(()) };
    // Only the executable bits are honoured. A mode from an archive is not a
    // security decision this agent delegates: group- and world-writable bits
    // from a package would be, so they are dropped.
    let mode = (mode & 0o111) | 0o600;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| PackageError::Io {
        what: "set permissions on an extracted runner package file",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _mode: Option<u32>) -> Result<(), PackageError> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Small filesystem helpers
// ---------------------------------------------------------------------------

fn create_dir_all(path: &Path) -> Result<(), PackageError> {
    fs::create_dir_all(path).map_err(|source| PackageError::Io {
        what: "create a runner package cache directory",
        path: path.to_path_buf(),
        source,
    })
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), PackageError> {
    let encoded = serde_json::to_vec_pretty(value).map_err(|error| PackageError::Extract {
        detail: format!("the package manifest could not be encoded: {error}"),
    })?;
    fs::write(path, encoded).map_err(|source| PackageError::Io {
        what: "write a runner package cache file",
        path: path.to_path_buf(),
        source,
    })
}

/// Reads a JSON file, answering `None` when it is absent or unreadable as `T`.
///
/// A corrupt manifest reads as "not an entry" rather than as an error: the
/// caller's next move is the same either way — treat the directory as not
/// installed — and a cache that refuses to answer at all because one directory
/// is damaged is worse than one that ignores it.
fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, PackageError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(PackageError::Io {
                what: "read a runner package cache file",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    Ok(serde_json::from_slice(&bytes).ok())
}
