// owner: b1-runner-path-platform

//! Where disposable runner attempts are placed, and whether a configured
//! location can actually hold them.
//!
//! `02-target-architecture.md` separates three path concepts that used to share
//! one directory. [`crate::paths::AppPaths`] owns the first — config, SQLite,
//! logs, diagnostics and the verified package cache — and nothing here moves
//! it. This module owns the other two: the **host runner root** under which
//! ephemeral attempts are created, and the operational check every
//! **repository persistent root** must also pass.
//!
//! ## Two layers, and why the split is load-bearing
//!
//! [`LocalAbsolutePath`] is the *pure* layer: it decides whether a string is a
//! shape the product will persist, with no syscall and no ambient state, so
//! opening the database never depends on a drive being mounted today. This
//! module is the *operational* layer named in "Path validation": it runs before
//! a mutation is committed and before the daemon accepts new allocation, and it
//! is the only one of the two allowed to ask the filesystem anything.
//!
//! ```text
//! LocalAbsolutePath   absolute? non-root? native? no UNC, device or `..`?
//! RootPreflight       local volume? writable? a real directory? contained?
//! ```
//!
//! ## What this module will not do
//!
//! **It never creates, deletes, or re-permissions anything.** Both writability
//! probes are pure queries — `access(2)` on Unix, and on Windows a directory
//! *handle* opened for `FILE_ADD_SUBDIRECTORY`, which runs the real access check
//! against the real DACL and produces no file. That is deliberate: "validation
//! performs no deletion or permission mutation" is then a property of the code
//! rather than a convention, and a preflight that probed by writing a marker
//! would be a preflight that can leave litter in an operator's directory.
//! Creating the validated leaf and applying the narrow default-root ACL are
//! explicit steps their callers take *after* this returns `Ok`, in `b2` and
//! `c1`.
//!
//! ## The Windows default
//!
//! D1 is `%SystemDrive%\rman`, "normally `C:\rman`". The drive letter is read
//! from `GetSystemDirectoryW`, not from `%SystemDrive%`: an environment
//! variable is writable by whatever launched the process, and this value
//! decides where a recursive cleanup will later run. Nothing here assumes `C:`
//! — [`default_runner_root_from`] takes the system directory as an argument, so
//! the Linux and macOS CI legs test the Windows rule too.

use std::cmp::Ordering;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use runner_manager_domain::path::{LocalAbsolutePath, LocalPathError, PathPlatform};

use crate::paths::AppPaths;

/// The directory appended to the Windows system drive to form the default host
/// runner root.
///
/// Short on purpose: the feature exists because
/// `%LOCALAPPDATA%\IvanMurzak\runner-manager\data\runtime\<attempt>` plus a
/// deep repository checkout exceeds what some build tools tolerate. The owner
/// selected `rman` over `rm` (ledger, 2026-08-31).
pub const WINDOWS_RUNNER_ROOT_NAME: &str = "rman";

// ---------------------------------------------------------------------------
// Who a root belongs to
// ---------------------------------------------------------------------------

/// Which setting a root came from.
///
/// Carried by the preflight so that two roots belonging to the same owner are
/// never compared with each other — re-validating a repository's *current* root
/// must not report that it overlaps itself — and so that a failure can name the
/// command that fixes it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RootOwner {
    /// `Host.runner_root_override`, or the platform default standing in for it.
    Host,
    /// A repository's persistent workspace root, by `owner/name`.
    Repository(String),
}

impl RootOwner {
    /// The command an operator runs to change this root.
    ///
    /// `03-migration-rollout.md` requires a failure to "report the exact
    /// `host set-runtime-root` remediation command"; the repository half is the
    /// same requirement for `d1`'s other mutation.
    #[must_use]
    pub fn remediation(&self) -> String {
        match self {
            RootOwner::Host => "runner-manager host set-runtime-root --path <PATH>".to_string(),
            RootOwner::Repository(repository) => format!(
                "runner-manager repo set-workspace {repository} --mode persistent --path <PATH>"
            ),
        }
    }
}

impl fmt::Display for RootOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RootOwner::Host => f.write_str("the host runner root"),
            RootOwner::Repository(repository) => {
                write!(f, "the persistent workspace root for {repository}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Overlap
// ---------------------------------------------------------------------------

/// How two paths sit relative to one another.
///
/// Every relation other than [`Overlap::Disjoint`] is refused for a configured
/// root: equality and descent would put runner material among application data
/// or another repository's slots, and ancestry would put *that* data inside a
/// directory this product later removes recursively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overlap {
    /// Neither path contains the other.
    Disjoint,
    /// The two paths are the same directory.
    Same,
    /// The first path is below the second.
    Inside,
    /// The first path is above the second.
    Contains,
}

impl fmt::Display for Overlap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Overlap::Disjoint => "is unrelated to",
            Overlap::Same => "is the same directory as",
            Overlap::Inside => "is inside",
            Overlap::Contains => "contains",
        })
    }
}

/// Splits a path into the components an overlap test compares.
///
/// Deliberately string-based rather than [`Path`]-based: `Path` only parses the
/// syntax of the platform it was compiled for, so a `Path`-based comparison
/// could only be tested on one CI leg, and the Windows drive-prefix case is
/// exactly the one worth testing everywhere. A Windows path yields its drive as
/// an ordinary first component (`C:\rman` becomes `["C:", "rman"]`), which is
/// what keeps `C:\rman` and `D:\rman` disjoint.
fn components_of(path: &str, platform: PathPlatform) -> Vec<&str> {
    path.split(|c| platform.is_separator(c))
        .filter(|component| !component.is_empty() && *component != ".")
        .collect()
}

/// Whether two path components name the same directory on `platform`.
///
/// Windows compares case-insensitively, and over the whole of Unicode rather
/// than over ASCII alone: NTFS folds `Ärman` and `ärman` to one directory, so an
/// ASCII-only comparison would call two roots disjoint that later turn out to be
/// the same tree, which is the direction that loses data. Unix does not fold: a
/// Linux volume is case-sensitive, and refusing to distinguish `/srv/Rman` from
/// `/srv/rman` there would reject two directories an operator legitimately has.
/// A case-insensitive macOS volume is the residual, and it is the safe direction
/// only for the containment test, so it is stated rather than hidden.
fn same_component(left: &str, right: &str, platform: PathPlatform) -> bool {
    match platform {
        PathPlatform::Windows => left
            .chars()
            .flat_map(char::to_lowercase)
            .eq(right.chars().flat_map(char::to_lowercase)),
        PathPlatform::Unix => left == right,
    }
}

/// How `candidate` sits relative to `other`.
fn overlap_of(candidate: &str, other: &str, platform: PathPlatform) -> Overlap {
    let left = components_of(candidate, platform);
    let right = components_of(other, platform);
    let shared = left
        .iter()
        .zip(right.iter())
        .take_while(|(l, r)| same_component(l, r, platform))
        .count();
    if shared < left.len().min(right.len()) {
        return Overlap::Disjoint;
    }
    match left.len().cmp(&right.len()) {
        Ordering::Equal => Overlap::Same,
        Ordering::Greater => Overlap::Inside,
        Ordering::Less => Overlap::Contains,
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a runner root cannot be resolved, or cannot be used.
///
/// One type for every caller: CLI, TUI, daemon startup and restart recovery all
/// reach the same decision, and `02-target-architecture.md` requires them to
/// reach it with the same messages. No variant may ever be handed a token or a
/// JIT configuration — these are paths, and they are printed verbatim.
#[derive(Debug, thiserror::Error)]
pub enum RunnerRootError {
    #[error(
        "the operating system did not report a system directory, so the default runner \
         root <system-drive>\\{WINDOWS_RUNNER_ROOT_NAME} cannot be resolved: {source}. \
         Configure one explicitly with \
         `runner-manager host set-runtime-root --path <PATH>`."
    )]
    SystemDirectoryUnavailable {
        #[source]
        source: io::Error,
    },

    #[error(
        "the system directory {got:?} is not a usable volume for the default runner \
         root: {source}. Configure one explicitly with \
         `runner-manager host set-runtime-root --path <PATH>`."
    )]
    SystemDirectoryUnusable {
        got: String,
        #[source]
        source: LocalPathError,
    },

    #[error(
        "the application runtime directory {} cannot be used as the default runner \
         root: {source}",
        got.display()
    )]
    ApplicationRuntimeDirectoryUnusable {
        got: PathBuf,
        #[source]
        source: LocalPathError,
    },

    #[error(
        "{} cannot be represented as text, and a runner root is stored, printed and \
         compared as text",
        got.display()
    )]
    NonUnicode { got: PathBuf },

    #[error(
        "{got:?} is written in {platform} path syntax, but this host uses {}; a row \
         written on another operating system is corrupt state here rather than a \
         usable root",
        PathPlatform::NATIVE
    )]
    ForeignPlatform { got: String, platform: PathPlatform },

    #[error("cannot inspect {}: {source}", path.display())]
    Inspect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error(
        "{} already exists and is not a directory; a runner root is a directory that \
         attempt directories are created inside",
        path.display()
    )]
    ExistingFile { path: PathBuf },

    #[error(
        "{} is a symbolic link, junction or other reparse point. A runner root is the \
         base of a recursive cleanup, so it must be the real directory rather than a \
         name that can be repointed at one; configure the target directly.",
        path.display()
    )]
    Symlinked { path: PathBuf },

    #[error(
        "{} cannot be created because more than its last component is missing; the \
         deepest directory that does exist is {}. Create the intermediate directories \
         first, or configure a path one level below an existing directory.",
        path.display(),
        deepest_existing.display()
    )]
    MissingParents {
        path: PathBuf,
        deepest_existing: PathBuf,
    },

    #[error(
        "{} exists but is not a directory, so nothing can be created inside it",
        parent.display()
    )]
    ParentIsNotADirectory { parent: PathBuf },

    #[error(
        "{} exists but this account may not create entries in it. Grant this account \
         write access, or configure a directory it owns with `{remediation}`.",
        path.display()
    )]
    NotWritable { path: PathBuf, remediation: String },

    #[error(
        "{} does not exist yet and this account may not create it: its parent {} \
         refuses. Grant this account write access to that directory, or configure a \
         directory it owns with `{remediation}`.",
        leaf.display(),
        parent.display()
    )]
    ParentNotWritable {
        parent: PathBuf,
        leaf: PathBuf,
        remediation: String,
    },

    #[error(
        "{} is on {filesystem}. Runner correctness and restart recovery may not depend \
         on a remote share that can disappear or change identity while a job runs \
         (D10); configure a directory on a local volume.",
        path.display()
    )]
    RemoteFilesystem { path: PathBuf, filesystem: String },

    #[error(
        "this host cannot prove that {} is on a local filesystem (it reported \
         {filesystem}). A runner root is accepted only when locality is provable, so \
         this fails closed; configure a directory on a local volume.",
        path.display()
    )]
    UnprovableFilesystem { path: PathBuf, filesystem: String },

    #[error(
        "{} resolves to {}, which is a filesystem root. A runner root must be a \
         directory below a root, because everything inside it is removed on cleanup.",
        path.display(),
        canonical.display()
    )]
    ResolvesToFilesystemRoot { path: PathBuf, canonical: PathBuf },

    #[error(
        "{} {relation} {other_owner} ({}). {detail}",
        candidate.display(),
        other.display()
    )]
    Overlaps {
        candidate: PathBuf,
        relation: Overlap,
        other: PathBuf,
        other_owner: String,
        detail: &'static str,
    },

    #[error(
        "{} is derived from the runner root {} but resolves to {}, which is outside it",
        child.display(),
        root.display(),
        resolved.display()
    )]
    Escapes {
        root: PathBuf,
        child: PathBuf,
        resolved: PathBuf,
    },

    #[error("{source}")]
    DerivedName {
        #[source]
        source: LocalPathError,
    },
}

// ---------------------------------------------------------------------------
// Filesystem identity
// ---------------------------------------------------------------------------

/// What the host can prove about where a directory lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locality {
    /// Proven to be served by this machine from a local device.
    Local,
    /// Proven to be a network filesystem.
    Remote,
    /// The platform answered, but not with something that proves either.
    ///
    /// Treated as a refusal. `02-target-architecture.md`: "A platform that
    /// cannot prove the configured location is local fails closed."
    Unprovable,
}

/// The filesystem an existing directory sits on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemIdentity {
    /// Whether it is provably local.
    pub locality: Locality,
    /// What the platform called it, for the operator-facing message.
    pub name: String,
}

impl FilesystemIdentity {
    /// A filesystem the platform proved local.
    #[must_use]
    pub fn local(name: impl Into<String>) -> Self {
        Self {
            locality: Locality::Local,
            name: name.into(),
        }
    }

    /// A filesystem the platform proved remote.
    #[must_use]
    pub fn remote(name: impl Into<String>) -> Self {
        Self {
            locality: Locality::Remote,
            name: name.into(),
        }
    }

    /// A filesystem the platform could not classify either way.
    #[must_use]
    pub fn unprovable(name: impl Into<String>) -> Self {
        Self {
            locality: Locality::Unprovable,
            name: name.into(),
        }
    }
}

/// The two questions the preflight asks the operating system.
///
/// A trait rather than two free functions because a network share and a
/// directory this account may not write are not things a test may create: one
/// needs a file server and the other needs an account that is not the one
/// running the suite. `04-security-recovery.md` requires "table-driven
/// cross-platform validator tests" for exactly those cases, so the seam is part
/// of the design rather than a testing afterthought. [`HostFilesystem`] is the
/// real implementation and is what every production caller gets.
pub trait FilesystemProbe {
    /// The filesystem `directory` — which exists — sits on.
    ///
    /// # Errors
    /// Whatever the platform reported.
    fn identify(&self, directory: &Path) -> io::Result<FilesystemIdentity>;

    /// Whether this account may create entries in `directory`, which exists.
    ///
    /// Implementations must answer without creating, deleting, or
    /// re-permissioning anything.
    ///
    /// # Errors
    /// Whatever the platform reported, other than a plain refusal.
    fn is_writable(&self, directory: &Path) -> io::Result<bool>;
}

/// The real operating system.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostFilesystem;

impl FilesystemProbe for HostFilesystem {
    fn identify(&self, directory: &Path) -> io::Result<FilesystemIdentity> {
        sys::identify(directory)
    }

    fn is_writable(&self, directory: &Path) -> io::Result<bool> {
        sys::is_writable(directory)
    }
}

/// The default probe, borrowed by [`RootPreflight::new`].
static HOST_FILESYSTEM: HostFilesystem = HostFilesystem;

// ---------------------------------------------------------------------------
// The platform default
// ---------------------------------------------------------------------------

/// Where a platform default comes from.
///
/// The seam that keeps `C:` out of this crate: the Windows rule is a function
/// of the system directory the operating system reported, so every CI leg can
/// drive it with `E:\Windows\system32` and assert `E:\rman`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformDefault<'a> {
    /// Windows: whatever `GetSystemDirectoryW` returned.
    WindowsSystemDirectory(&'a str),
    /// macOS and Linux: the existing [`AppPaths::runtime_dir`], unchanged.
    ApplicationRuntimeDirectory(&'a Path),
}

/// Resolves a platform default from an explicit source.
///
/// # Errors
/// [`RunnerRootError::SystemDirectoryUnusable`] when the reported system
/// directory is not an ordinary drive path;
/// [`RunnerRootError::ApplicationRuntimeDirectoryUnusable`] or
/// [`RunnerRootError::NonUnicode`] when the application runtime directory is
/// not a storable local path.
pub fn default_runner_root_from(
    source: PlatformDefault<'_>,
) -> Result<LocalAbsolutePath, RunnerRootError> {
    match source {
        PlatformDefault::WindowsSystemDirectory(raw) => {
            let unusable = |source| RunnerRootError::SystemDirectoryUnusable {
                got: raw.to_string(),
                source,
            };
            // Parsed rather than pattern-matched by hand: this holds the value
            // the operating system reported to the same rules an operator's own
            // input is held to — no UNC, no device namespace, no drive-relative
            // form — and renders the root as exactly `X:\` with the drive letter
            // upper-cased, which is what makes the slice below total.
            let system =
                LocalAbsolutePath::parse_for(raw, PathPlatform::Windows).map_err(unusable)?;
            let volume: String = system.as_str().chars().take(3).collect();
            LocalAbsolutePath::parse_for(
                format!("{volume}{WINDOWS_RUNNER_ROOT_NAME}"),
                PathPlatform::Windows,
            )
            .map_err(unusable)
        }
        PlatformDefault::ApplicationRuntimeDirectory(path) => {
            let text = path.to_str().ok_or_else(|| RunnerRootError::NonUnicode {
                got: path.to_path_buf(),
            })?;
            LocalAbsolutePath::new(text).map_err(|source| {
                RunnerRootError::ApplicationRuntimeDirectoryUnusable {
                    got: path.to_path_buf(),
                    source,
                }
            })
        }
    }
}

/// The platform default host runner root for this machine.
///
/// Windows resolves `<system-drive>\rman` from `GetSystemDirectoryW`. The
/// `app_paths` argument is unused on this platform, and is part of the
/// signature only so that callers are not written twice: application data does
/// not move, and the runner root is not derived from it here.
///
/// # Errors
/// [`RunnerRootError::SystemDirectoryUnavailable`] or
/// [`RunnerRootError::SystemDirectoryUnusable`].
#[cfg(windows)]
pub fn default_runner_root(app_paths: &AppPaths) -> Result<LocalAbsolutePath, RunnerRootError> {
    let _ = app_paths;
    let system = sys::system_directory()
        .map_err(|source| RunnerRootError::SystemDirectoryUnavailable { source })?;
    default_runner_root_from(PlatformDefault::WindowsSystemDirectory(&system))
}

/// The platform default host runner root for this machine.
///
/// macOS and Linux keep the directory attempts have always used —
/// [`AppPaths::runtime_dir`] — byte for byte. Only Windows had a path-length
/// problem, and relocating the other two would move live workspaces for no
/// reason (`02-target-architecture.md`, "Platform defaults").
///
/// # Errors
/// [`RunnerRootError::ApplicationRuntimeDirectoryUnusable`] or
/// [`RunnerRootError::NonUnicode`] when the resolved application runtime
/// directory is not a storable local path, which for a discovered layout means
/// the account's own data directory is unusable.
#[cfg(not(windows))]
pub fn default_runner_root(app_paths: &AppPaths) -> Result<LocalAbsolutePath, RunnerRootError> {
    default_runner_root_from(PlatformDefault::ApplicationRuntimeDirectory(
        app_paths.runtime_dir(),
    ))
}

// ---------------------------------------------------------------------------
// Canonical projection
// ---------------------------------------------------------------------------

/// A path resolved as far as the filesystem can resolve it.
///
/// `02-target-architecture.md` requires "a stable canonical path for any
/// existing component", and a runner root is routinely configured before it is
/// created. So the deepest *existing* ancestor is canonicalised — which
/// resolves every symlink, junction and `8.3` alias on the way to it — and the
/// components that do not exist yet are appended lexically. That is the value
/// every overlap, containment and locality decision below is taken against,
/// which is what makes a symlinked parent unable to smuggle a root into the
/// application-data tree or onto a network share.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Projection {
    /// The deepest ancestor that exists, canonicalised.
    anchor: PathBuf,
    /// The deepest ancestor that exists, as written.
    anchor_as_written: PathBuf,
    /// `anchor` with the missing components appended.
    canonical: PathBuf,
    /// The components that do not exist yet, outermost first.
    missing: Vec<OsString>,
}

/// Whether an error means "this path is not there", as opposed to "this path
/// could not be inspected".
///
/// `NotADirectory` belongs here: `/srv/notes.txt/rman` does not exist, and the
/// operating system says so by complaining about the component that is a file.
/// Treating it as an inspection failure would report a confusing errno instead
/// of the actionable [`RunnerRootError::ParentIsNotADirectory`] the walk
/// reaches one step later.
fn means_absent(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// Walks up from `path` to the deepest ancestor that exists and canonicalises
/// it.
fn project(path: &Path) -> Result<Projection, RunnerRootError> {
    let mut missing: Vec<OsString> = Vec::new();
    let mut cursor = path.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&cursor) {
            Ok(_) => break,
            Err(error) if means_absent(&error) => {
                let name = cursor.file_name().map(OsString::from);
                let parent = cursor.parent().map(Path::to_path_buf);
                let (Some(name), Some(parent)) = (name, parent) else {
                    // A filesystem root that does not exist. Nothing above it
                    // can be inspected, so there is no deeper diagnosis to give.
                    return Err(RunnerRootError::Inspect {
                        path: cursor,
                        source: error,
                    });
                };
                missing.push(name);
                cursor = parent;
            }
            Err(source) => {
                return Err(RunnerRootError::Inspect {
                    path: cursor,
                    source,
                });
            }
        }
    }

    let anchor = std::fs::canonicalize(&cursor)
        .map(|canonical| plain(&canonical))
        .map_err(|source| RunnerRootError::Inspect {
            path: cursor.clone(),
            source,
        })?;

    missing.reverse();
    let mut canonical = anchor.clone();
    for component in &missing {
        canonical.push(component);
    }
    Ok(Projection {
        anchor,
        anchor_as_written: cursor,
        canonical,
        missing,
    })
}

/// Removes the extended-length prefix `std::fs::canonicalize` adds on Windows.
///
/// `\\?\C:\rman` and `C:\rman` are the same directory, but only one of them
/// compares equal to a configured path or prints as something an operator
/// recognises. `\\?\UNC\server\share` becomes `\\server\share`, which the
/// preflight then refuses as the network path it is.
#[cfg(windows)]
fn plain(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path.to_path_buf()
}

/// Unix `canonicalize` returns an ordinary absolute path already.
#[cfg(not(windows))]
fn plain(path: &Path) -> PathBuf {
    path.to_path_buf()
}

/// The canonical projection of `path` as text, or `None` when the filesystem
/// cannot answer.
///
/// Used only for the *other* paths a candidate is compared against. A protected
/// application-data directory that cannot be canonicalised — because the
/// account has no such directory yet — is still compared lexically, which is the
/// check that already ran; dropping the canonical half of one comparison is
/// therefore a lost second opinion rather than a lost rule.
fn canonical_text(path: &Path) -> Option<String> {
    project(path)
        .ok()
        .map(|projection| projection.canonical.to_string_lossy().into_owned())
}

/// Whether a path names a filesystem root: `/`, `C:\`, and nothing else.
fn is_filesystem_root(path: &Path) -> bool {
    path.parent().is_none()
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

/// A root that passed the operational preflight.
///
/// Holding one is the evidence a caller needs before it creates a directory or
/// accepts new allocation. It deliberately says whether the directory exists
/// rather than creating it: `02-target-architecture.md` keeps "directory
/// creation and the narrowly scoped default-root ACL operation" as explicit
/// application steps after validation passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightedRoot {
    root: LocalAbsolutePath,
    canonical: PathBuf,
    exists: bool,
    filesystem: FilesystemIdentity,
}

impl PreflightedRoot {
    /// The configured value, exactly as it is stored and displayed.
    #[must_use]
    pub const fn root(&self) -> &LocalAbsolutePath {
        &self.root
    }

    /// The same directory with every existing component resolved.
    #[must_use]
    pub fn canonical(&self) -> &Path {
        &self.canonical
    }

    /// Whether the directory is already there.
    #[must_use]
    pub const fn exists(&self) -> bool {
        self.exists
    }

    /// The single directory the caller must create, or `None` when it exists.
    #[must_use]
    pub fn leaf_to_create(&self) -> Option<&Path> {
        (!self.exists).then(|| self.root.as_path())
    }

    /// What the host proved about the volume this root sits on.
    #[must_use]
    pub const fn filesystem(&self) -> &FilesystemIdentity {
        &self.filesystem
    }
}

/// The operational check a configured or default runner root must pass.
///
/// Built once per decision with the application-data layout it must not
/// collide with, plus every *other* configured root on this host, and then
/// asked about one candidate at a time.
///
/// ```no_run
/// # use runner_manager_platform::paths::AppPaths;
/// # use runner_manager_platform::runner_root::{RootOwner, RootPreflight, default_runner_root};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let paths = AppPaths::discover()?;
/// let root = default_runner_root(&paths)?;
/// let checked = RootPreflight::new(&paths).check(&RootOwner::Host, &root)?;
/// if let Some(leaf) = checked.leaf_to_create() {
///     // Creation is the caller's explicit step, never the preflight's.
///     std::fs::create_dir(leaf)?;
/// }
/// # Ok(())
/// # }
/// ```
pub struct RootPreflight<'a> {
    app_paths: &'a AppPaths,
    others: Vec<(RootOwner, LocalAbsolutePath)>,
    probe: &'a dyn FilesystemProbe,
}

impl fmt::Debug for RootPreflight<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootPreflight")
            .field("app_paths", &self.app_paths)
            .field("others", &self.others)
            .finish_non_exhaustive()
    }
}

impl<'a> RootPreflight<'a> {
    /// A preflight that asks the real operating system.
    #[must_use]
    pub fn new(app_paths: &'a AppPaths) -> Self {
        Self {
            app_paths,
            others: Vec::new(),
            probe: &HOST_FILESYSTEM,
        }
    }

    /// A preflight that asks `probe` instead.
    #[must_use]
    pub fn with_probe(app_paths: &'a AppPaths, probe: &'a dyn FilesystemProbe) -> Self {
        Self {
            app_paths,
            others: Vec::new(),
            probe,
        }
    }

    /// Registers another configured root the candidate must not overlap.
    ///
    /// Pass the host runner root when checking a repository's, every other
    /// repository's root when checking one repository's, and every repository's
    /// root when checking the host's. A root registered under the same owner as
    /// the candidate is skipped, so re-validating a setting that is already
    /// stored does not report it as overlapping itself.
    #[must_use]
    pub fn against(mut self, owner: RootOwner, root: LocalAbsolutePath) -> Self {
        self.others.push((owner, root));
        self
    }

    /// The application-data directories a configured root may not collide with.
    ///
    /// `runtime/` is deliberately absent. It is not application data in the
    /// sense this rule protects — it is where runner attempts have always been
    /// created, and on macOS and Linux it *is* the platform default runner root.
    /// The three that remain hold the SQLite database, the attempt journal, the
    /// package cache and the diagnostics, which is the list
    /// `02-target-architecture.md` gives.
    fn protected(&self) -> [(&'static str, &Path); 3] {
        [
            (
                "the application configuration directory",
                self.app_paths.config_dir(),
            ),
            (
                "the application state directory",
                self.app_paths.state_dir(),
            ),
            ("the application log directory", self.app_paths.logs_dir()),
        ]
    }

    /// Refuses a candidate that collides with application data or another root.
    ///
    /// Run twice: once lexically, before the filesystem is touched at all, and
    /// once against canonical projections, which is what catches a symlink that
    /// points somewhere it should not.
    fn reject_overlap(
        &self,
        owner: &RootOwner,
        candidate: &str,
        canonical: bool,
    ) -> Result<(), RunnerRootError> {
        let native = PathPlatform::NATIVE;
        let text_of = |path: &Path| -> Option<String> {
            if canonical {
                canonical_text(path)
            } else {
                Some(path.to_string_lossy().into_owned())
            }
        };

        // On macOS every application-data directory is a child of one
        // `Application Support` directory, so `runtime/` — the platform default
        // runner root — is *inside* `config/`. That nesting is the product's own
        // layout rather than an operator mistake, so descent into a protected
        // directory is permitted for exactly the paths at or below `runtime/`.
        // Equality with a protected directory, and ancestry over one, stay
        // refused everywhere.
        let runtime = text_of(self.app_paths.runtime_dir());
        let inside_runtime = runtime.as_deref().is_some_and(|runtime| {
            matches!(
                overlap_of(candidate, runtime, native),
                Overlap::Same | Overlap::Inside
            )
        });

        for (label, path) in self.protected() {
            let Some(other) = text_of(path) else {
                continue;
            };
            let relation = overlap_of(candidate, &other, native);
            if relation == Overlap::Disjoint || (relation == Overlap::Inside && inside_runtime) {
                continue;
            }
            return Err(RunnerRootError::Overlaps {
                candidate: PathBuf::from(candidate),
                relation,
                other: PathBuf::from(other),
                other_owner: label.to_string(),
                detail: "Runner workspaces are removed recursively and application data must \
                     survive that; configure a directory outside the application data tree.",
            });
        }

        for (other_owner, root) in &self.others {
            if other_owner == owner {
                continue;
            }
            let Some(other) = text_of(root.as_path()) else {
                continue;
            };
            let relation = overlap_of(candidate, &other, native);
            if relation == Overlap::Disjoint {
                continue;
            }
            return Err(RunnerRootError::Overlaps {
                candidate: PathBuf::from(candidate),
                relation,
                other: PathBuf::from(other),
                other_owner: other_owner.to_string(),
                detail: "Two runner roots that contain one another can delete each other's \
                     workspaces; configure directories that do not overlap.",
            });
        }
        Ok(())
    }

    /// Decides whether `root` can hold runner workspaces on this host.
    ///
    /// Nothing is created, removed or re-permissioned. On success the caller
    /// learns whether the directory already exists and, if not, the single leaf
    /// it must create.
    ///
    /// # Errors
    /// Any [`RunnerRootError`] other than the three that belong to default
    /// resolution.
    pub fn check(
        &self,
        owner: &RootOwner,
        root: &LocalAbsolutePath,
    ) -> Result<PreflightedRoot, RunnerRootError> {
        if root.platform() != PathPlatform::NATIVE {
            return Err(RunnerRootError::ForeignPlatform {
                got: root.as_str().to_string(),
                platform: root.platform(),
            });
        }
        let candidate = root.as_path();

        // Lexical first: a candidate that collides on its face is refused
        // before the filesystem is asked anything at all, so a configured
        // overlap is reported identically on a host where the directory does
        // not exist yet.
        self.reject_overlap(owner, root.as_str(), false)?;

        // What the candidate itself is, before anything is resolved. This runs
        // ahead of the projection because a link whose target is gone cannot be
        // canonicalised: asking `project` first would report a bare "cannot
        // inspect … not found" for a name the operator can plainly see, instead
        // of the `Symlinked` refusal that says what to do about it.
        match std::fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RunnerRootError::Symlinked {
                    path: candidate.to_path_buf(),
                });
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(RunnerRootError::ExistingFile {
                    path: candidate.to_path_buf(),
                });
            }
            Ok(_) => {}
            // Absence is the ordinary case: the leaf is created after this
            // returns. Anything else is a genuine inspection failure.
            Err(error) if means_absent(&error) => {}
            Err(source) => {
                return Err(RunnerRootError::Inspect {
                    path: candidate.to_path_buf(),
                    source,
                });
            }
        }

        let projection = project(candidate)?;
        match projection.missing.len() {
            0 => {}
            1 => {
                if !projection.anchor.is_dir() {
                    return Err(RunnerRootError::ParentIsNotADirectory {
                        parent: projection.anchor_as_written.clone(),
                    });
                }
            }
            _ => {
                return Err(RunnerRootError::MissingParents {
                    path: candidate.to_path_buf(),
                    deepest_existing: projection.anchor_as_written.clone(),
                });
            }
        }

        if is_filesystem_root(&projection.canonical) {
            return Err(RunnerRootError::ResolvesToFilesystemRoot {
                path: candidate.to_path_buf(),
                canonical: projection.canonical.clone(),
            });
        }

        let filesystem =
            self.probe
                .identify(&projection.anchor)
                .map_err(|source| RunnerRootError::Inspect {
                    path: projection.anchor.clone(),
                    source,
                })?;
        match filesystem.locality {
            Locality::Local => {}
            Locality::Remote => {
                return Err(RunnerRootError::RemoteFilesystem {
                    path: projection.canonical.clone(),
                    filesystem: filesystem.name,
                });
            }
            Locality::Unprovable => {
                return Err(RunnerRootError::UnprovableFilesystem {
                    path: projection.canonical.clone(),
                    filesystem: filesystem.name,
                });
            }
        }

        let writable = self
            .probe
            .is_writable(&projection.anchor)
            .map_err(|source| RunnerRootError::Inspect {
                path: projection.anchor.clone(),
                source,
            })?;
        if !writable {
            // `05-user-workflows.md` requires an unwritable parent to "show
            // `host set-runtime-root` or `repo set-workspace` remediation",
            // which is what the owner was carried here for.
            return Err(if projection.missing.is_empty() {
                RunnerRootError::NotWritable {
                    path: projection.anchor_as_written.clone(),
                    remediation: owner.remediation(),
                }
            } else {
                RunnerRootError::ParentNotWritable {
                    parent: projection.anchor_as_written.clone(),
                    leaf: candidate.to_path_buf(),
                    remediation: owner.remediation(),
                }
            });
        }

        // Second opinion, against what the paths actually resolve to. A root
        // that is lexically unrelated to `state/` but reaches it through a
        // symlinked parent is refused here.
        self.reject_overlap(owner, &projection.canonical.to_string_lossy(), true)?;

        Ok(PreflightedRoot {
            root: root.clone(),
            canonical: projection.canonical,
            exists: projection.missing.is_empty(),
            filesystem,
        })
    }
}

// ---------------------------------------------------------------------------
// Derived paths
// ---------------------------------------------------------------------------

/// The path of one attempt directory or persistent slot below `root`.
///
/// Containment is by construction: `name` must be a single component, so
/// `<root>/<12-char-attempt>` and `<root>/sN` cannot escape however the caller
/// spells them. That is the lexical half of the requirement; the canonical half
/// is [`verify_containment`], which is what a junction planted inside the root
/// has to get past.
///
/// # Errors
/// [`RunnerRootError::DerivedName`] when `name` is not one component, or is not
/// a name this platform can store.
pub fn derive_child(
    root: &LocalAbsolutePath,
    name: &str,
) -> Result<LocalAbsolutePath, RunnerRootError> {
    root.join_child(name)
        .map_err(|source| RunnerRootError::DerivedName { source })
}

/// Proves that `child` is below `root`, lexically and after resolution.
///
/// `04-security-recovery.md` requires cleanup to "verify canonical containment
/// without following a link outside the root" before it removes anything, and
/// allocation to "build `<persistent-root>/sN` and validate containment" before
/// it journals. Both are this function.
///
/// # Errors
/// [`RunnerRootError::ForeignPlatform`] when either value is written in the
/// other operating system's path syntax, which the rest of this function would
/// otherwise judge against this host's filesystem;
/// [`RunnerRootError::Escapes`] when `child` is not strictly inside `root`
/// either lexically or once every existing component is resolved;
/// [`RunnerRootError::Inspect`] when the filesystem cannot answer.
pub fn verify_containment(
    root: &LocalAbsolutePath,
    child: &LocalAbsolutePath,
) -> Result<(), RunnerRootError> {
    // The same guard [`RootPreflight::check`] opens with. Both halves below ask
    // the *native* filesystem what these strings resolve to, so a row written on
    // another operating system is corrupt state here rather than a path whose
    // containment can be argued about.
    for value in [root, child] {
        if value.platform() != PathPlatform::NATIVE {
            return Err(RunnerRootError::ForeignPlatform {
                got: value.as_str().to_string(),
                platform: value.platform(),
            });
        }
    }
    let escapes = |resolved: PathBuf| RunnerRootError::Escapes {
        root: root.as_path().to_path_buf(),
        child: child.as_path().to_path_buf(),
        resolved,
    };
    if overlap_of(child.as_str(), root.as_str(), root.platform()) != Overlap::Inside {
        return Err(escapes(child.as_path().to_path_buf()));
    }
    let root_projection = project(root.as_path())?;
    let child_projection = project(child.as_path())?;
    let relation = overlap_of(
        &child_projection.canonical.to_string_lossy(),
        &root_projection.canonical.to_string_lossy(),
        root.platform(),
    );
    if relation != Overlap::Inside {
        return Err(escapes(child_projection.canonical));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Platform adapters
// ---------------------------------------------------------------------------
//
// Both implement the same two-function contract, and the Windows half adds the
// system-directory read that has no Unix equivalent:
//
//   identify(dir)        -> which filesystem `dir` is on, and whether it is local
//   is_writable(dir)     -> may this account create entries in `dir`?
//   system_directory()   -> Windows only; the source of the default drive letter

#[cfg(windows)]
mod sys {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ADD_SUBDIRECTORY, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW, GetVolumePathNameW, OPEN_EXISTING,
    };
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    use windows::Win32::System::WindowsProgramming::{
        DRIVE_CDROM, DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE,
        DRIVE_UNKNOWN,
    };
    use windows::core::PCWSTR;

    use super::FilesystemIdentity;

    /// `HRESULT_FROM_WIN32`, which windows-rs does not re-export as a function.
    const fn hresult_from_win32(code: u32) -> i32 {
        if code == 0 {
            0
        } else {
            ((code & 0x0000_ffff) | 0x8007_0000) as i32
        }
    }

    /// The `io::Error` a Windows failure really is.
    ///
    /// `io::Error::from_raw_os_error` expects the Win32 code, not the
    /// `HRESULT` windows-rs reports. Handing it `0x8007_0005` produces an error
    /// whose `kind()` is `Uncategorized` and whose text ends `(os error
    /// -2147024891)`, so the low word is unwrapped again whenever the facility
    /// is `FACILITY_WIN32`.
    fn io_error(error: &windows::core::Error) -> io::Error {
        let code = error.code().0;
        #[allow(clippy::cast_sign_loss)]
        let unsigned = code as u32;
        if unsigned & 0xffff_0000 == 0x8007_0000 {
            #[allow(clippy::cast_possible_wrap)]
            return io::Error::from_raw_os_error((unsigned & 0x0000_ffff) as i32);
        }
        io::Error::from_raw_os_error(code)
    }

    fn to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// The Windows system directory, for instance `C:\Windows\system32`.
    ///
    /// `%SystemDrive%` and `%SystemRoot%` are process environment variables and
    /// are writable by whatever started this process; the value read here
    /// decides where a recursive cleanup will later run, so it comes from the
    /// kernel.
    pub(super) fn system_directory() -> io::Result<String> {
        // The system directory is `<drive>\Windows\system32` on every supported
        // release, so `MAX_PATH` is already generous; the length is checked
        // rather than assumed all the same.
        let mut buffer = [0u16; 512];
        // SAFETY: `GetSystemDirectoryW` writes at most `buffer.len()` UTF-16
        // code units into the slice it is given and reads nothing else. The
        // slice is owned by this frame and outlives the call.
        let written = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        if written > buffer.len() {
            return Err(io::Error::other(format!(
                "the system directory needs {written} UTF-16 code units, which is more \
                 than a system path is expected to occupy"
            )));
        }
        String::from_utf16(&buffer[..written]).map_err(io::Error::other)
    }

    /// The mount point `directory` sits on, NUL-terminated.
    ///
    /// Asked for rather than assumed to be the drive letter: a volume can be
    /// mounted at `C:\mnt\builds`, and the drive type of `C:` says nothing
    /// about it.
    fn volume_path(directory: &Path) -> io::Result<Vec<u16>> {
        let file = to_wide(directory);
        let mut buffer = [0u16; 512];
        // SAFETY: `file` is NUL-terminated and outlives the call; the output
        // slice is owned by this frame and its length is passed by the binding.
        unsafe { GetVolumePathNameW(PCWSTR(file.as_ptr()), &mut buffer) }
            .map_err(|error| io_error(&error))?;
        let length = buffer
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(buffer.len());
        let mut mount = buffer[..length].to_vec();
        mount.push(0);
        Ok(mount)
    }

    pub(super) fn identify(directory: &Path) -> io::Result<FilesystemIdentity> {
        let mount = volume_path(directory)?;
        // SAFETY: `mount` is NUL-terminated and outlives the call.
        let kind = unsafe { GetDriveTypeW(PCWSTR(mount.as_ptr())) };
        Ok(match kind {
            DRIVE_FIXED => FilesystemIdentity::local("a fixed local volume"),
            DRIVE_REMOVABLE => FilesystemIdentity::local("a removable local volume"),
            DRIVE_RAMDISK => FilesystemIdentity::local("a RAM disk"),
            DRIVE_CDROM => FilesystemIdentity::local("an optical drive"),
            DRIVE_REMOTE => FilesystemIdentity::remote("a network drive"),
            DRIVE_NO_ROOT_DIR => FilesystemIdentity::unprovable("no mounted volume"),
            DRIVE_UNKNOWN => FilesystemIdentity::unprovable("an unknown drive type"),
            other => FilesystemIdentity::unprovable(format!("drive type {other}")),
        })
    }

    /// Whether this account may create entries in `directory`.
    ///
    /// Opening a *handle* to the directory for `FILE_ADD_SUBDIRECTORY` runs the
    /// real access check against the real DACL, including inherited and deny
    /// entries, and creates nothing. `_waccess` cannot answer this on Windows:
    /// it reports the read-only attribute and not the access-control entries
    /// that actually decide.
    ///
    /// `FILE_ADD_SUBDIRECTORY` alone, and deliberately not
    /// `FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY`: `CreateFileW` grants a handle
    /// only when *every* requested right is held, and the default DACL of the
    /// system drive root grants `Authenticated Users` exactly `AD` — add
    /// subdirectory — without `WD`. Asking for both therefore refuses `C:\`,
    /// which would make the product's own Windows default `C:\rman`
    /// unconfigurable for any process that is not elevated. Only directories
    /// are ever created directly in a runner root (`<root>/<attempt>` and
    /// `<root>/sN`), so this is also the right question rather than a weaker
    /// one; files below them are governed by the DACL those directories
    /// inherit.
    pub(super) fn is_writable(directory: &Path) -> io::Result<bool> {
        let wide = to_wide(directory);
        let access = FILE_ADD_SUBDIRECTORY.0;
        // SAFETY: `wide` is NUL-terminated and outlives the call. The handle is
        // closed on the success path below and nothing else is passed by
        // pointer. `FILE_FLAG_BACKUP_SEMANTICS` is what makes `CreateFileW`
        // willing to open a directory at all.
        let opened = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        };
        match opened {
            Ok(handle) => {
                // SAFETY: `handle` was just returned by `CreateFileW` and is
                // not used again.
                unsafe {
                    let _ = CloseHandle(handle);
                }
                Ok(true)
            }
            Err(error) if error.code().0 == hresult_from_win32(ERROR_ACCESS_DENIED.0) => Ok(false),
            Err(error) => Err(io_error(&error)),
        }
    }
}

#[cfg(unix)]
mod sys {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::FilesystemIdentity;

    fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::other("a path containing a NUL cannot be given to the operating system")
        })
    }

    /// Whether this account may create entries in `directory`.
    ///
    /// `access(2)` answers exactly the question and mutates nothing.
    /// `X_OK` is asked for alongside `W_OK` because a directory that cannot be
    /// traversed cannot hold a workspace either, however writable it claims to
    /// be. The check is against the real rather than the effective user
    /// identity; this program is never installed setuid, so the two agree.
    pub(super) fn is_writable(directory: &Path) -> io::Result<bool> {
        let path = c_path(directory)?;
        // SAFETY: `path` is a NUL-terminated C string that outlives the call,
        // and `access` writes nothing through it.
        let result = unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            // A refusal, rather than a failure to ask.
            Some(libc::EACCES | libc::EPERM | libc::EROFS) => Ok(false),
            _ => Err(error),
        }
    }

    /// Filesystems Linux reports that are served by this kernel from a local
    /// device.
    ///
    /// An allowlist, because the rule is "fails closed": a magic number that is
    /// not here is [`super::Locality::Unprovable`] and is refused, which is the
    /// safe direction for a value that decides where a recursive cleanup runs.
    /// `fuse` is deliberately absent — it is the same magic number for a local
    /// overlay and for `sshfs`.
    #[cfg(target_os = "linux")]
    const LOCAL_MAGICS: &[(u32, &str)] = &[
        (0x0000_ef53, "ext2/ext3/ext4"),
        (0x9123_683e, "btrfs"),
        (0x5846_5342, "xfs"),
        (0x0102_1994, "tmpfs"),
        (0x794c_7630, "overlayfs"),
        (0x2fc1_2fc1, "zfs"),
        (0xf2f5_2010, "f2fs"),
        (0x0000_4d44, "vfat"),
        (0x2011_bab0, "exfat"),
        (0x5346_544e, "ntfs"),
        (0x8584_58f6, "ramfs"),
        (0x0000_9660, "iso9660"),
        (0x7371_7368, "squashfs"),
        (0x3153_464a, "jfs"),
        (0x5265_4973, "reiserfs"),
        (0xca45_1a4e, "bcachefs"),
        (0x0000_4244, "hfs"),
        (0x0000_482b, "hfsplus"),
    ];

    /// Filesystems Linux reports that are served over a network.
    #[cfg(target_os = "linux")]
    const REMOTE_MAGICS: &[(u32, &str)] = &[
        (0x0000_6969, "nfs"),
        (0xff53_4d42, "cifs"),
        (0xfe53_4d42, "smb2"),
        (0x0000_517b, "smb"),
        (0x7375_7245, "coda"),
        (0x0000_564c, "ncpfs"),
        (0x5346_414f, "afs"),
        (0x6b41_4653, "afs"),
        (0x0bd0_0bd0, "lustre"),
        (0x00c3_6400, "ceph"),
        (0x0102_1997, "9p"),
        (0x0116_1970, "gfs2"),
        (0x7461_636f, "ocfs2"),
    ];

    #[cfg(target_os = "linux")]
    pub(super) fn identify(directory: &Path) -> io::Result<FilesystemIdentity> {
        let path = c_path(directory)?;
        let mut buffer: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is a NUL-terminated C string that outlives the call,
        // and `buffer` is a live, correctly sized `statfs` this frame owns.
        let result = unsafe { libc::statfs(path.as_ptr(), &raw mut buffer) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // `f_type` is a signed word on this platform and several magic numbers
        // have the high bit set; comparing as `u32` is what makes `cifs` match.
        let magic = buffer.f_type as u32;
        if let Some((_, name)) = LOCAL_MAGICS.iter().find(|(value, _)| *value == magic) {
            return Ok(FilesystemIdentity::local(*name));
        }
        if let Some((_, name)) = REMOTE_MAGICS.iter().find(|(value, _)| *value == magic) {
            return Ok(FilesystemIdentity::remote(*name));
        }
        Ok(FilesystemIdentity::unprovable(format!(
            "filesystem type 0x{magic:08x}"
        )))
    }

    /// macOS answers the question directly: `MNT_LOCAL` is set when the
    /// filesystem "is stored locally", so there is no magic-number table to
    /// keep current and no unprovable middle case.
    #[cfg(target_os = "macos")]
    pub(super) fn identify(directory: &Path) -> io::Result<FilesystemIdentity> {
        let path = c_path(directory)?;
        let mut buffer: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is a NUL-terminated C string that outlives the call,
        // and `buffer` is a live, correctly sized `statfs` this frame owns.
        let result = unsafe { libc::statfs(path.as_ptr(), &raw mut buffer) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `f_fstypename` is a NUL-terminated C string the kernel just
        // filled in, and the borrow ends before `buffer` does.
        let name = unsafe { std::ffi::CStr::from_ptr(buffer.f_fstypename.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        #[allow(clippy::cast_sign_loss)]
        let local = buffer.f_flags & (libc::MNT_LOCAL as u32) != 0;
        Ok(if local {
            FilesystemIdentity::local(name)
        } else {
            FilesystemIdentity::remote(name)
        })
    }

    /// Every other Unix. `crate::os` already refuses to classify such a host, so
    /// this exists to keep the crate compiling rather than to serve one.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn identify(_directory: &Path) -> io::Result<FilesystemIdentity> {
        Ok(FilesystemIdentity::unprovable(
            "an operating system this build cannot interrogate",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use PathPlatform::{Unix, Windows};

    // -- fixtures -----------------------------------------------------------

    /// A probe that answers whatever a test needs.
    ///
    /// A network share and a directory this account may not write cannot be
    /// created by a test: one needs a file server, the other needs a second
    /// account. Everything else below runs against the real filesystem through
    /// [`HostFilesystem`].
    #[derive(Debug)]
    struct StubFilesystem {
        identity: FilesystemIdentity,
        writable: bool,
    }

    impl StubFilesystem {
        fn saying(identity: FilesystemIdentity) -> Self {
            Self {
                identity,
                writable: true,
            }
        }

        fn unwritable() -> Self {
            Self {
                identity: FilesystemIdentity::local("a test volume"),
                writable: false,
            }
        }
    }

    impl FilesystemProbe for StubFilesystem {
        fn identify(&self, _directory: &Path) -> io::Result<FilesystemIdentity> {
            Ok(self.identity.clone())
        }

        fn is_writable(&self, _directory: &Path) -> io::Result<bool> {
            Ok(self.writable)
        }
    }

    /// A path this build's own platform accepts.
    fn native(path: &Path) -> LocalAbsolutePath {
        LocalAbsolutePath::new(path.to_str().expect("the fixture path is unicode"))
            .expect("the fixture path is a storable local path")
    }

    /// A path the *other* platform accepts, for the corrupt-row case.
    fn foreign() -> LocalAbsolutePath {
        if cfg!(windows) {
            LocalAbsolutePath::parse_for("/srv/rman", Unix)
        } else {
            LocalAbsolutePath::parse_for("C:\\rman", Windows)
        }
        .expect("the fixture is valid for the other platform")
    }

    /// Creates a directory symlink, or a junction on Windows.
    ///
    /// Returns `false` when the platform refused, which on Windows means this
    /// account has neither Developer Mode nor the privilege. The caller then
    /// skips, because what refused would not be the code under test.
    #[cfg(windows)]
    fn link_dir(target: &Path, link: &Path) -> bool {
        std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|output| output.status.success())
    }

    #[cfg(unix)]
    fn link_dir(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    /// An application-data layout, plus a `workspaces/` directory that is
    /// disjoint from all four of its directories.
    struct Fixture {
        root: tempfile::TempDir,
        paths: AppPaths,
        workspaces: PathBuf,
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(root.path());
        paths.create_all().expect("the layout is created");
        let workspaces = root.path().join("workspaces");
        std::fs::create_dir(&workspaces).expect("the workspace parent is created");
        Fixture {
            root,
            paths,
            workspaces,
        }
    }

    /// Every entry below `root`, carrying what a mutating check would change.
    fn snapshot(root: &Path) -> Vec<String> {
        fn walk(path: &Path, into: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(path) else {
                return;
            };
            for entry in entries.flatten() {
                let metadata = entry
                    .metadata()
                    .expect("an entry that was just listed can be inspected");
                #[cfg(unix)]
                let permissions = {
                    use std::os::unix::fs::PermissionsExt;
                    format!("{:04o}", metadata.permissions().mode() & 0o7777)
                };
                #[cfg(not(unix))]
                let permissions = format!("readonly={}", metadata.permissions().readonly());
                into.push(format!(
                    "{} dir={} len={} {permissions}",
                    entry.path().display(),
                    metadata.is_dir(),
                    metadata.len()
                ));
                if metadata.is_dir() {
                    walk(&entry.path(), into);
                }
            }
        }
        let mut entries = Vec::new();
        walk(root, &mut entries);
        entries.sort();
        entries
    }

    // -- the platform default -----------------------------------------------

    #[test]
    fn the_windows_default_is_the_system_drive_plus_rman() {
        // D1: `%SystemDrive%\rman`, "normally `C:\rman`". Driven by argument, so
        // the Linux and macOS legs assert the Windows rule too, and no case here
        // would pass if the drive letter were hard-coded.
        let cases = [
            ("C:\\Windows\\system32", "C:\\rman"),
            ("E:\\Windows\\system32", "E:\\rman"),
            ("c:/windows/system32", "C:\\rman"),
            ("Z:\\WINDOWS\\SYSTEM32", "Z:\\rman"),
            ("D:\\Windows", "D:\\rman"),
        ];
        for (system_directory, expected) in cases {
            let resolved =
                default_runner_root_from(PlatformDefault::WindowsSystemDirectory(system_directory))
                    .expect("a drive path resolves");
            assert_eq!(
                resolved.as_str(),
                expected,
                "system directory {system_directory:?}"
            );
            assert_eq!(resolved.platform(), Windows);
        }
    }

    #[test]
    fn a_system_directory_that_is_not_a_local_drive_fails_with_the_remediation() {
        for system_directory in [
            "\\\\nas\\share\\system32",
            "\\\\?\\C:\\Windows\\system32",
            "C:\\",
            "windows\\system32",
            "",
        ] {
            let error =
                default_runner_root_from(PlatformDefault::WindowsSystemDirectory(system_directory))
                    .expect_err("an unusable system directory must not resolve");
            let message = error.to_string();
            assert!(
                message.contains("host set-runtime-root"),
                "the message must name the command that fixes it: {message}"
            );
        }
    }

    #[test]
    fn the_application_runtime_directory_arm_changes_nothing() {
        // The macOS and Linux Definition of Done: "byte-identical to their
        // previous runtime paths". Asserted on every platform, because the arm
        // is the same code everywhere.
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(root.path());
        let resolved = default_runner_root_from(PlatformDefault::ApplicationRuntimeDirectory(
            paths.runtime_dir(),
        ))
        .expect("a resolved runtime directory is storable");
        assert_eq!(resolved.as_path(), paths.runtime_dir());
    }

    #[cfg(not(windows))]
    #[test]
    fn the_macos_and_linux_defaults_are_the_existing_runtime_directory() {
        let discovered = AppPaths::discover().expect("a home directory exists on every CI leg");
        assert_eq!(
            default_runner_root(&discovered)
                .expect("the discovered layout resolves")
                .as_path(),
            discovered.runtime_dir(),
            "moving the Unix defaults would relocate live workspaces for no reason"
        );

        let root = tempfile::tempdir().expect("a temporary directory");
        let rooted = AppPaths::rooted_at(root.path());
        assert_eq!(
            default_runner_root(&rooted)
                .expect("an explicit root resolves")
                .as_path(),
            rooted.runtime_dir()
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_windows_default_is_this_machines_system_drive() {
        let paths = AppPaths::rooted_at(Path::new("C:\\does-not-matter"));
        let resolved = default_runner_root(&paths).expect("this host has a system directory");
        let text = resolved.as_str();
        assert_eq!(
            &text[1..],
            format!(":\\{WINDOWS_RUNNER_ROOT_NAME}"),
            "the default is <system-drive> plus {WINDOWS_RUNNER_ROOT_NAME}, got {text}"
        );
        assert!(text.starts_with(|c: char| c.is_ascii_uppercase()));
    }

    #[cfg(windows)]
    #[test]
    #[serial_test::serial(environment)]
    fn the_windows_default_ignores_a_rewritten_system_drive_variable() {
        // `%SystemDrive%` is process environment and is writable by whatever
        // started this process. The value decides where a recursive cleanup
        // later runs, so it is read from the kernel instead.
        let paths = AppPaths::rooted_at(Path::new("C:\\does-not-matter"));
        let before = default_runner_root(&paths).expect("this host has a system directory");

        let restore_drive = std::env::var_os("SystemDrive");
        let restore_root = std::env::var_os("SystemRoot");
        // SAFETY: the suite is serialised on this key by `serial_test`, and both
        // variables are restored below before any assertion can unwind past it.
        unsafe {
            std::env::set_var("SystemDrive", "Q:");
            std::env::set_var("SystemRoot", "Q:\\Windows");
        }
        let after = default_runner_root(&paths);
        // SAFETY: as above.
        unsafe {
            match restore_drive {
                Some(value) => std::env::set_var("SystemDrive", value),
                None => std::env::remove_var("SystemDrive"),
            }
            match restore_root {
                Some(value) => std::env::set_var("SystemRoot", value),
                None => std::env::remove_var("SystemRoot"),
            }
        }

        let after = after.expect("the kernel still answers");
        assert_eq!(after, before);
        assert_ne!(after.as_str(), "Q:\\rman");
    }

    // -- overlap ------------------------------------------------------------

    #[test]
    fn overlap_is_decided_component_by_component_on_both_platforms() {
        let cases = [
            (Unix, "/srv/rman", "/srv/rman", Overlap::Same),
            (Unix, "/srv/rman/s1", "/srv/rman", Overlap::Inside),
            (Unix, "/srv", "/srv/rman", Overlap::Contains),
            (Unix, "/srv/rman", "/srv/other", Overlap::Disjoint),
            // A prefix of the *text* is not a prefix of the *path*.
            (Unix, "/srv/rman-old", "/srv/rman", Overlap::Disjoint),
            (Unix, "/", "/srv/rman", Overlap::Contains),
            // Unix is case-sensitive; refusing to distinguish these would reject
            // two directories an operator legitimately has.
            (Unix, "/srv/Rman", "/srv/rman", Overlap::Disjoint),
            (Windows, "C:\\rman", "C:\\rman", Overlap::Same),
            (Windows, "C:\\RMAN", "c:\\rman", Overlap::Same),
            (Windows, "C:\\rman\\s1", "C:\\rman", Overlap::Inside),
            (Windows, "C:\\", "C:\\rman", Overlap::Contains),
            // Different volumes never overlap, which is the whole reason the
            // drive is an ordinary component here.
            (Windows, "D:\\rman", "C:\\rman", Overlap::Disjoint),
            (Windows, "C:\\rman-old", "C:\\rman", Overlap::Disjoint),
        ];
        for (platform, candidate, other, expected) in cases {
            assert_eq!(
                overlap_of(candidate, other, platform),
                expected,
                "{platform}: {candidate:?} vs {other:?}"
            );
        }
    }

    #[test]
    fn a_filesystem_root_never_reaches_the_preflight() {
        // The pure layer refuses it, so the preflight's own root guard is a
        // second line rather than the first: a root is where a recursive cleanup
        // would take the whole volume.
        for (raw, platform) in [("/", Unix), ("C:\\", Windows), ("c:/", Windows)] {
            assert!(
                LocalAbsolutePath::parse_for(raw, platform).is_err(),
                "{raw:?} must not be storable"
            );
        }
        let (root, below) = if cfg!(windows) {
            ("C:\\", "C:\\rman")
        } else {
            ("/", "/srv")
        };
        assert!(is_filesystem_root(Path::new(root)));
        assert!(!is_filesystem_root(Path::new(below)));
    }

    // -- the preflight, against the real filesystem --------------------------

    #[test]
    fn an_existing_writable_local_directory_is_accepted() {
        let fixture = fixture();
        let root = fixture.workspaces.join("rman");
        std::fs::create_dir(&root).expect("the root is created");

        let checked = RootPreflight::new(&fixture.paths)
            .check(&RootOwner::Host, &native(&root))
            .expect("a plain writable directory on this machine is usable");

        assert!(checked.exists());
        assert_eq!(checked.leaf_to_create(), None);
        assert_eq!(checked.filesystem().locality, Locality::Local);
        assert_eq!(
            checked.canonical(),
            plain(&std::fs::canonicalize(&root).expect("it exists"))
        );
    }

    #[test]
    fn a_missing_leaf_below_a_writable_parent_is_accepted_and_not_created() {
        let fixture = fixture();
        let root = fixture.workspaces.join("rman");

        let checked = RootPreflight::new(&fixture.paths)
            .check(&RootOwner::Host, &native(&root))
            .expect("a creatable leaf is usable");

        assert!(!checked.exists());
        assert_eq!(checked.leaf_to_create(), Some(root.as_path()));
        assert!(
            !root.exists(),
            "creation is the caller's explicit step, never the preflight's"
        );
    }

    #[test]
    fn more_than_one_missing_level_is_refused_with_the_deepest_directory() {
        let fixture = fixture();
        let root = fixture.workspaces.join("a").join("b");

        let error = RootPreflight::new(&fixture.paths)
            .check(&RootOwner::Host, &native(&root))
            .expect_err("only the leaf may be missing");
        let RunnerRootError::MissingParents {
            deepest_existing, ..
        } = &error
        else {
            panic!("expected MissingParents, got {error}");
        };
        assert_eq!(deepest_existing, &fixture.workspaces);
    }

    #[test]
    fn an_existing_file_is_refused() {
        let fixture = fixture();
        let root = fixture.workspaces.join("rman");
        std::fs::write(&root, b"not a directory").expect("the file is created");

        let error = RootPreflight::new(&fixture.paths)
            .check(&RootOwner::Host, &native(&root))
            .expect_err("a file is not a runner root");
        assert!(
            matches!(error, RunnerRootError::ExistingFile { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_file_where_the_parent_should_be_is_refused() {
        let fixture = fixture();
        let file = fixture.workspaces.join("notes.txt");
        std::fs::write(&file, b"notes").expect("the file is created");
        let root = file.join("rman");

        let error = RootPreflight::new(&fixture.paths)
            .check(&RootOwner::Host, &native(&root))
            .expect_err("nothing can be created inside a file");
        assert!(
            matches!(error, RunnerRootError::ParentIsNotADirectory { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_linked_root_is_refused_rather_than_followed() {
        let fixture = fixture();
        let target = fixture.workspaces.join("real");
        std::fs::create_dir(&target).expect("the target is created");
        let root = fixture.workspaces.join("rman");
        if !link_dir(&target, &root) {
            return;
        }

        let error = RootPreflight::new(&fixture.paths)
            .check(&RootOwner::Host, &native(&root))
            .expect_err("a runner root is the base of a recursive cleanup");
        assert!(
            matches!(error, RunnerRootError::Symlinked { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_link_whose_target_is_gone_is_still_reported_as_a_link() {
        // A junction left behind by a removed target is the ordinary way this
        // shows up. It cannot be canonicalised, so a preflight that resolved
        // before it classified would answer "cannot inspect … not found" for a
        // name the operator can see in a directory listing.
        let fixture = fixture();
        let root = fixture.workspaces.join("rman");
        if !link_dir(&fixture.workspaces.join("gone"), &root) {
            return;
        }

        let error = RootPreflight::new(&fixture.paths)
            .check(&RootOwner::Host, &native(&root))
            .expect_err("a dangling link is not a runner root");
        assert!(
            matches!(error, RunnerRootError::Symlinked { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_link_in_the_path_cannot_smuggle_a_root_into_application_data() {
        let fixture = fixture();
        let bridge = fixture.workspaces.join("bridge");
        if !link_dir(fixture.paths.state_dir(), &bridge) {
            return;
        }
        // Lexically unrelated to `state/`; it is only the resolved path that
        // lands inside it.
        let root = bridge.join("rman");

        let error = RootPreflight::new(&fixture.paths)
            .check(&RootOwner::Host, &native(&root))
            .expect_err("the canonical check must see through the link");
        let RunnerRootError::Overlaps { relation, .. } = &error else {
            panic!("expected Overlaps, got {error}");
        };
        assert_eq!(*relation, Overlap::Inside);
    }

    #[test]
    fn a_root_that_collides_with_application_data_is_refused() {
        let fixture = fixture();
        let preflight = RootPreflight::new(&fixture.paths);
        let cases = [
            // The directory itself.
            (fixture.paths.state_dir().to_path_buf(), Overlap::Same),
            // Inside it.
            (fixture.paths.logs_dir().join("rman"), Overlap::Inside),
            // Above it: a cleanup under this root would take the database too.
            (fixture.root.path().to_path_buf(), Overlap::Contains),
        ];
        for (candidate, expected) in cases {
            let error = preflight
                .check(&RootOwner::Host, &native(&candidate))
                .expect_err("application data may not share a tree with runner workspaces");
            let RunnerRootError::Overlaps { relation, .. } = &error else {
                panic!("{} gave {error}", candidate.display());
            };
            assert_eq!(*relation, expected, "{}", candidate.display());
        }
    }

    #[test]
    fn the_macos_shaped_layout_still_accepts_its_own_runtime_directory() {
        // On macOS `config`, `state`, `runtime` and `logs` all live under one
        // `Application Support` directory, so the platform default runner root
        // is *inside* the configuration directory. That nesting is the product's
        // own layout, not an operator mistake.
        let root = tempfile::tempdir().expect("a temporary directory");
        let base = root.path();
        let paths = AppPaths::from_directories(
            base,
            base.join("state"),
            base.join("runtime"),
            base.join("logs"),
        );
        paths.create_all().expect("the layout is created");
        let preflight = RootPreflight::new(&paths);

        preflight
            .check(&RootOwner::Host, &native(paths.runtime_dir()))
            .expect("the platform default must pass its own preflight");
        preflight
            .check(
                &RootOwner::Host,
                &native(&paths.runtime_dir().join("nested")),
            )
            .expect("a directory below the runtime directory is still the runner area");

        for refused in [base.to_path_buf(), base.join("state"), base.join("beside")] {
            let error = preflight
                .check(&RootOwner::Host, &native(&refused))
                .expect_err("only the runtime subtree is exempt");
            assert!(
                matches!(error, RunnerRootError::Overlaps { .. }),
                "{} gave {error}",
                refused.display()
            );
        }
    }

    #[test]
    fn two_roots_may_not_contain_one_another() {
        let fixture = fixture();
        let host = fixture.workspaces.join("host");
        let repository = host.join("acme");
        let other = fixture.workspaces.join("other");
        std::fs::create_dir_all(&repository).expect("both roots are created");
        std::fs::create_dir(&other).expect("the third root is created");

        let owner = RootOwner::Repository("acme/widgets".to_string());
        let preflight = RootPreflight::new(&fixture.paths)
            .against(RootOwner::Host, native(&host))
            .against(
                RootOwner::Repository("acme/gadgets".to_string()),
                native(&other),
            );

        let error = preflight
            .check(&owner, &native(&repository))
            .expect_err("a repository root inside the host root is refused");
        let RunnerRootError::Overlaps {
            relation,
            other_owner,
            ..
        } = &error
        else {
            panic!("expected Overlaps, got {error}");
        };
        assert_eq!(*relation, Overlap::Inside);
        assert_eq!(other_owner, &RootOwner::Host.to_string());

        let error = preflight
            .check(&owner, &native(&other))
            .expect_err("two repositories may not share a root");
        assert!(
            matches!(error, RunnerRootError::Overlaps { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_root_does_not_overlap_itself_when_it_is_revalidated() {
        let fixture = fixture();
        let root = fixture.workspaces.join("acme");
        std::fs::create_dir(&root).expect("the root is created");
        let owner = RootOwner::Repository("acme/widgets".to_string());

        RootPreflight::new(&fixture.paths)
            .against(owner.clone(), native(&root))
            .check(&owner, &native(&root))
            .expect("re-checking a stored setting must not report it against itself");
    }

    #[test]
    fn a_row_written_on_another_operating_system_fails_closed() {
        let fixture = fixture();
        let error = RootPreflight::new(&fixture.paths)
            .check(&RootOwner::Host, &foreign())
            .expect_err("a foreign path is corrupt state on this host");
        assert!(
            matches!(error, RunnerRootError::ForeignPlatform { .. }),
            "got {error}"
        );
    }

    // -- the preflight, against a stubbed platform ---------------------------

    #[test]
    fn a_remote_filesystem_is_refused() {
        let fixture = fixture();
        let root = fixture.workspaces.join("rman");
        std::fs::create_dir(&root).expect("the root is created");
        let probe = StubFilesystem::saying(FilesystemIdentity::remote("nfs"));

        let error = RootPreflight::with_probe(&fixture.paths, &probe)
            .check(&RootOwner::Host, &native(&root))
            .expect_err("a network share may not hold runner workspaces");
        assert!(
            matches!(error, RunnerRootError::RemoteFilesystem { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_filesystem_this_host_cannot_classify_fails_closed() {
        let fixture = fixture();
        let root = fixture.workspaces.join("rman");
        std::fs::create_dir(&root).expect("the root is created");
        let probe =
            StubFilesystem::saying(FilesystemIdentity::unprovable("filesystem type 0x00001234"));

        let error = RootPreflight::with_probe(&fixture.paths, &probe)
            .check(&RootOwner::Host, &native(&root))
            .expect_err("unprovable locality is a refusal, not a shrug");
        assert!(
            matches!(error, RunnerRootError::UnprovableFilesystem { .. }),
            "got {error}"
        );
    }

    #[test]
    fn an_unwritable_directory_and_an_unwritable_parent_are_reported_apart() {
        let fixture = fixture();
        let existing = fixture.workspaces.join("rman");
        std::fs::create_dir(&existing).expect("the root is created");
        let missing = fixture.workspaces.join("other");
        let probe = StubFilesystem::unwritable();
        let preflight = RootPreflight::with_probe(&fixture.paths, &probe);

        let error = preflight
            .check(&RootOwner::Host, &native(&existing))
            .expect_err("an unwritable root is unusable");
        assert!(
            matches!(error, RunnerRootError::NotWritable { .. }),
            "got {error}"
        );
        assert!(
            error.to_string().contains(&RootOwner::Host.remediation()),
            "the refusal must show the command that fixes it: {error}"
        );

        let error = preflight
            .check(&RootOwner::Host, &native(&missing))
            .expect_err("an unwritable parent cannot hold a new leaf");
        let RunnerRootError::ParentNotWritable { parent, leaf, .. } = &error else {
            panic!("expected ParentNotWritable, got {error}");
        };
        assert_eq!(parent, &fixture.workspaces);
        assert_eq!(leaf, &missing);
        assert!(
            error.to_string().contains(&RootOwner::Host.remediation()),
            "the refusal must show the command that fixes it: {error}"
        );

        let repository = RootOwner::Repository("acme/widgets".to_string());
        let error = preflight
            .check(&repository, &native(&missing))
            .expect_err("an unwritable parent cannot hold a new leaf");
        assert!(
            error.to_string().contains(&repository.remediation()),
            "a repository root must name its own command: {error}"
        );
    }

    #[test]
    fn nothing_is_created_removed_or_repermissioned_by_any_verdict() {
        // "Validation performs no deletion or permission mutation." Asserted
        // over the accepting path and every refusing path at once, because a
        // probe that wrote a marker would only show up on one of them.
        let fixture = fixture();
        let existing = fixture.workspaces.join("rman");
        std::fs::create_dir(&existing).expect("the root is created");
        let file = fixture.workspaces.join("notes.txt");
        std::fs::write(&file, b"operator data").expect("the file is created");

        let before = snapshot(fixture.root.path());

        let stub = StubFilesystem::unwritable();
        let host_preflight = RootPreflight::new(&fixture.paths);
        let stub_preflight = RootPreflight::with_probe(&fixture.paths, &stub);
        for preflight in [&host_preflight, &stub_preflight] {
            for candidate in [
                existing.clone(),
                fixture.workspaces.join("missing"),
                fixture.workspaces.join("a").join("b"),
                file.clone(),
                file.join("leaf"),
                fixture.paths.state_dir().to_path_buf(),
            ] {
                let _ = preflight.check(&RootOwner::Host, &native(&candidate));
            }
        }

        assert_eq!(
            before,
            snapshot(fixture.root.path()),
            "the preflight changed the filesystem"
        );
    }

    // -- the real probe ------------------------------------------------------

    #[test]
    fn this_machines_temporary_directory_is_local_and_writable() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let canonical = plain(&std::fs::canonicalize(root.path()).expect("it exists"));

        let identity = HostFilesystem
            .identify(&canonical)
            .expect("the platform answers");
        assert_eq!(
            identity.locality,
            Locality::Local,
            "the suite's own temporary directory reported {identity:?}; a CI leg whose \
             temporary filesystem is unknown to this table would refuse every runner root"
        );
        assert!(
            HostFilesystem
                .is_writable(&canonical)
                .expect("the platform answers"),
            "a directory this process just created must be writable"
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_system_drive_root_is_writable_when_a_directory_can_be_created_in_it() {
        // The default DACL of the system drive root grants `Authenticated
        // Users` `AD` without `WD`, so a probe that asks for
        // `FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY` refuses `C:\` for every
        // process that is not elevated — and with it the product's own default
        // `C:\rman`. Probe rather than ask: the assertion only runs on a host
        // where the account demonstrably can create the directory.
        let paths = AppPaths::rooted_at(Path::new("C:\\does-not-matter"));
        let default = default_runner_root(&paths).expect("this host has a system directory");
        let parent = default
            .as_path()
            .parent()
            .expect("the default root is one level below the system drive")
            .to_path_buf();

        let probe = parent.join(format!("rman-preflight-probe-{}", std::process::id()));
        if std::fs::create_dir(&probe).is_err() {
            return;
        }
        let writable = HostFilesystem.is_writable(&parent);
        std::fs::remove_dir(&probe).expect("the probe is removed");

        assert!(
            writable.expect("the platform answers"),
            "{} accepts a new directory, so the preflight must not refuse the default \
             runner root as unwritable",
            parent.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_this_account_cannot_write_is_reported_as_such() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("a temporary directory");
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).expect("the directory is created");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555))
            .expect("the directory is made unwritable");

        // Root ignores the mode bits, and containers routinely run as root.
        // Probe rather than ask.
        let probe = locked.join("probe");
        let is_root = std::fs::create_dir(&probe).is_ok();
        if is_root {
            std::fs::remove_dir(&probe).expect("the probe is removed");
        }
        let writable = HostFilesystem.is_writable(&locked);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
            .expect("the directory is restored");
        if is_root {
            return;
        }
        assert!(
            !writable.expect("the platform answers"),
            "a 0555 directory must not be reported writable"
        );
    }

    // -- derived paths -------------------------------------------------------

    #[test]
    fn a_derived_child_is_one_component_below_the_root() {
        let root = LocalAbsolutePath::parse_for("/srv/rman", Unix).expect("a valid root");
        assert_eq!(
            derive_child(&root, "s1").expect("a valid slot").as_str(),
            "/srv/rman/s1"
        );
        let root = LocalAbsolutePath::parse_for("C:\\rman", Windows).expect("a valid root");
        assert_eq!(
            derive_child(&root, "0123456789ab")
                .expect("a valid attempt")
                .as_str(),
            "C:\\rman\\0123456789ab"
        );
        for name in ["..", "a/b", "", "."] {
            assert!(
                derive_child(&root, name).is_err(),
                "{name:?} must not be a derived child"
            );
        }
    }

    #[test]
    fn containment_is_proven_lexically_and_after_resolution() {
        let fixture = fixture();
        let directory = fixture.workspaces.join("rman");
        std::fs::create_dir(&directory).expect("the root is created");
        let root = native(&directory);

        let slot = derive_child(&root, "s1").expect("a valid slot");
        verify_containment(&root, &slot)
            .expect("a slot that does not exist yet is still contained");
        std::fs::create_dir(slot.as_path()).expect("the slot is created");
        verify_containment(&root, &slot).expect("an existing slot is contained");

        let sibling = native(&fixture.workspaces.join("elsewhere"));
        assert!(
            matches!(
                verify_containment(&root, &sibling),
                Err(RunnerRootError::Escapes { .. })
            ),
            "a sibling is not contained"
        );
        assert!(
            matches!(
                verify_containment(&root, &root),
                Err(RunnerRootError::Escapes { .. })
            ),
            "the root is not strictly inside itself"
        );
    }

    #[test]
    fn a_link_inside_the_root_that_points_outside_it_is_not_contained() {
        let fixture = fixture();
        let root = fixture.workspaces.join("rman");
        std::fs::create_dir(&root).expect("the root is created");
        let outside = fixture.workspaces.join("outside");
        std::fs::create_dir(&outside).expect("the escape target is created");
        let escape = root.join("s1");
        if !link_dir(&outside, &escape) {
            return;
        }

        let error = verify_containment(&native(&root), &native(&escape))
            .expect_err("cleanup may not follow a link out of the root it was given");
        assert!(
            matches!(error, RunnerRootError::Escapes { .. }),
            "got {error}"
        );
    }

    // -- messages ------------------------------------------------------------

    #[test]
    fn each_owner_names_the_command_that_changes_it() {
        assert_eq!(
            RootOwner::Host.remediation(),
            "runner-manager host set-runtime-root --path <PATH>"
        );
        assert_eq!(
            RootOwner::Repository("acme/widgets".to_string()).remediation(),
            "runner-manager repo set-workspace acme/widgets --mode persistent --path <PATH>"
        );
        assert!(RootOwner::Host.to_string().contains("host runner root"));
        assert!(
            RootOwner::Repository("acme/widgets".to_string())
                .to_string()
                .contains("acme/widgets")
        );
    }

    #[test]
    fn a_refusal_names_the_paths_and_says_what_to_do_about_it() {
        // These strings are what an operator sees in the CLI, the TUI and the
        // daemon log, so the wording is pinned rather than left to the next
        // edit of the enum.
        let fixture = fixture();
        let root = fixture.workspaces.join("rman");
        std::fs::create_dir(&root).expect("the root is created");

        let probe = StubFilesystem::saying(FilesystemIdentity::remote("nfs"));
        let message = RootPreflight::with_probe(&fixture.paths, &probe)
            .check(&RootOwner::Host, &native(&root))
            .expect_err("a network share is refused")
            .to_string();
        assert!(message.contains("nfs"), "{message}");
        assert!(message.contains("local volume"), "{message}");

        let message = RootPreflight::new(&fixture.paths)
            .check(&RootOwner::Host, &native(fixture.paths.state_dir()))
            .expect_err("application data is protected")
            .to_string();
        assert!(
            message.contains(&fixture.paths.state_dir().display().to_string()),
            "the directory that refused must be named: {message}"
        );
        assert!(
            message.contains("the application state directory"),
            "the operator must be told what it collided with: {message}"
        );
        assert!(
            message.contains("outside the application data tree"),
            "the message must say what to do instead: {message}"
        );
    }
}
