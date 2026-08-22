// owner: d1-platform-core

//! The four application-data directories the daemon owns, resolved to
//! platform-standard locations.
//!
//! `05-infrastructure.md` names them and says what each holds:
//!
//! ```text
//! config/      non-secret TOML and SQLite database
//! state/       agent lock, attempt journal, retained runner package/cache
//! runtime/     per-attempt disposable directories
//! logs/        rotating redacted agent diagnostics
//! ```
//!
//! and then states the rule this module exists to enforce: *"Platform-standard
//! application-data directories are used; no repository or runner material is
//! stored in the current working directory by default."*
//!
//! ## The invariant, and how it is tested
//!
//! "Not the current working directory" is easy to satisfy by accident and easy
//! to lose by accident — one `PathBuf::from("state")` anywhere in the
//! resolution chain and the daemon starts writing runner workspaces wherever
//! it happened to be launched from. The property that actually holds it is
//! stronger and is what the tests assert: **the resolved paths do not change
//! when the process changes directory.** A resolver that consults
//! `current_dir()` fails that immediately, whereas an assertion phrased as "the
//! path is not inside the current directory" passes for a developer whose shell
//! happens to be somewhere else and fails for one whose shell is at `$HOME`.
//!
//! ## Placement, per platform
//!
//! | | `config` | `state` | `runtime`, `logs` |
//! |---|---|---|---|
//! | Windows | `%LOCALAPPDATA%\IvanMurzak\runner-manager\config` | `…\data\state` | `…\data\{runtime,logs}` |
//! | macOS | `~/Library/Application Support/io.github.IvanMurzak.runner-manager` | `…/state` | `…/{runtime,logs}` |
//! | Linux | `$XDG_CONFIG_HOME/runner-manager` | `$XDG_STATE_HOME/runner-manager` | `$XDG_DATA_HOME/runner-manager/{runtime,logs}` |
//!
//! Three choices in that table are deliberate:
//!
//! - **Local, not roaming, on Windows.** `config_local_dir` rather than
//!   `config_dir`. A SQLite database and a runner package cache have no
//!   business being copied around a domain profile, and D13 stores this host's
//!   token machine-scoped precisely because the agent is a machine-local
//!   thing.
//! - **`$XDG_STATE_HOME` on Linux.** That is the directory the XDG base
//!   directory specification defines for exactly this content — state that
//!   survives a restart but is neither configuration nor portable data. It has
//!   no equivalent on Windows or macOS, so those fall back to a `state`
//!   subdirectory of the local data directory.
//! - **`runtime/` is *not* `$XDG_RUNTIME_DIR`.** That directory is a
//!   size-limited tmpfs that the system clears when the user's session ends,
//!   and D13's service starts at machine boot, outside any session — so it may
//!   not exist at all. `runtime/` here holds per-attempt runner workspaces,
//!   which are large and must outlive a logout, so it lives under the local
//!   data directory instead.

use std::fmt;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;

/// Reverse-domain qualifier; used on macOS only.
const QUALIFIER: &str = "io.github";
/// Organization segment; used on macOS and Windows only.
const ORGANIZATION: &str = "IvanMurzak";
/// Application segment; used on all three platforms.
const APPLICATION: &str = "runner-manager";

/// The four directory names, as `05-infrastructure.md` writes them. Also the
/// layout [`AppPaths::rooted_at`] produces verbatim.
const CONFIG: &str = "config";
const STATE: &str = "state";
const RUNTIME: &str = "runtime";
const LOGS: &str = "logs";

/// Something went wrong resolving or creating an application-data directory.
#[derive(Debug, thiserror::Error)]
pub enum PathsError {
    /// The operating system reported no home directory for this account.
    #[error(
        "cannot determine a home directory for this account, so the platform-standard \
         application-data directories cannot be resolved. A service account normally hits \
         this when it is configured with no profile; give the account a home directory, or \
         run the agent against an explicit root."
    )]
    NoHomeDirectory,

    /// A directory could not be created.
    #[error("cannot create the {purpose} directory {}: {source}", path.display())]
    Create {
        /// Which of the four directories failed.
        purpose: &'static str,
        /// The path that could not be created.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// A directory could not be created because its parent refused.
    ///
    /// Split out from [`PathsError::Create`] because the message a bare
    /// `EACCES` produces is a dead end. It names the leaf, and the leaf is not
    /// the obstacle: it does not exist yet, so it cannot be what refused.
    /// `mkdir(2)` reports `EACCES` about the **parent**, and the parent here
    /// is one of the shared directories this program deliberately does not
    /// tighten -- `~/.local`, `~/.config`, or whatever the account's
    /// application-data root resolves under. An operator handed the leaf path
    /// goes and looks at a directory that is not there.
    ///
    /// Nothing about the permission policy changes on the strength of this.
    /// Parents are still not this program's to tighten, and this still fails
    /// rather than widening anything. The diagnosis is the whole of the
    /// remedy: say which directory refused and what state it is in, so the
    /// operator can decide.
    #[error(
        "cannot create the {purpose} directory {}: permission denied. The directory named is \
         not the obstacle -- it does not exist yet, so it cannot be what refused; the refusal \
         comes from its parent. {} is {parent_state}. This program will not change it: an \
         intermediate directory is shared with every other application and is not the agent's \
         to tighten. Grant this account write access to that directory, or run the agent \
         against an explicit root under a directory it owns.",
        path.display(),
        path.parent().unwrap_or(path.as_path()).display()
    )]
    ParentDenies {
        /// Which of the four directories failed.
        purpose: &'static str,
        /// The leaf that could not be created. The directory that actually
        /// refused is its parent, which is derived rather than stored: keeping
        /// both is redundant, and it pushed `Result<_, LoggingError>` past
        /// clippy's `result_large_err` threshold, which is a fair complaint
        /// about an error type carrying a path twice.
        path: PathBuf,
        /// What the platform can say about that parent: its mode on Unix,
        /// whatever `std::fs` can report on Windows.
        parent_state: String,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
}

/// The four directories the daemon owns.
///
/// Resolved once and passed down, rather than recomputed at each use. Two
/// resolutions in one process must agree, and the cheapest way to guarantee
/// that is to only resolve once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    config: PathBuf,
    state: PathBuf,
    runtime: PathBuf,
    logs: PathBuf,
}

impl AppPaths {
    /// Resolves the platform-standard locations for this account.
    ///
    /// # Errors
    ///
    /// [`PathsError::NoHomeDirectory`] when the operating system reports no
    /// home directory, which is the only way this can fail: nothing is touched
    /// on disk here. Use [`AppPaths::create_all`] for that.
    pub fn discover() -> Result<Self, PathsError> {
        let dirs = ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
            .ok_or(PathsError::NoHomeDirectory)?;

        // `state_dir` is `Some` on Linux only; see the module documentation.
        let state = dirs
            .state_dir()
            .map_or_else(|| dirs.data_local_dir().join(STATE), Path::to_path_buf);

        Ok(Self {
            config: dirs.config_local_dir().to_path_buf(),
            state,
            runtime: dirs.data_local_dir().join(RUNTIME),
            logs: dirs.data_local_dir().join(LOGS),
        })
    }

    /// Places all four directories under one root, using the names
    /// `05-infrastructure.md` gives them.
    ///
    /// This is how a test gets a disposable layout and how a service that was
    /// installed against an explicitly configured root reproduces it. It is
    /// deliberately *not* what [`AppPaths::discover`] falls back to: a relative
    /// root passed here stays relative, and that is the caller's decision to
    /// make rather than a default anything acquires by accident.
    pub fn rooted_at(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            config: root.join(CONFIG),
            state: root.join(STATE),
            runtime: root.join(RUNTIME),
            logs: root.join(LOGS),
        }
    }

    /// Non-secret TOML configuration and the SQLite database.
    #[must_use]
    pub fn config_dir(&self) -> &Path {
        &self.config
    }

    /// The agent lock, the attempt journal, and the retained runner package
    /// cache.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state
    }

    /// Per-attempt disposable runner workspaces.
    #[must_use]
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime
    }

    /// Rotating redacted agent diagnostics.
    #[must_use]
    pub fn logs_dir(&self) -> &Path {
        &self.logs
    }

    /// The four directories, paired with the name each is known by. Ordered
    /// as `05-infrastructure.md` lists them.
    #[must_use]
    pub fn all(&self) -> [(&'static str, &Path); 4] {
        [
            (CONFIG, self.config.as_path()),
            (STATE, self.state.as_path()),
            (RUNTIME, self.runtime.as_path()),
            (LOGS, self.logs.as_path()),
        ]
    }

    /// Creates every directory that does not already exist.
    ///
    /// Idempotent, and restrictive where the platform expresses that through
    /// mode bits: on Unix each leaf is created *at* `0700`, so a runner
    /// workspace, an attempt journal, and a diagnostics file are not readable
    /// by other local accounts. Intermediate directories — `~/.local`,
    /// `~/.config` — are left alone, because they are shared with every other
    /// application and are not this program's to tighten.
    ///
    /// The mode is passed to `mkdir(2)` rather than applied with a following
    /// `chmod`, for the same reason [`crate::process::RestrictiveHandoff`]
    /// passes it to `open(2)`: the two-step version leaves a window in which
    /// `state/` and `runtime/` exist at the umask default — typically `0755` —
    /// and those are the directories holding the attempt journal and the runner
    /// workspaces. A directory that was *already* there is still tightened,
    /// which is what keeps this idempotent and what upgrades a tree created by
    /// an earlier version.
    ///
    /// On Windows the per-account `AppData` tree already denies other
    /// non-administrative users, and the one file whose exposure actually
    /// matters gets an explicit DACL of its own rather than relying on that:
    /// see [`crate::process::RestrictiveHandoff`].
    ///
    /// # Errors
    ///
    /// [`PathsError::Create`], naming which of the four failed and why.
    pub fn create_all(&self) -> Result<(), PathsError> {
        for (purpose, path) in self.all() {
            let failed = |source| PathsError::Create {
                purpose,
                path: path.to_path_buf(),
                source,
            };

            // The parents are created at whatever the umask says, deliberately:
            // they are `~/.local` and its like, and are not this program's to
            // tighten.
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(failed)?;
            }

            match create_restricted_leaf(path) {
                Ok(()) => {
                    // `DirBuilder::mode` passes the mode through `mkdir(2)`,
                    // which applies `& ~umask`. The result is therefore always
                    // a *subset* of `0700` -- never more permissive, so this is
                    // not a security hole -- but it is no longer exactly `0700`
                    // the way an explicit `set_permissions` made it. An unusual
                    // umask that strips owner bits would leave a tree this
                    // program cannot write, and would fail the `0700` assertion
                    // the logging installer makes about these directories.
                    //
                    // Chmodding the freshly-created path does not reopen the
                    // window that creating-then-tightening used to have:
                    // created at `0700` or tighter and then set to `0700`, the
                    // directory is not permissive at any instant.
                    restrict_directory(purpose, path)?;
                }
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Already there. It may predate this rule, or predate this
                    // program, so tighten it rather than assume. A non-
                    // directory at the path is still an error, exactly as it
                    // was when this used `create_dir_all`.
                    if !path.is_dir() {
                        return Err(failed(source));
                    }
                    restrict_directory(purpose, path)?;
                }
                Err(source) if source.kind() == std::io::ErrorKind::PermissionDenied => {
                    // `mkdir(2)` reports `EACCES` about the parent: the leaf
                    // does not exist yet, so it cannot be what refused. The
                    // parent is known exactly here -- `create_dir_all` above
                    // just returned `Ok` for it -- which is why this is the
                    // one place the diagnosis can be made without guessing.
                    let parent = path.parent().unwrap_or(path);
                    return Err(PathsError::ParentDenies {
                        purpose,
                        path: path.to_path_buf(),
                        parent_state: describe_parent(parent),
                        source,
                    });
                }
                Err(source) => return Err(failed(source)),
            }
        }
        Ok(())
    }
}

/// Creates one leaf directory with its final permissions already applied.
///
/// Fails with [`std::io::ErrorKind::AlreadyExists`] when anything is at the
/// path; the caller decides what that means.
#[cfg(unix)]
fn create_restricted_leaf(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new().mode(0o700).create(path)
}

/// Windows has no mode bits to set at creation; the per-account `AppData` tree
/// already denies other non-administrative users, and the one file whose
/// exposure matters carries its own DACL.
#[cfg(not(unix))]
fn create_restricted_leaf(path: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new().create(path)
}

/// How the parent of a leaf that could not be created presents to this account.
///
/// Reported rather than acted on. This is the directory the operator has to
/// look at, and the whole point of naming it is that the message about the
/// leaf sends them somewhere that does not exist yet.
fn describe_parent(parent: &Path) -> String {
    match std::fs::metadata(parent) {
        Ok(metadata) if metadata.is_dir() => permission_summary(&metadata),
        // Both of these contradict the caller's premise -- `create_dir_all`
        // returned `Ok` for this path a moment ago -- so say so plainly rather
        // than inventing a mode for something that is not a directory.
        Ok(_) => "not a directory".to_string(),
        Err(error) => format!("not inspectable ({error})"),
    }
}

/// What the platform can say about a directory's permissions.
#[cfg(unix)]
fn permission_summary(metadata: &std::fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;

    format!("mode {:04o}", metadata.permissions().mode() & 0o7777)
}

/// Windows has no mode bits. The read-only attribute is the only thing
/// `std::fs` exposes, and it is almost never the reason -- so say which of the
/// two answers this is, rather than implying the attribute is the whole story.
#[cfg(not(unix))]
fn permission_summary(metadata: &std::fs::Metadata) -> String {
    if metadata.permissions().readonly() {
        "marked read-only".to_string()
    } else {
        "not marked read-only, so an access-control entry is what refused".to_string()
    }
}

impl fmt::Display for AppPaths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately multi-line: this is what `host show` prints, and four
        // long absolute paths on one line are unreadable.
        for (name, path) in self.all() {
            writeln!(f, "{name}/ {}", path.display())?;
        }
        Ok(())
    }
}

/// Sets a directory to exactly `0700`.
///
/// Called on both paths, and for two different reasons. A directory that
/// already existed may predate this rule and can be anything at all. A
/// directory this program just created is already a subset of `0700`, because
/// `mkdir(2)` applied the mode through the umask -- but a subset is not the
/// same as exactly `0700`, and the callers of these directories assume the
/// owner bits are present.
#[cfg(unix)]
fn restrict_directory(purpose: &'static str, path: &Path) -> Result<(), PathsError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|source| {
        PathsError::Create {
            purpose,
            path: path.to_path_buf(),
            source,
        }
    })
}

// Returns `Result` only so that the two arms share one signature; the Windows
// and macOS-without-mode-bits case has nothing to do here.
#[cfg(not(unix))]
fn restrict_directory(_purpose: &'static str, _path: &Path) -> Result<(), PathsError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// True when a path has no `.` or `..` component and is absolute — the
    /// shape a resolved application-data path must have before anything else
    /// is worth asserting about it.
    fn is_clean_absolute(path: &Path) -> bool {
        use std::path::Component;
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    }

    /// Resolves with `resolve`, moves the process to `elsewhere`, resolves
    /// again, and reports whether the two answers agreed.
    ///
    /// Written as a helper returning `Result` rather than as inline assertions
    /// so that `the_independence_check_catches_a_cwd_relative_resolver` below
    /// can point it at a resolver that is wrong in exactly the way this module
    /// exists to prevent. A test that only ever sees the correct
    /// implementation cannot tell a working check from a vacuous one.
    fn check_cwd_independence(
        resolve: impl Fn() -> AppPaths,
        elsewhere: &Path,
    ) -> Result<(), String> {
        let original = std::env::current_dir().expect("a current directory");
        let before = resolve();
        std::env::set_current_dir(elsewhere).expect("can enter the temporary directory");
        let after = resolve();
        std::env::set_current_dir(&original).expect("can return to the original directory");

        if before == after {
            Ok(())
        } else {
            Err(format!(
                "the resolved layout moved with the process: before={before:?} after={after:?}"
            ))
        }
    }

    #[test]
    fn discover_returns_four_distinct_clean_absolute_paths() {
        let paths = AppPaths::discover().expect("a home directory exists on every CI leg");

        let mut seen: Vec<&Path> = Vec::new();
        for (name, path) in paths.all() {
            assert!(
                is_clean_absolute(path),
                "{name}/ resolved to {}, which is not a clean absolute path",
                path.display()
            );
            assert!(
                !seen.contains(&path),
                "{name}/ collides with another of the four: {}",
                path.display()
            );
            seen.push(path);
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    #[serial_test::serial(current_dir)]
    fn discover_does_not_move_with_the_process() {
        let elsewhere = tempfile::tempdir().expect("a temporary directory");

        check_cwd_independence(
            || AppPaths::discover().expect("a home directory exists"),
            elsewhere.path(),
        )
        .expect("the platform-standard layout must not depend on the current directory");
    }

    #[test]
    #[serial_test::serial(current_dir)]
    fn the_independence_check_catches_a_cwd_relative_resolver() {
        let elsewhere = tempfile::tempdir().expect("a temporary directory");

        // The exact defect `05-infrastructure.md` forbids: runner material
        // landing wherever the daemon happened to be launched from.
        let cwd_relative =
            || AppPaths::rooted_at(std::env::current_dir().expect("a current directory"));

        let complaint = check_cwd_independence(cwd_relative, elsewhere.path())
            .expect_err("a current-directory-relative layout must be caught");
        assert!(
            complaint.contains("moved with the process"),
            "the complaint must name the failure mode, got: {complaint}"
        );
    }

    /// On all three platforms the standard locations live under the account's
    /// home directory — `%LOCALAPPDATA%` on Windows, `~/Library` on macOS,
    /// `~/.config` and `~/.local` on Linux. Asserting that is not the same as
    /// asserting the path equals what `directories` returned, which would only
    /// restate the implementation.
    #[test]
    fn discover_stays_under_the_account_home_directory() {
        // An operator who has repointed an XDG base directory has deliberately
        // moved it out of `$HOME`, and honouring that is the correct behaviour
        // rather than a violation. Skip rather than fail in that case.
        let overridden = ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"]
            .iter()
            .any(|name| std::env::var_os(name).is_some());
        if overridden {
            return;
        }

        let home = directories::BaseDirs::new()
            .expect("a home directory exists on every CI leg")
            .home_dir()
            .to_path_buf();
        let paths = AppPaths::discover().expect("a home directory exists");

        for (name, path) in paths.all() {
            assert!(
                path.starts_with(&home),
                "{name}/ resolved to {}, which is outside the account home {}",
                path.display(),
                home.display()
            );
            assert_ne!(
                path,
                home.as_path(),
                "{name}/ must be a directory of this application's own, not the home directory"
            );
        }
    }

    #[test]
    fn rooted_at_produces_the_layout_the_infrastructure_document_names() {
        let root = Path::new("/srv/runner-manager");
        let paths = AppPaths::rooted_at(root);

        assert_eq!(paths.config_dir(), root.join("config"));
        assert_eq!(paths.state_dir(), root.join("state"));
        assert_eq!(paths.runtime_dir(), root.join("runtime"));
        assert_eq!(paths.logs_dir(), root.join("logs"));

        assert_eq!(
            paths.all().map(|(name, _)| name),
            ["config", "state", "runtime", "logs"],
            "the order and the names are what `host show` prints"
        );
    }

    /// A denied creation must name the directory that actually refused.
    ///
    /// The diagnosis, not the policy. `create_all` still fails, and still
    /// leaves the parent alone -- an intermediate directory is shared with
    /// every other application and is not the agent's to tighten. What
    /// changes is that the message stops sending the operator to a path that
    /// does not exist.
    #[cfg(unix)]
    #[test]
    fn a_denied_creation_names_the_parent_rather_than_the_leaf() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("a temporary directory");
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).expect("the parent is created writable");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555))
            .expect("the parent is made unwritable");

        // Root ignores the mode bits, and containers routinely run as root.
        // Probe rather than ask: if a child can still be created here, this
        // account is not the one the test needs, and skipping is honest where
        // failing would be a lie about the code.
        let probe = locked.join("probe");
        let skip = std::fs::create_dir(&probe).is_ok();
        if skip {
            std::fs::remove_dir(&probe).expect("the probe is removed");
        }
        // Restored before any assertion can unwind past it, or the temporary
        // directory cannot be cleaned up.
        let restore = || {
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).ok();
        };
        if skip {
            restore();
            return;
        }

        // Rooted *at* the unwritable directory, so that the leaf's parent
        // already exists and the refusal comes from `create_restricted_leaf`
        // rather than from the `create_dir_all` above it.
        let paths = AppPaths::rooted_at(&locked);
        let outcome = paths.create_all();
        restore();

        let error = outcome.expect_err("an unwritable parent must not succeed");
        let PathsError::ParentDenies {
            purpose,
            path,
            parent_state,
            ..
        } = &error
        else {
            panic!("a denied creation must be reported as such, not as a bare Create: {error}");
        };

        assert_eq!(*purpose, "config", "the first of the four is what failed");
        assert_eq!(path, &locked.join("config"));
        assert_eq!(
            path.parent(),
            Some(locked.as_path()),
            "the parent is the directory that refused"
        );
        assert_eq!(parent_state, "mode 0555", "{parent_state}");

        // The message is the whole point of the variant, so assert on it.
        let message = error.to_string();
        assert!(
            message.contains(&locked.display().to_string()),
            "the parent must be named: {message}"
        );
        assert!(
            message.contains("mode 0555"),
            "the parent's state must be given, or the operator has to go and \
             look it up before they can act: {message}"
        );
        assert!(
            message.contains("not the obstacle"),
            "the message must say why the leaf is not the thing to look at, \
             or naming the parent reads as an aside: {message}"
        );

        // The policy is unchanged: nothing was widened on the way out.
        let mode = std::fs::metadata(&locked)
            .expect("the parent still exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o755,
            "only this test's own restore may have touched the parent"
        );
    }

    #[test]
    fn create_all_is_idempotent() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(root.path());

        paths.create_all().expect("first creation succeeds");
        // A daemon calls this on every start, including the ones where the
        // directories are already there.
        paths.create_all().expect("second creation succeeds");

        for (name, path) in paths.all() {
            assert!(
                path.is_dir(),
                "{name}/ was not created at {}",
                path.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn create_all_leaves_no_directory_readable_by_other_accounts() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(root.path());
        paths.create_all().expect("creation succeeds");

        for (name, path) in paths.all() {
            let mode = std::fs::metadata(path)
                .expect("the directory exists")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode, 0o700,
                "{name}/ is mode {mode:o}; group and other must have no access at all, \
                 because the attempt journal and the runner workspaces live here"
            );
        }
    }

    #[test]
    fn display_lists_all_four_directories() {
        let paths = AppPaths::rooted_at(Path::new("/srv/runner-manager"));
        let rendered = paths.to_string();

        for name in ["config/", "state/", "runtime/", "logs/"] {
            assert!(rendered.contains(name), "{name} missing from:\n{rendered}");
        }
        assert_eq!(rendered.lines().count(), 4);
    }
}
