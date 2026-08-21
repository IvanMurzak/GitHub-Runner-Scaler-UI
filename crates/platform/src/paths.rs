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
    /// mode bits: on Unix each leaf is set to `0700` after creation, so a
    /// runner workspace, an attempt journal, and a diagnostics file are not
    /// readable by other local accounts. Intermediate directories — `~/.local`,
    /// `~/.config` — are left alone, because they are shared with every other
    /// application and are not this program's to tighten.
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
            std::fs::create_dir_all(path).map_err(|source| PathsError::Create {
                purpose,
                path: path.to_path_buf(),
                source,
            })?;
            restrict_directory(purpose, path)?;
        }
        Ok(())
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
