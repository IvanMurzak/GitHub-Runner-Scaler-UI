// owner: d1-platform-core

//! The unprivileged account a Linux boot service runs its runners as.
//!
//! A boot service's daemon runs as `root`, because only `root` can read the
//! machine-scoped credential. Its runners do not have to, and must not: a job
//! running as `root` with no capabilities cannot change a file's owner, so
//! `tar`, npm and `node-gyp` fail on any archive whose entries another account
//! owns, and with capabilities a hostile workflow would hold them too.
//!
//! So the daemon keeps the capabilities it needs to hand a runner its
//! directories and to signal it, and starts the runner as [`RUNNER_ACCOUNT`].
//! Moving from `root` to another uid clears every capability the kernel would
//! otherwise pass on, and `NoNewPrivileges=yes` stops a set-user-ID or
//! file-capability binary from granting one back, so the job runs with none.
//!
//! The account has no password, no login shell and no home directory. Each
//! runner gets a `HOME` inside its own attempt (see
//! [`crate::runner_env::platform_defaults`]).

use std::io;
use std::path::Path;

/// The system account Linux boot-mode runners run as.
pub const RUNNER_ACCOUNT: &str = "rm-runner";

/// A resolved account: what a runner is started as and what its directories
/// are handed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerAccount {
    /// The account's user id.
    pub uid: u32,
    /// Its primary group id.
    pub gid: u32,
}

impl RunnerAccount {
    /// The account runners launched by this process run as: `Ok(None)` when
    /// they run as this process does.
    ///
    /// `Some` only for `root` on Linux with [`RUNNER_ACCOUNT`] present, which
    /// is what `service install --start-at boot` sets up. A login service, a
    /// foreground daemon and every other platform keep their runners in their
    /// own account, as before.
    ///
    /// A boot unit's daemon is `root` with a narrowed capability bounding set
    /// that still holds `CAP_DAC_OVERRIDE` and the rest of
    /// [`crate::service::BOOT_CAPABILITIES`]. A runner it started as itself
    /// would keep them, so without [`RUNNER_ACCOUNT`] it must start none. A
    /// `root` with every capability -- `sudo runner-manager daemon run` in a
    /// terminal -- keeps its runners as itself, as before.
    ///
    /// # Errors
    ///
    /// Why no runner may start: the account is missing under a confined `root`.
    pub fn for_this_daemon() -> Result<Option<Self>, String> {
        #[cfg(target_os = "linux")]
        {
            if !crate::host_fitness::is_elevated() {
                return Ok(None);
            }
            if let Some(account) = Self::lookup(RUNNER_ACCOUNT) {
                return Ok(Some(account));
            }
            if sys::bounding_set_is_narrowed() {
                return Err(format!(
                    "the {RUNNER_ACCOUNT} account that this service runs jobs as does not exist, \
                     so no runner starts rather than run as root with the service's \
                     capabilities. Run `sudo runner-manager service install --start-at boot` \
                     to create it"
                ));
            }
        }
        Ok(None)
    }

    /// The account called `name`, when it exists.
    #[must_use]
    pub fn lookup(name: &str) -> Option<Self> {
        #[cfg(unix)]
        {
            sys::lookup(name)
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            None
        }
    }

    /// [`RUNNER_ACCOUNT`], created as a system account when it is missing.
    ///
    /// # Errors
    ///
    /// What `useradd` reported, when it had to run and failed.
    pub fn ensure() -> Result<Self, String> {
        if let Some(account) = Self::lookup(RUNNER_ACCOUNT) {
            return Ok(account);
        }
        let output = std::process::Command::new("useradd")
            .args([
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "--comment",
                "runner-manager job runner",
                RUNNER_ACCOUNT,
            ])
            .output()
            .map_err(|error| format!("cannot run useradd: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "useradd could not create the {RUNNER_ACCOUNT} account: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Self::lookup(RUNNER_ACCOUNT)
            .ok_or_else(|| format!("useradd reported success but {RUNNER_ACCOUNT} does not exist"))
    }

    /// Hands `path` itself to this account, without following a link there.
    ///
    /// # Errors
    ///
    /// What `lchown` reported.
    pub fn give(&self, path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::lchown(path, Some(self.uid), Some(self.gid))
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(())
        }
    }

    /// Hands `path` and everything under it to this account.
    ///
    /// Links are handed over themselves and never followed, so a link a
    /// previous job left pointing outside the tree cannot carry the change
    /// anywhere else. Below `path`, a directory the account already owns is
    /// not entered: only the account writes inside one, so nothing there needs
    /// handing over, and a retained `_work` or an already handed package is
    /// not walked again.
    ///
    /// # Errors
    ///
    /// The first error met, after which the rest of the tree is not visited.
    pub fn give_tree(&self, path: &Path) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !self.owns(&metadata) {
            self.give(path)?;
        }
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let child = entry?.path();
                let owned_directory = std::fs::symlink_metadata(&child)
                    .is_ok_and(|metadata| metadata.is_dir() && self.owns(&metadata));
                if !owned_directory {
                    self.give_tree(&child)?;
                }
            }
        }
        Ok(())
    }

    /// Whether this account already owns what `metadata` describes.
    #[must_use]
    pub fn owns(&self, metadata: &std::fs::Metadata) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            metadata.uid() == self.uid && metadata.gid() == self.gid
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            true
        }
    }
}

#[cfg(unix)]
mod sys {
    use super::RunnerAccount;

    /// Whether this process's capability bounding set lacks `CAP_SYS_ADMIN`,
    /// which only a deliberately confined process -- a systemd unit with a
    /// `CapabilityBoundingSet=` -- does.
    #[cfg(target_os = "linux")]
    pub(super) fn bounding_set_is_narrowed() -> bool {
        const CAP_SYS_ADMIN: libc::c_ulong = 21;
        // SAFETY: PR_CAPBSET_READ only reads this process's bounding set.
        unsafe { libc::prctl(libc::PR_CAPBSET_READ, CAP_SYS_ADMIN, 0, 0, 0) == 0 }
    }

    pub(super) fn lookup(name: &str) -> Option<RunnerAccount> {
        let name = std::ffi::CString::new(name).ok()?;
        let mut buffer = vec![0_u8; 4096];
        loop {
            // SAFETY: `passwd` is plain data that `getpwnam_r` fills in, and
            // zero is a valid value for every field until it does.
            let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
            let mut found: *mut libc::passwd = std::ptr::null_mut();
            // SAFETY: every pointer is valid for the call: `name` is
            // NUL-terminated, `buffer` is writable for its length, and `entry`
            // and `found` are local.
            let status = unsafe {
                libc::getpwnam_r(
                    name.as_ptr(),
                    &mut entry,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut found,
                )
            };
            if status == libc::ERANGE && buffer.len() < 1 << 20 {
                buffer.resize(buffer.len() * 2, 0);
                continue;
            }
            if status != 0 || found.is_null() {
                return None;
            }
            return Some(RunnerAccount {
                uid: entry.pw_uid,
                gid: entry.pw_gid,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn an_account_that_exists_is_found_and_one_that_does_not_is_not() {
        let root = RunnerAccount::lookup("root").expect("every Unix host has root");
        assert_eq!(root.uid, 0);
        assert_eq!(
            RunnerAccount::lookup("runner-manager-no-such-account-x"),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn giving_a_tree_to_its_own_owner_changes_nothing_and_never_follows_links() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join("a/b")).unwrap();
        std::fs::write(directory.path().join("a/b/file"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path(), directory.path().join("a/link")).unwrap();
        let metadata = std::fs::metadata(directory.path()).unwrap();
        let me = RunnerAccount {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        me.give_tree(directory.path()).unwrap();
        assert!(me.owns(&std::fs::metadata(directory.path().join("a/b/file")).unwrap()));

        // Another owner is refused for an unprivileged test process, which
        // shows the call reaches lchown; root is skipped since it may.
        if !crate::host_fitness::is_elevated() {
            let other = RunnerAccount {
                uid: me.uid + 1,
                gid: me.gid,
            };
            assert!(other.give_tree(directory.path()).is_err());
        }
    }

    #[test]
    fn no_account_is_used_unless_this_is_root_on_linux() {
        if !(cfg!(target_os = "linux") && crate::host_fitness::is_elevated()) {
            assert_eq!(RunnerAccount::for_this_daemon(), Ok(None));
        }
    }
}
