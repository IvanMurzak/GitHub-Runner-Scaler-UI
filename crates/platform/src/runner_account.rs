// owner: d1-platform-core

//! The unprivileged accounts a Linux boot service runs its runners as.
//!
//! A boot service's daemon runs as `root`, because only `root` can read the
//! machine-scoped credential. Its runners do not have to, and must not: a job
//! running as `root` with no capabilities cannot change a file's owner, so
//! `tar`, npm and `node-gyp` fail on any archive whose entries another account
//! owns, and with capabilities a hostile workflow would hold them too.
//!
//! So the daemon keeps the capabilities it needs to hand a runner its
//! directories and to signal it, and starts each runner as an account of its
//! own from a [`RunnerPool`]. One account per concurrent runner is what keeps
//! jobs apart from each other: a job cannot read another job's workspace, its
//! runner's credentials or its processes' environment, nor signal them. The
//! accounts share one group, [`RUNNER_GROUP`], which is how they share the
//! dependency caches the operator chose to share.
//! Moving from `root` to another uid clears every capability the kernel would
//! otherwise pass on, and `NoNewPrivileges=yes` stops a set-user-ID or
//! file-capability binary from granting one back, so the job runs with none.
//!
//! The account has no password, no login shell and no home directory. Each
//! runner gets a `HOME` inside its own attempt (see
//! [`crate::runner_env::platform_defaults`]).

use std::io;
use std::path::Path;

/// The group every runner account belongs to, and the account 0.4.56 ran every
/// runner as, which a pool still accepts for an attempt that predates it.
pub const RUNNER_GROUP: &str = "rm-runner";

/// How many runner accounts `service install --start-at boot` creates: the
/// most runners a host can run at once without two of them sharing an account.
pub const POOL_SIZE: u32 = 32;

/// The name of the pool's `n`th account, counting from one.
#[must_use]
pub fn pool_account_name(n: u32) -> String {
    format!("{RUNNER_GROUP}-{n}")
}

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

/// The accounts a Linux boot service's runners run as, one per concurrent
/// runner, all in [`RUNNER_GROUP`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerPool {
    /// [`RUNNER_GROUP`]'s id.
    pub gid: u32,
    /// The accounts a new attempt may be given, in order of preference.
    pub accounts: Vec<RunnerAccount>,
    /// The single account an earlier release ran every runner as: accepted
    /// for an attempt it already owns, and given to a new one only when the
    /// pool has no account of its own yet.
    pub legacy: Option<RunnerAccount>,
}

impl RunnerPool {
    /// The pool runners launched by this process run as: `Ok(None)` when they
    /// run as this process does.
    ///
    /// `Some` only for `root` on Linux with the pool present, which is what
    /// `service install --start-at boot` sets up. A login service, a foreground
    /// daemon and every other platform keep their runners in their own
    /// account, as before.
    ///
    /// A boot unit's daemon is `root` with a narrowed capability bounding set
    /// that still holds `CAP_DAC_OVERRIDE` and the rest of
    /// [`crate::service::BOOT_CAPABILITIES`]. A runner it started as itself
    /// would keep them, so without the pool it must start none. A `root` with
    /// every capability -- `sudo runner-manager daemon run` in a terminal --
    /// keeps its runners as itself, as before.
    ///
    /// # Errors
    ///
    /// Why no runner may start: the pool is missing under a confined `root`.
    pub fn for_this_daemon() -> Result<Option<Self>, String> {
        #[cfg(target_os = "linux")]
        {
            if !crate::host_fitness::is_elevated() {
                return Ok(None);
            }
            // A unit registered before the pool existed has an empty bounding
            // set: it can switch to no account, and a runner it starts as
            // itself holds no capability, so it keeps doing that.
            if sys::bounding_set_is_narrowed() && !sys::bounding_set_holds_any() {
                return Ok(None);
            }
            if sys::can_switch_account()
                && let Some(pool) = Self::lookup()
            {
                return Ok(Some(pool));
            }
            if sys::bounding_set_is_narrowed() {
                return Err(format!(
                    "the {RUNNER_GROUP} accounts that this service runs jobs as do not exist, \
                     or the service lacks the capabilities to start jobs as them, so no runner \
                     starts rather than run as root with the service's capabilities. Run \
                     `sudo runner-manager service install --start-at boot` to set both up"
                ));
            }
        }
        Ok(None)
    }

    /// The pool as it exists on this host, or `None` when it has no account
    /// at all.
    #[must_use]
    pub fn lookup() -> Option<Self> {
        let gid = Self::group_id()?;
        let accounts = (1..=POOL_SIZE)
            .filter_map(|n| RunnerAccount::lookup(&pool_account_name(n)))
            .filter(|account| account.gid == gid)
            .collect::<Vec<_>>();
        let legacy = RunnerAccount::lookup(RUNNER_GROUP).filter(|account| account.gid == gid);
        (!accounts.is_empty() || legacy.is_some()).then_some(Self {
            gid,
            accounts,
            legacy,
        })
    }

    fn group_id() -> Option<u32> {
        #[cfg(unix)]
        {
            sys::group(RUNNER_GROUP)
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    /// The pool, with [`RUNNER_GROUP`] and every account up to [`POOL_SIZE`]
    /// created as system accounts where missing.
    ///
    /// # Errors
    ///
    /// What `groupadd` or `useradd` reported, when one had to run and failed.
    pub fn ensure() -> Result<Self, String> {
        if Self::group_id().is_none() {
            run("groupadd", &["--system", RUNNER_GROUP])?;
        }
        for n in 1..=POOL_SIZE {
            let name = pool_account_name(n);
            if RunnerAccount::lookup(&name).is_none() {
                run(
                    "useradd",
                    &[
                        "--system",
                        "--gid",
                        RUNNER_GROUP,
                        "--no-create-home",
                        "--home-dir",
                        "/nonexistent",
                        "--shell",
                        "/usr/sbin/nologin",
                        "--comment",
                        "runner-manager job runner",
                        &name,
                    ],
                )?;
            }
        }
        Self::lookup()
            .filter(|pool| pool.accounts.len() == POOL_SIZE as usize)
            .ok_or_else(|| {
                format!("the {RUNNER_GROUP} accounts are incomplete after creating them")
            })
    }

    /// The pool account, or the legacy one, with user id `uid`.
    #[must_use]
    pub fn account(&self, uid: u32) -> Option<RunnerAccount> {
        self.accounts
            .iter()
            .chain(self.legacy.iter())
            .find(|account| account.uid == uid)
            .copied()
    }

    /// The accounts a new attempt may be given: the pool's own, or the legacy
    /// account while the pool has none.
    #[must_use]
    pub fn assignable(&self) -> Vec<RunnerAccount> {
        if self.accounts.is_empty() {
            self.legacy.iter().copied().collect()
        } else {
            self.accounts.clone()
        }
    }

    /// Shares `path` and everything under it with every account in the pool:
    /// the group becomes [`RUNNER_GROUP`], which may read and write it, new
    /// entries in a directory inherit that group (set-group-ID), and a default
    /// ACL gives the group write access to what any account creates later,
    /// whatever umask that account's job runs with.
    ///
    /// A directory already shared is not entered, so a second call over a
    /// large cache costs one `lstat`. Links are never followed.
    ///
    /// # Errors
    ///
    /// The first error met, after which the rest of the tree is not visited.
    pub fn share_tree(&self, path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            sys::share_tree(self.gid, path)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(())
        }
    }

    /// Whether `metadata` describes a directory [`Self::share_tree`] has
    /// already shared.
    #[must_use]
    pub fn is_shared(&self, metadata: &std::fs::Metadata) -> bool {
        #[cfg(unix)]
        {
            sys::is_shared(self.gid, metadata)
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            true
        }
    }
}

fn run(program: &str, arguments: &[&str]) -> Result<(), String> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {} failed: {}",
            arguments.last().unwrap_or(&""),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(unix)]
mod sys {
    use std::io;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::Path;

    use super::RunnerAccount;

    pub(super) fn is_shared(gid: u32, metadata: &std::fs::Metadata) -> bool {
        metadata.is_dir() && metadata.gid() == gid && metadata.mode() & 0o2070 == 0o2070
    }

    pub(super) fn share_tree(gid: u32, path: &Path) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        share(gid, path, &metadata)?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let child = entry?.path();
                let shared = std::fs::symlink_metadata(&child)
                    .is_ok_and(|metadata| is_shared(gid, &metadata));
                if !shared {
                    share_tree(gid, &child)?;
                }
            }
        }
        Ok(())
    }

    fn share(gid: u32, path: &Path, metadata: &std::fs::Metadata) -> io::Result<()> {
        if metadata.gid() != gid {
            std::os::unix::fs::lchown(path, None, Some(gid))?;
        }
        if metadata.file_type().is_symlink() {
            return Ok(());
        }
        let mode = metadata.mode() & 0o7777;
        let wanted = if metadata.is_dir() {
            mode | 0o2070
        } else {
            // The group gets what the owner has, short of the special bits.
            mode | ((mode & 0o700) >> 3)
        };
        if wanted != mode {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(wanted))?;
        }
        if metadata.is_dir() {
            set_default_acl(path)?;
        }
        Ok(())
    }

    /// The default ACL `user::rwx group::rwx other::---`, in the kernel's
    /// `system.posix_acl_default` encoding.
    pub(super) fn default_acl() -> Vec<u8> {
        const VERSION: u32 = 2;
        const UNDEFINED: u32 = u32::MAX;
        let mut acl = VERSION.to_le_bytes().to_vec();
        // (tag, permissions): ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_OTHER.
        for (tag, permissions) in [(0x01_u16, 7_u16), (0x04, 7), (0x20, 0)] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permissions.to_le_bytes());
            acl.extend_from_slice(&UNDEFINED.to_le_bytes());
        }
        acl
    }

    fn set_default_acl(path: &Path) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStrExt as _;
            let path = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            let acl = default_acl();
            // SAFETY: both strings are NUL-terminated and `acl` is valid for
            // its length for the duration of the call.
            let status = unsafe {
                libc::lsetxattr(
                    path.as_ptr(),
                    c"system.posix_acl_default".as_ptr(),
                    acl.as_ptr().cast(),
                    acl.len(),
                    0,
                )
            };
            if status != 0 {
                let error = io::Error::last_os_error();
                // A filesystem without ACLs still gets the group and the
                // set-group-ID bit; what one account creates there is then
                // readable by the others, though not writable.
                if !matches!(error.raw_os_error(), Some(libc::ENOTSUP)) {
                    return Err(error);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = path;
        Ok(())
    }

    pub(super) fn group(name: &str) -> Option<u32> {
        let name = std::ffi::CString::new(name).ok()?;
        let mut buffer = vec![0_u8; 4096];
        loop {
            // SAFETY: `group` is plain data that `getgrnam_r` fills in, and
            // zero is a valid value for every field until it does.
            let mut entry: libc::group = unsafe { std::mem::zeroed() };
            let mut found: *mut libc::group = std::ptr::null_mut();
            // SAFETY: as for `getpwnam_r` in `lookup` below.
            let status = unsafe {
                libc::getgrnam_r(
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
            return Some(entry.gr_gid);
        }
    }

    /// Whether this process's capability bounding set lacks `CAP_SYS_ADMIN`,
    /// which only a deliberately confined process -- a systemd unit with a
    /// `CapabilityBoundingSet=` -- does.
    #[cfg(target_os = "linux")]
    pub(super) fn bounding_set_is_narrowed() -> bool {
        const CAP_SYS_ADMIN: libc::c_ulong = 21;
        !in_bounding_set(CAP_SYS_ADMIN)
    }

    /// Whether this process's bounding set holds any capability at all.
    #[cfg(target_os = "linux")]
    pub(super) fn bounding_set_holds_any() -> bool {
        // CAP_LAST_CAP has grown over kernel releases; an unknown number reads
        // as an error, which `in_bounding_set` reports as absent.
        (0..64).any(in_bounding_set)
    }

    /// Whether this process may start a child as another account and hand it
    /// its directories: `CAP_CHOWN`, `CAP_SETGID` and `CAP_SETUID`.
    #[cfg(target_os = "linux")]
    pub(super) fn can_switch_account() -> bool {
        const CAP_CHOWN: libc::c_ulong = 0;
        const CAP_SETGID: libc::c_ulong = 6;
        const CAP_SETUID: libc::c_ulong = 7;
        [CAP_CHOWN, CAP_SETGID, CAP_SETUID]
            .into_iter()
            .all(in_bounding_set)
    }

    #[cfg(target_os = "linux")]
    fn in_bounding_set(capability: libc::c_ulong) -> bool {
        // SAFETY: PR_CAPBSET_READ only reads this process's bounding set.
        unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) == 1 }
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
            assert_eq!(RunnerPool::for_this_daemon(), Ok(None));
        }
    }

    #[test]
    fn pool_accounts_are_numbered_from_one_in_the_runner_group() {
        assert_eq!(pool_account_name(1), "rm-runner-1");
        assert_eq!(pool_account_name(POOL_SIZE), "rm-runner-32");
    }

    #[test]
    fn a_pool_hands_out_its_own_accounts_and_the_legacy_one_only_alone() {
        let legacy = RunnerAccount { uid: 997, gid: 972 };
        let first = RunnerAccount { uid: 990, gid: 972 };
        let mut pool = RunnerPool {
            gid: 972,
            accounts: vec![first],
            legacy: Some(legacy),
        };
        assert_eq!(pool.assignable(), [first]);
        assert_eq!(pool.account(997), Some(legacy));
        assert_eq!(pool.account(990), Some(first));
        assert_eq!(pool.account(0), None);
        pool.accounts.clear();
        assert_eq!(pool.assignable(), [legacy]);
    }

    #[cfg(unix)]
    #[test]
    fn the_default_acl_is_the_kernel_encoding_of_group_rwx() {
        assert_eq!(
            sys::default_acl(),
            [
                2, 0, 0, 0, // version
                1, 0, 7, 0, 255, 255, 255, 255, // user::rwx
                4, 0, 7, 0, 255, 255, 255, 255, // group::rwx
                32, 0, 0, 0, 255, 255, 255, 255, // other::---
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sharing_a_tree_opens_it_to_the_group_once_and_never_follows_links() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = directory.path().join("cache");
        std::fs::create_dir_all(root.join("npm/_cacache")).unwrap();
        std::fs::write(root.join("npm/_cacache/entry"), b"x").unwrap();
        std::fs::set_permissions(
            root.join("npm/_cacache/entry"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
        let gid = std::fs::metadata(&root).unwrap().gid();
        let pool = RunnerPool {
            gid,
            accounts: Vec::new(),
            legacy: None,
        };

        pool.share_tree(&root).unwrap();

        let mode = |path: &Path| std::fs::metadata(path).unwrap().mode() & 0o7777;
        assert_eq!(mode(&root.join("npm")) & 0o2070, 0o2070);
        assert_eq!(mode(&root.join("npm/_cacache/entry")), 0o660);
        assert!(pool.is_shared(&std::fs::metadata(root.join("npm")).unwrap()));
        assert_eq!(
            mode(outside.path()) & 0o2000,
            0,
            "a link's target is never touched"
        );
    }
}
