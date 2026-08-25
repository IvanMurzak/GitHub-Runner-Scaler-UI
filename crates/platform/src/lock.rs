// owner: d1-platform-core

//! The two host locks: one that keeps a second agent from reconciling the same
//! policies, and one that serialises runtime creation.
//!
//! `03-control-flows.md`, flow 3.1: *"A single-instance lock prevents two
//! agents on one host from reconciling the same policy."* Flow 2.4: the agent
//! *"takes the host-wide allocation lock before creating each local runtime"*.
//! `07-security.md`'s threat table names the single-instance lock as one of the
//! four controls on *"API replay or a duplicate agent creates too many
//! runners"*.
//!
//! # Why an operating-system file lock, and not a PID file
//!
//! The requirement that decides the mechanism is *"released on crash rather
//! than leaking"*. A PID file cannot do that: a process that is `SIGKILL`ed, or
//! whose machine loses power, leaves the file behind, and every recovery
//! strategy built on top — is that PID still alive? was it reused? — is
//! guesswork that fails exactly when it matters. An operating-system file lock
//! is released by the kernel when the holding process ends, for *any* reason,
//! with no cooperation from the process and nothing left to clean up.
//!
//! Two mechanisms, one behaviour:
//!
//! - **Windows** opens the file for read and write while sharing only read
//!   access. A second acquirer asks for write access as well, which the
//!   holder's share mode denies, and gets `ERROR_SHARING_VIOLATION`. A
//!   *reader* asks only for read access, which the share mode permits — which
//!   is what lets the loser find out who beat it.
//! - **Unix** takes `flock(LOCK_EX | LOCK_NB)`. `flock` is advisory and does
//!   not stand in the way of an ordinary `open` for reading, so the loser can
//!   read the holder record there too. Locks are held per open file
//!   description, so a second acquisition from the *same* process is refused as
//!   firmly as one from another process.
//!
//! # The lock file is never deleted
//!
//! Not on release, not on a clean shutdown, not by `Drop`. On Unix a lock is a
//! property of the inode, so a holder that unlinks the file lets the next
//! acquirer create and lock a *different* inode — after which two processes
//! each hold "the lock" and neither can see the other. Leaving a zero-cost
//! empty file behind is the whole price of not having that bug.
//!
//! # What "host-wide" means, precisely
//!
//! The lock is a file under [`crate::paths::AppPaths::state_dir`], as
//! `05-infrastructure.md` specifies (*"state/ agent lock"*). Two agents
//! contend if and only if they resolve the same state directory — which is what
//! makes the lock host-wide for every configuration this product supports, and
//! is worth stating rather than assuming: the platform-standard state directory
//! is per-account on all three operating systems, so a daemon running as a
//! service account and an interactive `daemon run` by a logged-in operator
//! resolve *different* paths and would not contend. That is why
//! `05-infrastructure.md` requires `service install` to record its resolved
//! configuration and why `service status` reports it. A future host-wide
//! machine lock (`%ProgramData%`, `/var/lock`) would need the installer to
//! create it with the right ownership, which is `d3`'s territory, not this
//! module's.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::paths::AppPaths;
use crate::process::{Adoption, ProcessIdentity};

/// Which of the two host locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockKind {
    /// Held for the whole life of the agent process. One holder per host means
    /// one reconciler per host.
    SingleInstance,
    /// Held only while one runtime is being created, so that two concurrent
    /// allocations cannot both read the same headroom and both use it.
    Allocation,
}

impl LockKind {
    /// The file this lock lives in, inside `state/`.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::SingleInstance => "agent.lock",
            Self::Allocation => "allocation.lock",
        }
    }

    /// How to name this lock to an operator.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::SingleInstance => "the single-instance agent lock",
            Self::Allocation => "the runtime allocation lock",
        }
    }

    /// What an operator who lost the race should do about it. Present because
    /// "the lock is held" is a statement and not yet an instruction.
    #[must_use]
    pub const fn advice(self) -> &'static str {
        match self {
            Self::SingleInstance => {
                "Only one agent may reconcile policies on a host. Stop the other agent, or wait \
                 for it to exit; the operating system releases this lock when that process ends, \
                 including after a crash, so there is never anything to clean up by hand."
            }
            Self::Allocation => {
                "This lock is held only for as long as it takes to create one runtime. Retry \
                 shortly."
            }
        }
    }
}

impl fmt::Display for LockKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

/// Who holds a lock, as recorded by the holder itself.
///
/// Written into the lock file after the lock is taken, so that the process
/// that loses the race can say something useful instead of "somebody else".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockHolder {
    /// The holder's process identity — a PID alone would not survive being
    /// read back by a process that started after a reboot.
    pub identity: ProcessIdentity,
    /// The holder's executable, when it could be resolved. `05-infrastructure.md`
    /// requires `service status` to report a stale or moved binary path, and
    /// an operator looking at a contended lock has the same question.
    pub executable: Option<PathBuf>,
    /// When the lock was taken.
    pub acquired_at: DateTime<Utc>,
    /// Which lock the record belongs to. Recorded so that a file opened by
    /// mistake is recognised rather than misreported.
    pub lock: LockKind,
}

impl fmt::Display for LockHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "process {}", self.identity.pid())?;
        if let Some(executable) = &self.executable {
            write!(f, " ({})", executable.display())?;
        }
        write!(f, ", holding since {}", self.acquired_at.to_rfc3339())
    }
}

/// Something went wrong taking or inspecting a lock.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Somebody else has it.
    #[error(
        "{kind} ({}) is already held on this host by {}. {}",
        path.display(),
        describe(holder),
        kind.advice()
    )]
    Held {
        /// Which lock.
        kind: LockKind,
        /// Where the lock file is, so the message is actionable on a host with
        /// a non-default layout.
        path: PathBuf,
        /// Who holds it, when the record could be read. `None` is not the same
        /// as "nobody": it means the holder had not finished identifying
        /// itself, which is a race of microseconds and not a reason to proceed.
        holder: Option<LockHolder>,
    },

    /// The lock file could not be opened, read, or written.
    #[error("cannot use the lock file {}: {source}", path.display())]
    Io {
        /// The lock file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The holder's own identity could not be read, so it could not record who
    /// it is.
    #[error("cannot record this process as the holder of {kind}: {source}")]
    Identity {
        /// Which lock.
        kind: LockKind,
        /// The underlying error.
        #[source]
        source: crate::process::ProcessError,
    },
}

/// Renders the holder half of a [`LockError::Held`] message.
fn describe(holder: &Option<LockHolder>) -> String {
    match holder {
        Some(holder) => holder.to_string(),
        None => "a process that has not finished identifying itself".to_string(),
    }
}

/// A held lock. Releasing it is dropping it.
///
/// There is no `release()` returning a `Result`, deliberately: releasing is
/// closing a file descriptor, the kernel does it whether this program asks or
/// not, and an API that suggested release could fail would invite a caller to
/// handle a failure that does not exist.
#[derive(Debug)]
pub struct HostLock {
    /// Held open for the lock's whole life. Closing it *is* the release, which
    /// is why this field exists even though nothing reads it after
    /// acquisition.
    file: File,
    path: PathBuf,
    kind: LockKind,
}

impl HostLock {
    /// Takes the lock, or reports who has it, without waiting.
    ///
    /// # Errors
    ///
    /// [`LockError::Held`] when another process has it, [`LockError::Io`] when
    /// the lock file cannot be opened, and [`LockError::Identity`] when this
    /// process cannot describe itself.
    pub fn try_acquire(paths: &AppPaths, kind: LockKind) -> Result<Self, LockError> {
        Self::try_acquire_at(&paths.state_dir().join(kind.file_name()), kind)
    }

    /// Takes the lock, retrying until `wait` elapses.
    ///
    /// `e1` takes the allocation lock before each runtime it creates, and brief
    /// contention there is expected rather than exceptional, so waiting a
    /// little is the right default for that caller. The single-instance lock
    /// should normally use [`HostLock::try_acquire`]: a second agent is a
    /// configuration problem, and waiting for it makes the problem quieter
    /// rather than fixing it.
    ///
    /// # This blocks the calling thread
    ///
    /// The retry loop is `std::thread::sleep`, not a timer an executor can
    /// park. `e1` takes the allocation lock from inside async reconciliation,
    /// and calling this directly from a `tokio` task blocks a worker thread for
    /// up to `wait` — starving every other task scheduled on it, and with a
    /// current-thread runtime deadlocking against the very task that would
    /// release the lock. **Async callers must wrap it in
    /// [`tokio::task::spawn_blocking`]**, which is also where the returned
    /// [`HostLock`] should then live, since dropping it is the release.
    ///
    /// [`HostLock::try_acquire`] does not block and is safe to call inline.
    ///
    /// # Errors
    ///
    /// As [`HostLock::try_acquire`], reporting the last holder seen.
    pub fn acquire(paths: &AppPaths, kind: LockKind, wait: Duration) -> Result<Self, LockError> {
        Self::acquire_at(&paths.state_dir().join(kind.file_name()), kind, wait)
    }

    /// [`HostLock::try_acquire`] against an explicit path.
    ///
    /// # Errors
    ///
    /// As [`HostLock::try_acquire`].
    pub fn try_acquire_at(path: &Path, kind: LockKind) -> Result<Self, LockError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| LockError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }

        // Best effort in both contention branches below: an unreadable or
        // half-written record makes the message vaguer, and is never a reason
        // to behave as if the lock were free.
        let held = |path: &Path| LockError::Held {
            kind,
            path: path.to_path_buf(),
            holder: read_holder(path).ok().flatten(),
        };

        let file = match open_for_locking(path) {
            Ok(file) => file,
            // Windows excludes at the open itself, through the share mode, so
            // this is where contention surfaces there. On Unix nothing fails
            // the open for contention and this arm never fires.
            Err(source) if sys::is_contention(&source) => return Err(held(path)),
            Err(source) => return Err(io_error(path, source)),
        };

        if !sys::try_lock(&file).map_err(|source| io_error(path, source))? {
            return Err(held(path));
        }

        let lock = Self {
            file,
            path: path.to_path_buf(),
            kind,
        };
        lock.record_holder()?;
        Ok(lock)
    }

    /// [`HostLock::acquire`] against an explicit path.
    ///
    /// # Errors
    ///
    /// As [`HostLock::try_acquire`].
    pub fn acquire_at(path: &Path, kind: LockKind, wait: Duration) -> Result<Self, LockError> {
        let deadline = Instant::now() + wait;
        loop {
            match Self::try_acquire_at(path, kind) {
                Ok(lock) => return Ok(lock),
                Err(error @ LockError::Held { .. }) => {
                    if Instant::now() >= deadline {
                        return Err(error);
                    }
                    std::thread::sleep(RETRY_INTERVAL);
                }
                Err(other) => return Err(other),
            }
        }
    }

    /// Reads the holder record of a lock without trying to take it.
    ///
    /// Answers `Ok(None)` when the file does not exist or carries no readable
    /// record. It deliberately says nothing about whether the lock is *held*:
    /// the record outlives its writer by design, and the only authority on
    /// whether a lock is free is trying to take it.
    ///
    /// # Errors
    ///
    /// [`LockError::Io`] when the file exists but cannot be read.
    pub fn holder_of(path: &Path) -> Result<Option<LockHolder>, LockError> {
        read_holder(path)
    }

    /// Where the lock file is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Which lock this is.
    #[must_use]
    pub const fn kind(&self) -> LockKind {
        self.kind
    }

    /// Whether the recorded holder of `path` is still running.
    ///
    /// For diagnostics — `host show` reporting a lock whose record names a
    /// process that no longer exists tells an operator something a bare
    /// "locked/unlocked" does not.
    ///
    /// # Errors
    ///
    /// [`LockError::Io`] when the record cannot be read.
    pub fn recorded_holder_is_live(path: &Path) -> Result<bool, LockError> {
        let Some(holder) = read_holder(path)? else {
            return Ok(false);
        };
        Ok(matches!(holder.identity.recheck(), Ok(Adoption::Live)))
    }

    /// Writes this process's identity into the lock file.
    ///
    /// Runs *after* the lock is taken, which leaves a window of a few
    /// microseconds in which a loser sees the previous holder's record or none
    /// at all. That is why [`LockError::Held`] carries an `Option` and why the
    /// message for `None` says the holder has not identified itself yet, rather
    /// than implying the lock might be free.
    fn record_holder(&self) -> Result<(), LockError> {
        let holder = LockHolder {
            identity: ProcessIdentity::of_current_process().map_err(|source| {
                LockError::Identity {
                    kind: self.kind,
                    source,
                }
            })?,
            executable: std::env::current_exe().ok(),
            acquired_at: Utc::now(),
            lock: self.kind,
        };

        let encoded = serde_json::to_vec_pretty(&holder).map_err(|source| {
            io_error(
                &self.path,
                std::io::Error::new(std::io::ErrorKind::InvalidData, source),
            )
        })?;

        let mut file = &self.file;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| io_error(&self.path, source))?;
        // The previous holder's record is longer or shorter than this one; a
        // write without a truncate would leave its tail behind and produce
        // unparseable JSON for the next reader.
        file.set_len(0)
            .map_err(|source| io_error(&self.path, source))?;
        file.write_all(&encoded)
            .map_err(|source| io_error(&self.path, source))?;
        file.flush()
            .map_err(|source| io_error(&self.path, source))?;
        // Durable before the caller does anything with the lock: a record that
        // is only in the page cache is not there for the operator diagnosing
        // the machine that just stopped responding.
        file.sync_all()
            .map_err(|source| io_error(&self.path, source))
    }
}

fn io_error(path: &Path, source: std::io::Error) -> LockError {
    LockError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// How often [`HostLock::acquire_at`] retries. Short enough that an allocation
/// waiting on the lock is not noticeably delayed.
const RETRY_INTERVAL: Duration = Duration::from_millis(25);

fn open_for_locking(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    // `truncate(false)` is explicit rather than implied: the previous holder's
    // record must survive the open, because it is what a *loser* reads, and the
    // loser's open is this same call.
    options.read(true).write(true).create(true).truncate(false);
    sys::prepare_for_locking(&mut options);
    options.open(path)
}

fn read_holder(path: &Path) -> Result<Option<LockHolder>, LockError> {
    let mut options = OpenOptions::new();
    options.read(true);
    sys::prepare_for_reading(&mut options);

    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error(path, source)),
    };

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|source| io_error(path, source))?;

    // An empty or half-written file is the acquisition race described on
    // `HostLock::record_holder`, not a corrupt installation. Say "no record"
    // and let the caller's message be vaguer.
    Ok(serde_json::from_str(&contents).ok())
}

// ---------------------------------------------------------------------------
// Platform implementations
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod sys {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;

    use windows::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    /// The acquisition open. Sharing *read* only: a second acquirer also asks
    /// for write access, which this share mode denies, so `CreateFile` fails
    /// with `ERROR_SHARING_VIOLATION` before any lock call is needed. The
    /// exclusion is the open itself, which is why `try_lock` below has nothing
    /// left to do.
    pub(super) fn prepare_for_locking(options: &mut OpenOptions) {
        options.share_mode(FILE_SHARE_READ.0);
    }

    /// The diagnostic open. Read access only, and permissive sharing, so that
    /// it is compatible with the holder's open in both directions: the holder
    /// permits readers, and this permits the holder's read/write access.
    pub(super) fn prepare_for_reading(options: &mut OpenOptions) {
        options.share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);
    }

    /// Always `true` on Windows: if the open in `open_for_locking` succeeded,
    /// this process is the exclusive writer, and when the process ends — for
    /// any reason, including a crash — the kernel closes the handle and the
    /// next acquirer's open succeeds.
    pub(super) fn try_lock(_file: &File) -> io::Result<bool> {
        Ok(true)
    }

    /// Windows reports a share-mode conflict as `ERROR_SHARING_VIOLATION`, and
    /// `std` maps it to a generic error, so the raw code is what identifies it.
    pub(super) const SHARING_VIOLATION: i32 =
        windows::Win32::Foundation::ERROR_SHARING_VIOLATION.0 as i32;

    /// Whether an open failure means "somebody else holds it" rather than
    /// something an operator should investigate.
    pub(super) fn is_contention(error: &io::Error) -> bool {
        error.raw_os_error() == Some(SHARING_VIOLATION)
    }
}

#[cfg(unix)]
mod sys {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::unix::io::AsRawFd;

    /// Nothing to prepare: on Unix the open is ordinary and the exclusion comes
    /// from `flock` below.
    pub(super) fn prepare_for_locking(_options: &mut OpenOptions) {}

    pub(super) fn prepare_for_reading(_options: &mut OpenOptions) {}

    /// `flock(LOCK_EX | LOCK_NB)`.
    ///
    /// Chosen over `fcntl` record locks for one reason that matters here:
    /// `fcntl` locks are dropped when *any* file descriptor for the file is
    /// closed by the process, so an unrelated `read_holder` in the same process
    /// would silently release the agent's lock. `flock` locks belong to the
    /// open file description and are immune to that.
    pub(super) fn try_lock(file: &File) -> io::Result<bool> {
        // SAFETY: `flock` takes a file descriptor and a flag word and touches
        // no memory this program owns. The descriptor is valid for the life of
        // `file`, which outlives the call.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if is_contention(&error) {
            return Ok(false);
        }
        Err(error)
    }

    /// `EWOULDBLOCK` — and `EAGAIN`, which is the same number on Linux and
    /// macOS but is written both ways in the documentation.
    pub(super) fn is_contention(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::process::{OutputMode, SpawnSpec};

    /// The environment variable that turns `lock_holder_helper` below from a
    /// no-op into a process that takes a lock and holds it until it is killed.
    const HELPER_PATH: &str = "RUNNER_MANAGER_LOCK_HELPER_PATH";
    /// What the helper prints once it holds the lock.
    ///
    /// Searched for *within* a line rather than at the start of one, because
    /// libtest writes `test <name> ... ` with no trailing newline before the
    /// test body runs — so the helper's first line of output is that prefix
    /// followed by this marker, not the marker alone.
    const HELPER_READY: &str = "@@LOCK-HELD@@";

    fn lock_path(directory: &tempfile::TempDir, kind: LockKind) -> PathBuf {
        directory.path().join(kind.file_name())
    }

    /// Takes the lock twice with `acquire` and reports whether exactly one
    /// acquisition won.
    ///
    /// A helper returning `Result` rather than inline assertions, so that
    /// `the_contention_check_catches_a_lock_that_never_excludes` can point it
    /// at a lock that excludes nothing. A mutual-exclusion test that has only
    /// ever been run against a working lock cannot distinguish "the lock works"
    /// from "the test asserts nothing".
    fn check_mutual_exclusion<G>(acquire: impl Fn() -> Result<G, LockError>) -> Result<(), String> {
        let first = acquire().map_err(|error| format!("the first acquisition failed: {error}"))?;

        let outcome = match acquire() {
            Ok(_) => Err("both acquisitions succeeded; nothing is being excluded".to_string()),
            Err(LockError::Held { .. }) => Ok(()),
            Err(other) => Err(format!(
                "the second acquisition failed, but not because the lock was held: {other}"
            )),
        };

        drop(first);
        outcome
    }

    #[test]
    fn two_contenders_produce_exactly_one_holder() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = lock_path(&directory, LockKind::SingleInstance);

        check_mutual_exclusion(|| HostLock::try_acquire_at(&path, LockKind::SingleInstance))
            .expect("the single-instance lock must admit exactly one holder");
    }

    #[test]
    fn the_contention_check_catches_a_lock_that_never_excludes() {
        let complaint = check_mutual_exclusion(|| Ok::<(), LockError>(()))
            .expect_err("a lock that excludes nothing must be caught");
        assert!(
            complaint.contains("nothing is being excluded"),
            "the complaint must name the failure mode, got: {complaint}"
        );
    }

    #[test]
    fn releasing_the_lock_lets_the_next_contender_take_it() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = lock_path(&directory, LockKind::SingleInstance);

        let first = HostLock::try_acquire_at(&path, LockKind::SingleInstance).expect("acquired");
        assert!(HostLock::try_acquire_at(&path, LockKind::SingleInstance).is_err());
        drop(first);

        let second = HostLock::try_acquire_at(&path, LockKind::SingleInstance)
            .expect("the lock must be free once the holder drops it");
        assert_eq!(second.path(), path);
        assert_eq!(second.kind(), LockKind::SingleInstance);
    }

    #[test]
    fn the_two_locks_do_not_contend_with_each_other() {
        // `e1` takes the allocation lock while the agent already holds the
        // single-instance lock. If those two shared a file, the agent would
        // deadlock against itself on the first runtime it tried to create.
        let directory = tempfile::tempdir().expect("a temporary directory");

        let instance = HostLock::try_acquire_at(
            &lock_path(&directory, LockKind::SingleInstance),
            LockKind::SingleInstance,
        )
        .expect("the instance lock is free");

        let allocation = HostLock::try_acquire_at(
            &lock_path(&directory, LockKind::Allocation),
            LockKind::Allocation,
        )
        .expect("the allocation lock is a different lock and must be free");

        assert_ne!(instance.path(), allocation.path());
        assert_ne!(
            LockKind::SingleInstance.file_name(),
            LockKind::Allocation.file_name()
        );
    }

    #[test]
    fn the_loser_gets_a_message_naming_the_holder_and_saying_what_to_do() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = lock_path(&directory, LockKind::SingleInstance);

        let _held = HostLock::try_acquire_at(&path, LockKind::SingleInstance).expect("acquired");
        let error = HostLock::try_acquire_at(&path, LockKind::SingleInstance)
            .expect_err("the second acquisition must fail");

        let LockError::Held { holder, kind, .. } = &error else {
            panic!("expected a contention error, got {error}");
        };
        assert_eq!(*kind, LockKind::SingleInstance);

        let holder = holder.as_ref().expect("the holder recorded itself");
        assert_eq!(holder.identity.pid(), std::process::id());
        assert_eq!(holder.lock, LockKind::SingleInstance);
        assert_eq!(
            holder.executable.as_deref(),
            std::env::current_exe().ok().as_deref()
        );

        let message = error.to_string();
        assert!(
            message.contains(&std::process::id().to_string()),
            "the message must name the holding process: {message}"
        );
        assert!(
            message.contains("Stop the other agent"),
            "the message must say what to do, not only what happened: {message}"
        );
    }

    #[test]
    fn the_recorded_holder_survives_a_read_by_a_second_process_shape() {
        // Reading the record must work while the lock is held — on Windows that
        // is a share-mode question and it is easy to get wrong in a way that
        // only shows up when it matters, because the only caller is the loser.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = lock_path(&directory, LockKind::SingleInstance);

        let _held = HostLock::try_acquire_at(&path, LockKind::SingleInstance).expect("acquired");

        let holder = HostLock::holder_of(&path)
            .expect("the record must be readable while the lock is held")
            .expect("a record must be there");
        assert_eq!(holder.identity.pid(), std::process::id());
        assert!(HostLock::recorded_holder_is_live(&path).expect("readable"));
    }

    #[test]
    fn a_stale_record_is_reported_as_not_live() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = lock_path(&directory, LockKind::SingleInstance);

        // A record naming a process that has come and gone: exactly what a
        // crashed holder leaves behind.
        //
        // THE CHILD HAS TO OUTLIVE ITS OWN IDENTITY LOOKUP.
        //
        // `SpawnSpec::spawn` reads `ProcessIdentity::of_child` immediately after
        // starting the process, because the start token is what stops a reused
        // pid from being mistaken for the original. A child that exits INSTANTLY
        // -- `true` did -- can be gone before that read, and the spawn then
        // fails with `NoSuchProcess` rather than yielding the identity this test
        // needs. It blocked release 0.1.5 on the macOS leg, where a loaded
        // runner made the race easy to lose.
        //
        // So the child sleeps briefly: long enough to be observed, short enough
        // that waiting for it costs nothing. What is being tested is unchanged
        // -- the record is stale by the time it is read, because `wait` below
        // returns only after the process is gone.
        let mut child = SpawnSpec::new(if cfg!(windows) { "cmd" } else { "sh" })
            .args(if cfg!(windows) {
                vec!["/C", "exit", "0"]
            } else {
                vec!["-c", "sleep 0.3"]
            })
            .spawn()
            .expect("the child starts");
        let identity = child.identity().clone();
        child.wait().expect("the child exits");

        let stale = LockHolder {
            identity,
            executable: None,
            acquired_at: Utc::now(),
            lock: LockKind::SingleInstance,
        };
        std::fs::write(&path, serde_json::to_vec(&stale).expect("serialisable")).expect("writable");

        assert!(
            !HostLock::recorded_holder_is_live(&path).expect("readable"),
            "a record naming a dead process must not be reported as live"
        );
        // And the lock itself is free, because nothing holds the file.
        HostLock::try_acquire_at(&path, LockKind::SingleInstance)
            .expect("a stale record must not keep the lock held");
    }

    #[test]
    fn an_unidentified_holder_still_reads_as_a_holder() {
        // The microsecond between taking the lock and writing the record. The
        // message gets vaguer; the exclusion does not, and the wording must not
        // leave a reader thinking the lock might be free.
        let no_record = describe(&None);
        assert!(
            no_record.contains("not finished identifying itself"),
            "an unidentified holder must still read as a holder: {no_record}"
        );

        let error = LockError::Held {
            kind: LockKind::SingleInstance,
            path: PathBuf::from("/var/lib/runner-manager/state/agent.lock"),
            holder: None,
        };
        let message = error.to_string();
        assert!(message.contains("already held"), "{message}");
        assert!(message.contains("agent.lock"), "{message}");
        assert!(message.contains("Stop the other agent"), "{message}");
    }

    #[test]
    fn acquire_waits_and_then_reports_the_holder() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = lock_path(&directory, LockKind::Allocation);

        let _held = HostLock::try_acquire_at(&path, LockKind::Allocation).expect("acquired");

        let wait = Duration::from_millis(200);
        let started = Instant::now();
        let error = HostLock::acquire_at(&path, LockKind::Allocation, wait)
            .expect_err("the lock is held for the whole window");
        let elapsed = started.elapsed();

        assert!(matches!(error, LockError::Held { .. }), "{error}");
        assert!(
            elapsed >= wait,
            "acquire must actually wait; it returned after {elapsed:?} of a {wait:?} window"
        );
    }

    #[test]
    fn acquire_returns_immediately_when_the_lock_is_free() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = lock_path(&directory, LockKind::Allocation);

        let started = Instant::now();
        let lock = HostLock::acquire_at(&path, LockKind::Allocation, Duration::from_secs(30))
            .expect("the lock is free");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a free lock must not be waited for"
        );
        drop(lock);
    }

    #[test]
    fn try_acquire_uses_the_state_directory() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(root.path());

        let lock = HostLock::try_acquire(&paths, LockKind::SingleInstance).expect("acquired");
        assert_eq!(lock.path(), paths.state_dir().join("agent.lock"));
        assert!(
            lock.path().exists(),
            "the lock file must have been created under state/, as 05-infrastructure.md says"
        );
    }

    // -----------------------------------------------------------------------
    // The cross-process half of the Definition of Done
    // -----------------------------------------------------------------------

    /// Runs as an ordinary no-op test, unless `RUNNER_MANAGER_LOCK_HELPER_PATH`
    /// is set — in which case this process *is* the second contender: it takes
    /// the lock named by that variable, announces that it has it, and then
    /// waits to be killed.
    ///
    /// Re-executing the test binary is what makes a genuinely separate process
    /// available without shipping a second binary. The two tests below drive
    /// it.
    #[test]
    fn lock_holder_helper() {
        let Some(path) = std::env::var_os(HELPER_PATH) else {
            return;
        };

        let _lock = HostLock::try_acquire_at(Path::new(&path), LockKind::SingleInstance)
            .expect("the helper must be able to take the lock");

        println!("{HELPER_READY} {}", std::process::id());
        let _ = std::io::stdout().flush();

        // Long enough that the parent always kills it first, short enough that
        // a parent which somehow died leaves nothing behind for long.
        std::thread::sleep(Duration::from_secs(120));
    }

    /// Starts the helper and waits until it reports that it holds the lock.
    fn start_helper(path: &Path) -> (crate::process::ChildProcess, u32) {
        let executable = std::env::current_exe().expect("the test binary's own path");

        let mut child = SpawnSpec::new(executable)
            .args([
                "--exact",
                "lock::tests::lock_holder_helper",
                // Without this, libtest swallows the helper's announcement and
                // the parent waits forever for a line that was captured.
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HELPER_PATH, path)
            .output(OutputMode::Capture)
            .spawn()
            .expect("the helper process starts");

        let stdout = child.take_stdout().expect("captured");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some((_, rest)) = line.split_once(HELPER_READY) {
                    let _ = sender.send(rest.trim().to_string());
                    return;
                }
            }
            let _ = sender.send(String::new());
        });

        let announced = receiver
            .recv_timeout(Duration::from_secs(60))
            .expect("the helper must announce that it holds the lock");
        let pid: u32 = announced
            .parse()
            .unwrap_or_else(|_| panic!("the helper announced {announced:?} instead of a PID"));

        (child, pid)
    }

    #[test]
    fn two_processes_contending_produce_exactly_one_holder() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = lock_path(&directory, LockKind::SingleInstance);

        let (mut helper, helper_pid) = start_helper(&path);
        assert_ne!(helper_pid, std::process::id());

        let error = HostLock::try_acquire_at(&path, LockKind::SingleInstance)
            .expect_err("a second agent must not get the lock");

        let LockError::Held { holder, .. } = &error else {
            panic!("expected a contention error, got {error}");
        };
        let holder = holder.as_ref().expect("the helper recorded itself");
        assert_eq!(
            holder.identity.pid(),
            helper_pid,
            "the record must name the process that actually holds it"
        );
        assert!(
            error.to_string().contains(&helper_pid.to_string()),
            "the loser's message must name the holder: {error}"
        );

        helper.stop(Duration::ZERO).expect("cleanup");
    }

    #[test]
    fn killing_the_holder_releases_the_lock_with_no_manual_cleanup() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = lock_path(&directory, LockKind::SingleInstance);

        let (mut helper, helper_pid) = start_helper(&path);
        assert!(
            HostLock::try_acquire_at(&path, LockKind::SingleInstance).is_err(),
            "the helper holds it"
        );

        // `Duration::ZERO` leaves the helper no grace period. On Windows that
        // is literally straight to `TerminateProcess`, because there is no
        // signal to send; on Unix a SIGTERM is still sent first, but the grace
        // period it is given is zero, so SIGKILL follows before the helper can
        // act on it. Either way no destructor and no cleanup code runs, which
        // is the point: this is a crash, not a shutdown.
        helper.stop(Duration::ZERO).expect("the helper is killed");
        assert!(!helper.is_running().expect("observable"));

        // Nothing is deleted, nothing is reset, no PID file is reaped: the next
        // acquisition simply succeeds.
        let recovered = HostLock::try_acquire_at(&path, LockKind::SingleInstance)
            .unwrap_or_else(|error| panic!("the lock leaked after its holder was killed: {error}"));

        assert!(
            path.exists(),
            "the lock file itself must survive; deleting it is how two processes end up \
             locking different inodes"
        );

        let holder = HostLock::holder_of(&path)
            .expect("readable")
            .expect("the new holder recorded itself");
        assert_eq!(holder.identity.pid(), std::process::id());
        assert_ne!(
            holder.identity.pid(),
            helper_pid,
            "the record must have been replaced, not inherited"
        );
        drop(recovered);
    }
}
