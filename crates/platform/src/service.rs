// owner: d3-service-installers

//! Registering `daemon run` with the operating system, so that a home host
//! resumes work by itself after a reboot with nobody logged in.
//!
//! Journey 5 is the whole of the requirement: *"the machine reboots with nobody
//! logged in; the boot-start service starts the agent, which reads the user
//! access token from the machine-scoped secret store"*. Everything in this file
//! exists to make that sentence true on Windows, macOS, and Linux, and to make
//! `service status` say so — or say precisely why not.
//!
//! # The shape: render, then apply
//!
//! A service manager is the one dependency a `cargo test` run cannot have. So
//! this module is split in two, and the split is the reason most of it is
//! testable on a developer's laptop whatever OS that laptop runs:
//!
//! * **Rendering** is pure. [`ServiceDefinition`] turns an [`InstallPlan`] into
//!   the exact text the platform consumes — a systemd unit, a launchd property
//!   list, a Task Scheduler XML document, or a canonical descriptor of the
//!   Windows service parameters. No `cfg`, no privileges, no I/O. A Windows
//!   developer renders and asserts the systemd unit; a Linux CI leg renders and
//!   asserts the launchd plist.
//! * **Applying** is behind [`ServiceControl`], one trait with a backend per
//!   platform and a public in-memory double ([`RecordingControls`]) that `f3`
//!   and this crate's own tests drive without touching the host.
//!
//! [`ServiceOperations`] is the layer above both, and it is where the logic
//! that is *not* platform-specific lives: refusing an install while the
//! single-instance lock is held, recording the resolved absolute binary path,
//! detecting a stale one, switching start mode without reinstalling, and
//! uninstalling without deleting a byte of configuration, secrets, or cache.
//!
//! # Two domains, not two products
//!
//! `--start-at boot` and `--start-at login` are the same daemon registered in
//! two different *domains*:
//!
//! | | boot | login |
//! |---|---|---|
//! | Windows | a service in the Service Control Manager, `LocalSystem` | a Task Scheduler task with a logon trigger, running at `LeastPrivilege` |
//! | macOS | a LaunchDaemon in `/Library/LaunchDaemons` | a LaunchAgent in `~/Library/LaunchAgents` |
//! | Linux | a system unit in `/etc/systemd/system` | a user unit in `~/.config/systemd/user` |
//!
//! The Windows row is the one that is not symmetric, and it is worth saying why
//! rather than leaving a reader to wonder. **Windows services cannot start at
//! logon.** Service trigger-start covers domain join, an IP address becoming
//! available, a device arriving, a firewall port event and a group-policy
//! change; there is no logon trigger, and there is no user-session service
//! type this product could use instead. Task Scheduler is the mechanism Windows
//! actually provides for "run this when the operator signs in", so that is what
//! `--start-at login` uses there. It is registered, inspected, and removed
//! through the same [`ServiceControl`] trait as everything else, so nothing
//! above this module has to know.
//!
//! # What the account can reach, and why it is not more
//!
//! `05-infrastructure.md` requires *"a least-privilege account that can read the
//! machine-scoped secret store and write its configured cache and runtime
//! directories"*. Those two clauses pull in opposite directions on every
//! platform, and the resolution is recorded per platform in
//! `docs/service-account.md` and checked by [`review_least_privilege`], which
//! reads the rendered definition back and reports anything it grants beyond the
//! requirement.
//!
//! The Windows resolution is the one that surprises people. `d2` protects the
//! machine-scoped store with `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)` and
//! documents that the DACL *is* the access control, because a machine-scope
//! DPAPI blob is decryptable by any process on the host. `NT AUTHORITY\
//! LocalService` and `NT AUTHORITY\NetworkService` — the two accounts a
//! "least privilege service" reflex reaches for — are named by none of those
//! three ACEs and therefore **cannot read the token at all**. Widening the DACL
//! to reach them would grant every service on the host read access to the one
//! credential this product holds, which is strictly worse than running as
//! `LocalSystem`. `secrets.rs` is not this task's file and is not widened; the
//! service runs as `LocalSystem`, and [`review_least_privilege`] records the
//! account together with the reason it is the minimum that satisfies the
//! requirement rather than pretending it is small.
//!
//! # What is deliberately not claimed
//!
//! **A reboot is not something a test suite can have.** Every assertion here is
//! about configuration a boot-time start depends on — the start type, the
//! account, the recorded absolute path, the restart policy the service manager
//! reports back — and about a store that is readable outside any login session,
//! which `d2` proves separately. That the machine actually comes back up and
//! the agent actually resumes is human gate 3 in `06-migration-rollout.md`, and
//! nothing in this file is evidence for it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use runner_manager_domain::model::StartMode;
use runner_manager_domain::path::LocalAbsolutePath;
use serde::{Deserialize, Serialize};

use crate::lock::{HostLock, LockError, LockKind};
use crate::paths::AppPaths;
#[cfg(windows)]
use crate::runner_root_access::RootAdmission;
use crate::runner_root_access::{
    Reversal, RootAccessChange, RootAccessError, RootAccessReport, RootAccessSummary,
};

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// The product's own service name, on every platform that wants a short one.
pub const SERVICE_NAME: &str = "runner-manager";
/// Hidden CLI marker carried only by Windows boot-service registrations.
///
/// Application-data arguments are shared by every service manager and cannot
/// distinguish SCM from Task Scheduler. This marker is the durable routing
/// contract between the Windows installer and the shipping binary.
pub const WINDOWS_SCM_HOST_ARGUMENT: &str = "--windows-service-host";

/// What an operator sees in `services.msc`, `launchctl list`, or
/// `systemctl status`.
pub const DISPLAY_NAME: &str = "GitHub Actions Runner Manager";

/// One line of explanation, for the same three places.
pub const DESCRIPTION: &str =
    "Starts ephemeral GitHub Actions self-hosted runners on this machine on demand.";

/// The arguments the installed command line carries.
///
/// `05-infrastructure.md`: *"`service install` registers `daemon run` for the
/// current host"*. Spelled once, here, so the installer and `f3`'s command
/// surface cannot disagree about what was registered.
pub const DAEMON_ARGUMENTS: [&str; 2] = ["daemon", "run"];

/// The file `install` writes and `status` reads, inside `config/`.
///
/// `config/` and not `state/`: `05-infrastructure.md` gives `config/` to
/// *"non-secret TOML"*, and this is exactly that — a record of what was
/// registered, holding no credential. It is also the one file `uninstall`
/// removes, which is what keeps "uninstall deletes no configuration" honest:
/// the record is not configuration, it is the registration's own footprint.
pub const RECORD_FILE: &str = "service.toml";

/// The file the daemon touches after every successful GitHub call, inside
/// `state/`.
///
/// See [`record_github_contact`] for the contract; `service status` reads it
/// and Journey 5 step 4 requires it.
pub const CONTACT_FILE: &str = "github-contact.toml";

/// The rotating diagnostic log [`crate::logging::install`] writes, inside
/// `logs/`.
///
/// `tracing_appender::rolling::daily` appends its own date suffix, so this is
/// the stem rather than a file that exists. `service status` reports the
/// directory and the stem, because that is what an operator needs in order to
/// find today's file and yesterday's.
pub const LOG_FILE_STEM: &str = "runner-manager.log";

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// What the operating system calls this registration.
///
/// A type rather than three constants, for one reason that is not tidiness: the
/// privileged installer tests register a **real** service on a **real** machine,
/// and they must not be able to collide with — or remove — an operator's
/// installation. [`ServiceIdentity::fixture`] produces a name that is
/// unmistakably a test artefact, and every backend takes its name from here, so
/// there is no path by which a test reaches the product's own registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIdentity {
    name: String,
    display_name: String,
    description: String,
}

impl ServiceIdentity {
    /// The registration an operator installs.
    #[must_use]
    pub fn product() -> Self {
        Self {
            name: SERVICE_NAME.to_string(),
            display_name: DISPLAY_NAME.to_string(),
            description: DESCRIPTION.to_string(),
        }
    }

    /// A disposable registration for a privileged test, named so that it cannot
    /// be mistaken for — or collide with — [`ServiceIdentity::product`].
    ///
    /// `tag` distinguishes concurrent runs; it is reduced to ASCII alphanumerics
    /// and `-` so that it is a legal service name, launchd label, systemd unit
    /// name, and Task Scheduler task name at once.
    #[must_use]
    pub fn fixture(tag: &str) -> Self {
        let tag: String = tag
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        let name = format!("{SERVICE_NAME}-selftest-{tag}");
        Self {
            display_name: format!("{DISPLAY_NAME} (self-test fixture {tag})"),
            description: "Disposable fixture created by runner-manager's own installer tests. \
                          Safe to remove."
                .to_string(),
            name,
        }
    }

    /// Whether this identity is a disposable test fixture.
    ///
    /// The privileged tests assert this before they delete anything, which is
    /// the mechanical half of *"never touch a service you did not create"*.
    #[must_use]
    pub fn is_fixture(&self) -> bool {
        self.name.starts_with(&format!("{SERVICE_NAME}-selftest-"))
    }

    /// The Windows service name, the systemd unit stem, and the Task Scheduler
    /// task name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The human-readable name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// One line of explanation.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The launchd label — reverse-domain, as launchd expects.
    ///
    /// Built from the same three product segments [`crate::paths`] resolves the
    /// application-data directories with, so a label and a directory cannot
    /// drift apart.
    #[must_use]
    pub fn launchd_label(&self) -> String {
        format!(
            "{}.{}.{}",
            crate::paths::QUALIFIER,
            crate::paths::ORGANIZATION,
            self.name
        )
    }

    /// The systemd unit file name.
    #[must_use]
    pub fn systemd_unit(&self) -> String {
        format!("{}.service", self.name)
    }
}

impl fmt::Display for ServiceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

// ---------------------------------------------------------------------------
// Restart policy
// ---------------------------------------------------------------------------

/// The restart-on-failure policy, and the bound on how fast it may retry.
///
/// `05-infrastructure.md` item 3: *"set a restart-on-failure policy with bounded
/// delay"*. Both halves matter and they are different requirements. A service
/// that does not come back after a crash defeats Journey 5; a service that comes
/// back instantly, forever, turns one bad configuration into a fork bomb against
/// GitHub's rate limit. So the delay has a floor as well as a ceiling, and the
/// floor is what `does not restart-loop faster than that bound` is measured
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    delay: Duration,
    reset_after: Duration,
}

impl RestartPolicy {
    /// The shortest delay this will accept.
    ///
    /// One second is not a tuning preference. Below it, launchd's own throttle
    /// and systemd's start-limit logic both take over and the configured number
    /// stops being the number in force, so a policy under this floor would be a
    /// value `service status` reported and the platform ignored.
    pub const MIN_DELAY: Duration = Duration::from_secs(1);

    /// The longest delay this will accept. Past five minutes an operator
    /// watching a restart would reasonably conclude the service is simply gone.
    pub const MAX_DELAY: Duration = Duration::from_secs(300);

    /// What `service install` uses when nothing is said.
    pub const DEFAULT_DELAY: Duration = Duration::from_secs(15);

    /// How long the service must stay up before its failure count is forgotten.
    pub const DEFAULT_RESET_AFTER: Duration = Duration::from_secs(600);

    /// # Errors
    ///
    /// [`ServiceError::RestartDelay`] when `delay` is outside
    /// [`RestartPolicy::MIN_DELAY`]..=[`RestartPolicy::MAX_DELAY`], or when
    /// `reset_after` is not longer than `delay` — a reset window shorter than
    /// the delay can never elapse between two restarts, so the failure count
    /// would reset on every attempt and no start-limit could ever trip.
    pub fn new(delay: Duration, reset_after: Duration) -> Result<Self, ServiceError> {
        if delay < Self::MIN_DELAY || delay > Self::MAX_DELAY {
            return Err(ServiceError::RestartDelay {
                requested_secs: delay.as_secs(),
                min_secs: Self::MIN_DELAY.as_secs(),
                max_secs: Self::MAX_DELAY.as_secs(),
            });
        }
        if reset_after <= delay {
            return Err(ServiceError::RestartResetWindow {
                reset_secs: reset_after.as_secs(),
                delay_secs: delay.as_secs(),
            });
        }
        Ok(Self { delay, reset_after })
    }

    /// How long the service manager waits before restarting a failed service.
    #[must_use]
    pub const fn delay(&self) -> Duration {
        self.delay
    }

    /// How long the service must run before its failure count resets.
    #[must_use]
    pub const fn reset_after(&self) -> Duration {
        self.reset_after
    }

    /// The delay a given manager can actually express.
    ///
    /// Three of the four take seconds and enforce exactly what they are given.
    /// **Windows Task Scheduler does not**: `RestartOnFailure/Interval` is
    /// expressed in whole minutes with a one-minute floor, and it *rejects* the
    /// registration outright rather than rounding — `PT15S` comes back as
    /// "The task XML contains a value which is incorrectly formatted or out of
    /// range", which is how this was found.
    ///
    /// So the interval is rounded **up**, never down, and never below one
    /// minute. The direction is the point: the requirement is that the service
    /// *"does not restart-loop faster than that bound"*, and a delay longer
    /// than the configured one still satisfies it, while a shorter one would
    /// not. `service status` reports the difference as a note so that an
    /// operator reading `15s` in the record and `60s` from the manager is told
    /// why rather than left to wonder.
    #[must_use]
    pub const fn effective_delay(&self, kind: DefinitionKind) -> Duration {
        match kind {
            DefinitionKind::WindowsScheduledTask => {
                let seconds = self.delay.as_secs();
                let minutes = seconds.div_ceil(60);
                Duration::from_secs(if minutes == 0 { 60 } else { minutes * 60 })
            }
            _ => self.delay,
        }
    }
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            delay: Self::DEFAULT_DELAY,
            reset_after: Self::DEFAULT_RESET_AFTER,
        }
    }
}

impl fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "restart after {}s, failure count resets after {}s",
            self.delay.as_secs(),
            self.reset_after.as_secs()
        )
    }
}

// ---------------------------------------------------------------------------
// The account
// ---------------------------------------------------------------------------

/// The account a registration runs under.
///
/// Not an operator choice. It is a function of the start mode and the platform,
/// because the start mode decides which secret store the daemon must read and
/// the store's own access control decides which accounts can read it. See
/// `docs/service-account.md`, and [`review_least_privilege`] for the check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAccount {
    /// `NT AUTHORITY\SYSTEM`. The only stock Windows account named by the
    /// machine-scoped store's DACL.
    LocalSystem,
    /// `root`. What a LaunchDaemon and a systemd system unit run as, and what
    /// the macOS System Keychain's root-only master key requires.
    Root,
    /// The operator's own account, for a login-mode registration.
    InvokingUser,
}

impl ServiceAccount {
    /// The account a given kind of definition obliges.
    ///
    /// Keyed on the definition rather than on `cfg!(windows)`, and the
    /// difference is not academic: a Windows developer rendering the launchd
    /// property list would otherwise write `UserName = NT AUTHORITY\SYSTEM`
    /// into it, which is not an account macOS has. A definition's account is a
    /// property of the definition, and the whole point of rendering being pure
    /// is that any host can render any platform's and get the right answer.
    #[must_use]
    pub const fn for_definition(kind: DefinitionKind, mode: StartMode) -> Self {
        match (kind, mode) {
            (DefinitionKind::WindowsService, _) => Self::LocalSystem,
            (DefinitionKind::WindowsScheduledTask, _) | (_, StartMode::Login) => Self::InvokingUser,
            (_, StartMode::Boot) => Self::Root,
        }
    }

    /// The account the given start mode obliges on the platform this binary was
    /// built for.
    #[must_use]
    pub const fn for_start_mode(mode: StartMode) -> Self {
        Self::for_definition(host_definition_kind(mode), mode)
    }

    /// How the platform spells it.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LocalSystem => "NT AUTHORITY\\SYSTEM",
            Self::Root => "root",
            Self::InvokingUser => "the invoking user",
        }
    }

    /// Why this is the *minimum* account that can do the job, not merely the
    /// convenient one.
    ///
    /// Printed by `service status` and by [`review_least_privilege`], because a
    /// privileged account with no stated reason is indistinguishable from a
    /// privileged account nobody thought about.
    #[must_use]
    pub const fn justification(&self) -> &'static str {
        match self {
            Self::LocalSystem => {
                "the machine-scoped store's DACL names SY, BA and OW only; LocalService and \
                 NetworkService cannot read it, and widening the DACL to reach them would grant \
                 every service on this host read access to the one credential this product holds"
            }
            Self::Root => {
                "a boot-time registration runs outside every login session: on macOS the System \
                 Keychain is unlocked by /var/db/SystemKey, which is root-only, and on Linux the \
                 machine-scoped store is a 0600 file under /var/lib that only root can open \
                 before a session exists"
            }
            Self::InvokingUser => {
                "a login-mode registration reads the user-scoped store, which is deliberately \
                 readable by exactly one account and needs no elevation at all"
            }
        }
    }

    /// Whether registering under this account needs administrative rights.
    #[must_use]
    pub const fn needs_elevation(&self) -> bool {
        matches!(self, Self::LocalSystem | Self::Root)
    }
}

impl fmt::Display for ServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Something went wrong installing, inspecting, or removing the registration.
///
/// Every variant is formatted straight into an operator-facing message, so each
/// one says what to do next rather than only what failed. No variant carries a
/// secret: this module never reads the token, only the *location* `d2` publishes
/// for exactly this purpose.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The single-instance lock is held, so a second agent must not be
    /// registered.
    ///
    /// `05-infrastructure.md` item 1. The message is `d1`'s, verbatim, because
    /// `d1` already worked out what to tell an operator who lost that race.
    #[error("cannot install the service while an agent is already running on this host: {source}")]
    LockHeld {
        /// What `d1` said, including who holds it.
        #[source]
        source: Box<LockError>,
    },

    /// The lock could not be inspected at all, which is not the same as it being
    /// free.
    #[error(
        "cannot tell whether an agent is already running on this host, so the service was not \
         installed: {source}. Fix the reported problem with the state directory and try again."
    )]
    LockUnreadable {
        /// The underlying failure.
        #[source]
        source: Box<LockError>,
    },

    /// The runner root this registration would run jobs under could not be
    /// created, inspected, or given the access the registration's account needs.
    ///
    /// Reported *before* anything is registered. A registration whose workspaces
    /// would land in a directory ordinary local users can write is a
    /// registration that should not exist, and `04-security-recovery.md` asks
    /// for exactly that refusal rather than a warning.
    #[error(
        "this registration would run jobs under the default runner root, and that root could \
         not be prepared, so nothing was registered: {source}"
    )]
    RunnerRoot {
        /// What [`crate::runner_root_access`] reported, including the remedy.
        #[source]
        source: Box<RootAccessError>,
    },

    /// The path of the running binary could not be resolved.
    #[error(
        "cannot resolve the absolute path of this executable, so there is nothing to register: \
         {detail}. Run the installer from the installed binary rather than through a shell \
         function or a wrapper that replaces argv[0]."
    )]
    BinaryPath {
        /// What the platform reported.
        detail: String,
    },

    /// The binary named for the registration is not there.
    #[error(
        "{} is not a file, so registering it would create a service that cannot start. Install \
         the product first, then run `service install` from the installed binary.",
        path.display()
    )]
    BinaryMissing {
        /// The path that was to be registered.
        path: PathBuf,
    },

    /// The requested restart delay is outside the bound.
    #[error(
        "a restart delay of {requested_secs}s is outside the supported range \
         {min_secs}s-{max_secs}s. Below the floor the platform's own throttle overrides the \
         value, so `service status` would report a delay that is not the one in force."
    )]
    RestartDelay {
        /// What was asked for.
        requested_secs: u64,
        /// The floor.
        min_secs: u64,
        /// The ceiling.
        max_secs: u64,
    },

    /// The failure-count reset window is not longer than the restart delay.
    #[error(
        "a failure-count reset window of {reset_secs}s is not longer than the {delay_secs}s \
         restart delay, so the count would reset between every pair of restarts and no \
         start limit could ever apply."
    )]
    RestartResetWindow {
        /// What was asked for.
        reset_secs: u64,
        /// The delay it has to exceed.
        delay_secs: u64,
    },

    /// A registration is already there.
    #[error(
        "{name} is already registered to start at {existing}. Use `service uninstall` first, or \
         switch the start mode in place, which does not re-register anything."
    )]
    AlreadyInstalled {
        /// Which registration.
        name: String,
        /// The mode it currently carries.
        existing: StartMode,
    },

    /// No registration is there.
    #[error("{name} is not registered on this host, so there is nothing to {operation}.")]
    NotInstalled {
        /// Which registration.
        name: String,
        /// What was being attempted.
        operation: &'static str,
    },

    /// The record `install` wrote could not be read or written.
    #[error("cannot {operation} the service record {}: {detail}", path.display())]
    Record {
        /// Read, write, or remove.
        operation: &'static str,
        /// The record file.
        path: PathBuf,
        /// The underlying failure.
        detail: String,
    },

    /// The record is there but is not one this version wrote.
    #[error(
        "the service record {} was not written by this product, or was written by a version \
         this one cannot read: {detail}. Run `service uninstall` and `service install` again; \
         neither touches configuration, secrets, or the cache.",
        path.display()
    )]
    RecordUnreadable {
        /// The record file.
        path: PathBuf,
        /// What was wrong with it.
        detail: String,
    },

    /// The application-data directories could not be resolved or created.
    #[error("cannot prepare this host's application-data directories: {source}")]
    Paths {
        /// The underlying failure.
        #[source]
        source: Box<crate::paths::PathsError>,
    },

    /// The platform's service manager refused, or could not be reached.
    #[error("cannot {operation} {name} through {manager}: {detail}")]
    Control {
        /// What was being attempted.
        operation: &'static str,
        /// Which registration.
        name: String,
        /// Which service manager.
        manager: &'static str,
        /// What it said.
        detail: String,
    },

    /// An operation failed and its compensating action failed too.
    #[error(
        "cannot {operation} {name}: {cause}. The attempted rollback also failed: {rollback}. \
         Inspect `service status` before retrying."
    )]
    Rollback {
        /// The transaction that could not be completed.
        operation: &'static str,
        /// Which registration was involved.
        name: String,
        /// The original failure.
        cause: String,
        /// The failure while restoring the previous state.
        rollback: String,
    },

    /// The operation needs administrative rights it does not have.
    #[error("{operation} {name} needs administrative rights: {detail}. {remedy}")]
    NeedsElevation {
        /// What was being attempted.
        operation: &'static str,
        /// Which registration.
        name: String,
        /// What the platform said.
        detail: String,
        /// How to get them, in this platform's own terms.
        remedy: &'static str,
    },
}

// ---------------------------------------------------------------------------
// Directories
// ---------------------------------------------------------------------------

/// The four directories the registration was installed against.
///
/// Recorded rather than re-derived, because `05-infrastructure.md` item 2 speaks
/// of the *configured* cache and runtime directories: the account the service
/// runs under and the account that ran `service install` do not always resolve
/// the same platform-standard locations, and a claim about what the service can
/// write is only checkable against a specific set of paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDirectories {
    /// Non-secret TOML and the SQLite database.
    pub config: PathBuf,
    /// The agent lock, the attempt journal, and the runner package cache.
    pub state: PathBuf,
    /// Per-attempt disposable runner workspaces.
    pub runtime: PathBuf,
    /// Rotating redacted diagnostics.
    pub logs: PathBuf,
}

impl ServiceDirectories {
    /// Snapshots the four directories a resolved [`AppPaths`] names.
    #[must_use]
    pub fn of(paths: &AppPaths) -> Self {
        Self {
            config: paths.config_dir().to_path_buf(),
            state: paths.state_dir().to_path_buf(),
            runtime: paths.runtime_dir().to_path_buf(),
            logs: paths.logs_dir().to_path_buf(),
        }
    }

    /// The four, in the order `05-infrastructure.md` lists them.
    #[must_use]
    pub fn all(&self) -> [&Path; 4] {
        [
            self.config.as_path(),
            self.state.as_path(),
            self.runtime.as_path(),
            self.logs.as_path(),
        ]
    }

    /// The rotating diagnostic log's stem, which is what `service status`
    /// reports and what `05-infrastructure.md` item 4 requires be preserved.
    #[must_use]
    pub fn log_file(&self) -> PathBuf {
        self.logs.join(LOG_FILE_STEM)
    }
}

// ---------------------------------------------------------------------------
// The install plan
// ---------------------------------------------------------------------------

/// What `service install` was asked for, before anything has been resolved.
///
/// Separate from [`InstallPlan`] because a request is the operator's words and
/// a plan is what the host actually supports: the plan carries a *resolved
/// absolute* binary path, the account the start mode obliges, and the four
/// directories the registration is installed against, none of which the caller
/// supplies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRequest {
    start_mode: StartMode,
    binary: Option<PathBuf>,
    source_binary: Option<PathBuf>,
    arguments: Vec<OsString>,
    restart: RestartPolicy,
    on_demand: bool,
}

impl InstallRequest {
    /// Register the binary that is running this call.
    #[must_use]
    pub fn new(start_mode: StartMode) -> Self {
        Self {
            start_mode,
            binary: None,
            source_binary: None,
            arguments: DAEMON_ARGUMENTS.iter().map(OsString::from).collect(),
            restart: RestartPolicy::default(),
            on_demand: false,
        }
    }

    /// Registers the service but does not ask the manager to start it by
    /// itself.
    ///
    /// Production never uses this: a boot-mode registration that does not start
    /// at boot is the failure `service status` reports. **The privileged
    /// installer tests use it for every fixture they create**, so that a
    /// registration which somehow escaped its cleanup guard cannot start with
    /// the owner's machine on the next reboot. A leaked service is bad; a
    /// leaked service that runs is worse, and the difference costs one flag.
    #[must_use]
    pub const fn started_on_demand(mut self) -> Self {
        self.on_demand = true;
        self
    }

    /// Register a named binary instead of the running one.
    ///
    /// The privileged installer tests use this to register a fixture service
    /// host. Production does not: `05-infrastructure.md` item 6 is specifically
    /// about the path of *the running binary*, and letting an operator name a
    /// different one would defeat the stale-path detection it asks for.
    #[must_use]
    pub fn for_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = Some(binary.into());
        self
    }

    /// Where the registered binary was copied from.
    ///
    /// # Why a registration has a source at all
    ///
    /// A service registered directly against a package manager's own file can
    /// never be upgraded on Windows, because the running service holds that
    /// file open and `npm i -g` cannot replace it. What it does instead is
    /// worse than failing: it rewrites the package metadata, reports success,
    /// and leaves the old executable in place — so the operator is told the new
    /// version is installed while the old one keeps running. That was observed,
    /// twice in a row, before this existed.
    ///
    /// So the service runs a copy the product owns, and this records where that
    /// copy came from. The source is what a package manager updates, what
    /// [`inspect_binary`] watches for item 6's stale-path case, and what the
    /// daemon compares its own version against to know an upgrade is waiting.
    #[must_use]
    pub fn copied_from(mut self, source: impl Into<PathBuf>) -> Self {
        self.source_binary = Some(source.into());
        self
    }

    /// Replace the registered arguments. Defaults to [`DAEMON_ARGUMENTS`].
    #[must_use]
    pub fn with_arguments<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments = arguments.into_iter().map(Into::into).collect();
        self
    }

    /// Replace the restart-on-failure policy. Defaults to
    /// [`RestartPolicy::default`].
    #[must_use]
    pub const fn with_restart(mut self, restart: RestartPolicy) -> Self {
        self.restart = restart;
        self
    }

    /// The start mode asked for.
    #[must_use]
    pub const fn start_mode(&self) -> StartMode {
        self.start_mode
    }
}

/// Everything a backend needs, resolved and validated.
///
/// Constructing one is where `05-infrastructure.md` item 6 is actually
/// satisfied: the binary path is made absolute and is confirmed to be a file
/// *before* anything is registered, so a registration that would fail at boot
/// is refused at install time instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    identity: ServiceIdentity,
    start_mode: StartMode,
    binary: PathBuf,
    source_binary: Option<PathBuf>,
    arguments: Vec<OsString>,
    account: ServiceAccount,
    restart: RestartPolicy,
    directories: ServiceDirectories,
    secret_guard: Option<PathBuf>,
    on_demand: bool,
}

impl InstallPlan {
    /// Resolves a request against this host.
    ///
    /// # Errors
    ///
    /// [`ServiceError::BinaryPath`] when the running executable cannot be
    /// located, and [`ServiceError::BinaryMissing`] when the path that would be
    /// registered is not a file.
    pub fn resolve(
        identity: ServiceIdentity,
        request: &InstallRequest,
        directories: ServiceDirectories,
    ) -> Result<Self, ServiceError> {
        let binary = match &request.binary {
            Some(named) => absolute(named)?,
            None => running_executable()?,
        };
        if !binary.is_file() {
            return Err(ServiceError::BinaryMissing { path: binary });
        }
        // `d2` publishes both halves of the systemd credential seam — the
        // credential's name and the guard file the store lives in — precisely so
        // that a unit file can name them without this module reimplementing
        // either. A store that cannot be resolved at all is not fatal here: it
        // means the unit carries no `LoadCredential=` line and the daemon opens
        // the file itself, which is the pre-systemd-credential path `d2` still
        // supports.
        let secret_guard = crate::secrets::PlatformSecretStore::for_start_mode(request.start_mode)
            .ok()
            .map(|store| store.guard());
        Ok(Self {
            identity,
            start_mode: request.start_mode,
            binary,
            source_binary: request.source_binary.clone(),
            arguments: request.arguments.clone(),
            account: ServiceAccount::for_start_mode(request.start_mode),
            restart: request.restart,
            directories,
            secret_guard,
            on_demand: request.on_demand,
        })
    }

    /// Builds a plan from values a caller already holds, without touching the
    /// filesystem.
    ///
    /// This is what makes the renderers testable on a host that has none of the
    /// paths involved: a Windows developer can render the systemd unit for
    /// `/opt/runner-manager/bin/runner-manager` and assert every line of it.
    #[must_use]
    pub fn unchecked(
        identity: ServiceIdentity,
        start_mode: StartMode,
        binary: impl Into<PathBuf>,
        directories: ServiceDirectories,
    ) -> Self {
        Self {
            identity,
            start_mode,
            binary: binary.into(),
            source_binary: None,
            arguments: DAEMON_ARGUMENTS.iter().map(OsString::from).collect(),
            account: ServiceAccount::for_start_mode(start_mode),
            restart: RestartPolicy::default(),
            directories,
            secret_guard: None,
            on_demand: false,
        }
    }

    /// Registers without arming the manager's automatic start. See
    /// [`InstallRequest::started_on_demand`].
    #[must_use]
    pub const fn started_on_demand(mut self) -> Self {
        self.on_demand = true;
        self
    }

    /// Whether the manager was asked not to start this by itself.
    #[must_use]
    pub const fn is_on_demand(&self) -> bool {
        self.on_demand
    }

    /// Names the file the machine-scoped secret store lives in, for the
    /// systemd `LoadCredential=` line.
    ///
    /// [`InstallPlan::resolve`] fills this from `d2`; a test names it directly
    /// so that a Windows or macOS CI leg can assert the Linux unit's credential
    /// line for a path that platform does not have.
    #[must_use]
    pub fn with_secret_guard(mut self, guard: impl Into<PathBuf>) -> Self {
        self.secret_guard = Some(guard.into());
        self
    }

    /// The file the machine-scoped secret store lives in, when one resolved.
    #[must_use]
    pub fn secret_guard(&self) -> Option<&Path> {
        self.secret_guard.as_deref()
    }

    /// Overrides the restart policy on an already-built plan.
    #[must_use]
    pub const fn with_restart(mut self, restart: RestartPolicy) -> Self {
        self.restart = restart;
        self
    }

    /// Overrides the registered arguments on an already-built plan.
    #[must_use]
    pub fn with_arguments<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments = arguments.into_iter().map(Into::into).collect();
        self
    }

    /// What the operating system calls this registration.
    #[must_use]
    pub const fn identity(&self) -> &ServiceIdentity {
        &self.identity
    }

    /// Boot or login.
    #[must_use]
    pub const fn start_mode(&self) -> StartMode {
        self.start_mode
    }

    /// The resolved absolute path of the binary to register.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Where [`Self::binary`] was copied from, when it is a copy.
    ///
    /// `None` is the legacy layout: the registration names the file a package
    /// manager owns, and cannot be upgraded while it runs. See
    /// [`InstallRequest::copied_from`].
    #[must_use]
    pub fn source_binary(&self) -> Option<&Path> {
        self.source_binary.as_deref()
    }

    /// The arguments it is registered with.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// The account it runs under.
    #[must_use]
    pub const fn account(&self) -> &ServiceAccount {
        &self.account
    }

    /// The restart-on-failure policy.
    #[must_use]
    pub const fn restart(&self) -> RestartPolicy {
        self.restart
    }

    /// The four directories it was installed against.
    #[must_use]
    pub const fn directories(&self) -> &ServiceDirectories {
        &self.directories
    }

    /// The command line as one string, quoted the way each platform expects.
    #[must_use]
    pub fn command_line(&self) -> String {
        let mut out = quote_argument(&self.binary.to_string_lossy());
        for argument in &self.arguments {
            out.push(' ');
            out.push_str(&quote_argument(&argument.to_string_lossy()));
        }
        out
    }
}

/// Undoes a runner-root change, and says what could not be undone.
///
/// `None` when the rollback was complete — either because there was nothing to
/// undo, or because the directory this operation created was removed again and
/// the descriptor it replaced was written back. `Some` is the "report any
/// non-reversible existing directory state explicitly" half of the requirement,
/// and the caller folds it into the failure it was already reporting.
fn retained_runner_root(change: &RootAccessChange) -> Option<String> {
    let reversal = change.revert();
    matches!(reversal, Reversal::Retained { .. }).then(|| reversal.to_string())
}

/// The error a failed step returns once both of its rollbacks have been
/// attempted.
///
/// `retained` is [`retained_runner_root`]'s answer and `rollback` is what
/// undoing the *registration* reported — whatever it reports on success, which
/// a failure has no use for. Both arrive already evaluated, because each may be
/// attempted exactly once and the order is the caller's to choose.
///
/// A complete rollback leaves `cause` exactly as it was: the operator's problem
/// is what failed, not the tidying up afterwards. An incomplete one is promoted
/// to [`ServiceError::Rollback`], which is the variant that exists to say "this
/// failed *and* something is left behind" — and it names everything that did.
fn rolled_back<T>(
    retained: Option<String>,
    rollback: Result<T, ServiceError>,
    operation: &'static str,
    identity: &ServiceIdentity,
    cause: ServiceError,
) -> ServiceError {
    let left_behind = match (rollback.err(), retained) {
        (Some(rollback), Some(retained)) => Some(format!("{rollback}; {retained}")),
        (Some(rollback), None) => Some(rollback.to_string()),
        (None, retained) => retained,
    };
    match left_behind {
        Some(rollback) => ServiceError::Rollback {
            operation,
            name: identity.name().to_string(),
            cause: cause.to_string(),
            rollback,
        },
        None => cause,
    }
}

/// [`rolled_back`] for a failure with nothing registered yet, where the runner
/// root is the only thing there is to undo.
fn undo_runner_root(
    change: &RootAccessChange,
    operation: &'static str,
    identity: &ServiceIdentity,
    cause: ServiceError,
) -> ServiceError {
    rolled_back(
        retained_runner_root(change),
        Ok(()),
        operation,
        identity,
        cause,
    )
}

/// Makes a path absolute without resolving symlinks.
///
/// Symbolic links are deliberately left alone. A Homebrew installation puts a
/// stable link at `/opt/homebrew/bin/runner-manager` and moves the file it
/// points at on every upgrade; recording the link's target would make an
/// ordinary `brew upgrade` look exactly like the npm failure this module exists
/// to detect, and recording the link records the thing the operator installed.
///
/// Linux is the one platform where this is not fully in the caller's hands:
/// `std::env::current_exe` reads `/proc/self/exe`, which the kernel has already
/// resolved. There the recorded path is the real file rather than the shim —
/// which is still correct for the npm case, because a real file under a Node
/// prefix disappears with the prefix.
fn absolute(path: &Path) -> Result<PathBuf, ServiceError> {
    std::path::absolute(path).map_err(|error| ServiceError::BinaryPath {
        detail: format!("{} could not be made absolute: {error}", path.display()),
    })
}

/// The absolute path of the executable running this call.
fn running_executable() -> Result<PathBuf, ServiceError> {
    let raw = std::env::current_exe().map_err(|error| ServiceError::BinaryPath {
        detail: error.to_string(),
    })?;
    absolute(&raw)
}

/// Quotes one command-line argument when it needs it.
///
/// The rule is Windows', because Windows is the platform where a command line is
/// a single string the callee re-splits, and because `windows-service` applies
/// exactly this rule when it builds `lpBinaryPathName`. The Unix backends embed
/// arguments in a plist array and in a systemd `ExecStart=`, both of which
/// accept the same quoting, so one rule serves all three rather than three
/// nearly-identical ones.
fn quote_argument(argument: &str) -> String {
    if !argument.is_empty() && !argument.contains([' ', '"', '\t', '\n']) {
        return argument.to_string();
    }
    let mut out = String::with_capacity(argument.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in argument.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                // Every backslash immediately before a quote must be doubled,
                // and the quote itself escaped.
                for _ in 0..=backslashes {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            other => {
                backslashes = 0;
                out.push(other);
            }
        }
    }
    // Trailing backslashes would otherwise escape the closing quote.
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Reads the executable back out of a command line quoted by
/// [`quote_argument`].
///
/// `service status` needs this because the Windows Service Control Manager
/// stores the binary and its arguments as one string and hands the whole thing
/// back from `QueryServiceConfigW`. Comparing a record against a registration
/// means splitting that string the same way Windows itself does.
///
/// Returns `None` for an empty or whitespace-only command line, which is the
/// only input with no first argument to find.
#[must_use]
pub fn executable_from_command_line(command_line: &str) -> Option<PathBuf> {
    let trimmed = command_line.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut chars = trimmed.chars().peekable();
    let quoted = chars.peek() == Some(&'"');
    if quoted {
        chars.next();
        let mut backslashes = 0usize;
        for c in chars {
            match c {
                '\\' => {
                    backslashes += 1;
                }
                '"' => {
                    // `2n` backslashes then a quote closes the argument; `2n+1`
                    // is a literal quote inside it.
                    out.extend(std::iter::repeat_n('\\', backslashes / 2));
                    if backslashes.is_multiple_of(2) {
                        break;
                    }
                    backslashes = 0;
                    out.push('"');
                }
                other => {
                    out.extend(std::iter::repeat_n('\\', backslashes));
                    backslashes = 0;
                    out.push(other);
                }
            }
        }
    } else {
        for c in chars {
            if c == ' ' || c == '\t' {
                break;
            }
            out.push(c);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(PathBuf::from(out))
    }
}

// ---------------------------------------------------------------------------
// Rendered definitions
// ---------------------------------------------------------------------------

/// Which of the four things a platform reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionKind {
    /// The parameters `CreateServiceW` is called with, rendered as a canonical
    /// descriptor so that they can be reviewed and asserted like the other
    /// three. The Service Control Manager has no file.
    WindowsService,
    /// A Task Scheduler XML document, for `--start-at login` on Windows.
    WindowsScheduledTask,
    /// A launchd property list — a LaunchDaemon at boot, a LaunchAgent at login.
    LaunchdPlist,
    /// A systemd unit — a system unit at boot, a user unit at login.
    SystemdUnit,
}

impl DefinitionKind {
    /// What to call the thing that reads it, in an operator-facing message.
    #[must_use]
    pub const fn manager(self) -> &'static str {
        match self {
            Self::WindowsService => "the Windows Service Control Manager",
            Self::WindowsScheduledTask => "Windows Task Scheduler",
            Self::LaunchdPlist => "launchd",
            Self::SystemdUnit => "systemd",
        }
    }
}

impl fmt::Display for DefinitionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.manager())
    }
}

/// One platform's definition of the registration, as text.
///
/// Producing this is pure: no `cfg`, no privileges, no filesystem. That is what
/// lets every leg of the CI matrix assert every platform's definition, instead
/// of each leg asserting only its own and the other two being reviewed by
/// reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDefinition {
    kind: DefinitionKind,
    text: String,
    install_path: Option<PathBuf>,
}

impl ServiceDefinition {
    /// Which platform this is for.
    #[must_use]
    pub const fn kind(&self) -> DefinitionKind {
        self.kind
    }

    /// The definition itself.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Where the platform expects the file, when the platform reads a file.
    ///
    /// `None` for [`DefinitionKind::WindowsService`], whose "definition" is a
    /// set of arguments to `CreateServiceW`, and for a Task Scheduler document,
    /// which is handed to `schtasks` from a temporary file and is not stored
    /// where it was written.
    #[must_use]
    pub fn install_path(&self) -> Option<&Path> {
        self.install_path.as_deref()
    }

    /// The definition this host's own service manager would be given.
    ///
    /// The value-level twin of [`host_definition_kind`]. Rendering needs no
    /// privileges and no service manager, so anything that wants to *see* what
    /// an install would register — `f3`'s `service install --dry-run`, a
    /// support bundle, [`RecordingControls`] — can have it without registering
    /// anything.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Control`] when a Windows logon-triggered registration is
    /// asked for and the session reports no account to register it for.
    pub fn for_host(plan: &InstallPlan) -> Result<Self, ServiceError> {
        Ok(match host_definition_kind(plan.start_mode()) {
            DefinitionKind::WindowsService => Self::windows_service(plan),
            DefinitionKind::WindowsScheduledTask => {
                Self::windows_scheduled_task(plan, &TaskPrincipal::current()?)
            }
            DefinitionKind::LaunchdPlist => Self::launchd(plan, host_home().as_deref()),
            DefinitionKind::SystemdUnit => Self::systemd(plan, host_home().as_deref()),
        })
    }

    /// The Windows service parameters, as a canonical descriptor.
    #[must_use]
    pub fn windows_service(plan: &InstallPlan) -> Self {
        Self {
            kind: DefinitionKind::WindowsService,
            text: windows_service_descriptor(plan),
            install_path: None,
        }
    }

    /// A Task Scheduler document for `--start-at login`.
    #[must_use]
    pub fn windows_scheduled_task(plan: &InstallPlan, principal: &TaskPrincipal) -> Self {
        Self {
            kind: DefinitionKind::WindowsScheduledTask,
            text: windows_scheduled_task_xml(plan, principal),
            install_path: None,
        }
    }

    /// A launchd property list.
    ///
    /// `home` is only consulted for `--start-at login`, where the file belongs
    /// in the operator's own `~/Library/LaunchAgents`.
    #[must_use]
    pub fn launchd(plan: &InstallPlan, home: Option<&Path>) -> Self {
        let file = format!("{}.plist", plan.identity().launchd_label());
        let install_path = match plan.start_mode() {
            StartMode::Boot => Some(PathBuf::from(LAUNCH_DAEMONS_DIR).join(file)),
            StartMode::Login => home.map(|home| home.join(LAUNCH_AGENTS_SUBDIR).join(file)),
        };
        Self {
            kind: DefinitionKind::LaunchdPlist,
            text: launchd_plist(plan),
            install_path,
        }
    }

    /// Wraps text this module did not render.
    ///
    /// Two callers need it and both matter. A test builds a deliberately
    /// widened definition and watches [`review_least_privilege`] reject it —
    /// without which the review would be a function nobody had ever seen fail.
    /// And `service status` can review the definition **actually on disk**,
    /// which on Linux and macOS an operator is free to edit after installation.
    #[must_use]
    pub fn from_text(kind: DefinitionKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
            install_path: None,
        }
    }

    /// A systemd unit.
    ///
    /// `home` is only consulted for `--start-at login`, where the unit belongs
    /// in the operator's own `~/.config/systemd/user`.
    #[must_use]
    pub fn systemd(plan: &InstallPlan, home: Option<&Path>) -> Self {
        let file = plan.identity().systemd_unit();
        let install_path = match plan.start_mode() {
            StartMode::Boot => Some(PathBuf::from(SYSTEMD_SYSTEM_DIR).join(file)),
            StartMode::Login => home.map(|home| home.join(SYSTEMD_USER_SUBDIR).join(file)),
        };
        Self {
            kind: DefinitionKind::SystemdUnit,
            text: systemd_unit(plan),
            install_path,
        }
    }
}

/// Where a LaunchDaemon lives.
pub const LAUNCH_DAEMONS_DIR: &str = "/Library/LaunchDaemons";
/// Where a LaunchAgent lives, under the operator's home directory.
pub const LAUNCH_AGENTS_SUBDIR: &str = "Library/LaunchAgents";
/// Where a systemd system unit lives.
pub const SYSTEMD_SYSTEM_DIR: &str = "/etc/systemd/system";
/// Where a systemd user unit lives, under the operator's home directory.
pub const SYSTEMD_USER_SUBDIR: &str = ".config/systemd/user";

/// The product's own page, cited by every definition so an operator who finds
/// one on a host can find out what put it there.
const DOCUMENTATION: &str = "https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI";

/// How many consecutive failures the platform tolerates before it stops
/// retrying.
///
/// The companion to [`RestartPolicy::reset_after`]: the delay bounds how *fast*
/// a restart may come, and this bounds how *many* come before the host gives
/// up and leaves the failure visible instead of hiding it behind an endless
/// retry.
pub const START_LIMIT_BURST: u32 = 5;

// -- systemd -----------------------------------------------------------------

/// Renders the systemd unit for this plan.
///
/// # Why the sandbox is this tight, and what it costs
///
/// `05-infrastructure.md` item 2 ends *"and write its configured cache and
/// runtime directories — and no more"*. `ProtectSystem=strict` plus an explicit
/// `ReadWritePaths` is what "and no more" means on Linux: everything outside the
/// four recorded directories is read-only to this unit.
///
/// **The runner inherits it.** The agent spawns the GitHub Actions runner as a
/// child, so a workflow running on this host also runs inside this sandbox: it
/// cannot write outside the four directories and its private `/tmp`, and
/// `NoNewPrivileges=yes` means it cannot `sudo`. `07-security.md` assumes a
/// hostile workflow may run here, so that is the intended direction — but it is
/// a real behavioural limit and `docs/service-account.md` states it where an
/// operator will find it.
#[must_use]
pub fn systemd_unit(plan: &InstallPlan) -> String {
    let identity = plan.identity();
    let restart = plan.restart();
    let directories = plan.directories();

    let mut out = String::new();
    out.push_str("[Unit]\n");
    out.push_str(&format!("Description={}\n", identity.display_name()));
    out.push_str(&format!("Documentation={DOCUMENTATION}\n"));
    out.push_str("After=network-online.target\n");
    out.push_str("Wants=network-online.target\n");
    // In `[Unit]` rather than `[Service]`: systemd moved these in v229 and only
    // accepts them here without a deprecation warning.
    out.push_str(&format!(
        "StartLimitIntervalSec={}\n",
        restart.reset_after().as_secs()
    ));
    out.push_str(&format!("StartLimitBurst={START_LIMIT_BURST}\n"));

    out.push_str("\n[Service]\n");
    out.push_str("Type=simple\n");
    out.push_str(&format!("ExecStart={}\n", plan.command_line()));
    out.push_str(&format!(
        "WorkingDirectory={}\n",
        directories.state.display()
    ));
    out.push_str(&format!("SyslogIdentifier={identity}\n"));
    out.push_str("Restart=on-failure\n");
    out.push_str(&format!("RestartSec={}\n", restart.delay().as_secs()));

    // `d2` publishes the credential name so the unit and the reader cannot
    // disagree about it. A user unit never carries one: the file it would name
    // is root-owned, and a user-scoped store is deliberately not for a service.
    if plan.start_mode() == StartMode::Boot
        && let Some(guard) = plan.secret_guard()
    {
        out.push_str(&format!(
            "LoadCredential={}:{}\n",
            crate::secrets::SYSTEMD_CREDENTIAL,
            guard.display()
        ));
    }

    out.push_str("\n# Least privilege. See docs/service-account.md.\n");
    for directive in SYSTEMD_HARDENING {
        out.push_str(directive);
        out.push('\n');
    }
    out.push_str(&format!(
        "ReadWritePaths={}\n",
        directories
            .all()
            .iter()
            .map(|path| quote_argument(&path.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(" ")
    ));

    out.push_str("\n[Install]\n");
    out.push_str(match plan.start_mode() {
        StartMode::Boot => "WantedBy=multi-user.target\n",
        StartMode::Login => "WantedBy=default.target\n",
    });
    out
}

/// The hardening directives every unit carries, in the order they are rendered.
///
/// A constant rather than a sequence of `push_str` calls so that
/// [`review_least_privilege`] can be written against the same list the renderer
/// emits: a directive dropped from the unit is a directive the review then
/// reports as missing, rather than one that silently stops being checked.
pub const SYSTEMD_HARDENING: [&str; 13] = [
    "NoNewPrivileges=yes",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectSystem=strict",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes",
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
];

// -- launchd -----------------------------------------------------------------

/// Renders the launchd property list for this plan.
///
/// `KeepAlive` is a dictionary rather than `<true/>` on purpose: the
/// requirement is *restart on failure*, and a bare `KeepAlive` also restarts a
/// job that exited cleanly, which would turn a deliberate `service stop` into a
/// fight with launchd.
#[must_use]
pub fn launchd_plist(plan: &InstallPlan) -> String {
    let identity = plan.identity();
    let directories = plan.directories();
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    out.push_str("<plist version=\"1.0\">\n<dict>\n");
    out.push_str(&plist_string("Label", &identity.launchd_label()));

    out.push_str("  <key>ProgramArguments</key>\n  <array>\n");
    out.push_str(&format!(
        "    <string>{}</string>\n",
        xml_escape(&plan.binary().to_string_lossy())
    ));
    for argument in plan.arguments() {
        out.push_str(&format!(
            "    <string>{}</string>\n",
            xml_escape(&argument.to_string_lossy())
        ));
    }
    out.push_str("  </array>\n");

    out.push_str("  <key>RunAtLoad</key>\n  <true/>\n");
    out.push_str("  <key>KeepAlive</key>\n  <dict>\n");
    out.push_str("    <key>SuccessfulExit</key>\n    <false/>\n");
    out.push_str("  </dict>\n");
    out.push_str(&format!(
        "  <key>ThrottleInterval</key>\n  <integer>{}</integer>\n",
        plan.restart().delay().as_secs()
    ));
    // A background job yields CPU and I/O to whatever the operator is doing.
    // Anything above it asks the scheduler for more than a daemon needs.
    out.push_str(&plist_string("ProcessType", "Background"));
    out.push_str(&plist_string(
        "WorkingDirectory",
        &directories.state.to_string_lossy(),
    ));
    out.push_str(&plist_string(
        "StandardOutPath",
        &directories
            .logs
            .join("runner-manager.launchd.out.log")
            .to_string_lossy(),
    ));
    out.push_str(&plist_string(
        "StandardErrorPath",
        &directories
            .logs
            .join("runner-manager.launchd.err.log")
            .to_string_lossy(),
    ));

    match plan.start_mode() {
        StartMode::Boot => {
            // A LaunchDaemon runs as root unless told otherwise, and here it
            // must: the System Keychain's master key is root-only.
            out.push_str(&plist_string(
                "UserName",
                ServiceAccount::for_definition(DefinitionKind::LaunchdPlist, StartMode::Boot)
                    .as_str(),
            ));
            // A daemon has no user session and must not be given one.
            out.push_str("  <key>SessionCreate</key>\n  <false/>\n");
        }
        StartMode::Login => {
            // A LaunchAgent already runs as the operator. Naming a `UserName`
            // here would be asking launchd for an account switch a login-mode
            // registration has no reason to want.
        }
    }

    out.push_str("</dict>\n</plist>\n");
    out
}

/// One `<key>`/`<string>` pair, indented as the rest of the plist is.
fn plist_string(key: &str, value: &str) -> String {
    format!(
        "  <key>{}</key>\n  <string>{}</string>\n",
        xml_escape(key),
        xml_escape(value)
    )
}

// -- Windows Task Scheduler --------------------------------------------------

/// The account a Task Scheduler task runs as.
///
/// Task Scheduler, unlike the other three managers, needs the principal spelled
/// out in the document. Isolating the one impure step keeps
/// [`windows_scheduled_task_xml`] a pure function that every CI leg can assert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPrincipal {
    user_id: String,
}

impl TaskPrincipal {
    /// The account running this call, as `DOMAIN\user`.
    ///
    /// # Errors
    ///
    /// [`ServiceError::BinaryPath`] is not the right shape here, so this
    /// reports [`ServiceError::Control`] naming what the environment failed to
    /// say.
    pub fn current() -> Result<Self, ServiceError> {
        let user = std::env::var("USERNAME")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let Some(user) = user else {
            return Err(ServiceError::Control {
                operation: "identify the account for",
                name: SERVICE_NAME.to_string(),
                manager: "Windows Task Scheduler",
                detail: "this session reports no %USERNAME%, so there is no principal to \
                         register a logon-triggered task for"
                    .to_string(),
            });
        };
        let domain = std::env::var("USERDOMAIN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        Ok(Self {
            user_id: match domain {
                Some(domain) => format!("{domain}\\{user}"),
                None => user,
            },
        })
    }

    /// A named principal, for tests and for a caller that already knows.
    #[must_use]
    pub fn named(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
        }
    }

    /// `DOMAIN\user`.
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }
}

/// Renders the Task Scheduler document for a `--start-at login` registration.
///
/// `RunLevel` is `LeastPrivilege`, which is the whole of Windows' answer to
/// item 2 in this domain: the task runs with the operator's ordinary filtered
/// token and never with an elevated one, whatever the operator's group
/// membership.
#[must_use]
pub fn windows_scheduled_task_xml(plan: &InstallPlan, principal: &TaskPrincipal) -> String {
    let identity = plan.identity();
    let user = xml_escape(principal.user_id());
    let arguments = plan
        .arguments()
        .iter()
        .map(|argument| quote_argument(&argument.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ");
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n");
    out.push_str(
        "<Task version=\"1.4\" \
         xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n",
    );
    out.push_str("  <RegistrationInfo>\n");
    out.push_str(&format!(
        "    <Description>{}</Description>\n",
        xml_escape(identity.description())
    ));
    out.push_str(&format!(
        "    <URI>\\{}</URI>\n",
        xml_escape(identity.name())
    ));
    out.push_str("  </RegistrationInfo>\n");

    out.push_str("  <Triggers>\n    <LogonTrigger>\n");
    out.push_str("      <Enabled>true</Enabled>\n");
    out.push_str(&format!("      <UserId>{user}</UserId>\n"));
    out.push_str("    </LogonTrigger>\n  </Triggers>\n");

    out.push_str("  <Principals>\n    <Principal id=\"Author\">\n");
    out.push_str(&format!("      <UserId>{user}</UserId>\n"));
    out.push_str("      <LogonType>InteractiveToken</LogonType>\n");
    out.push_str("      <RunLevel>LeastPrivilege</RunLevel>\n");
    out.push_str("    </Principal>\n  </Principals>\n");

    out.push_str("  <Settings>\n");
    // One agent per host is `d1`'s lock; saying so here means Task Scheduler
    // refuses the second start rather than starting a process that then loses
    // the race and exits.
    out.push_str("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n");
    out.push_str("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n");
    out.push_str("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n");
    out.push_str("    <AllowHardTerminate>true</AllowHardTerminate>\n");
    out.push_str("    <StartWhenAvailable>true</StartWhenAvailable>\n");
    out.push_str("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n");
    out.push_str("    <IdleSettings>\n");
    out.push_str("      <StopOnIdleEnd>false</StopOnIdleEnd>\n");
    out.push_str("      <RestartOnIdle>false</RestartOnIdle>\n");
    out.push_str("    </IdleSettings>\n");
    out.push_str("    <AllowStartOnDemand>true</AllowStartOnDemand>\n");
    out.push_str("    <Enabled>true</Enabled>\n");
    out.push_str("    <Hidden>false</Hidden>\n");
    out.push_str("    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n");
    out.push_str("    <WakeToRun>false</WakeToRun>\n");
    // A daemon has no natural end, so any limit here would be a scheduled kill.
    out.push_str("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n");
    out.push_str("    <Priority>7</Priority>\n");
    out.push_str("    <RestartOnFailure>\n");
    out.push_str(&format!(
        "      <Interval>{}</Interval>\n",
        iso8601_minutes(
            plan.restart()
                .effective_delay(DefinitionKind::WindowsScheduledTask)
        )
    ));
    out.push_str(&format!("      <Count>{START_LIMIT_BURST}</Count>\n"));
    out.push_str("    </RestartOnFailure>\n");
    out.push_str("  </Settings>\n");

    out.push_str("  <Actions Context=\"Author\">\n    <Exec>\n");
    out.push_str(&format!(
        "      <Command>{}</Command>\n",
        xml_escape(&plan.binary().to_string_lossy())
    ));
    if !arguments.is_empty() {
        out.push_str(&format!(
            "      <Arguments>{}</Arguments>\n",
            xml_escape(&arguments)
        ));
    }
    out.push_str(&format!(
        "      <WorkingDirectory>{}</WorkingDirectory>\n",
        xml_escape(&plan.directories().state.to_string_lossy())
    ));
    out.push_str("    </Exec>\n  </Actions>\n");
    out.push_str("</Task>\n");
    out
}

/// `PT<n>M`, which is the only shape Task Scheduler accepts for a restart
/// interval. See [`RestartPolicy::effective_delay`].
fn iso8601_minutes(duration: Duration) -> String {
    format!("PT{}M", duration.as_secs() / 60)
}

/// Escapes the five XML entities. Applied to every value that reaches a plist
/// or a task document, because a Windows account name may legitimately contain
/// `&` and a path may contain `<`.
fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// The inverse of [`xml_escape`], for reading a definition back off disk.
///
/// `&amp;` is replaced last, which is the whole subtlety: replacing it first
/// would turn a literal `&amp;amp;` into `&` in two passes instead of `&amp;`
/// in one.
fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

// -- Windows Service Control Manager -----------------------------------------

/// How `CreateServiceW` should be called, in a form that can be reviewed,
/// asserted, and printed on any platform.
///
/// The Windows backend builds its `ServiceInfo` from **this** value rather than
/// from the plan, so the descriptor a Linux CI leg asserts and the parameters a
/// Windows host registers cannot drift apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsServiceSpec {
    /// The service name.
    pub name: String,
    /// What `services.msc` shows.
    pub display_name: String,
    /// The one-line description.
    pub description: String,
    /// `true` for `SERVICE_AUTO_START`, `false` for `SERVICE_DEMAND_START`.
    pub automatic_start: bool,
    /// The account, or `None` for `LocalSystem`, which is what
    /// `CreateServiceW` takes a null `lpServiceStartName` to mean.
    pub account: Option<String>,
    /// The full launch command, quoted.
    pub command_line: String,
    /// The restart-on-failure policy.
    pub restart: RestartPolicy,
}

/// Derives the Windows service parameters from a plan.
#[must_use]
pub fn windows_service_spec(plan: &InstallPlan) -> WindowsServiceSpec {
    WindowsServiceSpec {
        name: plan.identity().name().to_string(),
        display_name: plan.identity().display_name().to_string(),
        description: plan.identity().description().to_string(),
        // Only a boot-mode registration is a service at all; a login-mode one
        // is a scheduled task. So an automatic start is the only kind here, and
        // the field exists because the privileged tests register an on-demand
        // fixture rather than one that starts with the test machine.
        automatic_start: plan.start_mode() == StartMode::Boot && !plan.is_on_demand(),
        account: match ServiceAccount::for_definition(
            DefinitionKind::WindowsService,
            plan.start_mode(),
        ) {
            // `None` means LocalSystem to `CreateServiceW`, and naming it
            // explicitly would be one more string to spell right.
            ServiceAccount::LocalSystem => None,
            other => Some(other.as_str().to_string()),
        },
        command_line: plan.command_line(),
        restart: plan.restart(),
    }
}

/// Renders the descriptor [`review_least_privilege`] reads and `service status`
/// can print.
#[must_use]
fn windows_service_descriptor(plan: &InstallPlan) -> String {
    let spec = windows_service_spec(plan);
    let mut out = String::new();
    out.push_str("[windows-service]\n");
    out.push_str(&format!("Name={}\n", spec.name));
    out.push_str(&format!("DisplayName={}\n", spec.display_name));
    out.push_str(&format!("Description={}\n", spec.description));
    // OWN_PROCESS and never INTERACTIVE_PROCESS: an interactive service would
    // put a process this product controls on the operator's desktop, which is
    // both deprecated by Windows and more than the requirement asks for.
    out.push_str("ServiceType=OWN_PROCESS\n");
    out.push_str(&format!(
        "StartType={}\n",
        if spec.automatic_start {
            "AutoStart"
        } else {
            "OnDemand"
        }
    ));
    out.push_str("ErrorControl=Normal\n");
    out.push_str(&format!(
        "Account={}\n",
        spec.account
            .as_deref()
            .unwrap_or(ServiceAccount::LocalSystem.as_str())
    ));
    out.push_str(&format!("CommandLine={}\n", spec.command_line));
    out.push_str(&format!(
        "FailureActionRestartDelaySecs={}\n",
        spec.restart.delay().as_secs()
    ));
    out.push_str(&format!(
        "FailureActionsResetPeriodSecs={}\n",
        spec.restart.reset_after().as_secs()
    ));
    // Without this flag the Service Control Manager applies failure actions
    // only to a crash, and a daemon that exits non-zero after failing to reach
    // GitHub is not a crash.
    out.push_str("FailureActionsOnNonCrashFailures=true\n");
    out.push_str(&format!(
        "ReadWritePaths={}\n",
        plan.directories()
            .all()
            .iter()
            .map(|path| quote_argument(&path.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(" ")
    ));
    out
}

// ---------------------------------------------------------------------------
// The least-privilege review
// ---------------------------------------------------------------------------

/// Whether a finding is about too much authority or too little.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// The definition grants more than `05-infrastructure.md` item 2 asks for.
    /// This is what makes a review fail.
    Excess,
    /// The definition does not grant something the daemon needs, or does not
    /// state something the review cannot verify without.
    Shortfall,
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Excess => "excess",
            Self::Shortfall => "shortfall",
        })
    }
}

/// One thing the review has to say about a definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeFinding {
    /// Excess or shortfall.
    pub kind: FindingKind,
    /// The directive, key, or element it is about.
    pub subject: String,
    /// What is wrong with it, in terms an operator can act on.
    pub detail: String,
}

impl fmt::Display for PrivilegeFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} -- {}", self.kind, self.subject, self.detail)
    }
}

/// What a definition actually grants, measured against the requirement.
///
/// `05-infrastructure.md` item 2 and `07-security.md`'s release gate
/// (*"Service account permissions are documented and verified least
/// privilege"*) are the same requirement stated twice, and this is the
/// verification half. The documentation half is `docs/service-account.md`.
///
/// The review reads the **rendered text**, not the plan it came from. That is
/// deliberate and it is the only version of this check worth having: a review
/// that re-derived its expectations from the same values the renderer used
/// would agree with the renderer by construction and could never fail. Reading
/// the text means a hand-edited unit on a real host is reviewed as it is, and
/// means a test can widen a definition and watch this say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeReview {
    kind: DefinitionKind,
    account: ServiceAccount,
    controls: Vec<String>,
    findings: Vec<PrivilegeFinding>,
}

impl PrivilegeReview {
    /// Whether the definition grants nothing beyond the requirement.
    #[must_use]
    pub fn is_least_privilege(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|finding| finding.kind == FindingKind::Excess)
    }

    /// Everything the review found, excesses and shortfalls together.
    #[must_use]
    pub fn findings(&self) -> &[PrivilegeFinding] {
        &self.findings
    }

    /// Only the excesses — the findings that make [`Self::is_least_privilege`]
    /// false.
    #[must_use]
    pub fn excesses(&self) -> Vec<&PrivilegeFinding> {
        self.findings
            .iter()
            .filter(|finding| finding.kind == FindingKind::Excess)
            .collect()
    }

    /// The controls the definition was confirmed to carry.
    ///
    /// Present so that a passing review says *what it checked* rather than only
    /// that it passed. A check that reports nothing when it succeeds is
    /// indistinguishable from a check that did not run.
    #[must_use]
    pub fn controls(&self) -> &[String] {
        &self.controls
    }

    /// The account the registration runs under, and why it is the minimum.
    #[must_use]
    pub const fn account(&self) -> &ServiceAccount {
        &self.account
    }

    /// Which platform's definition was reviewed.
    #[must_use]
    pub const fn kind(&self) -> DefinitionKind {
        self.kind
    }
}

impl fmt::Display for PrivilegeReview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} runs as {} ({})",
            self.kind,
            self.account,
            self.account.justification()
        )?;
        for control in &self.controls {
            writeln!(f, "  confirmed  {control}")?;
        }
        for finding in &self.findings {
            writeln!(f, "  {finding}")?;
        }
        if self.is_least_privilege() {
            write!(f, "  verdict    least privilege")
        } else {
            write!(
                f,
                "  verdict    NOT least privilege: {} excess(es)",
                self.excesses().len()
            )
        }
    }
}

/// Reads a definition back and reports what it grants.
///
/// `plan` supplies only the two things the text cannot: the four directories
/// the registration is *allowed* to write, and the start mode, which decides
/// which account is the minimum.
#[must_use]
pub fn review_least_privilege(
    definition: &ServiceDefinition,
    plan: &InstallPlan,
) -> PrivilegeReview {
    let mut controls = Vec::new();
    let mut findings = Vec::new();
    match definition.kind() {
        DefinitionKind::SystemdUnit => {
            review_systemd(definition.text(), plan, &mut controls, &mut findings);
        }
        DefinitionKind::LaunchdPlist => {
            review_launchd(definition.text(), plan, &mut controls, &mut findings);
        }
        DefinitionKind::WindowsScheduledTask => {
            review_scheduled_task(definition.text(), &mut controls, &mut findings);
        }
        DefinitionKind::WindowsService => {
            review_windows_service(definition.text(), plan, &mut controls, &mut findings);
        }
    }
    PrivilegeReview {
        kind: definition.kind(),
        // The definition's account, not the plan's: a Linux CI leg reviewing the
        // Windows descriptor must report `LocalSystem`, which is the account
        // that descriptor registers, and not `root`, which is the account this
        // leg's own host would use.
        account: ServiceAccount::for_definition(definition.kind(), plan.start_mode()),
        controls,
        findings,
    }
}

/// Every writable path a definition may name, as the strings it names them by.
fn permitted_paths(plan: &InstallPlan) -> Vec<String> {
    plan.directories()
        .all()
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}

/// Whether two path spellings name the same place on **this host's**
/// filesystem. Case-insensitive on Windows, exact elsewhere.
///
/// For a rendered definition use [`same_path_for`] instead: which comparison is
/// right there follows the platform the definition is *for*, and every leg of
/// the CI matrix reviews all four.
fn same_path_text(left: &str, right: &str) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

/// Whether two path spellings name the same place on the platform a given
/// definition targets.
fn same_path_for(kind: DefinitionKind, left: &str, right: &str) -> bool {
    match kind {
        DefinitionKind::WindowsService | DefinitionKind::WindowsScheduledTask => {
            left.eq_ignore_ascii_case(right)
        }
        DefinitionKind::LaunchdPlist | DefinitionKind::SystemdUnit => left == right,
    }
}

/// Checks a `ReadWritePaths`-style list against the four permitted directories.
fn review_writable_paths(
    kind: DefinitionKind,
    subject: &str,
    listed: &[String],
    plan: &InstallPlan,
    controls: &mut Vec<String>,
    findings: &mut Vec<PrivilegeFinding>,
) {
    let permitted = permitted_paths(plan);
    for entry in listed {
        if !permitted
            .iter()
            .any(|allowed| same_path_for(kind, allowed, entry))
        {
            findings.push(PrivilegeFinding {
                kind: FindingKind::Excess,
                subject: subject.to_string(),
                detail: format!(
                    "{entry} is writable but is not one of this registration's four \
                     application-data directories"
                ),
            });
        }
    }
    for allowed in &permitted {
        if !listed
            .iter()
            .any(|entry| same_path_for(kind, allowed, entry))
        {
            findings.push(PrivilegeFinding {
                kind: FindingKind::Shortfall,
                subject: subject.to_string(),
                detail: format!(
                    "{allowed} is one of this registration's directories but is not writable, \
                     so the daemon cannot use it"
                ),
            });
        }
    }
    if listed.len() == permitted.len() && findings.iter().all(|f| f.subject != subject) {
        controls.push(format!(
            "{subject} names exactly the four application-data directories"
        ));
    }
}

/// The one inbound-surface rule, applied to whichever platform names it.
///
/// `07-security.md` handling rule 2: *"The product exposes no inbound HTTP,
/// socket, or RPC surface anywhere, in any command."* A definition that asks the
/// service manager to open a socket or publish a Mach service on the daemon's
/// behalf would create exactly that surface without a line of product code
/// changing, which is why it is checked here and not only in review.
fn review_inbound_surface(
    text: &str,
    markers: &[(&str, &str)],
    controls: &mut Vec<String>,
    findings: &mut Vec<PrivilegeFinding>,
) {
    let mut clean = true;
    for (marker, detail) in markers {
        if text.contains(marker) {
            clean = false;
            findings.push(PrivilegeFinding {
                kind: FindingKind::Excess,
                subject: (*marker).to_string(),
                detail: (*detail).to_string(),
            });
        }
    }
    if clean {
        controls.push(
            "no socket, listener, or Mach service is published on the daemon's behalf".to_string(),
        );
    }
}

fn review_systemd(
    text: &str,
    plan: &InstallPlan,
    controls: &mut Vec<String>,
    findings: &mut Vec<PrivilegeFinding>,
) {
    let directives = ini_directives(text, "Service");
    for expected in SYSTEMD_HARDENING {
        let (key, value) = expected
            .split_once('=')
            .expect("every hardening directive is written as key=value");
        match directives.get(key) {
            Some(actual) if actual == value => controls.push((*expected).to_string()),
            Some(actual) => findings.push(PrivilegeFinding {
                kind: FindingKind::Excess,
                subject: key.to_string(),
                detail: format!(
                    "is `{actual}`, not `{value}`, so the unit keeps authority the \
                                 requirement does not ask for"
                ),
            }),
            None => findings.push(PrivilegeFinding {
                kind: FindingKind::Excess,
                subject: key.to_string(),
                detail: format!(
                    "is absent, so the unit inherits systemd's default rather than `{value}`"
                ),
            }),
        }
    }

    match directives.get("ReadWritePaths") {
        Some(value) => {
            let listed = split_quoted(value);
            review_writable_paths(
                DefinitionKind::SystemdUnit,
                "ReadWritePaths",
                &listed,
                plan,
                controls,
                findings,
            );
        }
        None => findings.push(PrivilegeFinding {
            kind: FindingKind::Shortfall,
            subject: "ReadWritePaths".to_string(),
            detail: "is absent, so `ProtectSystem=strict` leaves the daemon nowhere to write"
                .to_string(),
        }),
    }

    // `User=` on a system unit is an escalation only in the other direction, so
    // what is checked is the pair systemd actually treats as privileged.
    if directives.contains_key("PrivateUsers")
        && directives.get("PrivateUsers") == Some(&"no".to_string())
    {
        findings.push(PrivilegeFinding {
            kind: FindingKind::Excess,
            subject: "PrivateUsers".to_string(),
            detail: "is explicitly disabled, which is broader than leaving it at systemd's default"
                .to_string(),
        });
    }

    review_inbound_surface(
        text,
        &[
            (
                "ListenStream=",
                "asks systemd to open a listening socket for this service, which \
                 07-security.md rule 2 forbids the product to have",
            ),
            (
                "ListenDatagram=",
                "asks systemd to open a listening socket for this service, which \
                 07-security.md rule 2 forbids the product to have",
            ),
        ],
        controls,
        findings,
    );
}

fn review_launchd(
    text: &str,
    plan: &InstallPlan,
    controls: &mut Vec<String>,
    findings: &mut Vec<PrivilegeFinding>,
) {
    match plist_string_value(text, "ProcessType").as_deref() {
        Some("Background") => controls.push("ProcessType=Background".to_string()),
        Some(other) => findings.push(PrivilegeFinding {
            kind: FindingKind::Excess,
            subject: "ProcessType".to_string(),
            detail: format!(
                "is `{other}`, which asks the scheduler for more CPU and I/O than a background \
                 daemon needs"
            ),
        }),
        None => findings.push(PrivilegeFinding {
            kind: FindingKind::Excess,
            subject: "ProcessType".to_string(),
            detail: "is absent, so launchd applies its `Standard` default rather than \
                     `Background`"
                .to_string(),
        }),
    }

    match plan.start_mode() {
        StartMode::Boot => {
            if plist_bool_value(text, "SessionCreate") == Some(true) {
                findings.push(PrivilegeFinding {
                    kind: FindingKind::Excess,
                    subject: "SessionCreate".to_string(),
                    detail: "asks launchd to create a security session for a job that runs \
                             outside every login session and has no use for one"
                        .to_string(),
                });
            } else {
                controls.push("SessionCreate is not requested".to_string());
            }
            match plist_string_value(text, "UserName").as_deref() {
                Some("root") => {
                    controls.push("UserName=root, stated rather than inherited".to_string())
                }
                Some(other) => findings.push(PrivilegeFinding {
                    kind: FindingKind::Shortfall,
                    subject: "UserName".to_string(),
                    detail: format!(
                        "is `{other}`, which cannot unlock the System Keychain: \
                         /var/db/SystemKey is root-only, so the daemon would start and then \
                         find no credential"
                    ),
                }),
                None => findings.push(PrivilegeFinding {
                    kind: FindingKind::Shortfall,
                    subject: "UserName".to_string(),
                    detail: "is absent, so the account is launchd's implicit default and this \
                             review cannot confirm it"
                        .to_string(),
                }),
            }
        }
        StartMode::Login => {
            if let Some(named) = plist_string_value(text, "UserName") {
                findings.push(PrivilegeFinding {
                    kind: FindingKind::Excess,
                    subject: "UserName".to_string(),
                    detail: format!(
                        "names `{named}` in a LaunchAgent, which already runs as the operator; \
                         naming an account here asks launchd for a switch a login-mode \
                         registration has no reason to want"
                    ),
                });
            } else {
                controls
                    .push("no UserName: the agent runs as the operator and no other".to_string());
            }
        }
    }

    review_inbound_surface(
        text,
        &[
            (
                "<key>Sockets</key>",
                "asks launchd to open a socket for this job, which 07-security.md rule 2 \
                 forbids the product to have",
            ),
            (
                "<key>MachServices</key>",
                "publishes a Mach service, which is the RPC surface 07-security.md rule 2 \
                 forbids the product to have",
            ),
        ],
        controls,
        findings,
    );
}

fn review_scheduled_task(
    text: &str,
    controls: &mut Vec<String>,
    findings: &mut Vec<PrivilegeFinding>,
) {
    match xml_value(text, "RunLevel").as_deref() {
        Some("LeastPrivilege") => controls.push("RunLevel=LeastPrivilege".to_string()),
        Some(other) => findings.push(PrivilegeFinding {
            kind: FindingKind::Excess,
            subject: "RunLevel".to_string(),
            detail: format!(
                "is `{other}`, so the task runs with an elevated token whenever the operator is \
                 an administrator"
            ),
        }),
        None => findings.push(PrivilegeFinding {
            kind: FindingKind::Excess,
            subject: "RunLevel".to_string(),
            detail: "is absent, so Task Scheduler decides the token rather than the definition"
                .to_string(),
        }),
    }

    match xml_value(text, "LogonType").as_deref() {
        Some("InteractiveToken") => controls.push("LogonType=InteractiveToken".to_string()),
        Some(other) => findings.push(PrivilegeFinding {
            kind: FindingKind::Excess,
            subject: "LogonType".to_string(),
            detail: format!(
                "is `{other}`, which asks Windows to store or synthesise a credential for this \
                 task; an interactive token needs neither"
            ),
        }),
        None => findings.push(PrivilegeFinding {
            kind: FindingKind::Shortfall,
            subject: "LogonType".to_string(),
            detail: "is absent, so this review cannot confirm that no credential is stored"
                .to_string(),
        }),
    }
}

fn review_windows_service(
    text: &str,
    plan: &InstallPlan,
    controls: &mut Vec<String>,
    findings: &mut Vec<PrivilegeFinding>,
) {
    let directives = ini_directives(text, "windows-service");

    match directives.get("ServiceType").map(String::as_str) {
        Some("OWN_PROCESS") => controls.push("ServiceType=OWN_PROCESS".to_string()),
        Some(other) => findings.push(PrivilegeFinding {
            kind: FindingKind::Excess,
            subject: "ServiceType".to_string(),
            detail: format!(
                "is `{other}`; an interactive or shared-process service reaches further than a \
                 daemon that only talks to GitHub over HTTPS"
            ),
        }),
        None => findings.push(PrivilegeFinding {
            kind: FindingKind::Shortfall,
            subject: "ServiceType".to_string(),
            detail: "is absent, so this review cannot confirm the service is not interactive"
                .to_string(),
        }),
    }

    // The account is not a free choice on Windows: `d2`'s DACL decides it. What
    // the review can check is that the definition names the one account that
    // DACL admits, and no broader one.
    match directives.get("Account").map(String::as_str) {
        Some(account) if account == ServiceAccount::LocalSystem.as_str() => {
            controls.push(format!(
                "Account={account}: the only stock account the machine-scoped store's DACL \
                 (SY, BA, OW) admits"
            ));
        }
        Some(other) => findings.push(PrivilegeFinding {
            kind: FindingKind::Shortfall,
            subject: "Account".to_string(),
            detail: format!(
                "is `{other}`, which the machine-scoped store's DACL does not name, so the \
                 daemon would start and then find no credential. Widening that DACL is not this \
                 registration's to do: an ACE reaching `{other}` would also reach every other \
                 service running under it"
            ),
        }),
        None => findings.push(PrivilegeFinding {
            kind: FindingKind::Shortfall,
            subject: "Account".to_string(),
            detail: "is absent, so this review cannot confirm which account was registered"
                .to_string(),
        }),
    }

    match directives.get("ReadWritePaths") {
        Some(value) => {
            let listed = split_quoted(value);
            review_writable_paths(
                DefinitionKind::WindowsService,
                "ReadWritePaths",
                &listed,
                plan,
                controls,
                findings,
            );
        }
        None => findings.push(PrivilegeFinding {
            kind: FindingKind::Shortfall,
            subject: "ReadWritePaths".to_string(),
            detail: "is absent, so the directories the service was installed against are not \
                     recorded"
                .to_string(),
        }),
    }
}

// -- parsing helpers ---------------------------------------------------------

/// Reads `key=value` lines out of one `[section]` of an INI-shaped document.
///
/// systemd's unit format and this module's Windows descriptor are both this
/// shape. A repeated key takes its last value, which is systemd's own rule for
/// every directive here.
fn ini_directives(text: &str, section: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            inside = &line[1..line.len() - 1] == section;
            continue;
        }
        if !inside || line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            out.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    out
}

/// Splits a whitespace-separated list that may contain arguments quoted by
/// [`quote_argument`].
fn split_quoted(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = value.trim();
    while !rest.is_empty() {
        if rest.starts_with('"') {
            // `executable_from_command_line` already implements Windows' quoting
            // rules; reuse it rather than write a second, subtly different one.
            if let Some(parsed) = executable_from_command_line(rest) {
                out.push(parsed.to_string_lossy().into_owned());
            }
            // Advance past the closing quote.
            let mut depth = 0usize;
            let mut end = rest.len();
            for (index, c) in rest.char_indices() {
                match c {
                    '\\' => depth += 1,
                    '"' => {
                        if depth.is_multiple_of(2) && index > 0 {
                            end = index + 1;
                            break;
                        }
                        depth = 0;
                    }
                    _ => depth = 0,
                }
            }
            rest = rest[end..].trim_start();
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            out.push(rest[..end].to_string());
            rest = rest[end..].trim_start();
        }
    }
    out
}

/// The text between `<tag>` and `</tag>`, unescaped, for the small, known
/// documents this module renders. Not a general XML parser and does not pretend
/// to be one.
fn xml_value(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(xml_unescape(text[start..end].trim()))
}

/// The `<string>` that follows `<key>key</key>` in a property list.
fn plist_value_after_key<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("<key>{key}</key>");
    let start = text.find(&marker)? + marker.len();
    Some(text[start..].trim_start())
}

fn plist_string_value(text: &str, key: &str) -> Option<String> {
    let rest = plist_value_after_key(text, key)?;
    if !rest.starts_with("<string>") {
        return None;
    }
    xml_value(rest, "string")
}

fn plist_bool_value(text: &str, key: &str) -> Option<bool> {
    let rest = plist_value_after_key(text, key)?;
    if rest.starts_with("<true/>") {
        Some(true)
    } else if rest.starts_with("<false/>") {
        Some(false)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// The install record
// ---------------------------------------------------------------------------

/// The version of [`InstallRecord`] on disk.
///
/// Bumped when a record written by an older version can no longer be read.
/// `service status` reports an unreadable record as a problem with a remedy
/// rather than failing, because the remedy — uninstall and install again —
/// touches no configuration, no secret and no cache.
pub const RECORD_SCHEMA_VERSION: u32 = 1;

/// What `service install` wrote down, and what `service status` reads back.
///
/// This is the *record* half of `05-infrastructure.md` item 6. The service
/// manager also knows the binary path, and the two are compared: a registration
/// whose command line no longer matches the record is a registration something
/// else has edited, and saying so is more useful than picking one of them to
/// believe.
///
/// It holds no credential. The nearest thing is the *location* of the secret
/// store, which `d2` publishes for `host show` to print, and even that is
/// derived rather than stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallRecord {
    /// [`RECORD_SCHEMA_VERSION`] at the time of writing.
    pub schema_version: u32,
    /// What the operating system calls the registration.
    pub service_name: String,
    /// Which service manager holds it.
    pub manager: String,
    /// Boot or login.
    pub start_mode: StartMode,
    /// The account it runs under.
    pub account: ServiceAccount,
    /// **The resolved absolute path of the binary at install time.** Item 6.
    pub binary: PathBuf,
    /// Where [`Self::binary`] was copied from, when it is a copy.
    ///
    /// `#[serde(default)]` rather than a schema bump: a record written before
    /// this existed is still readable, and reads as `None`. That is not a
    /// silent downgrade — `None` means the registration names a package
    /// manager's own file, which is the layout that cannot be upgraded while
    /// the service runs, and `service status` says so by name.
    #[serde(default)]
    pub source_binary: Option<PathBuf>,
    /// The arguments it was registered with.
    pub arguments: Vec<String>,
    /// The restart-on-failure delay.
    pub restart_delay_secs: u64,
    /// How long it must run before the failure count resets.
    pub restart_reset_secs: u64,
    /// The rotating diagnostic log's stem. Item 4.
    pub log_file: PathBuf,
    /// Whether the manager was asked not to start this by itself. Always
    /// `false` for a registration an operator made; see
    /// [`InstallRequest::started_on_demand`].
    ///
    /// `#[serde(default)]` so that a record missing the field is rejected by
    /// the schema check below, with its remedy, rather than by a parse error
    /// that names a field an operator has never heard of.
    #[serde(default)]
    pub starts_on_demand: bool,
    /// Where the platform's definition file was written, when there is one.
    pub definition_path: Option<PathBuf>,
    /// When the registration was made.
    pub installed_at: DateTime<Utc>,
    /// Which build of the product made it.
    pub installed_by_version: String,
    // A TOML table has to follow every scalar at its level, so this field is
    // last by necessity rather than by taste.
    /// The four directories the registration was installed against. Item 2's
    /// *"configured cache and runtime directories"*.
    pub directories: ServiceDirectories,
}

impl InstallRecord {
    /// Where the record lives, given this host's directories.
    #[must_use]
    pub fn path(paths: &AppPaths) -> PathBuf {
        paths.config_dir().join(RECORD_FILE)
    }

    /// Builds the record for a plan that has just been applied.
    #[must_use]
    pub fn of(plan: &InstallPlan, definition: &ServiceDefinition, at: DateTime<Utc>) -> Self {
        Self {
            schema_version: RECORD_SCHEMA_VERSION,
            service_name: plan.identity().name().to_string(),
            manager: definition.kind().manager().to_string(),
            start_mode: plan.start_mode(),
            account: plan.account().clone(),
            binary: plan.binary().to_path_buf(),
            arguments: plan
                .arguments()
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect(),
            restart_delay_secs: plan.restart().delay().as_secs(),
            restart_reset_secs: plan.restart().reset_after().as_secs(),
            starts_on_demand: plan.is_on_demand(),
            source_binary: plan.source_binary().map(Path::to_path_buf),
            log_file: plan.directories().log_file(),
            definition_path: definition.install_path().map(Path::to_path_buf),
            installed_at: at,
            installed_by_version: env!("CARGO_PKG_VERSION").to_string(),
            directories: plan.directories().clone(),
        }
    }

    /// The restart policy this record describes, or [`RestartPolicy::default`]
    /// when the recorded numbers are outside the supported range — which can
    /// only happen to a record something else has edited.
    #[must_use]
    pub fn restart(&self) -> RestartPolicy {
        RestartPolicy::new(
            Duration::from_secs(self.restart_delay_secs),
            Duration::from_secs(self.restart_reset_secs),
        )
        .unwrap_or_default()
    }

    /// Reads the record, or reports that there is none.
    ///
    /// `Ok(None)` means no registration was made by this product on this host.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Record`] when the file exists and cannot be read, and
    /// [`ServiceError::RecordUnreadable`] when it is not a record this version
    /// understands.
    pub fn read(paths: &AppPaths) -> Result<Option<Self>, ServiceError> {
        let path = Self::path(paths);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(ServiceError::Record {
                    operation: "read",
                    path,
                    detail: error.to_string(),
                });
            }
        };
        let record: Self =
            toml::from_str(&text).map_err(|error| ServiceError::RecordUnreadable {
                path: path.clone(),
                detail: error.to_string(),
            })?;
        if record.schema_version != RECORD_SCHEMA_VERSION {
            return Err(ServiceError::RecordUnreadable {
                path,
                detail: format!(
                    "it declares schema version {} and this build reads version {}",
                    record.schema_version, RECORD_SCHEMA_VERSION
                ),
            });
        }
        Ok(Some(record))
    }

    /// Writes the record, replacing whatever was there.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Record`].
    pub fn write(&self, paths: &AppPaths) -> Result<(), ServiceError> {
        use std::io::Write as _;

        let path = Self::path(paths);
        let text = toml::to_string_pretty(self).map_err(|error| ServiceError::Record {
            operation: "encode",
            path: path.clone(),
            detail: error.to_string(),
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| ServiceError::Record {
                operation: "write",
                path: path.clone(),
                detail: error.to_string(),
            })?;
        }
        let parent = path.parent().ok_or_else(|| ServiceError::Record {
            operation: "write",
            path: path.clone(),
            detail: "the record path has no parent directory".to_string(),
        })?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|error| ServiceError::Record {
                operation: "write",
                path: path.clone(),
                detail: error.to_string(),
            })?;
        temporary
            .write_all(text.as_bytes())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| ServiceError::Record {
                operation: "write",
                path: path.clone(),
                detail: error.to_string(),
            })?;
        temporary
            .persist(&path)
            .map(|_| ())
            .map_err(|error| ServiceError::Record {
                operation: "write",
                path,
                detail: error.error.to_string(),
            })
    }

    /// Removes the record. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Record`].
    pub fn remove(paths: &AppPaths) -> Result<bool, ServiceError> {
        let path = Self::path(paths);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(ServiceError::Record {
                operation: "remove",
                path,
                detail: error.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// The last successful GitHub contact
// ---------------------------------------------------------------------------

/// The heartbeat file's own schema version.
const CONTACT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContactRecord {
    schema_version: u32,
    last_success: DateTime<Utc>,
}

/// Records that GitHub was reached successfully, for `service status` to
/// report.
///
/// # The contract, for `f3` and for the agent
///
/// Journey 5 step 4 requires `service status` to report *"the last successful
/// GitHub contact"*, and `service status` runs in the operator's terminal while
/// the daemon runs in a service. They share no memory, so the fact has to be on
/// disk, and this is the file. **The daemon calls this after each successful
/// GitHub call; nothing else writes it.**
///
/// It is a single timestamp and deliberately not a log: an operator asking this
/// question wants to know whether the agent is alive and reaching GitHub *now*,
/// and a value that is minutes old answers it. Writing it is a whole-file
/// replace through a temporary in the same directory, so a status command can
/// never read a half-written timestamp.
///
/// # Errors
///
/// [`ServiceError::Record`] when `state/` cannot be written.
pub fn record_github_contact(paths: &AppPaths, at: DateTime<Utc>) -> Result<(), ServiceError> {
    let path = contact_path(paths);
    let record = ContactRecord {
        schema_version: CONTACT_SCHEMA_VERSION,
        last_success: at,
    };
    let failed = |detail: String| ServiceError::Record {
        operation: "write",
        path: path.clone(),
        detail,
    };
    let text = toml::to_string_pretty(&record).map_err(|error| failed(error.to_string()))?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(directory).map_err(|error| failed(error.to_string()))?;
    let temporary = path.with_extension("toml.new");
    std::fs::write(&temporary, text).map_err(|error| failed(error.to_string()))?;
    std::fs::rename(&temporary, &path).map_err(|error| failed(error.to_string()))
}

/// Reads the last successful GitHub contact, or reports that none was recorded.
///
/// `Ok(None)` is the honest answer on a host whose agent has never run, and it
/// is what `service status` prints rather than a zero timestamp.
///
/// # Errors
///
/// [`ServiceError::Record`] when the file exists and cannot be read or parsed.
/// A malformed heartbeat is reported rather than treated as absence: absence
/// means *"the agent has never reached GitHub"*, and reporting a parse failure
/// as that would be a wrong answer to the question Journey 5 asks.
pub fn last_github_contact(paths: &AppPaths) -> Result<Option<DateTime<Utc>>, ServiceError> {
    let path = contact_path(paths);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ServiceError::Record {
                operation: "read",
                path,
                detail: error.to_string(),
            });
        }
    };
    let record: ContactRecord = toml::from_str(&text).map_err(|error| ServiceError::Record {
        operation: "read",
        path,
        detail: error.to_string(),
    })?;
    Ok(Some(record.last_success))
}

/// Where the heartbeat lives.
#[must_use]
pub fn contact_path(paths: &AppPaths) -> PathBuf {
    paths.state_dir().join(CONTACT_FILE)
}

// ---------------------------------------------------------------------------
// The recorded binary path
// ---------------------------------------------------------------------------

/// What became of the absolute path `install` recorded.
///
/// `05-infrastructure.md` item 6 in one type. Three of the four variants are
/// errors, and `service status` reports them as errors rather than as health —
/// which is the whole point, because the npm case produces a service that looks
/// installed, is registered, and cannot start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryPath {
    /// The recorded path is a file, and the service manager still starts it.
    Current {
        /// The path.
        path: PathBuf,
    },
    /// **Nothing is at the recorded path.**
    ///
    /// This is the npm upgrade: `npm i -g @ivan-murzak/runner-manager` puts the binary under
    /// the active Node installation's global prefix, and switching Node versions
    /// with `nvm`, `fnm`, or `volta` moves that prefix. The service is still
    /// registered, still set to start at boot, and starts nothing.
    Missing {
        /// The path the record names.
        recorded: PathBuf,
    },
    /// Something is at the recorded path, but it is not a file the service
    /// manager could start.
    NotExecutable {
        /// The path the record names.
        recorded: PathBuf,
        /// What is there instead.
        detail: String,
    },
    /// The record and the service manager name different binaries.
    Diverged {
        /// What the record says.
        recorded: PathBuf,
        /// What the service manager is registered to start.
        registered: PathBuf,
    },
}

impl BinaryPath {
    /// Whether this is a state `service status` must report as an error.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        !matches!(self, Self::Current { .. })
    }

    /// The path the record names, whatever state it is in.
    #[must_use]
    pub fn recorded(&self) -> &Path {
        match self {
            Self::Current { path } => path,
            Self::Missing { recorded }
            | Self::NotExecutable { recorded, .. }
            | Self::Diverged { recorded, .. } => recorded,
        }
    }
}

impl fmt::Display for BinaryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current { path } => write!(f, "{}", path.display()),
            Self::Missing { recorded } => write!(
                f,
                "{} -- STALE: nothing is at the recorded path, so the service cannot start. A \
                 package manager that moved the binary is the usual cause; an `npm i -g` \
                 installation moves with the active Node version. Run `service install` again \
                 from the binary that is now installed.",
                recorded.display()
            ),
            Self::NotExecutable { recorded, detail } => write!(
                f,
                "{} -- STALE: {detail}, so the service cannot start. Run `service install` again \
                 from the installed binary.",
                recorded.display()
            ),
            Self::Diverged {
                recorded,
                registered,
            } => write!(
                f,
                "{} -- STALE: the service manager is registered to start {} instead. Something \
                 has edited the registration since it was installed. Run `service uninstall` and \
                 `service install`; neither touches configuration, secrets, or the cache.",
                recorded.display(),
                registered.display()
            ),
        }
    }
}

/// Decides what became of a recorded path.
///
/// `registered` is what the service manager says it will start, when the
/// platform can be asked. Order matters and is deliberate: **absence is checked
/// first**, because a missing binary is the failure item 6 exists for and an
/// operator hearing "the registration disagrees with the record" about a file
/// that is not there would be sent to the wrong problem.
#[must_use]
pub fn inspect_binary(recorded: &Path, registered: Option<&Path>) -> BinaryPath {
    match std::fs::metadata(recorded) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return BinaryPath::Missing {
                recorded: recorded.to_path_buf(),
            };
        }
        Err(error) => {
            return BinaryPath::NotExecutable {
                recorded: recorded.to_path_buf(),
                detail: format!("it cannot be inspected ({error})"),
            };
        }
        Ok(metadata) if !metadata.is_file() => {
            return BinaryPath::NotExecutable {
                recorded: recorded.to_path_buf(),
                detail: "what is there is not a file".to_string(),
            };
        }
        Ok(_) => {}
    }
    if let Some(registered) = registered
        && !same_path_text(&recorded.to_string_lossy(), &registered.to_string_lossy())
    {
        return BinaryPath::Diverged {
            recorded: recorded.to_path_buf(),
            registered: registered.to_path_buf(),
        };
    }
    BinaryPath::Current {
        path: recorded.to_path_buf(),
    }
}

// ---------------------------------------------------------------------------
// The control seam
// ---------------------------------------------------------------------------

/// What a service manager says about a registration it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// Which manager holds it, which is also what decides the start mode:
    /// a Windows service is a boot registration and a Task Scheduler task is a
    /// login one; a LaunchDaemon and a system unit are boot, a LaunchAgent and
    /// a user unit are login.
    pub manager: DefinitionKind,
    /// The start mode the *domain* it was found in implies.
    pub start_mode: StartMode,
    /// The full command line, as the manager stores it.
    pub command_line: String,
    /// The account it runs under, when the manager reports one.
    pub account: Option<String>,
    /// Whether it is running now.
    pub running: bool,
    /// Whether it will start by itself.
    ///
    /// Distinct from [`Registration::start_mode`]: a Windows service can be
    /// registered in the boot domain and still be set to `demand` start, which
    /// is a service that exists, looks installed, and does not come back after
    /// a reboot.
    pub starts_automatically: bool,
    /// The restart-on-failure delay the manager reports, when it reports one.
    ///
    /// The *delay* rather than the whole [`RestartPolicy`], because that is the
    /// half every one of the four managers can be asked for. The failure-count
    /// reset window has no representation at all in Task Scheduler or launchd,
    /// so a `RestartPolicy` read back from them would carry one number the
    /// manager reported and one this module invented — and a comparison against
    /// an invented number is a comparison that cannot fail.
    pub restart_delay: Option<Duration>,
}

impl Registration {
    /// The executable the manager will start, parsed out of the command line.
    #[must_use]
    pub fn binary(&self) -> Option<PathBuf> {
        executable_from_command_line(&self.command_line)
    }
}

/// One platform's service manager, for one start-mode domain.
///
/// Every method takes the identity rather than storing it, so one control can
/// answer about the product's registration and about a test fixture's without
/// either being able to reach the other by accident.
pub trait ServiceControl: fmt::Debug {
    /// Which manager this is.
    fn manager(&self) -> DefinitionKind;

    /// Registers the plan, returning the definition that was applied.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Control`] or [`ServiceError::NeedsElevation`].
    fn install(&self, plan: &InstallPlan) -> Result<ServiceDefinition, ServiceError>;

    /// Deregisters. Returns whether there was a registration to remove.
    ///
    /// **Removes the registration and nothing else.** No implementation of this
    /// method may delete a directory, a database, a secret, or a cache;
    /// `05-infrastructure.md` item 5 is a property of every backend, not a
    /// check somewhere above them.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Control`] or [`ServiceError::NeedsElevation`].
    fn uninstall(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError>;

    /// What the manager knows about this registration, if anything.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Control`].
    fn query(&self, identity: &ServiceIdentity) -> Result<Option<Registration>, ServiceError>;

    /// Starts it now, without waiting for the next boot or logon.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Control`], [`ServiceError::NeedsElevation`], or
    /// [`ServiceError::NotInstalled`].
    fn start(&self, identity: &ServiceIdentity) -> Result<(), ServiceError>;

    /// Stops it. Returns whether it was running.
    ///
    /// # Errors
    ///
    /// As [`ServiceControl::start`].
    fn stop(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError>;
}

/// Chooses the control for a start mode.
///
/// The indirection is what makes [`ServiceOperations`] testable: production
/// hands it [`HostControls`], every test in this file hands it
/// [`RecordingControls`], and neither knows the difference.
pub trait ControlFactory: fmt::Debug + Send + Sync {
    /// The control for one start-mode domain.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Control`] when this host has no manager for that domain.
    fn control(&self, mode: StartMode) -> Result<Box<dyn ServiceControl>, ServiceError>;
}

/// The real service managers of the host this binary was built for.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostControls;

// ---------------------------------------------------------------------------
// The operations
// ---------------------------------------------------------------------------

/// What `install` did.
#[derive(Debug, Clone)]
pub struct Installed {
    /// The plan that was applied, including the resolved absolute binary path.
    pub plan: InstallPlan,
    /// The definition the platform was given.
    pub definition: ServiceDefinition,
    /// The record that was written.
    pub record: InstallRecord,
    /// What the definition grants, measured against the requirement.
    pub review: PrivilegeReview,
    /// What was done to the runner root the registration will run jobs under.
    ///
    /// Named trustees rather than SIDs, so printing it adds no identity to the
    /// output. See [`crate::runner_root_access`].
    pub runner_root: RootAccessSummary,
}

/// What `uninstall` did — and, as importantly, what it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uninstalled {
    /// Whether a registration was removed.
    pub removed_registration: bool,
    /// Whether the install record was removed.
    pub removed_record: bool,
    /// Whether a definition file was removed, and which.
    pub removed_definition: Option<PathBuf>,
    /// The directories that were **left exactly as they were**.
    ///
    /// `05-infrastructure.md` item 5 stated as a value rather than as a
    /// promise: `service uninstall` prints this list, so an operator can see
    /// that the configuration, the SQLite database, the stored token and the
    /// runner package cache are all still there.
    pub preserved: Vec<PathBuf>,
}

impl fmt::Display for Uninstalled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.removed_registration {
            writeln!(f, "The service registration was removed.")?;
        } else {
            writeln!(f, "There was no service registration to remove.")?;
        }
        writeln!(f, "Nothing else was deleted. These are untouched:")?;
        for path in &self.preserved {
            writeln!(f, "  {}", path.display())?;
        }
        write!(
            f,
            "The stored GitHub token is untouched too; `auth logout` is what purges it."
        )
    }
}

/// What `set_start_mode` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartModeChange {
    /// What it was.
    pub from: StartMode,
    /// What it is now.
    pub to: StartMode,
    /// `false` when the registration was already in the requested mode.
    pub changed: bool,
    /// The secret store the new mode obliges, so a caller can tell an operator
    /// whether the token has to move too.
    pub store_scope: crate::secrets::SecretScope,
    /// What the mode change did to the runner root's access control.
    ///
    /// A mode change moves the account the daemon runs as, and the runner root
    /// admits that account by name — so the two move together or the new
    /// registration cannot write its own workspaces.
    pub runner_root: RootAccessSummary,
}

impl fmt::Display for StartModeChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.changed {
            return write!(f, "The service already starts at {}.", self.to);
        }
        write!(
            f,
            "The service now starts at {} instead of {}. It reads the {}-scoped secret store; \
             if the token was stored under the other scope, run `auth login` again. {}",
            self.to, self.from, self.store_scope, self.runner_root
        )
    }
}

/// Install, uninstall, inspect, and switch start mode.
///
/// This is the whole of the library contract `f3` builds `service install`,
/// `service uninstall` and `service status` on. Nothing here prints; every
/// operation returns a value with a [`fmt::Display`] a command can write, so the
/// same facts are available to the TUI and to a JSON document without being
/// re-derived from text.
#[derive(Debug, Clone)]
pub struct ServiceOperations {
    paths: AppPaths,
    identity: ServiceIdentity,
    controls: std::sync::Arc<dyn ControlFactory>,
    runner_root: Option<LocalAbsolutePath>,
}

impl ServiceOperations {
    /// Operates on this host's real service managers.
    #[must_use]
    pub fn on_this_host(paths: AppPaths) -> Self {
        Self::with_controls(
            paths,
            ServiceIdentity::product(),
            std::sync::Arc::new(HostControls),
        )
    }

    /// Operates on the controls a caller supplies.
    ///
    /// Both other arguments are explicit for the same reason: the privileged
    /// installer tests register a real service under a
    /// [`ServiceIdentity::fixture`] name, against a disposable
    /// [`AppPaths::rooted_at`] tree, and must not be able to touch an operator's
    /// installation even by mistake.
    #[must_use]
    pub fn with_controls(
        paths: AppPaths,
        identity: ServiceIdentity,
        controls: std::sync::Arc<dyn ControlFactory>,
    ) -> Self {
        Self {
            paths,
            identity,
            controls,
            runner_root: None,
        }
    }

    /// Points runner-root preparation at a directory the caller owns, for the
    /// **current account**.
    ///
    /// **Only a [`ServiceIdentity::fixture`] registration is allowed to move
    /// it, and the guard is here rather than at the call site.** A product
    /// registration ignores the override entirely and resolves
    /// [`crate::runner_root::default_runner_root`] itself, which is what keeps
    /// "custom roots are never re-ACLed" true no matter what a caller passes.
    ///
    /// It exists because the directory the product uses is
    /// `%SystemDrive%\rman`, and a smoke test that created and re-permissioned
    /// *that* would be editing the machine it runs on from outside its own
    /// fixture. So a fixture aims this at a temporary directory it created and
    /// will delete — and "and will delete" is why the override is always
    /// reconciled for the calling account rather than for the account the start
    /// mode obliges. A boot-mode root admits `SY` and `BA` only, which an
    /// ordinary filtered token is neither, so a test that supplied one could
    /// not then inspect or remove its own temporary directory.
    #[must_use]
    pub fn with_runner_root(mut self, root: LocalAbsolutePath) -> Self {
        self.runner_root = Some(root);
        self
    }

    /// The directories this operates against.
    #[must_use]
    pub const fn paths(&self) -> &AppPaths {
        &self.paths
    }

    /// The registration this operates on.
    #[must_use]
    pub const fn identity(&self) -> &ServiceIdentity {
        &self.identity
    }

    /// Registers `daemon run` with the operating system.
    ///
    /// The order is the contract, and each step is a requirement:
    ///
    /// 1. the four directories are created, because item 2 is about writing them;
    /// 2. **the single-instance lock is taken** — item 1. It is held for the
    ///    whole of the install rather than probed and released, so a daemon that
    ///    starts halfway through cannot end up racing a registration;
    /// 3. neither start-mode domain already holds a registration — item 6's
    ///    record would otherwise describe one of two;
    /// 4. the binary path is resolved and confirmed to be a file — item 6;
    /// 5. the platform registers it;
    /// 6. the record is written.
    ///
    /// # Errors
    ///
    /// [`ServiceError::LockHeld`] when an agent is already running,
    /// [`ServiceError::AlreadyInstalled`], [`ServiceError::BinaryMissing`], and
    /// whatever the platform reports.
    pub fn install(&self, request: &InstallRequest) -> Result<Installed, ServiceError> {
        self.paths
            .create_all()
            .map_err(|source| ServiceError::Paths {
                source: Box::new(source),
            })?;

        // Item 1. The guard lives until the end of this function; dropping it is
        // the release, so an early return releases it too.
        let _guard = self.refuse_while_an_agent_runs()?;

        if let Some((mode, _)) = self.find_registration()? {
            return Err(ServiceError::AlreadyInstalled {
                name: self.identity.name().to_string(),
                existing: mode,
            });
        }

        let plan = InstallPlan::resolve(
            self.identity.clone(),
            request,
            ServiceDirectories::of(&self.paths),
        )?;

        // Resolved before the runner root, and used after it: every step from
        // here on has to be able to undo the directory, and a `?` between the
        // preparation and the first fallible use would leave one behind with
        // nothing to say so.
        let control = self.controls.control(plan.start_mode())?;

        // Item 8, and the one step that can refuse an otherwise valid install.
        // Before the platform is asked to register anything, because a
        // registration whose workspaces would land in a directory ordinary local
        // users can write is one that should never have existed — and because
        // undoing a directory is cheaper than undoing a service.
        let root = self.prepare_runner_root(plan.start_mode())?;

        let definition = match control.install(&plan) {
            Ok(definition) => definition,
            Err(cause) => return Err(undo_runner_root(&root, "install", &self.identity, cause)),
        };
        let review = review_least_privilege(&definition, &plan);
        let record = InstallRecord::of(&plan, &definition, Utc::now());
        if let Err(cause) = record.write(&self.paths) {
            return Err(rolled_back(
                retained_runner_root(&root),
                control.uninstall(&self.identity),
                "install",
                &self.identity,
                cause,
            ));
        }
        Ok(Installed {
            plan,
            definition,
            record,
            review,
            runner_root: root.summary().clone(),
        })
    }

    /// Deregisters, and deletes nothing else.
    ///
    /// # Errors
    ///
    /// Whatever the platform reports. A missing registration is **not** an
    /// error: `service uninstall` on a host that has none should say so and
    /// exit cleanly, because an operator running it twice has not made a
    /// mistake.
    pub fn uninstall(&self) -> Result<Uninstalled, ServiceError> {
        let record = InstallRecord::read(&self.paths).ok().flatten();
        let removed_definition = record
            .as_ref()
            .and_then(|record| record.definition_path.clone());

        let mut removed_registration = false;
        // Both domains, not only the recorded one. A record can be lost while a
        // registration survives, and leaving a registration behind because a
        // TOML file was deleted is exactly the state `uninstall` exists to end.
        for mode in [StartMode::Boot, StartMode::Login] {
            let control = self.controls.control(mode)?;
            if control.uninstall(&self.identity)? {
                removed_registration = true;
            }
        }
        let removed_record = InstallRecord::remove(&self.paths)?;
        Ok(Uninstalled {
            removed_registration,
            removed_record,
            removed_definition: removed_definition.filter(|_| removed_registration),
            preserved: self
                .paths
                .all()
                .iter()
                .map(|(_, path)| (*path).to_path_buf())
                .collect(),
        })
    }

    /// Switches between `boot` and `login` **without re-resolving anything**.
    ///
    /// `05-infrastructure.md` item 7. Everything the new registration carries —
    /// the absolute binary path, the arguments, the restart policy, the four
    /// directories — comes from the existing record, so the operator is not
    /// asked to reinstall the product and a binary that has since moved is not
    /// silently swapped for whichever one happens to be running this command.
    ///
    /// On Windows the registration necessarily moves between two different
    /// Windows facilities, because Windows has no service that starts at logon;
    /// see this module's documentation. That is still not a reinstall: no file
    /// is downloaded, replaced, or re-resolved.
    ///
    /// The caller must persist the new mode onto this host's `Host` record so
    /// that `host show` reports it — [`StartModeChange::to`] is the value, and
    /// `f1` already emits `host.service_start_mode` from that field.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotInstalled`] when there is no record to switch, and
    /// whatever the platform reports.
    pub fn set_start_mode(&self, to: StartMode) -> Result<StartModeChange, ServiceError> {
        let Some(record) = InstallRecord::read(&self.paths)? else {
            return Err(ServiceError::NotInstalled {
                name: self.identity.name().to_string(),
                operation: "switch the start mode of",
            });
        };
        let from = record.start_mode;
        if from == to {
            // Nothing moves, so nothing about the root's access control has to.
            // Reconciling it here would turn a no-op command into one that can
            // fail on a permission it does not need.
            return Ok(StartModeChange {
                from,
                to,
                changed: false,
                store_scope: crate::secrets::SecretScope::for_start_mode(to),
                runner_root: RootAccessSummary::NotApplicable,
            });
        }

        #[cfg(windows)]
        let arguments = {
            let mut arguments = record.arguments.clone();
            arguments.retain(|argument| argument != WINDOWS_SCM_HOST_ARGUMENT);
            if to == StartMode::Boot {
                arguments.push(WINDOWS_SCM_HOST_ARGUMENT.to_string());
            }
            arguments
        };
        #[cfg(not(windows))]
        let arguments = record.arguments.clone();
        let plan = InstallPlan::unchecked(
            self.identity.clone(),
            to,
            record.binary.clone(),
            record.directories.clone(),
        )
        .with_arguments(arguments)
        .with_restart(record.restart());
        let plan = if record.starts_on_demand {
            plan.started_on_demand()
        } else {
            plan
        };
        let plan = match crate::secrets::PlatformSecretStore::for_start_mode(to) {
            Ok(store) => plan.with_secret_guard(store.guard()),
            Err(_) => plan,
        };

        // Install the target domain before touching the live one. This makes a
        // failed target install a no-op from the operator's point of view and,
        // unlike uninstall-first ordering, never trades a working service for
        // an error message. Resolved before the runner root and used after it,
        // so that no `?` sits between preparing the directory and the first
        // step that knows how to undo it.
        let target = self.controls.control(to)?;
        // The domain being left, resolved here rather than where it is used for
        // the same reason: the only step that removes it runs after the runner
        // root has been prepared, and a `?` there would abandon the target
        // registration, the record and the directory without a word.
        let previous = self.controls.control(from)?;

        // The account changes with the mode, and so must the account the runner
        // root admits: `04-security-recovery.md` requires the selected identity
        // to be *reconciled* when service mode changes, which means adding the
        // operator's on the way to login and dropping it again on the way back.
        // Before the target install, for the same reason `install` does it
        // first — a root that cannot be made safe must not produce a working
        // registration.
        let root = self.prepare_runner_root(to)?;

        let definition = match target.install(&plan) {
            Ok(definition) => definition,
            Err(cause) => {
                return Err(undo_runner_root(
                    &root,
                    "switch start mode",
                    &self.identity,
                    cause,
                ));
            }
        };
        let next_record = InstallRecord::of(&plan, &definition, record.installed_at);
        if let Err(cause) = next_record.write(&self.paths) {
            return Err(rolled_back(
                retained_runner_root(&root),
                target.uninstall(&self.identity),
                "switch start mode",
                &self.identity,
                cause,
            ));
        }

        // Only after the target registration and its durable record exist is
        // it safe to remove the old domain. If that last step fails, remove the
        // target and put the old record back so status and reality agree.
        if let Err(cause) = previous.uninstall(&self.identity) {
            let target_rollback = target.uninstall(&self.identity);
            let record_rollback = record.write(&self.paths);
            return Err(rolled_back(
                retained_runner_root(&root),
                target_rollback.and(record_rollback),
                "switch start mode",
                &self.identity,
                cause,
            ));
        }
        Ok(StartModeChange {
            from,
            to,
            changed: true,
            store_scope: crate::secrets::SecretScope::for_start_mode(to),
            runner_root: root.summary().clone(),
        })
    }

    /// Starts the registration now.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotInstalled`], or whatever the platform reports.
    pub fn start(&self) -> Result<(), ServiceError> {
        let Some((mode, _)) = self.find_registration()? else {
            return Err(ServiceError::NotInstalled {
                name: self.identity.name().to_string(),
                operation: "start",
            });
        };
        self.controls.control(mode)?.start(&self.identity)
    }

    /// Stops the registration. Returns whether it was running.
    ///
    /// # Errors
    ///
    /// As [`ServiceOperations::start`].
    pub fn stop(&self) -> Result<bool, ServiceError> {
        let Some((mode, _)) = self.find_registration()? else {
            return Err(ServiceError::NotInstalled {
                name: self.identity.name().to_string(),
                operation: "stop",
            });
        };
        self.controls.control(mode)?.stop(&self.identity)
    }

    /// Everything Journey 5 step 4 asks `service status` to report.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Record`] when local state cannot be read, and whatever
    /// the platform reports. A *stale binary path* is deliberately **not** an
    /// error here: it is a reported state, because a status command that
    /// refused to print anything else would hide the very facts an operator
    /// needs in order to fix it.
    pub fn status(&self) -> Result<ServiceStatus, ServiceError> {
        let record = InstallRecord::read(&self.paths)?;
        let found = self.find_registration()?;
        let last_github_contact = last_github_contact(&self.paths)?;
        Ok(ServiceStatus::compose(
            self.identity.clone(),
            record,
            found.map(|(_, registration)| registration),
            last_github_contact,
            &self.paths,
        ))
    }

    /// Creates or reconciles the runner root this start mode's account needs.
    ///
    /// The account is not an argument: it is [`ServiceAccount::for_start_mode`],
    /// the same function the registration's own principal comes from, so the
    /// directory admits exactly the identity the definition registers and a mode
    /// change reconciles both together or neither.
    ///
    /// On macOS and Linux this is a no-op that returns
    /// [`RootAccessSummary::NotApplicable`]; see [`crate::runner_root_access`].
    fn prepare_runner_root(&self, mode: StartMode) -> Result<RootAccessChange, ServiceError> {
        #[cfg(not(windows))]
        {
            // `runner_root` is consumed here as well as in the Windows arm: a
            // field only one platform reads is a dead field on the other.
            let _ = (mode, &self.runner_root);
            Ok(RootAccessChange::not_applicable())
        }
        #[cfg(windows)]
        {
            let wrap = |source| ServiceError::RunnerRoot {
                source: Box::new(source),
            };
            // The test seam, and the two things allowed through it. `cfg!(test)`
            // is false in every shipped binary, so what a released build honours
            // is the fixture name alone — and a fixture name cannot be the
            // product's, which is what keeps a released `service install`
            // pointed at the platform default whatever a caller passes.
            //
            // An overridden root is always reconciled **for this account**,
            // which is the foreground admission — a real mode of the product
            // rather than a concession invented here. It has to be: a boot-mode
            // root admits `SY` and `BA` only, and a test process holding an
            // ordinary filtered token is neither, so it could not inspect the
            // temporary directory it just supplied nor delete it afterwards.
            // What that costs is that the *boot* descriptor is not proved
            // through this path; it is proved purely, by this module's
            // `the_runner_root_a_boot_registration_needs_admits_only_the_service`
            // and by `runner_root_access`'s own tests, and for real by the
            // privileged installer test, which runs elevated.
            if let Some(root) = self
                .runner_root
                .as_ref()
                .filter(|_| self.identity.is_fixture() || cfg!(test))
            {
                let admission = RootAdmission::of_this_account().map_err(wrap)?;
                return crate::runner_root_access::reconcile(&self.paths, root, &admission)
                    .map_err(wrap);
            }

            let admission = match ServiceAccount::for_start_mode(mode) {
                // A boot registration runs as LocalSystem, which the constant
                // `SY` ace already names.
                ServiceAccount::LocalSystem => RootAdmission::LocalSystem,
                // A login registration runs as this account, under a filtered
                // token in which Administrators is deny-only — so without an
                // ace of its own it would be admitted by nothing.
                ServiceAccount::InvokingUser | ServiceAccount::Root => {
                    RootAdmission::of_this_account().map_err(wrap)?
                }
            };
            crate::runner_root_access::ensure_default_root(&self.paths, &admission).map_err(wrap)
        }
    }

    /// Takes the single-instance lock, or refuses with `d1`'s own message.
    fn refuse_while_an_agent_runs(&self) -> Result<HostLock, ServiceError> {
        HostLock::try_acquire(&self.paths, LockKind::SingleInstance).map_err(
            |source| match source {
                held @ LockError::Held { .. } => ServiceError::LockHeld {
                    source: Box::new(held),
                },
                other => ServiceError::LockUnreadable {
                    source: Box::new(other),
                },
            },
        )
    }

    /// The registration, in whichever domain holds it.
    fn find_registration(&self) -> Result<Option<(StartMode, Registration)>, ServiceError> {
        for mode in [StartMode::Boot, StartMode::Login] {
            let control = self.controls.control(mode)?;
            if let Some(registration) = control.query(&self.identity)? {
                return Ok(Some((registration.start_mode, registration)));
            }
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// One thing `service status` has to report as wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusProblem {
    /// What it is about.
    pub subject: &'static str,
    /// What is wrong, and what to do.
    pub detail: String,
}

impl fmt::Display for StatusProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.subject, self.detail)
    }
}

/// Everything `service status` reports.
///
/// Journey 5 step 4 names four of these — the start mode, the resolved binary
/// path, the diagnostic log path, and the last successful GitHub contact — and
/// the release gate adds the fifth: *"`service status` reports a stale binary
/// path as an error rather than appearing healthy"*. [`Self::is_healthy`] is
/// what an exit code should be derived from, and it is false whenever
/// [`Self::problems`] is non-empty.
#[derive(Debug, Clone)]
pub struct ServiceStatus {
    identity: ServiceIdentity,
    record: Option<InstallRecord>,
    registration: Option<Registration>,
    binary: Option<BinaryPath>,
    log_file: PathBuf,
    store: Option<crate::secrets::ActiveStore>,
    last_github_contact: Option<DateTime<Utc>>,
    runner_root: Option<(PathBuf, RootAccessReport)>,
    problems: Vec<StatusProblem>,
    notes: Vec<String>,
}

impl ServiceStatus {
    fn compose(
        identity: ServiceIdentity,
        record: Option<InstallRecord>,
        registration: Option<Registration>,
        last_github_contact: Option<DateTime<Utc>>,
        paths: &AppPaths,
    ) -> Self {
        let mut problems = Vec::new();
        let mut notes = Vec::new();

        let log_file = record.as_ref().map_or_else(
            || ServiceDirectories::of(paths).log_file(),
            |record| record.log_file.clone(),
        );

        let binary = record.as_ref().map(|record| {
            inspect_binary(
                &record.binary,
                registration
                    .as_ref()
                    .and_then(Registration::binary)
                    .as_deref(),
            )
        });
        if let Some(state) = &binary
            && state.is_error()
        {
            problems.push(StatusProblem {
                subject: "binary",
                detail: state.to_string(),
            });
        }

        match (&record, &registration) {
            (Some(_), None) => problems.push(StatusProblem {
                subject: "registration",
                detail: "this host has a service record but no service manager knows the \
                         registration. Run `service install` again; it deletes nothing."
                    .to_string(),
            }),
            (None, Some(found)) => problems.push(StatusProblem {
                subject: "record",
                detail: format!(
                    "{} holds a registration for this service but there is no install record, so \
                     the path it was installed from and the directories it was installed against \
                     are unknown. Run `service uninstall` and `service install`.",
                    found.manager
                ),
            }),
            (Some(record), Some(found)) => {
                if record.start_mode != found.start_mode {
                    problems.push(StatusProblem {
                        subject: "start mode",
                        detail: format!(
                            "the record says {} and {} holds a {} registration. Switch the start \
                             mode again to make them agree.",
                            record.start_mode, found.manager, found.start_mode
                        ),
                    });
                }
                if record.start_mode == StartMode::Boot && !found.starts_automatically {
                    problems.push(StatusProblem {
                        subject: "start mode",
                        detail: format!(
                            "{} holds the registration but will not start it by itself, so this \
                             host does not resume work after a reboot.",
                            found.manager
                        ),
                    });
                }
                if let Some(actual) = found.restart_delay {
                    let expected = record.restart().effective_delay(found.manager);
                    if actual != expected {
                        problems.push(StatusProblem {
                            subject: "restart policy",
                            detail: format!(
                                "the record says the service restarts after {}s and {} reports \
                                 {}s. Something has edited the registration since it was \
                                 installed.",
                                expected.as_secs(),
                                found.manager,
                                actual.as_secs()
                            ),
                        });
                    } else if expected != record.restart().delay() {
                        // Not a fault. Task Scheduler expresses this in whole
                        // minutes, so the delay in force is longer than the one
                        // asked for -- never shorter, which is the direction
                        // the requirement cares about.
                        notes.push(format!(
                            "{} expresses the restart delay in whole minutes, so the {}s asked \
                             for is enforced as {}s. The service therefore never restarts faster \
                             than the configured bound.",
                            found.manager,
                            record.restart().delay().as_secs(),
                            expected.as_secs()
                        ));
                    }
                }
            }
            (None, None) => {}
        }

        // The two facts here really are independent, which is what `f1`'s
        // `status.rs` says this check needs and could not have there: the scope
        // is derived from the mode the **record** carries, and it is compared
        // against the mode the **service manager** actually holds.
        let store = record.as_ref().and_then(|record| {
            let registered_mode = registration
                .as_ref()
                .map_or(record.start_mode, |found| found.start_mode);
            crate::secrets::PlatformSecretStore::for_start_mode(record.start_mode)
                .ok()
                .map(|store| crate::secrets::ActiveStore::of(&store, registered_mode))
        });
        if let Some(store) = &store
            && !store.agrees_with_start_mode()
        {
            problems.push(StatusProblem {
                subject: "secret store",
                detail: format!(
                    "{store}. Run `auth login` again so the token is stored where the registered \
                     start mode can read it."
                ),
            });
        }

        if record.as_ref().map(|record| record.start_mode) == Some(StartMode::Login) {
            notes.push(
                "This registration starts at login, so the agent does not run until the operator \
                 signs in; this host does not resume work after an unattended reboot."
                    .to_string(),
            );
        }
        if last_github_contact.is_none() {
            notes.push(
                "GitHub has not been reached successfully since this host's state directory was \
                 created."
                    .to_string(),
            );
        }

        // The privileged inspection output. Read-only, tolerant of an account
        // that may not read the descriptor at all, and never a `problem`: a
        // root this account cannot inspect is a true statement about this
        // account's rights, not a fault in the registration. What refuses an
        // install is the preflight in `runner_root_access`, which runs as the
        // installing account and has the authority to know.
        let runner_root = crate::runner_root::default_runner_root(paths)
            .ok()
            .map(|root| {
                let path = root.as_path().to_path_buf();
                let report = crate::runner_root_access::report(&path);
                (path, report)
            });
        // Reported, and deliberately not a `problem`. The Definition of Done
        // asks for a broad root to be "reported and fail the security
        // preflight", and the security preflight is `install`'s -- which runs
        // as the installing account and refuses outright. `service status` runs
        // as whoever typed it, is expected to be readable on a host with
        // nothing installed at all, and drives an exit code; turning a
        // directory that predates this feature into a non-zero exit for a
        // machine that has never installed the service would report a fault
        // that is not this registration's.
        if let Some((
            path,
            RootAccessReport::Present {
                broad_write: true, ..
            },
        )) = &runner_root
        {
            notes.push(format!(
                "the platform default runner root {} can be written by ordinary local users, so \
                 it is not a safe place to run jobs. `service install` refuses it rather than \
                 tightening it, because the contents of a directory anybody could write cannot \
                 be trusted: remove or empty it, or choose another root with `runner-manager \
                 host set-runtime-root --path <PATH>`.",
                path.display()
            ));
        }

        Self {
            identity,
            record,
            registration,
            binary,
            log_file,
            store,
            last_github_contact,
            runner_root,
            problems,
            notes,
        }
    }

    /// What this host's default runner root grants, and to whom.
    ///
    /// `None` when the platform default could not even be resolved. The
    /// descriptor inside has been through
    /// [`crate::runner_root_access::redact`], so it names the well-known
    /// trustees and says "an account" for everything else — no more identity
    /// than the `account` line above it already prints.
    #[must_use]
    pub fn runner_root(&self) -> Option<(&Path, &RootAccessReport)> {
        self.runner_root
            .as_ref()
            .map(|(path, report)| (path.as_path(), report))
    }

    /// Whether a registration exists at all.
    #[must_use]
    pub const fn is_installed(&self) -> bool {
        self.registration.is_some() || self.record.is_some()
    }

    /// Whether the daemon is running now.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.registration
            .as_ref()
            .is_some_and(|registration| registration.running)
    }

    /// **False whenever anything is wrong**, including a stale binary path.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.problems.is_empty()
    }

    /// Everything that is wrong.
    #[must_use]
    pub fn problems(&self) -> &[StatusProblem] {
        &self.problems
    }

    /// True statements that are not faults — a login-mode registration not
    /// running unattended, or an agent that has not yet reached GitHub.
    #[must_use]
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// The recorded start mode. Journey 5 step 4.
    #[must_use]
    pub fn start_mode(&self) -> Option<StartMode> {
        self.record.as_ref().map(|record| record.start_mode)
    }

    /// The resolved absolute binary path and what became of it. Journey 5
    /// step 4 and `05-infrastructure.md` item 6.
    #[must_use]
    pub const fn binary(&self) -> Option<&BinaryPath> {
        self.binary.as_ref()
    }

    /// The diagnostic log path. `05-infrastructure.md` item 4.
    #[must_use]
    pub fn log_file(&self) -> &Path {
        &self.log_file
    }

    /// The last successful GitHub contact. Journey 5 step 4.
    #[must_use]
    pub const fn last_github_contact(&self) -> Option<DateTime<Utc>> {
        self.last_github_contact
    }

    /// Which store the daemon reads, and whether that agrees with the
    /// registration.
    #[must_use]
    pub const fn secret_store(&self) -> Option<&crate::secrets::ActiveStore> {
        self.store.as_ref()
    }

    /// The record `install` wrote.
    #[must_use]
    pub const fn record(&self) -> Option<&InstallRecord> {
        self.record.as_ref()
    }

    /// What the service manager says.
    #[must_use]
    pub const fn registration(&self) -> Option<&Registration> {
        self.registration.as_ref()
    }
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Service: {}", self.identity)?;
        match (&self.record, &self.registration) {
            (None, None) => {
                writeln!(
                    f,
                    "  installed                 no. `service install` registers `{} {}`.",
                    SERVICE_NAME,
                    DAEMON_ARGUMENTS.join(" ")
                )?;
            }
            _ => {
                let manager = self
                    .registration
                    .as_ref()
                    .map(|registration| registration.manager.manager());
                writeln!(
                    f,
                    "  installed                 {}",
                    manager.unwrap_or("yes, but no service manager knows it")
                )?;
                writeln!(
                    f,
                    "  state                     {}",
                    if self.is_running() {
                        "running"
                    } else {
                        "not running"
                    }
                )?;
            }
        }
        if let Some(record) = &self.record {
            writeln!(f, "  start mode                {}", record.start_mode)?;
            writeln!(f, "  account                   {}", record.account)?;
            writeln!(f, "  restart on failure        {}", record.restart())?;
            writeln!(
                f,
                "  arguments                 {}",
                record.arguments.join(" ")
            )?;
        }
        if let Some(binary) = &self.binary {
            writeln!(f, "  binary                    {binary}")?;
        }
        writeln!(f, "  diagnostic log            {}", self.log_file.display())?;
        if let Some((path, report)) = &self.runner_root {
            // Named as the *default* rather than as "the runner root", because
            // it is only the effective one until an operator runs
            // `host set-runtime-root`. This crate cannot see that setting — it
            // lives in the application's store — so an unqualified label here
            // would contradict the `runner root … (host-configured)` row that
            // `status` and `host show` print from the value that is in force.
            writeln!(f, "  default runner root       {}", path.display())?;
            if *report != RootAccessReport::NotApplicable {
                writeln!(f, "  default root access       {report}")?;
            }
        }
        if let Some(store) = &self.store {
            writeln!(f, "  secret store              {store}")?;
        }
        writeln!(
            f,
            "  last GitHub contact       {}",
            match self.last_github_contact {
                Some(at) => at.to_rfc3339(),
                None => "never".to_string(),
            }
        )?;
        for note in &self.notes {
            writeln!(f, "  note                      {note}")?;
        }
        for problem in &self.problems {
            writeln!(f, "  ERROR                     {problem}")?;
        }
        write!(
            f,
            "  verdict                   {}",
            if self.is_healthy() {
                "healthy"
            } else {
                "NOT healthy"
            }
        )
    }
}

// ---------------------------------------------------------------------------
// The in-memory double
// ---------------------------------------------------------------------------

/// A [`ControlFactory`] that registers nothing and remembers everything.
///
/// Public rather than `#[cfg(test)]` on purpose. `f3` builds three commands on
/// [`ServiceOperations`] and has to be able to test them without a service
/// manager, and a double that lived behind `#[cfg(test)]` here would be
/// invisible from another crate — which would leave `f3` either untested or
/// writing a second double that drifts from this one.
///
/// It is not a simulator. It stores what it was asked to register and reports it
/// back, which is exactly enough to exercise the logic that sits *above* a
/// service manager: the lock refusal, the record, the stale-path detection, the
/// start-mode switch, and the promise that uninstall deletes nothing else.
#[derive(Debug, Clone, Default)]
pub struct RecordingControls {
    state: std::sync::Arc<std::sync::Mutex<RecordingState>>,
}

#[derive(Debug, Default)]
struct RecordingState {
    registrations: BTreeMap<(StartMode, String), Registration>,
    definitions: BTreeMap<String, ServiceDefinition>,
    calls: Vec<String>,
    #[cfg(test)]
    install_failures: BTreeMap<StartMode, String>,
    #[cfg(test)]
    after_install: BTreeMap<StartMode, TestInstallSideEffect>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
enum TestInstallSideEffect {
    HideDirectory { directory: PathBuf, hidden: PathBuf },
}

impl RecordingControls {
    /// A factory holding no registrations.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every call made through this factory, in order, as
    /// `"<operation> <name> (<mode>)"`.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.state.lock().expect("not poisoned").calls.clone()
    }

    /// Every registration currently held, with the domain it is in.
    #[must_use]
    pub fn registrations(&self) -> Vec<(StartMode, String, Registration)> {
        self.state
            .lock()
            .expect("not poisoned")
            .registrations
            .iter()
            .map(|((mode, name), registration)| (*mode, name.clone(), registration.clone()))
            .collect()
    }

    /// The definition applied for a registration, if it is held.
    #[must_use]
    pub fn definition(&self, name: &str) -> Option<ServiceDefinition> {
        self.state
            .lock()
            .expect("not poisoned")
            .definitions
            .get(name)
            .cloned()
    }

    /// Edits a held registration, as something outside this product would.
    ///
    /// This is how the divergence and start-type problems are made reachable
    /// from a test: `sc config`, `launchctl` and `systemctl` can all change a
    /// registration after installation, and a status command that could not be
    /// shown detecting that would be a status command nobody had tested against
    /// the case it exists for.
    ///
    /// Does nothing when no registration of that name is held.
    pub fn edit(&self, name: &str, edit: impl FnOnce(&mut Registration)) {
        let mut state = self.state.lock().expect("not poisoned");
        if let Some((_, registration)) = state
            .registrations
            .iter_mut()
            .find(|((_, held), _)| held == name)
        {
            edit(registration);
        }
    }

    #[cfg(test)]
    fn fail_next_install(&self, mode: StartMode, detail: &str) {
        self.state
            .lock()
            .expect("not poisoned")
            .install_failures
            .insert(mode, detail.to_string());
    }

    #[cfg(test)]
    fn hide_directory_after_install(&self, mode: StartMode, directory: PathBuf, hidden: PathBuf) {
        self.state
            .lock()
            .expect("not poisoned")
            .after_install
            .insert(
                mode,
                TestInstallSideEffect::HideDirectory { directory, hidden },
            );
    }
}

impl ControlFactory for RecordingControls {
    fn control(&self, mode: StartMode) -> Result<Box<dyn ServiceControl>, ServiceError> {
        Ok(Box::new(RecordingControl {
            mode,
            state: std::sync::Arc::clone(&self.state),
        }))
    }
}

#[derive(Debug)]
struct RecordingControl {
    mode: StartMode,
    state: std::sync::Arc<std::sync::Mutex<RecordingState>>,
}

impl RecordingControl {
    fn note(&self, operation: &str, name: &str) {
        self.state
            .lock()
            .expect("not poisoned")
            .calls
            .push(format!("{operation} {name} ({})", self.mode));
    }
}

impl ServiceControl for RecordingControl {
    fn manager(&self) -> DefinitionKind {
        // The double reports the kind this host's real backend would, so a test
        // that asserts on the manager name asserts something true of the
        // platform it is running on.
        host_definition_kind(self.mode)
    }

    fn install(&self, plan: &InstallPlan) -> Result<ServiceDefinition, ServiceError> {
        self.note("install", plan.identity().name());
        #[cfg(test)]
        if let Some(detail) = self
            .state
            .lock()
            .expect("not poisoned")
            .install_failures
            .remove(&self.mode)
        {
            return Err(ServiceError::Control {
                operation: "install",
                name: plan.identity().name().to_string(),
                manager: "recording control",
                detail,
            });
        }
        // The real definition, not a stub. Rendering is pure, so the double can
        // afford it -- and a stub would make `Installed::review` report that the
        // definition confirms nothing, which is exactly the shape of false
        // assurance a test double must never hand back.
        let definition = ServiceDefinition::for_host(plan)?;
        let mut state = self.state.lock().expect("not poisoned");
        state.registrations.insert(
            (self.mode, plan.identity().name().to_string()),
            Registration {
                manager: host_definition_kind(self.mode),
                start_mode: self.mode,
                command_line: plan.command_line(),
                account: Some(plan.account().as_str().to_string()),
                running: false,
                starts_automatically: true,
                restart_delay: Some(plan.restart().delay()),
            },
        );
        state
            .definitions
            .insert(plan.identity().name().to_string(), definition.clone());
        #[cfg(test)]
        let side_effect = state.after_install.remove(&self.mode);
        drop(state);
        #[cfg(test)]
        if let Some(TestInstallSideEffect::HideDirectory { directory, hidden }) = side_effect {
            std::fs::rename(&directory, &hidden).expect("test fault can hide the record directory");
            std::fs::write(&directory, b"blocks recreation")
                .expect("test fault can block record directory recreation");
        }
        Ok(definition)
    }

    fn uninstall(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError> {
        self.note("uninstall", identity.name());
        let mut state = self.state.lock().expect("not poisoned");
        state.definitions.remove(identity.name());
        Ok(state
            .registrations
            .remove(&(self.mode, identity.name().to_string()))
            .is_some())
    }

    fn query(&self, identity: &ServiceIdentity) -> Result<Option<Registration>, ServiceError> {
        self.note("query", identity.name());
        Ok(self
            .state
            .lock()
            .expect("not poisoned")
            .registrations
            .get(&(self.mode, identity.name().to_string()))
            .cloned())
    }

    fn start(&self, identity: &ServiceIdentity) -> Result<(), ServiceError> {
        self.note("start", identity.name());
        let mut state = self.state.lock().expect("not poisoned");
        match state
            .registrations
            .get_mut(&(self.mode, identity.name().to_string()))
        {
            Some(registration) => {
                registration.running = true;
                Ok(())
            }
            None => Err(ServiceError::NotInstalled {
                name: identity.name().to_string(),
                operation: "start",
            }),
        }
    }

    fn stop(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError> {
        self.note("stop", identity.name());
        let mut state = self.state.lock().expect("not poisoned");
        match state
            .registrations
            .get_mut(&(self.mode, identity.name().to_string()))
        {
            Some(registration) => Ok(std::mem::replace(&mut registration.running, false)),
            None => Err(ServiceError::NotInstalled {
                name: identity.name().to_string(),
                operation: "stop",
            }),
        }
    }
}

impl ControlFactory for HostControls {
    fn control(&self, mode: StartMode) -> Result<Box<dyn ServiceControl>, ServiceError> {
        sys::control(mode)
    }
}

/// The operator's home directory, when the platform reports one.
///
/// Only login-mode registrations need it — a LaunchAgent and a systemd user
/// unit both live under it — and it is resolved lazily so that a boot-mode
/// operation on an account with no profile is not refused for wanting something
/// it never uses.
fn host_home() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf())
}

/// The Unix backends' name for the same thing.
#[cfg(unix)]
fn home_directory() -> Option<PathBuf> {
    host_home()
}

/// Runs a command and returns its exit status with both streams as text.
///
/// The three Unix backends and the Windows Task Scheduler backend all drive a
/// stock command-line tool, and all four want the same three things back. The
/// tools are chosen for machine-readable, locale-independent output wherever one
/// exists — `systemctl is-active`, `launchctl print`, `schtasks /XML` — because
/// parsing a localised human-facing table is how a status command starts lying
/// on somebody else's machine.
fn run(program: &str, arguments: &[&std::ffi::OsStr]) -> std::io::Result<(bool, String, String)> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

/// Which manager holds a given start-mode domain on the platform this binary
/// was built for.
#[must_use]
pub const fn host_definition_kind(mode: StartMode) -> DefinitionKind {
    if cfg!(windows) {
        match mode {
            StartMode::Boot => DefinitionKind::WindowsService,
            StartMode::Login => DefinitionKind::WindowsScheduledTask,
        }
    } else if cfg!(target_os = "macos") {
        DefinitionKind::LaunchdPlist
    } else {
        DefinitionKind::SystemdUnit
    }
}

/// Enables a launchd label after it has been bootstrapped.
///
/// `launchctl bootstrap` deliberately preserves a label's disabled bit. An
/// `enable` failure therefore means the new registration cannot satisfy its
/// start policy. Compensate by booting it out and removing the plist so a
/// failed install cannot look installed to `service status`.
#[cfg(any(target_os = "macos", test))]
fn enable_launchd_registration(
    mut launchctl: impl FnMut(&[&std::ffi::OsStr]) -> (bool, String),
    domain: &str,
    service_target: &str,
    plist: &Path,
    name: &str,
    elevation_remedy: &'static str,
) -> Result<(), ServiceError> {
    let (enabled, cause) = launchctl(&[
        std::ffi::OsStr::new("enable"),
        std::ffi::OsStr::new(service_target),
    ]);
    if enabled {
        return Ok(());
    }

    let (booted_out, bootout_detail) = launchctl(&[
        std::ffi::OsStr::new("bootout"),
        std::ffi::OsStr::new(service_target),
    ]);
    let removed = std::fs::remove_file(plist);
    if !booted_out || removed.is_err() {
        return Err(ServiceError::Rollback {
            operation: "enable launchd registration",
            name: name.to_string(),
            cause,
            rollback: format!(
                "launchctl bootout {domain}: {}; remove {}: {}",
                if booted_out {
                    "succeeded".to_string()
                } else {
                    bootout_detail
                },
                plist.display(),
                removed
                    .err()
                    .map_or_else(|| "succeeded".to_string(), |error| error.to_string())
            ),
        });
    }

    if cause.to_ascii_lowercase().contains("permission denied") {
        Err(ServiceError::NeedsElevation {
            operation: "enable",
            name: name.to_string(),
            detail: cause,
            remedy: elevation_remedy,
        })
    } else {
        Err(ServiceError::Control {
            operation: "enable",
            name: name.to_string(),
            manager: "launchd",
            detail: cause,
        })
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

/// A stop request delivered by the Windows Service Control Manager.
///
/// The application owns the drain policy; this platform boundary only turns
/// `SERVICE_CONTROL_STOP`/`SHUTDOWN` into an awaitable notification.
#[derive(Debug)]
pub struct ServiceShutdown(tokio::sync::watch::Receiver<bool>);

impl ServiceShutdown {
    /// Waits until SCM asks the service to stop or shut down.
    pub async fn wait(mut self) {
        if !*self.0.borrow() {
            let _ = self.0.changed().await;
        }
    }
}

/// Runs the production process as a real Windows service host.
///
/// `StartServiceCtrlDispatcher` must run in the service process's main thread,
/// so the callback is handed through a process-global slot to the entrypoint
/// invoked by SCM. The slot is single-use by design: one process hosts exactly
/// one own-process service.
#[cfg(windows)]
pub fn run_windows_service_host<F>(run: F) -> Result<u8, ServiceError>
where
    F: FnOnce(ServiceShutdown) -> u8 + Send + 'static,
{
    windows_host::run(Box::new(run))
}

#[cfg(windows)]
mod windows_host {
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex, OnceLock, mpsc};
    use std::time::Duration;

    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };

    use super::{SERVICE_NAME, ServiceError, ServiceShutdown};

    type Runner = Box<dyn FnOnce(ServiceShutdown) -> u8 + Send>;

    struct Invocation {
        run: Runner,
        result: mpsc::SyncSender<Result<u8, String>>,
    }

    static INVOCATION: OnceLock<Mutex<Option<Invocation>>> = OnceLock::new();

    windows_service::define_windows_service!(ffi_service_main, service_main);

    pub(super) fn run(run: Runner) -> Result<u8, ServiceError> {
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let slot = INVOCATION.get_or_init(|| Mutex::new(None));
        let mut invocation = slot
            .lock()
            .map_err(|_| host_error("prepare", "the service-host slot is poisoned"))?;
        if invocation.is_some() {
            return Err(host_error(
                "prepare",
                "the service-host slot was already used",
            ));
        }
        *invocation = Some(Invocation {
            run,
            result: result_tx,
        });
        drop(invocation);

        windows_service::service_dispatcher::start("", ffi_service_main)
            .map_err(|error| host_error("connect", &error.to_string()))?;
        result_rx
            .recv()
            .map_err(|error| host_error("finish", &error.to_string()))?
            .map_err(|detail| host_error("run", &detail))
    }

    fn service_main(_arguments: Vec<OsString>) {
        let Some(invocation) = INVOCATION.get().and_then(|slot| slot.lock().ok()?.take()) else {
            return;
        };
        let result = run_service(invocation.run);
        let _ = invocation.result.send(result);
    }

    fn run_service(run: Runner) -> Result<u8, String> {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let status: Arc<Mutex<Option<ServiceStatusHandle>>> = Arc::new(Mutex::new(None));
        let handler_status = Arc::clone(&status);
        let handler = move |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(handle) = handler_status.lock().ok().and_then(|guard| *guard) {
                    let _ = handle.set_service_status(service_status(
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        1,
                        Duration::from_secs(300),
                        0,
                    ));
                }
                let _ = stop_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let handle = service_control_handler::register("", handler)
            .map_err(|error| format!("cannot register the service control handler: {error}"))?;
        *status
            .lock()
            .map_err(|_| "the service status handle is poisoned".to_string())? = Some(handle);
        handle
            .set_service_status(service_status(
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                0,
                Duration::default(),
                0,
            ))
            .map_err(|error| format!("cannot report SERVICE_RUNNING: {error}"))?;

        let exit = run(ServiceShutdown(stop_rx));
        handle
            .set_service_status(service_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                0,
                Duration::default(),
                u32::from(exit),
            ))
            .map_err(|error| format!("cannot report SERVICE_STOPPED: {error}"))?;
        Ok(exit)
    }

    fn service_status(
        state: ServiceState,
        accepted: ServiceControlAccept,
        checkpoint: u32,
        wait_hint: Duration,
        exit: u32,
    ) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code: if exit == 0 {
                ServiceExitCode::Win32(0)
            } else {
                ServiceExitCode::ServiceSpecific(exit)
            },
            checkpoint,
            wait_hint,
            process_id: None,
        }
    }

    fn host_error(operation: &'static str, detail: &str) -> ServiceError {
        ServiceError::Control {
            operation,
            name: SERVICE_NAME.to_string(),
            manager: "the Windows Service Control Manager",
            detail: detail.to_string(),
        }
    }
}

#[cfg(windows)]
mod sys {
    //! Two managers, because Windows has two answers.
    //!
    //! `--start-at boot` is a service in the Service Control Manager, which is
    //! the only Windows facility that starts something before anybody logs in.
    //! `--start-at login` is a Task Scheduler task with a logon trigger, which
    //! is the only Windows facility that starts something when somebody does.
    //! There is no single mechanism that does both: service trigger-start has no
    //! logon trigger, and a scheduled task cannot run before a session exists.

    use std::ffi::{OsStr, OsString};
    use std::time::{Duration, Instant};

    use runner_manager_domain::model::StartMode;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::{
        DefinitionKind, InstallPlan, Registration, ServiceControl, ServiceDefinition, ServiceError,
        ServiceIdentity, TaskPrincipal, run, windows_service_spec, xml_value,
    };

    /// `ERROR_SERVICE_DOES_NOT_EXIST`. Not an error here: it is the answer to
    /// "is this registered".
    const SERVICE_DOES_NOT_EXIST: i32 = 1060;
    /// `ERROR_SERVICE_MARKED_FOR_DELETE`. `DeleteService` is asynchronous: the
    /// registration remains in this state until every open service handle is
    /// closed, and callers must not mistake that short window for a leak.
    const SERVICE_MARKED_FOR_DELETE: i32 = 1072;
    /// `ERROR_ACCESS_DENIED`.
    const ACCESS_DENIED: i32 = 5;
    const DELETE_TIMEOUT: Duration = Duration::from_secs(30);
    const DELETE_POLL_INTERVAL: Duration = Duration::from_millis(200);

    const ELEVATION_REMEDY: &str = "Run the command from an elevated prompt: right-click Windows Terminal or PowerShell and \
         choose \"Run as administrator\".";

    pub(super) fn control(mode: StartMode) -> Result<Box<dyn ServiceControl>, ServiceError> {
        Ok(match mode {
            StartMode::Boot => Box::new(ScmControl),
            StartMode::Login => Box::new(TaskControl),
        })
    }

    // -- the Service Control Manager -----------------------------------------

    #[derive(Debug)]
    struct ScmControl;

    /// Turns a `windows-service` failure into this module's error, keeping the
    /// "needs elevation" case separate: an operator told "access is denied" and
    /// an operator told "run this elevated" are not equally well served.
    fn scm_error(
        operation: &'static str,
        name: &str,
        error: &windows_service::Error,
    ) -> ServiceError {
        let raw = match error {
            windows_service::Error::Winapi(io) => io.raw_os_error(),
            _ => None,
        };
        let detail = match error {
            windows_service::Error::Winapi(io) => io.to_string(),
            other => other.to_string(),
        };
        if raw == Some(ACCESS_DENIED) {
            return ServiceError::NeedsElevation {
                operation,
                name: name.to_string(),
                detail,
                remedy: ELEVATION_REMEDY,
            };
        }
        ServiceError::Control {
            operation,
            name: name.to_string(),
            manager: "the Windows Service Control Manager",
            detail,
        }
    }

    fn open_manager(
        access: ServiceManagerAccess,
        operation: &'static str,
        name: &str,
    ) -> Result<ServiceManager, ServiceError> {
        ServiceManager::local_computer(None::<&OsStr>, access)
            .map_err(|error| scm_error(operation, name, &error))
    }

    impl ServiceControl for ScmControl {
        fn manager(&self) -> DefinitionKind {
            DefinitionKind::WindowsService
        }

        fn install(&self, plan: &InstallPlan) -> Result<ServiceDefinition, ServiceError> {
            let spec = windows_service_spec(plan);
            let manager = open_manager(
                ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
                "install",
                &spec.name,
            )?;
            let info = ServiceInfo {
                name: OsString::from(&spec.name),
                display_name: OsString::from(&spec.display_name),
                // Never INTERACTIVE_PROCESS: see `windows_service_descriptor`.
                service_type: ServiceType::OWN_PROCESS,
                start_type: if spec.automatic_start {
                    ServiceStartType::AutoStart
                } else {
                    ServiceStartType::OnDemand
                },
                error_control: ServiceErrorControl::Normal,
                executable_path: plan.binary().to_path_buf(),
                launch_arguments: plan.arguments().to_vec(),
                dependencies: Vec::new(),
                // `None` is LocalSystem, which is the account `d2`'s DACL admits.
                account_name: spec.account.as_ref().map(OsString::from),
                // No password is ever taken, asked for, or stored. An account
                // that needed one would be an account this installer refuses.
                account_password: None,
            };
            let service = manager
                .create_service(
                    &info,
                    ServiceAccess::CHANGE_CONFIG
                        | ServiceAccess::QUERY_CONFIG
                        | ServiceAccess::QUERY_STATUS
                        | ServiceAccess::START
                        | ServiceAccess::STOP
                        | ServiceAccess::DELETE,
                )
                .map_err(|error| scm_error("install", &spec.name, &error))?;
            service
                .set_description(&spec.description)
                .map_err(|error| scm_error("describe", &spec.name, &error))?;
            service
                .update_failure_actions(ServiceFailureActions {
                    reset_period: ServiceFailureResetPeriod::After(spec.restart.reset_after()),
                    reboot_msg: None,
                    command: None,
                    // Three identical restart actions rather than one: the
                    // Service Control Manager applies the first action to the
                    // first failure, the second to the second, and the last to
                    // every failure after that. One action would leave the
                    // second and later failures unhandled, which is a service
                    // that comes back once and then stays down.
                    actions: Some(vec![
                        ServiceAction {
                            action_type: ServiceActionType::Restart,
                            delay: spec.restart.delay(),
                        };
                        3
                    ]),
                })
                .map_err(|error| scm_error("set the restart policy of", &spec.name, &error))?;
            // Without this the failure actions apply only to a crash, and a
            // daemon that exits non-zero is not a crash.
            service
                .set_failure_actions_on_non_crash_failures(true)
                .map_err(|error| scm_error("set the restart policy of", &spec.name, &error))?;
            Ok(ServiceDefinition::windows_service(plan))
        }

        fn uninstall(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError> {
            let manager =
                open_manager(ServiceManagerAccess::CONNECT, "uninstall", identity.name())?;
            let service = match manager.open_service(
                identity.name(),
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            ) {
                Ok(service) => service,
                Err(error) if is_missing(&error) => return Ok(false),
                Err(error) => return Err(scm_error("uninstall", identity.name(), &error)),
            };
            // A running service can be deleted, but it lingers until it stops.
            // Stopping first is what makes `uninstall` followed by `install`
            // work in one sitting, which is what the start-mode switch needs.
            if let Ok(status) = service.query_status()
                && status.current_state != ServiceState::Stopped
            {
                let _ = service.stop();
            }
            service
                .delete()
                .map_err(|error| scm_error("uninstall", identity.name(), &error))?;

            // `DeleteService` marks a registration for deletion and returns;
            // SCM removes it only after the last service handle closes. Drop
            // ours before polling, then wait for the observable postcondition
            // promised by `uninstall`: an immediate status check must not see
            // a registration that is merely on its way out. This also keeps a
            // stop/uninstall/install sequence deterministic on busy hosts.
            drop(service);
            let absent = wait_until_scm_absent(DELETE_TIMEOUT, DELETE_POLL_INTERVAL, || {
                match manager.open_service(identity.name(), ServiceAccess::QUERY_STATUS) {
                    Ok(service) => {
                        drop(service);
                        Ok(false)
                    }
                    Err(error) if is_missing(&error) => Ok(true),
                    Err(error) if is_marked_for_delete(&error) => Ok(false),
                    Err(error) => Err(scm_error("verify uninstall of", identity.name(), &error)),
                }
            })?;
            if !absent {
                return Err(ServiceError::Control {
                    operation: "verify uninstall of",
                    name: identity.name().to_string(),
                    manager: "the Windows Service Control Manager",
                    detail: format!(
                        "the registration was still visible {} seconds after DeleteService; \
                         retry `service uninstall` from an elevated prompt",
                        DELETE_TIMEOUT.as_secs()
                    ),
                });
            }
            Ok(true)
        }

        fn query(&self, identity: &ServiceIdentity) -> Result<Option<Registration>, ServiceError> {
            let manager = open_manager(ServiceManagerAccess::CONNECT, "inspect", identity.name())?;
            let service = match manager.open_service(
                identity.name(),
                ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
            ) {
                Ok(service) => service,
                Err(error) if is_missing(&error) => return Ok(None),
                Err(error) => return Err(scm_error("inspect", identity.name(), &error)),
            };
            let config = service
                .query_config()
                .map_err(|error| scm_error("inspect", identity.name(), &error))?;
            let status = service
                .query_status()
                .map_err(|error| scm_error("inspect", identity.name(), &error))?;
            let restart_delay = service.get_failure_actions().ok().and_then(|actions| {
                actions
                    .actions
                    .and_then(|actions| actions.into_iter().next())
                    .filter(|action| action.action_type == ServiceActionType::Restart)
                    .map(|action| action.delay)
            });
            Ok(Some(Registration {
                manager: DefinitionKind::WindowsService,
                start_mode: StartMode::Boot,
                // `lpBinaryPathName` holds the executable *and* its arguments
                // as one string, which is why this module carries its own
                // parser rather than trusting `executable_path`'s name.
                command_line: config.executable_path.to_string_lossy().into_owned(),
                account: config
                    .account_name
                    .map(|account| account.to_string_lossy().into_owned()),
                running: status.current_state == ServiceState::Running,
                starts_automatically: config.start_type == ServiceStartType::AutoStart,
                restart_delay,
            }))
        }

        fn start(&self, identity: &ServiceIdentity) -> Result<(), ServiceError> {
            let manager = open_manager(ServiceManagerAccess::CONNECT, "start", identity.name())?;
            let service = manager
                .open_service(identity.name(), ServiceAccess::START)
                .map_err(|error| scm_error("start", identity.name(), &error))?;
            service
                .start::<&OsStr>(&[])
                .map_err(|error| scm_error("start", identity.name(), &error))
        }

        fn stop(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError> {
            let manager = open_manager(ServiceManagerAccess::CONNECT, "stop", identity.name())?;
            let service = manager
                .open_service(
                    identity.name(),
                    ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
                )
                .map_err(|error| scm_error("stop", identity.name(), &error))?;
            let status = service
                .query_status()
                .map_err(|error| scm_error("stop", identity.name(), &error))?;
            if status.current_state == ServiceState::Stopped {
                return Ok(false);
            }
            service
                .stop()
                .map_err(|error| scm_error("stop", identity.name(), &error))?;
            Ok(true)
        }
    }

    fn is_missing(error: &windows_service::Error) -> bool {
        matches!(error, windows_service::Error::Winapi(io)
            if io.raw_os_error() == Some(SERVICE_DOES_NOT_EXIST))
    }

    fn is_marked_for_delete(error: &windows_service::Error) -> bool {
        matches!(error, windows_service::Error::Winapi(io)
            if io.raw_os_error() == Some(SERVICE_MARKED_FOR_DELETE))
    }

    pub(super) fn wait_until_scm_absent(
        timeout: Duration,
        poll_interval: Duration,
        mut probe_absent: impl FnMut() -> Result<bool, ServiceError>,
    ) -> Result<bool, ServiceError> {
        let deadline = Instant::now() + timeout;
        loop {
            if probe_absent()? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(poll_interval);
        }
    }

    // -- Task Scheduler ------------------------------------------------------

    #[derive(Debug)]
    struct TaskControl;

    fn task_error(operation: &'static str, name: &str, detail: String) -> ServiceError {
        if detail.to_ascii_lowercase().contains("access is denied") {
            return ServiceError::NeedsElevation {
                operation,
                name: name.to_string(),
                detail,
                remedy: ELEVATION_REMEDY,
            };
        }
        ServiceError::Control {
            operation,
            name: name.to_string(),
            manager: "Windows Task Scheduler",
            detail,
        }
    }

    fn schtasks(
        operation: &'static str,
        name: &str,
        arguments: &[&OsStr],
    ) -> Result<(bool, String), ServiceError> {
        match run("schtasks.exe", arguments) {
            Ok((ok, stdout, stderr)) => Ok((ok, if ok { stdout } else { stderr })),
            Err(error) => Err(task_error(operation, name, error.to_string())),
        }
    }

    /// Task Scheduler reads `/XML` files as UTF-16, so the document is written
    /// as UTF-16 little-endian with a byte-order mark rather than as UTF-8.
    fn write_utf16(path: &std::path::Path, text: &str) -> std::io::Result<()> {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(path, bytes)
    }

    impl ServiceControl for TaskControl {
        fn manager(&self) -> DefinitionKind {
            DefinitionKind::WindowsScheduledTask
        }

        fn install(&self, plan: &InstallPlan) -> Result<ServiceDefinition, ServiceError> {
            let name = plan.identity().name().to_string();
            let principal = TaskPrincipal::current()?;
            let definition = ServiceDefinition::windows_scheduled_task(plan, &principal);
            let directory = tempfile::tempdir()
                .map_err(|error| task_error("install", &name, error.to_string()))?;
            let document = directory.path().join("task.xml");
            write_utf16(&document, definition.text())
                .map_err(|error| task_error("install", &name, error.to_string()))?;
            let (ok, message) = schtasks(
                "install",
                &name,
                &[
                    OsStr::new("/Create"),
                    OsStr::new("/TN"),
                    OsStr::new(&name),
                    OsStr::new("/XML"),
                    document.as_os_str(),
                ],
            )?;
            if !ok {
                return Err(task_error("install", &name, message));
            }
            Ok(definition)
        }

        fn uninstall(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError> {
            if self.query(identity)?.is_none() {
                return Ok(false);
            }
            let name = identity.name().to_string();
            let (ok, message) = schtasks(
                "uninstall",
                &name,
                &[
                    OsStr::new("/Delete"),
                    OsStr::new("/TN"),
                    OsStr::new(&name),
                    OsStr::new("/F"),
                ],
            )?;
            if !ok {
                return Err(task_error("uninstall", &name, message));
            }
            Ok(true)
        }

        fn query(&self, identity: &ServiceIdentity) -> Result<Option<Registration>, ServiceError> {
            let name = identity.name().to_string();
            let (ok, document) = schtasks(
                "inspect",
                &name,
                &[
                    OsStr::new("/Query"),
                    OsStr::new("/TN"),
                    OsStr::new(&name),
                    OsStr::new("/XML"),
                    OsStr::new("ONE"),
                ],
            )?;
            if !ok {
                // `schtasks` reports a missing task and a broken Task Scheduler
                // the same way, with a non-zero exit; there is no distinct code.
                // Treating it as absence is the safe reading: the caller either
                // installs, which will then fail loudly, or reports "not
                // installed", which is what an operator with no task sees.
                return Ok(None);
            }
            let command = xml_value(&document, "Command").unwrap_or_default();
            let arguments = xml_value(&document, "Arguments").unwrap_or_default();
            let command_line = if arguments.is_empty() {
                super::quote_argument(&command)
            } else {
                format!("{} {arguments}", super::quote_argument(&command))
            };
            Ok(Some(Registration {
                manager: DefinitionKind::WindowsScheduledTask,
                start_mode: StartMode::Login,
                command_line,
                account: xml_value(&document, "UserId"),
                running: task_is_running(&name),
                starts_automatically: document.contains("<LogonTrigger>")
                    && xml_value(&document, "Enabled").as_deref() == Some("true"),
                restart_delay: xml_value(&document, "Interval")
                    .as_deref()
                    .and_then(parse_iso8601),
            }))
        }

        fn start(&self, identity: &ServiceIdentity) -> Result<(), ServiceError> {
            let name = identity.name().to_string();
            let (ok, message) = schtasks(
                "start",
                &name,
                &[OsStr::new("/Run"), OsStr::new("/TN"), OsStr::new(&name)],
            )?;
            if ok {
                Ok(())
            } else {
                Err(task_error("start", &name, message))
            }
        }

        fn stop(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError> {
            let running = self
                .query(identity)?
                .is_some_and(|registration| registration.running);
            if !running {
                return Ok(false);
            }
            let name = identity.name().to_string();
            let (ok, message) = schtasks(
                "stop",
                &name,
                &[OsStr::new("/End"), OsStr::new("/TN"), OsStr::new(&name)],
            )?;
            if ok {
                Ok(true)
            } else {
                Err(task_error("stop", &name, message))
            }
        }
    }

    /// Whether Task Scheduler reports the task as running.
    ///
    /// **This is the one value in this module read from localised output.**
    /// `schtasks /Query /FO CSV` prints a `Status` column in the machine's
    /// display language, and Task Scheduler exposes no locale-independent
    /// equivalent short of COM. On a non-English Windows this therefore reports
    /// `false` for a task that is in fact running.
    ///
    /// That is stated rather than hidden because of what does *not* depend on
    /// it: Journey 5's liveness question is answered by the last successful
    /// GitHub contact, which is a timestamp this product writes itself and no
    /// locale can move. Nothing in the Definition of Done rests on this
    /// boolean.
    fn task_is_running(name: &str) -> bool {
        let Ok((true, stdout, _)) = run(
            "schtasks.exe",
            &[
                OsStr::new("/Query"),
                OsStr::new("/TN"),
                OsStr::new(name),
                OsStr::new("/FO"),
                OsStr::new("CSV"),
                OsStr::new("/NH"),
            ],
        ) else {
            return false;
        };
        stdout
            .lines()
            .filter_map(|line| line.rsplit(',').next())
            .any(|status| {
                status
                    .trim()
                    .trim_matches('"')
                    .eq_ignore_ascii_case("running")
            })
    }

    /// Parses the `PT<n>M` shape this module writes, and the `PT<n>S` shape
    /// Task Scheduler would accept if it took seconds. Anything richer -- days,
    /// hours, a combination -- is `None` rather than a guess.
    fn parse_iso8601(value: &str) -> Option<Duration> {
        let rest = value.strip_prefix("PT")?;
        if let Some(minutes) = rest.strip_suffix('M') {
            return minutes
                .parse::<u64>()
                .ok()
                .map(|minutes| Duration::from_secs(minutes * 60));
        }
        rest.strip_suffix('S')?
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
    }
}

// ---------------------------------------------------------------------------
// Unix: shared plumbing
// ---------------------------------------------------------------------------

/// Writes a definition file, creating its directory, and says when the refusal
/// was a permissions one.
///
/// Both Unix backends write a file into a directory only `root` can write —
/// `/Library/LaunchDaemons` and `/etc/systemd/system` — and an operator who ran
/// `service install` without `sudo` deserves to be told that rather than handed
/// an `EACCES`.
#[cfg(unix)]
fn write_definition(
    operation: &'static str,
    name: &str,
    path: &Path,
    text: &str,
    remedy: &'static str,
) -> Result<(), ServiceError> {
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
        && error.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(definition_error(operation, name, error, remedy, parent));
    }
    std::fs::write(path, text)
        .map_err(|error| definition_error(operation, name, error, remedy, path))
}

#[cfg(unix)]
fn definition_error(
    operation: &'static str,
    name: &str,
    error: std::io::Error,
    remedy: &'static str,
    path: &Path,
) -> ServiceError {
    let detail = format!("{}: {error}", path.display());
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        ServiceError::NeedsElevation {
            operation,
            name: name.to_string(),
            detail,
            remedy,
        }
    } else {
        ServiceError::Control {
            operation,
            name: name.to_string(),
            manager: "the local service manager",
            detail,
        }
    }
}

/// `sudo` is the remedy on both Unixes, and the message says which command.
#[cfg(unix)]
const SUDO_REMEDY: &str = "A boot-start registration is machine-wide, so it needs root: run the same command with \
     `sudo`. `service install --start-at login` needs no elevation at all, at the cost of the \
     agent not running until you sign in.";

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod sys {
    //! One manager, two domains. `--start-at boot` is a LaunchDaemon in
    //! `/Library/LaunchDaemons`, loaded into launchd's `system` domain;
    //! `--start-at login` is a LaunchAgent in the operator's own
    //! `~/Library/LaunchAgents`, loaded into `gui/<uid>`.
    //!
    //! `launchctl print` is the only inspection command here whose output is
    //! parsed, and it is English-only on every macOS release — launchd has no
    //! localisation for it. The registration's *existence* is decided by the
    //! plist file rather than by that output, so a launchd that changed its
    //! wording would cost this module the running/not-running line and nothing
    //! else.

    use std::ffi::OsStr;
    use std::path::PathBuf;
    use std::time::Duration;

    use runner_manager_domain::model::StartMode;

    use super::{
        DefinitionKind, InstallPlan, LAUNCH_AGENTS_SUBDIR, LAUNCH_DAEMONS_DIR, Registration,
        SUDO_REMEDY, ServiceControl, ServiceDefinition, ServiceError, ServiceIdentity,
        enable_launchd_registration, home_directory, plist_string_value, quote_argument, run,
        write_definition, xml_value,
    };

    pub(super) fn control(mode: StartMode) -> Result<Box<dyn ServiceControl>, ServiceError> {
        Ok(Box::new(LaunchdControl { mode }))
    }

    #[derive(Debug)]
    struct LaunchdControl {
        mode: StartMode,
    }

    impl LaunchdControl {
        /// launchd's domain target for this start mode.
        fn domain(&self) -> String {
            match self.mode {
                StartMode::Boot => "system".to_string(),
                // SAFETY: `getuid` reads the calling process's real user id and
                // cannot fail; it takes no arguments and touches no memory.
                StartMode::Login => format!("gui/{}", unsafe { libc::getuid() }),
            }
        }

        fn service_target(&self, identity: &ServiceIdentity) -> String {
            format!("{}/{}", self.domain(), identity.launchd_label())
        }

        /// Where this domain's plist lives, when the domain has a home to put
        /// it in.
        fn plist_path(&self, identity: &ServiceIdentity) -> Option<PathBuf> {
            let file = format!("{}.plist", identity.launchd_label());
            match self.mode {
                StartMode::Boot => Some(PathBuf::from(LAUNCH_DAEMONS_DIR).join(file)),
                StartMode::Login => {
                    home_directory().map(|home| home.join(LAUNCH_AGENTS_SUBDIR).join(file))
                }
            }
        }

        fn failed(&self, operation: &'static str, name: &str, detail: String) -> ServiceError {
            ServiceError::Control {
                operation,
                name: name.to_string(),
                manager: "launchd",
                detail,
            }
        }

        fn launchctl(&self, arguments: &[&OsStr]) -> (bool, String) {
            match run("launchctl", arguments) {
                Ok((ok, stdout, stderr)) => (ok, if ok { stdout } else { stderr }),
                Err(error) => (false, error.to_string()),
            }
        }
    }

    impl ServiceControl for LaunchdControl {
        fn manager(&self) -> DefinitionKind {
            DefinitionKind::LaunchdPlist
        }

        fn install(&self, plan: &InstallPlan) -> Result<ServiceDefinition, ServiceError> {
            let name = plan.identity().name().to_string();
            let definition = ServiceDefinition::launchd(plan, home_directory().as_deref());
            let Some(path) = definition.install_path().map(std::path::Path::to_path_buf) else {
                return Err(self.failed(
                    "install",
                    &name,
                    "this account has no home directory, so there is nowhere to put a \
                     LaunchAgent. Use --start-at boot, which installs a LaunchDaemon under \
                     /Library/LaunchDaemons."
                        .to_string(),
                ));
            };
            write_definition("install", &name, &path, definition.text(), SUDO_REMEDY)?;
            let target = self.domain();
            let (ok, message) = self.launchctl(&[
                OsStr::new("bootstrap"),
                OsStr::new(&target),
                path.as_os_str(),
            ]);
            if !ok {
                // Leave nothing behind: a plist launchd refused is a file that
                // would make the next `service status` claim a registration
                // that does not exist.
                let _ = std::fs::remove_file(&path);
                if message.to_ascii_lowercase().contains("permission denied") {
                    return Err(ServiceError::NeedsElevation {
                        operation: "install",
                        name,
                        detail: message,
                        remedy: SUDO_REMEDY,
                    });
                }
                return Err(self.failed("install", &name, message));
            }
            // A previously disabled label stays disabled through a bootstrap,
            // which is a service that is installed and will never start.
            let service_target = self.service_target(plan.identity());
            enable_launchd_registration(
                |arguments| self.launchctl(arguments),
                &target,
                &service_target,
                &path,
                &name,
                SUDO_REMEDY,
            )?;
            Ok(definition)
        }

        fn uninstall(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError> {
            let Some(path) = self.plist_path(identity) else {
                return Ok(false);
            };
            if !path.exists() {
                return Ok(false);
            }
            let target = self.service_target(identity);
            let (ok, message) = self.launchctl(&[OsStr::new("bootout"), OsStr::new(&target)]);
            if !ok
                && !message.to_ascii_lowercase().contains("no such process")
                && !message.contains("113")
            {
                if message.to_ascii_lowercase().contains("permission denied") {
                    return Err(ServiceError::NeedsElevation {
                        operation: "uninstall",
                        name: identity.name().to_string(),
                        detail: message,
                        remedy: SUDO_REMEDY,
                    });
                }
                return Err(self.failed("uninstall", identity.name(), message));
            }
            // Only the definition. `05-infrastructure.md` item 5: nothing else
            // on this host is touched here or anywhere below it.
            std::fs::remove_file(&path).map_err(|error| {
                super::definition_error(
                    "uninstall",
                    identity.name(),
                    error,
                    SUDO_REMEDY,
                    path.as_path(),
                )
            })?;
            Ok(true)
        }

        fn query(&self, identity: &ServiceIdentity) -> Result<Option<Registration>, ServiceError> {
            let Some(path) = self.plist_path(identity) else {
                return Ok(None);
            };
            let Ok(document) = std::fs::read_to_string(&path) else {
                return Ok(None);
            };
            let target = self.service_target(identity);
            let (loaded, printed) = self.launchctl(&[OsStr::new("print"), OsStr::new(&target)]);
            Ok(Some(Registration {
                manager: DefinitionKind::LaunchdPlist,
                start_mode: self.mode,
                command_line: program_arguments(&document),
                account: plist_string_value(&document, "UserName")
                    .or_else(|| Some("the invoking user".to_string())),
                running: loaded && printed.contains("state = running"),
                starts_automatically: document.contains("<key>RunAtLoad</key>")
                    && super::plist_bool_value(&document, "RunAtLoad") == Some(true),
                restart_delay: xml_value(
                    super::plist_value_after_key(&document, "ThrottleInterval").unwrap_or(""),
                    "integer",
                )
                .and_then(|value| value.parse::<u64>().ok())
                .map(Duration::from_secs),
            }))
        }

        fn start(&self, identity: &ServiceIdentity) -> Result<(), ServiceError> {
            let target = self.service_target(identity);
            let (ok, message) = self.launchctl(&[
                OsStr::new("kickstart"),
                OsStr::new("-k"),
                OsStr::new(&target),
            ]);
            if ok {
                Ok(())
            } else {
                Err(self.failed("start", identity.name(), message))
            }
        }

        fn stop(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError> {
            let running = self
                .query(identity)?
                .is_some_and(|registration| registration.running);
            if !running {
                return Ok(false);
            }
            let target = self.service_target(identity);
            let (ok, message) = self.launchctl(&[
                OsStr::new("kill"),
                OsStr::new("SIGTERM"),
                OsStr::new(&target),
            ]);
            if ok {
                Ok(true)
            } else {
                Err(self.failed("stop", identity.name(), message))
            }
        }
    }

    /// Rebuilds the command line from a plist's `ProgramArguments` array.
    fn program_arguments(document: &str) -> String {
        let Some(rest) = super::plist_value_after_key(document, "ProgramArguments") else {
            return String::new();
        };
        let Some(end) = rest.find("</array>") else {
            return String::new();
        };
        let mut out = Vec::new();
        let mut cursor = &rest[..end];
        while let Some(open) = cursor.find("<string>") {
            let after = &cursor[open + "<string>".len()..];
            let Some(close) = after.find("</string>") else {
                break;
            };
            out.push(quote_argument(&super::xml_unescape(&after[..close])));
            cursor = &after[close..];
        }
        out.join(" ")
    }
}

// ---------------------------------------------------------------------------
// Linux and the other Unixes
// ---------------------------------------------------------------------------

#[cfg(all(unix, not(target_os = "macos")))]
mod sys {
    //! One manager, two domains. `--start-at boot` is a system unit in
    //! `/etc/systemd/system`, wanted by `multi-user.target`; `--start-at login`
    //! is a user unit in `~/.config/systemd/user`, wanted by `default.target`.
    //!
    //! Every inspection here goes through `systemctl is-active` and
    //! `systemctl is-enabled`, whose output is a fixed machine-readable word
    //! rather than a sentence, so nothing in this module depends on the
    //! machine's display language.

    use std::ffi::OsStr;
    use std::path::PathBuf;
    use std::time::Duration;

    use runner_manager_domain::model::StartMode;

    use super::{
        DefinitionKind, InstallPlan, Registration, SUDO_REMEDY, SYSTEMD_SYSTEM_DIR,
        SYSTEMD_USER_SUBDIR, ServiceControl, ServiceDefinition, ServiceError, ServiceIdentity,
        home_directory, ini_directives, run, write_definition,
    };

    pub(super) fn control(mode: StartMode) -> Result<Box<dyn ServiceControl>, ServiceError> {
        Ok(Box::new(SystemdControl { mode }))
    }

    #[derive(Debug)]
    struct SystemdControl {
        mode: StartMode,
    }

    impl SystemdControl {
        fn unit_path(&self, identity: &ServiceIdentity) -> Option<PathBuf> {
            let file = identity.systemd_unit();
            match self.mode {
                StartMode::Boot => Some(PathBuf::from(SYSTEMD_SYSTEM_DIR).join(file)),
                StartMode::Login => {
                    home_directory().map(|home| home.join(SYSTEMD_USER_SUBDIR).join(file))
                }
            }
        }

        /// `systemctl`, with `--user` for the login domain.
        fn systemctl(&self, arguments: &[&str]) -> (bool, String) {
            let mut all: Vec<&OsStr> = Vec::with_capacity(arguments.len() + 1);
            if self.mode == StartMode::Login {
                all.push(OsStr::new("--user"));
            }
            all.extend(arguments.iter().map(OsStr::new));
            match run("systemctl", &all) {
                Ok((ok, stdout, stderr)) => (
                    ok,
                    if stdout.trim().is_empty() {
                        stderr
                    } else {
                        stdout
                    },
                ),
                Err(error) => (false, error.to_string()),
            }
        }

        fn failed(&self, operation: &'static str, name: &str, detail: String) -> ServiceError {
            ServiceError::Control {
                operation,
                name: name.to_string(),
                manager: "systemd",
                detail,
            }
        }
    }

    impl ServiceControl for SystemdControl {
        fn manager(&self) -> DefinitionKind {
            DefinitionKind::SystemdUnit
        }

        fn install(&self, plan: &InstallPlan) -> Result<ServiceDefinition, ServiceError> {
            let name = plan.identity().name().to_string();
            let definition = ServiceDefinition::systemd(plan, home_directory().as_deref());
            let Some(path) = definition.install_path().map(std::path::Path::to_path_buf) else {
                return Err(self.failed(
                    "install",
                    &name,
                    "this account has no home directory, so there is nowhere to put a systemd \
                     user unit. Use --start-at boot, which installs a system unit under \
                     /etc/systemd/system."
                        .to_string(),
                ));
            };
            write_definition("install", &name, &path, definition.text(), SUDO_REMEDY)?;
            let unit = plan.identity().systemd_unit();
            let (reloaded, message) = self.systemctl(&["daemon-reload"]);
            if !reloaded {
                let _ = std::fs::remove_file(&path);
                return Err(self.failed("install", &name, message));
            }
            let (enabled, message) = self.systemctl(&["enable", &unit]);
            if !enabled {
                let _ = std::fs::remove_file(&path);
                let _ = self.systemctl(&["daemon-reload"]);
                return Err(self.failed("install", &name, message));
            }
            Ok(definition)
        }

        fn uninstall(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError> {
            let Some(path) = self.unit_path(identity) else {
                return Ok(false);
            };
            if !path.exists() {
                return Ok(false);
            }
            let unit = identity.systemd_unit();
            // `--now` stops it as well as disabling it. A failure here is not
            // fatal: the unit file is about to go, and refusing to remove it
            // because `systemctl` disliked something would leave the host with
            // a unit nothing manages.
            let _ = self.systemctl(&["disable", "--now", &unit]);
            std::fs::remove_file(&path).map_err(|error| {
                super::definition_error(
                    "uninstall",
                    identity.name(),
                    error,
                    SUDO_REMEDY,
                    path.as_path(),
                )
            })?;
            let _ = self.systemctl(&["daemon-reload"]);
            Ok(true)
        }

        fn query(&self, identity: &ServiceIdentity) -> Result<Option<Registration>, ServiceError> {
            let Some(path) = self.unit_path(identity) else {
                return Ok(None);
            };
            let Ok(document) = std::fs::read_to_string(&path) else {
                return Ok(None);
            };
            let unit = identity.systemd_unit();
            let directives = ini_directives(&document, "Service");
            let (_, active) = self.systemctl(&["is-active", &unit]);
            let (_, enabled) = self.systemctl(&["is-enabled", &unit]);
            Ok(Some(Registration {
                manager: DefinitionKind::SystemdUnit,
                start_mode: self.mode,
                command_line: directives.get("ExecStart").cloned().unwrap_or_default(),
                account: directives.get("User").cloned().or_else(|| {
                    Some(match self.mode {
                        StartMode::Boot => "root".to_string(),
                        StartMode::Login => "the invoking user".to_string(),
                    })
                }),
                running: active.trim() == "active",
                starts_automatically: enabled.trim() == "enabled",
                restart_delay: directives
                    .get("RestartSec")
                    .and_then(|value| value.trim().trim_end_matches('s').parse::<u64>().ok())
                    .map(Duration::from_secs),
            }))
        }

        fn start(&self, identity: &ServiceIdentity) -> Result<(), ServiceError> {
            let unit = identity.systemd_unit();
            let (ok, message) = self.systemctl(&["start", &unit]);
            if ok {
                Ok(())
            } else {
                Err(self.failed("start", identity.name(), message))
            }
        }

        fn stop(&self, identity: &ServiceIdentity) -> Result<bool, ServiceError> {
            let running = self
                .query(identity)?
                .is_some_and(|registration| registration.running);
            if !running {
                return Ok(false);
            }
            let unit = identity.systemd_unit();
            let (ok, message) = self.systemctl(&["stop", &unit]);
            if ok {
                Ok(true)
            } else {
                Err(self.failed("stop", identity.name(), message))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// A plan against paths that exist on no platform, so that every renderer
    /// can be asserted on every leg of the CI matrix.
    fn linux_plan(mode: StartMode) -> InstallPlan {
        InstallPlan::unchecked(
            ServiceIdentity::product(),
            mode,
            "/opt/runner-manager/bin/runner-manager",
            ServiceDirectories {
                config: PathBuf::from("/var/lib/runner-manager/config"),
                state: PathBuf::from("/var/lib/runner-manager/state"),
                runtime: PathBuf::from("/var/lib/runner-manager/runtime"),
                logs: PathBuf::from("/var/log/runner-manager"),
            },
        )
        .with_secret_guard("/var/lib/runner-manager/secrets/user-access-token")
    }

    fn windows_plan(mode: StartMode) -> InstallPlan {
        InstallPlan::unchecked(
            ServiceIdentity::product(),
            mode,
            "C:\\Program Files\\runner-manager\\runner-manager.exe",
            ServiceDirectories {
                config: PathBuf::from("C:\\Users\\op\\AppData\\Local\\rm\\config"),
                state: PathBuf::from("C:\\Users\\op\\AppData\\Local\\rm\\state"),
                runtime: PathBuf::from("C:\\Users\\op\\AppData\\Local\\rm\\runtime"),
                logs: PathBuf::from("C:\\Users\\op\\AppData\\Local\\rm\\logs"),
            },
        )
    }

    /// Replaces one fragment of a rendered definition, and **fails the test if
    /// the fragment was not there**.
    ///
    /// Without the assertion a renderer change would quietly turn every
    /// "widened definition is rejected" test below into a test that reviews the
    /// unmodified definition and passes for the wrong reason. This is the
    /// single guard that keeps that class of vacuity out of this file.
    fn edited(text: &str, from: &str, to: &str) -> String {
        assert!(
            text.contains(from),
            "the rendered definition does not contain `{from}`, so this test would assert \
             nothing about a widened one"
        );
        text.replace(from, to)
    }

    /// Every file under `root`, keyed by its path relative to `root`.
    fn snapshot(roots: &[&Path]) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(directory: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let Ok(entries) = std::fs::read_dir(directory) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if let Ok(bytes) = std::fs::read(&path) {
                    out.insert(path, bytes);
                }
            }
        }
        let mut out = BTreeMap::new();
        for root in roots {
            walk(root, &mut out);
        }
        out
    }

    struct Host {
        _root: tempfile::TempDir,
        paths: AppPaths,
        binary: PathBuf,
        /// A runner root inside this host's own temporary tree.
        ///
        /// Without it every `install` in this module would create and
        /// re-permission the **real** `%SystemDrive%\rman` on the machine
        /// running the tests, and would fail outright on any machine where that
        /// directory already exists with the access control `C:\` gives it.
        /// A sibling of the four application-data directories rather than a
        /// child of one, so `b1`'s overlap check has nothing to object to.
        runner_root: LocalAbsolutePath,
        controls: RecordingControls,
    }

    impl Host {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("a temporary directory");
            let paths = AppPaths::rooted_at(root.path());
            paths.create_all().expect("the four directories");
            let binary = root.path().join(if cfg!(windows) {
                "runner-manager.exe"
            } else {
                "runner-manager"
            });
            std::fs::write(&binary, b"not a real binary").expect("a stand-in binary");
            let runner_root = LocalAbsolutePath::new(
                root.path()
                    .join("runner-root")
                    .to_str()
                    .expect("a unicode temporary path"),
            )
            .expect("a local absolute path");
            Self {
                _root: root,
                paths,
                binary,
                runner_root,
                controls: RecordingControls::new(),
            }
        }

        fn operations(&self) -> ServiceOperations {
            ServiceOperations::with_controls(
                self.paths.clone(),
                ServiceIdentity::product(),
                std::sync::Arc::new(self.controls.clone()),
            )
            .with_runner_root(self.runner_root.clone())
        }

        fn request(&self, mode: StartMode) -> InstallRequest {
            InstallRequest::new(mode).for_binary(&self.binary)
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_uninstall_waits_through_the_marked_for_deletion_window() {
        let probes = std::cell::Cell::new(0);
        let absent =
            super::sys::wait_until_scm_absent(Duration::from_secs(1), Duration::ZERO, || {
                let next = probes.get() + 1;
                probes.set(next);
                Ok(next == 3)
            })
            .expect("the simulated SCM probe succeeds");

        assert!(absent);
        assert_eq!(
            probes.get(),
            3,
            "uninstall must recheck after transient presence instead of treating it as a leak"
        );
    }

    #[test]
    fn launchd_enable_failure_is_returned_and_removes_the_bootstrapped_registration() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let plist = root.path().join("fixture.plist");
        std::fs::write(&plist, b"fixture").expect("a plist fixture");
        let calls = std::cell::RefCell::new(Vec::new());

        let error = enable_launchd_registration(
            |arguments| {
                let call = arguments
                    .iter()
                    .map(|argument| argument.to_string_lossy().into_owned())
                    .collect::<Vec<_>>();
                let operation = call[0].clone();
                calls.borrow_mut().push(call);
                if operation == "enable" {
                    (false, "label remains disabled".to_string())
                } else {
                    (true, String::new())
                }
            },
            "system",
            "system/com.openai.runner-manager-selftest",
            &plist,
            "runner-manager-selftest",
            "rerun with administrative rights",
        )
        .expect_err("enable failure must fail the install");

        assert!(
            matches!(
                error,
                ServiceError::Control {
                    operation: "enable",
                    ..
                }
            ),
            "{error}"
        );
        assert_eq!(calls.borrow().len(), 2);
        assert_eq!(calls.borrow()[0][0], "enable");
        assert_eq!(calls.borrow()[1][0], "bootout");
        assert!(!plist.exists(), "rollback must remove the plist");
    }

    // -----------------------------------------------------------------------
    // Quoting, and reading a command line back
    // -----------------------------------------------------------------------

    #[test]
    fn a_path_with_spaces_survives_a_round_trip_through_a_command_line() {
        let plan = windows_plan(StartMode::Boot);
        let command_line = plan.command_line();
        assert!(
            command_line.starts_with('"'),
            "a path with a space must be quoted, got {command_line}"
        );
        assert_eq!(
            executable_from_command_line(&command_line).as_deref(),
            Some(plan.binary())
        );
    }

    #[test]
    fn a_path_without_spaces_is_not_quoted_and_still_reads_back() {
        let plan = linux_plan(StartMode::Boot);
        let command_line = plan.command_line();
        assert!(!command_line.starts_with('"'), "got {command_line}");
        assert_eq!(
            executable_from_command_line(&command_line).as_deref(),
            Some(plan.binary())
        );
    }

    #[test]
    fn a_quoted_path_containing_a_quote_reads_back_verbatim() {
        // Not a path anybody has, but it is the input that separates a real
        // implementation of Windows' quoting rules from a `split_whitespace`.
        let awkward = r#"C:\odd "name"\rm.exe"#;
        let quoted = quote_argument(awkward);
        assert_eq!(
            executable_from_command_line(&format!("{quoted} daemon run"))
                .as_deref()
                .map(Path::to_string_lossy)
                .as_deref(),
            Some(awkward)
        );
    }

    #[test]
    fn an_empty_command_line_has_no_executable() {
        assert_eq!(executable_from_command_line("   "), None);
        assert_eq!(executable_from_command_line(""), None);
    }

    #[test]
    fn xml_escaping_round_trips_the_characters_a_path_or_an_account_may_hold() {
        let awkward = r#"DOMAIN\R&D <team> "ops""#;
        assert_eq!(
            xml_escape(awkward),
            "DOMAIN\\R&amp;D &lt;team&gt; &quot;ops&quot;"
        );
        assert_eq!(xml_unescape(&xml_escape(awkward)), awkward);
    }

    // -----------------------------------------------------------------------
    // The restart policy is bounded at both ends
    // -----------------------------------------------------------------------

    #[test]
    fn a_restart_delay_under_the_floor_is_refused() {
        let error = RestartPolicy::new(Duration::from_millis(500), Duration::from_secs(60))
            .expect_err("half a second is under the one-second floor");
        assert!(
            matches!(error, ServiceError::RestartDelay { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_restart_delay_over_the_ceiling_is_refused() {
        let error = RestartPolicy::new(Duration::from_secs(3600), Duration::from_secs(7200))
            .expect_err("an hour is over the five-minute ceiling");
        assert!(
            matches!(error, ServiceError::RestartDelay { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_reset_window_no_longer_than_the_delay_is_refused() {
        let error = RestartPolicy::new(Duration::from_secs(15), Duration::from_secs(15))
            .expect_err("a window equal to the delay can never elapse between restarts");
        assert!(
            matches!(error, ServiceError::RestartResetWindow { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_delay_inside_the_bound_is_accepted() {
        let policy = RestartPolicy::new(Duration::from_secs(20), Duration::from_secs(300))
            .expect("twenty seconds is inside the bound");
        assert_eq!(policy.delay(), Duration::from_secs(20));
        assert_eq!(policy.reset_after(), Duration::from_secs(300));
    }

    // -----------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------

    #[test]
    fn a_fixture_identity_can_never_be_the_product_identity() {
        let fixture = ServiceIdentity::fixture("abc123");
        assert!(fixture.is_fixture());
        assert!(!ServiceIdentity::product().is_fixture());
        assert_ne!(fixture.name(), ServiceIdentity::product().name());
        assert_ne!(
            fixture.launchd_label(),
            ServiceIdentity::product().launchd_label()
        );
        assert_ne!(
            fixture.systemd_unit(),
            ServiceIdentity::product().systemd_unit()
        );
    }

    #[test]
    fn a_fixture_tag_is_reduced_to_characters_every_manager_accepts() {
        let fixture = ServiceIdentity::fixture("A b/c:\\d");
        assert!(
            fixture
                .name()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "got {}",
            fixture.name()
        );
    }

    // -----------------------------------------------------------------------
    // The systemd unit
    // -----------------------------------------------------------------------

    #[test]
    fn the_boot_unit_restarts_on_failure_after_the_bounded_delay() {
        let unit = systemd_unit(&linux_plan(StartMode::Boot));
        assert!(unit.contains("Restart=on-failure\n"), "{unit}");
        assert!(unit.contains("RestartSec=15\n"), "{unit}");
        assert!(unit.contains("StartLimitIntervalSec=600\n"), "{unit}");
        assert!(unit.contains("StartLimitBurst=5\n"), "{unit}");
        assert!(unit.contains("WantedBy=multi-user.target\n"), "{unit}");
    }

    #[test]
    fn the_boot_unit_reads_the_token_through_the_credential_d2_publishes() {
        let unit = systemd_unit(&linux_plan(StartMode::Boot));
        assert!(
            unit.contains(&format!(
                "LoadCredential={}:/var/lib/runner-manager/secrets/user-access-token\n",
                crate::secrets::SYSTEMD_CREDENTIAL
            )),
            "the unit must name the credential `d2` reads, got:\n{unit}"
        );
    }

    #[test]
    fn a_login_unit_carries_no_machine_credential_and_wants_the_session_target() {
        let unit = systemd_unit(&linux_plan(StartMode::Login));
        assert!(
            !unit.contains("LoadCredential="),
            "a user unit must not name a root-owned credential file, got:\n{unit}"
        );
        assert!(unit.contains("WantedBy=default.target\n"), "{unit}");
    }

    #[test]
    fn the_unit_makes_exactly_the_four_directories_writable() {
        let plan = linux_plan(StartMode::Boot);
        let unit = systemd_unit(&plan);
        let directives = ini_directives(&unit, "Service");
        let listed = split_quoted(
            directives
                .get("ReadWritePaths")
                .expect("the unit names its writable paths"),
        );
        assert_eq!(listed.len(), 4, "{listed:?}");
        for path in plan.directories().all() {
            assert!(
                listed.iter().any(|entry| entry == &path.to_string_lossy()),
                "{} is missing from {listed:?}",
                path.display()
            );
        }
    }

    #[test]
    fn the_unit_records_the_absolute_binary_path() {
        let plan = linux_plan(StartMode::Boot);
        let unit = systemd_unit(&plan);
        assert!(
            unit.contains("ExecStart=/opt/runner-manager/bin/runner-manager daemon run\n"),
            "{unit}"
        );
    }

    // -----------------------------------------------------------------------
    // The launchd property list
    // -----------------------------------------------------------------------

    #[test]
    fn the_daemon_restarts_only_after_an_unsuccessful_exit() {
        let plist = launchd_plist(&linux_plan(StartMode::Boot));
        // A bare `KeepAlive` would also restart a job the operator stopped
        // deliberately, which turns `service stop` into a fight with launchd.
        assert!(
            plist.contains(
                "<key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n"
            ),
            "{plist}"
        );
        assert!(
            plist.contains("<key>ThrottleInterval</key>\n  <integer>15</integer>"),
            "{plist}"
        );
    }

    #[test]
    fn a_launch_daemon_names_root_and_a_launch_agent_names_nobody() {
        let daemon = launchd_plist(&linux_plan(StartMode::Boot));
        assert_eq!(
            plist_string_value(&daemon, "UserName").as_deref(),
            Some("root")
        );
        assert_eq!(plist_bool_value(&daemon, "SessionCreate"), Some(false));

        let agent = launchd_plist(&linux_plan(StartMode::Login));
        assert_eq!(
            plist_string_value(&agent, "UserName"),
            None,
            "a LaunchAgent already runs as the operator:\n{agent}"
        );
    }

    #[test]
    fn the_plist_records_the_absolute_binary_path_and_the_daemon_arguments() {
        let plist = launchd_plist(&linux_plan(StartMode::Boot));
        assert!(
            plist.contains("<string>/opt/runner-manager/bin/runner-manager</string>"),
            "{plist}"
        );
        assert!(plist.contains("<string>daemon</string>"), "{plist}");
        assert!(plist.contains("<string>run</string>"), "{plist}");
    }

    #[test]
    fn the_launchd_label_is_the_product_identity_in_reverse_domain_form() {
        assert_eq!(
            ServiceIdentity::product().launchd_label(),
            "io.github.IvanMurzak.runner-manager"
        );
    }

    // -----------------------------------------------------------------------
    // The Task Scheduler document
    // -----------------------------------------------------------------------

    #[test]
    fn the_task_runs_at_least_privilege_on_a_logon_trigger() {
        let xml = windows_scheduled_task_xml(
            &windows_plan(StartMode::Login),
            &TaskPrincipal::named("HOST\\operator"),
        );
        assert!(xml.contains("<LogonTrigger>"), "{xml}");
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"), "{xml}");
        assert!(
            xml.contains("<LogonType>InteractiveToken</LogonType>"),
            "{xml}"
        );
        assert!(xml.contains("<UserId>HOST\\operator</UserId>"), "{xml}");
        assert!(
            xml.contains("<Interval>PT1M</Interval>"),
            "Task Scheduler takes whole minutes only, and rejects the registration outright \
             for anything finer:\n{xml}"
        );
    }

    #[test]
    fn task_schedulers_minute_granularity_only_ever_rounds_the_delay_up() {
        // Measured against the real Task Scheduler, which answers `PT15S` with
        // "The task XML contains a value which is incorrectly formatted or out
        // of range". Rounding *up* is what keeps "does not restart-loop faster
        // than that bound" true on this manager.
        for (asked, enforced) in [(1u64, 60u64), (15, 60), (60, 60), (61, 120), (300, 300)] {
            let policy =
                RestartPolicy::new(Duration::from_secs(asked), Duration::from_secs(asked + 600))
                    .expect("inside the supported range");
            assert_eq!(
                policy
                    .effective_delay(DefinitionKind::WindowsScheduledTask)
                    .as_secs(),
                enforced,
                "a {asked}s delay must be enforced as {enforced}s"
            );
            assert!(
                policy.effective_delay(DefinitionKind::WindowsScheduledTask) >= policy.delay(),
                "rounding must never shorten the bound"
            );
        }
    }

    #[test]
    fn every_other_manager_enforces_the_delay_exactly_as_configured() {
        let policy = RestartPolicy::default();
        for kind in [
            DefinitionKind::WindowsService,
            DefinitionKind::LaunchdPlist,
            DefinitionKind::SystemdUnit,
        ] {
            assert_eq!(
                policy.effective_delay(kind),
                policy.delay(),
                "{kind:?} takes seconds and enforces exactly what it is given"
            );
        }
    }

    #[test]
    fn a_task_whose_manager_reports_the_rounded_delay_is_not_a_fault() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Login))
            .expect("an install at login");
        // What a real Task Scheduler reports back for a 15-second policy.
        host.controls.edit("runner-manager", |registration| {
            registration.manager = DefinitionKind::WindowsScheduledTask;
            registration.restart_delay = Some(Duration::from_secs(60));
        });

        let status = operations.status().expect("a status");
        assert!(
            status.is_healthy(),
            "minute granularity is the manager's, not a mis-registration: {status}"
        );
        assert!(
            status
                .notes()
                .iter()
                .any(|note| note.contains("whole minutes")),
            "but the operator must be told why 15 became 60: {status}"
        );

        // The discriminator: a delay that is neither the configured one nor its
        // rounding is still a fault.
        host.controls.edit("runner-manager", |registration| {
            registration.restart_delay = Some(Duration::from_secs(1));
        });
        assert!(
            !operations.status().expect("a status").is_healthy(),
            "a one-second delay is not what any manager was asked for"
        );
    }

    #[test]
    fn the_task_records_the_absolute_binary_path_and_the_daemon_arguments() {
        let plan = windows_plan(StartMode::Login);
        let xml = windows_scheduled_task_xml(&plan, &TaskPrincipal::named("HOST\\operator"));
        assert_eq!(
            xml_value(&xml, "Command").as_deref(),
            Some("C:\\Program Files\\runner-manager\\runner-manager.exe"),
            "{xml}"
        );
        assert_eq!(xml_value(&xml, "Arguments").as_deref(), Some("daemon run"));
    }

    #[test]
    fn an_account_name_holding_xml_punctuation_is_escaped() {
        let xml = windows_scheduled_task_xml(
            &windows_plan(StartMode::Login),
            &TaskPrincipal::named("R&D\\ops"),
        );
        assert!(xml.contains("<UserId>R&amp;D\\ops</UserId>"), "{xml}");
        assert_eq!(xml_value(&xml, "UserId").as_deref(), Some("R&D\\ops"));
    }

    // -----------------------------------------------------------------------
    // The Windows service descriptor
    // -----------------------------------------------------------------------

    #[test]
    fn the_service_starts_automatically_under_the_account_the_store_admits() {
        let text = windows_service_descriptor(&windows_plan(StartMode::Boot));
        let directives = ini_directives(&text, "windows-service");
        assert_eq!(
            directives.get("StartType").map(String::as_str),
            Some("AutoStart")
        );
        assert_eq!(
            directives.get("Account").map(String::as_str),
            Some("NT AUTHORITY\\SYSTEM")
        );
        assert_eq!(
            directives.get("ServiceType").map(String::as_str),
            Some("OWN_PROCESS")
        );
        assert_eq!(
            directives
                .get("FailureActionRestartDelaySecs")
                .map(String::as_str),
            Some("15")
        );
        assert_eq!(
            directives
                .get("FailureActionsOnNonCrashFailures")
                .map(String::as_str),
            Some("true"),
            "without this flag a non-zero exit is not a failure the manager restarts"
        );
    }

    #[test]
    fn the_service_spec_leaves_the_account_unnamed_so_the_api_means_local_system() {
        let spec = windows_service_spec(&windows_plan(StartMode::Boot));
        assert_eq!(spec.account, None);
        assert!(spec.automatic_start);
        assert!(
            spec.command_line.contains("daemon run"),
            "{}",
            spec.command_line
        );
    }

    // -----------------------------------------------------------------------
    // Where each definition is installed
    // -----------------------------------------------------------------------

    #[test]
    fn each_definition_goes_where_its_platform_expects_it() {
        let home = PathBuf::from("/home/op");
        assert_eq!(
            ServiceDefinition::launchd(&linux_plan(StartMode::Boot), Some(&home)).install_path(),
            Some(Path::new(
                "/Library/LaunchDaemons/io.github.IvanMurzak.runner-manager.plist"
            ))
        );
        assert_eq!(
            ServiceDefinition::launchd(&linux_plan(StartMode::Login), Some(&home)).install_path(),
            Some(Path::new(
                "/home/op/Library/LaunchAgents/io.github.IvanMurzak.runner-manager.plist"
            ))
        );
        assert_eq!(
            ServiceDefinition::systemd(&linux_plan(StartMode::Boot), Some(&home)).install_path(),
            Some(Path::new("/etc/systemd/system/runner-manager.service"))
        );
        assert_eq!(
            ServiceDefinition::systemd(&linux_plan(StartMode::Login), Some(&home)).install_path(),
            Some(Path::new(
                "/home/op/.config/systemd/user/runner-manager.service"
            ))
        );
        assert_eq!(
            ServiceDefinition::windows_service(&windows_plan(StartMode::Boot)).install_path(),
            None,
            "the Service Control Manager has no file"
        );
    }

    #[test]
    fn a_login_definition_without_a_home_directory_has_nowhere_to_go() {
        assert_eq!(
            ServiceDefinition::systemd(&linux_plan(StartMode::Login), None).install_path(),
            None
        );
        assert_eq!(
            ServiceDefinition::launchd(&linux_plan(StartMode::Login), None).install_path(),
            None
        );
    }

    // -----------------------------------------------------------------------
    // The least-privilege review: the passing case, then every failing one
    // -----------------------------------------------------------------------

    #[test]
    fn the_rendered_definitions_are_all_least_privilege() {
        let linux = linux_plan(StartMode::Boot);
        let windows = windows_plan(StartMode::Boot);
        for (definition, plan) in [
            (ServiceDefinition::systemd(&linux, None), &linux),
            (ServiceDefinition::launchd(&linux, None), &linux),
            (ServiceDefinition::windows_service(&windows), &windows),
        ] {
            let review = review_least_privilege(&definition, plan);
            assert!(
                review.is_least_privilege(),
                "{:?} should be least privilege, got:\n{review}",
                definition.kind()
            );
            assert!(
                !review.controls().is_empty(),
                "a review that confirms nothing proves nothing: {:?}",
                definition.kind()
            );
        }
    }

    #[test]
    fn the_rendered_task_is_least_privilege_and_says_what_it_checked() {
        let plan = windows_plan(StartMode::Login);
        let definition =
            ServiceDefinition::windows_scheduled_task(&plan, &TaskPrincipal::named("HOST\\op"));
        let review = review_least_privilege(&definition, &plan);
        assert!(review.is_least_privilege(), "{review}");
        assert!(
            review
                .controls()
                .iter()
                .any(|control| control.contains("LeastPrivilege")),
            "{review}"
        );
    }

    #[test]
    fn a_unit_that_makes_one_more_directory_writable_is_not_least_privilege() {
        let plan = linux_plan(StartMode::Boot);
        let rendered = systemd_unit(&plan);
        let widened = edited(
            &rendered,
            "ReadWritePaths=/var/lib/runner-manager/config",
            "ReadWritePaths=/etc /var/lib/runner-manager/config",
        );
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::SystemdUnit, widened),
            &plan,
        );
        assert!(!review.is_least_privilege(), "{review}");
        assert!(
            review
                .excesses()
                .iter()
                .any(|finding| finding.detail.contains("/etc")),
            "the review must name the directory it objects to: {review}"
        );
    }

    #[test]
    fn a_unit_that_drops_a_hardening_directive_is_not_least_privilege() {
        let plan = linux_plan(StartMode::Boot);
        let rendered = systemd_unit(&plan);
        let weakened = edited(&rendered, "NoNewPrivileges=yes\n", "");
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::SystemdUnit, weakened),
            &plan,
        );
        assert!(!review.is_least_privilege(), "{review}");
        assert!(
            review
                .excesses()
                .iter()
                .any(|finding| finding.subject == "NoNewPrivileges"),
            "{review}"
        );
    }

    #[test]
    fn a_unit_that_keeps_capabilities_is_not_least_privilege() {
        let plan = linux_plan(StartMode::Boot);
        let rendered = systemd_unit(&plan);
        let widened = edited(
            &rendered,
            "CapabilityBoundingSet=\n",
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN\n",
        );
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::SystemdUnit, widened),
            &plan,
        );
        assert!(!review.is_least_privilege(), "{review}");
        assert!(
            review
                .excesses()
                .iter()
                .any(|finding| finding.subject == "CapabilityBoundingSet"),
            "{review}"
        );
    }

    #[test]
    fn a_unit_that_opens_a_listening_socket_is_not_least_privilege() {
        let plan = linux_plan(StartMode::Boot);
        let rendered = systemd_unit(&plan);
        let widened = edited(
            &rendered,
            "[Install]",
            "ListenStream=127.0.0.1:9000\n\n[Install]",
        );
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::SystemdUnit, widened),
            &plan,
        );
        assert!(
            !review.is_least_privilege(),
            "07-security.md rule 2 forbids any inbound surface: {review}"
        );
    }

    #[test]
    fn a_unit_that_makes_a_directory_unwritable_is_a_shortfall_not_an_excess() {
        let plan = linux_plan(StartMode::Boot);
        let rendered = systemd_unit(&plan);
        let narrowed = edited(&rendered, " /var/lib/runner-manager/runtime", "");
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::SystemdUnit, narrowed),
            &plan,
        );
        assert!(
            review.is_least_privilege(),
            "too little authority is not an excess: {review}"
        );
        assert!(
            review
                .findings()
                .iter()
                .any(|finding| finding.kind == FindingKind::Shortfall
                    && finding.detail.contains("runtime")),
            "{review}"
        );
    }

    #[test]
    fn a_launch_agent_that_names_an_account_is_not_least_privilege() {
        let plan = linux_plan(StartMode::Login);
        let rendered = launchd_plist(&plan);
        let widened = edited(
            &rendered,
            "<key>ProcessType</key>",
            "<key>UserName</key>\n  <string>root</string>\n  <key>ProcessType</key>",
        );
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::LaunchdPlist, widened),
            &plan,
        );
        assert!(!review.is_least_privilege(), "{review}");
        assert!(
            review
                .excesses()
                .iter()
                .any(|finding| finding.subject == "UserName"),
            "{review}"
        );
    }

    #[test]
    fn a_launch_daemon_that_asks_for_a_session_is_not_least_privilege() {
        let plan = linux_plan(StartMode::Boot);
        let rendered = launchd_plist(&plan);
        let widened = edited(
            &rendered,
            "<key>SessionCreate</key>\n  <false/>",
            "<key>SessionCreate</key>\n  <true/>",
        );
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::LaunchdPlist, widened),
            &plan,
        );
        assert!(!review.is_least_privilege(), "{review}");
        assert!(
            review
                .excesses()
                .iter()
                .any(|finding| finding.subject == "SessionCreate"),
            "{review}"
        );
    }

    #[test]
    fn a_launchd_job_that_publishes_a_mach_service_is_not_least_privilege() {
        let plan = linux_plan(StartMode::Boot);
        let rendered = launchd_plist(&plan);
        let widened = edited(
            &rendered,
            "<key>ProcessType</key>",
            "<key>MachServices</key>\n  <dict/>\n  <key>ProcessType</key>",
        );
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::LaunchdPlist, widened),
            &plan,
        );
        assert!(!review.is_least_privilege(), "{review}");
    }

    #[test]
    fn a_task_asking_for_the_highest_available_token_is_not_least_privilege() {
        let plan = windows_plan(StartMode::Login);
        let rendered = windows_scheduled_task_xml(&plan, &TaskPrincipal::named("HOST\\op"));
        let widened = edited(
            &rendered,
            "<RunLevel>LeastPrivilege</RunLevel>",
            "<RunLevel>HighestAvailable</RunLevel>",
        );
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::WindowsScheduledTask, widened),
            &plan,
        );
        assert!(!review.is_least_privilege(), "{review}");
        assert!(
            review
                .excesses()
                .iter()
                .any(|finding| finding.subject == "RunLevel"),
            "{review}"
        );
    }

    #[test]
    fn a_task_that_would_store_a_password_is_not_least_privilege() {
        let plan = windows_plan(StartMode::Login);
        let rendered = windows_scheduled_task_xml(&plan, &TaskPrincipal::named("HOST\\op"));
        let widened = edited(
            &rendered,
            "<LogonType>InteractiveToken</LogonType>",
            "<LogonType>Password</LogonType>",
        );
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::WindowsScheduledTask, widened),
            &plan,
        );
        assert!(!review.is_least_privilege(), "{review}");
    }

    #[test]
    fn an_interactive_windows_service_is_not_least_privilege() {
        let plan = windows_plan(StartMode::Boot);
        let rendered = windows_service_descriptor(&plan);
        let widened = edited(
            &rendered,
            "ServiceType=OWN_PROCESS",
            "ServiceType=OWN_PROCESS|INTERACTIVE_PROCESS",
        );
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::WindowsService, widened),
            &plan,
        );
        assert!(!review.is_least_privilege(), "{review}");
        assert!(
            review
                .excesses()
                .iter()
                .any(|finding| finding.subject == "ServiceType"),
            "{review}"
        );
    }

    #[test]
    fn a_windows_service_under_an_account_the_store_dacl_does_not_name_is_reported() {
        let plan = windows_plan(StartMode::Boot);
        let rendered = windows_service_descriptor(&plan);
        let changed = edited(
            &rendered,
            "Account=NT AUTHORITY\\SYSTEM",
            "Account=NT AUTHORITY\\LocalService",
        );
        let review = review_least_privilege(
            &ServiceDefinition::from_text(DefinitionKind::WindowsService, changed),
            &plan,
        );
        // LocalService is *less* privileged, so this is not an excess. It is
        // still wrong, because `d2`'s DACL names SY, BA and OW and nothing else:
        // the daemon would start and find no credential. Reporting it as a
        // shortfall rather than as an excess is the difference between a check
        // that understands the requirement and one that counts adjectives.
        assert!(review.is_least_privilege(), "{review}");
        assert!(
            review.findings().iter().any(|finding| {
                finding.kind == FindingKind::Shortfall && finding.subject == "Account"
            }),
            "{review}"
        );
    }

    // -----------------------------------------------------------------------
    // The recorded absolute path, and what became of it
    // -----------------------------------------------------------------------

    #[test]
    fn a_recorded_path_that_is_still_there_is_current() {
        let host = Host::new();
        let state = inspect_binary(&host.binary, Some(&host.binary));
        assert!(!state.is_error(), "{state}");
        assert!(matches!(state, BinaryPath::Current { .. }), "{state}");
    }

    #[test]
    fn the_npm_upgrade_case_reports_a_stale_path_as_an_error() {
        let host = Host::new();
        // An `npm i -g` binary lives under the active Node installation's
        // global prefix. Switching Node versions moves the prefix, and the
        // recorded path stops existing while the registration survives.
        let recorded = host.binary.clone();
        let healthy = inspect_binary(&recorded, Some(&recorded));
        assert!(
            !healthy.is_error(),
            "the discriminator: before the binary moves, this must be healthy"
        );

        std::fs::remove_file(&recorded).expect("the binary moves out from under the record");

        let state = inspect_binary(&recorded, Some(&recorded));
        assert!(state.is_error(), "{state}");
        assert!(matches!(state, BinaryPath::Missing { .. }), "{state}");
        assert!(
            state.to_string().contains("npm"),
            "the message must name the cause an operator will not otherwise connect: {state}"
        );
    }

    #[test]
    fn a_directory_at_the_recorded_path_is_not_something_the_manager_can_start() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let state = inspect_binary(root.path(), None);
        assert!(state.is_error(), "{state}");
        assert!(matches!(state, BinaryPath::NotExecutable { .. }), "{state}");
    }

    #[test]
    fn a_registration_naming_a_different_binary_is_a_divergence() {
        let host = Host::new();
        let other = host.binary.with_file_name("something-else");
        let state = inspect_binary(&host.binary, Some(&other));
        assert!(state.is_error(), "{state}");
        assert!(matches!(state, BinaryPath::Diverged { .. }), "{state}");
    }

    #[test]
    fn absence_is_reported_before_divergence() {
        let host = Host::new();
        let recorded = host.binary.clone();
        std::fs::remove_file(&recorded).expect("removable");
        let other = recorded.with_file_name("something-else");
        // Both faults are true at once. The operator needs to hear about the
        // missing file, not about a disagreement between two paths of which one
        // does not exist.
        assert!(matches!(
            inspect_binary(&recorded, Some(&other)),
            BinaryPath::Missing { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // The record
    // -----------------------------------------------------------------------

    #[test]
    fn the_record_round_trips_through_toml() {
        let host = Host::new();
        let plan = InstallPlan::resolve(
            ServiceIdentity::product(),
            &host.request(StartMode::Boot),
            ServiceDirectories::of(&host.paths),
        )
        .expect("a resolvable plan");
        let definition = ServiceDefinition::from_text(DefinitionKind::SystemdUnit, "[Service]\n");
        let record = InstallRecord::of(&plan, &definition, Utc::now());
        record.write(&host.paths).expect("a writable record");
        let read = InstallRecord::read(&host.paths)
            .expect("a readable record")
            .expect("a record is there");
        assert_eq!(read, record);
        assert_eq!(read.binary, host.binary);
        assert!(read.binary.is_absolute());
    }

    /// A record written before the service ran a copy of its own must still
    /// load. It reads as `None`, which is the truth about it: that registration
    /// names the package manager's file and cannot be upgraded under itself.
    #[test]
    fn a_record_without_a_source_binary_still_reads_and_says_it_has_none() {
        let host = Host::new();
        let path = InstallRecord::path(&host.paths);
        std::fs::write(
            &path,
            format!(
                "schema_version = {RECORD_SCHEMA_VERSION}
service_name = \"runner-manager\"
                 manager = \"systemd\"
start_mode = \"boot\"
account = \"root\"
                 binary = \"/x\"
arguments = []
restart_delay_secs = 15
                 restart_reset_secs = 600
log_file = \"/x\"
                 installed_at = \"2026-01-01T00:00:00Z\"
installed_by_version = \"0.1.0\"
                 [directories]
config = \"/a\"
state = \"/b\"
runtime = \"/c\"
logs = \"/d\"
"
            ),
        )
        .expect("a writable record");
        let read = InstallRecord::read(&host.paths)
            .expect("a record missing an optional field is still readable")
            .expect("a record is there");
        assert_eq!(
            read.source_binary, None,
            "the legacy layout has no source, and must not invent one"
        );
    }

    /// The field that makes an upgrade possible survives the write.
    #[test]
    fn a_registration_remembers_the_file_it_was_copied_from() {
        let host = Host::new();
        let source = host.binary.with_file_name("npm-installed-runner-manager");
        std::fs::copy(&host.binary, &source).expect("a second file to stand in for the package");
        let plan = InstallPlan::resolve(
            ServiceIdentity::product(),
            &host.request(StartMode::Boot).copied_from(&source),
            ServiceDirectories::of(&host.paths),
        )
        .expect("a resolvable plan");
        let definition = ServiceDefinition::from_text(
            DefinitionKind::SystemdUnit,
            "[Service]
",
        );
        let record = InstallRecord::of(&plan, &definition, Utc::now());
        record.write(&host.paths).expect("a writable record");

        let read = InstallRecord::read(&host.paths)
            .expect("a readable record")
            .expect("a record is there");
        assert_eq!(read.source_binary.as_deref(), Some(source.as_path()));
        assert_ne!(
            read.source_binary.as_deref(),
            Some(read.binary.as_path()),
            "the whole point is that the two are different files: one the service holds open,              one the package manager is free to replace"
        );
    }

    #[test]
    fn a_record_from_a_schema_this_build_cannot_read_is_refused_with_a_remedy() {
        let host = Host::new();
        let path = InstallRecord::path(&host.paths);
        std::fs::write(
            &path,
            format!(
                "schema_version = {}\nservice_name = \"runner-manager\"\nmanager = \"systemd\"\n\
                 start_mode = \"boot\"\naccount = \"root\"\nbinary = \"/x\"\narguments = []\n\
                 restart_delay_secs = 15\nrestart_reset_secs = 600\nlog_file = \"/x\"\n\
                 installed_at = \"2026-01-01T00:00:00Z\"\ninstalled_by_version = \"0.1.0\"\n\
                 [directories]\nconfig = \"/a\"\nstate = \"/b\"\nruntime = \"/c\"\nlogs = \"/d\"\n",
                RECORD_SCHEMA_VERSION + 1
            ),
        )
        .expect("a writable record");
        let error = InstallRecord::read(&host.paths).expect_err("a future schema is refused");
        assert!(
            matches!(error, ServiceError::RecordUnreadable { .. }),
            "{error}"
        );
        assert!(
            error.to_string().contains("service uninstall"),
            "the message must say how to recover: {error}"
        );
    }

    #[test]
    fn no_record_is_not_an_error() {
        let host = Host::new();
        assert_eq!(InstallRecord::read(&host.paths).expect("no record"), None);
        assert!(!InstallRecord::remove(&host.paths).expect("nothing to remove"));
    }

    // -----------------------------------------------------------------------
    // The last successful GitHub contact
    // -----------------------------------------------------------------------

    #[test]
    fn no_heartbeat_reads_as_never_rather_than_as_the_epoch() {
        let host = Host::new();
        assert_eq!(last_github_contact(&host.paths).expect("readable"), None);
    }

    #[test]
    fn the_heartbeat_round_trips_to_the_second() {
        let host = Host::new();
        let at = DateTime::parse_from_rfc3339("2026-08-22T10:11:12Z")
            .expect("a valid timestamp")
            .with_timezone(&Utc);
        record_github_contact(&host.paths, at).expect("a writable heartbeat");
        assert_eq!(
            last_github_contact(&host.paths).expect("readable"),
            Some(at)
        );
    }

    #[test]
    fn a_malformed_heartbeat_is_an_error_and_not_silently_never() {
        let host = Host::new();
        std::fs::write(contact_path(&host.paths), b"this is not toml \x00").expect("writable");
        let error = last_github_contact(&host.paths)
            .expect_err("a heartbeat that cannot be parsed is not the same as no heartbeat");
        assert!(matches!(error, ServiceError::Record { .. }), "{error}");
    }

    // -----------------------------------------------------------------------
    // Install
    // -----------------------------------------------------------------------

    #[test]
    fn install_records_the_absolute_binary_path_and_the_four_directories() {
        let host = Host::new();
        let installed = host
            .operations()
            .install(&host.request(StartMode::Boot))
            .expect("an install against the recording controls");

        assert_eq!(installed.record.binary, host.binary);
        assert!(installed.record.binary.is_absolute());
        assert_eq!(installed.record.start_mode, StartMode::Boot);
        assert_eq!(installed.record.arguments, vec!["daemon", "run"]);
        assert_eq!(
            installed.record.directories,
            ServiceDirectories::of(&host.paths)
        );
        assert_eq!(
            installed.record.log_file,
            host.paths.logs_dir().join(LOG_FILE_STEM)
        );
        assert_eq!(installed.record.restart_delay_secs, 15);

        let registrations = host.controls.registrations();
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].0, StartMode::Boot);
        assert_eq!(registrations[0].1, "runner-manager");
    }

    #[test]
    fn install_is_refused_while_the_single_instance_lock_is_held() {
        let host = Host::new();
        // The discriminator: with the lock free, the same call succeeds.
        {
            let operations = host.operations();
            operations
                .install(&host.request(StartMode::Boot))
                .expect("an install with the lock free");
            operations.uninstall().expect("a clean slate");
        }

        let _held = HostLock::try_acquire(&host.paths, LockKind::SingleInstance)
            .expect("this process takes the lock first");

        let error = host
            .operations()
            .install(&host.request(StartMode::Boot))
            .expect_err("a second agent must not be registered while one is running");
        assert!(matches!(error, ServiceError::LockHeld { .. }), "{error}");
        assert!(
            error.to_string().contains("already running"),
            "the message must be actionable: {error}"
        );
        assert!(
            host.controls.registrations().is_empty(),
            "a refused install must register nothing"
        );
        assert_eq!(
            InstallRecord::read(&host.paths).expect("readable"),
            None,
            "a refused install must write no record"
        );
    }

    #[test]
    fn installing_over_an_existing_registration_is_refused() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("the first install");
        let error = operations
            .install(&host.request(StartMode::Boot))
            .expect_err("the second install");
        assert!(
            matches!(error, ServiceError::AlreadyInstalled { .. }),
            "{error}"
        );
        assert_eq!(host.controls.registrations().len(), 1);
    }

    #[test]
    fn install_rolls_back_the_registration_when_record_persistence_fails() {
        let host = Host::new();
        let record_path = InstallRecord::path(&host.paths);
        std::fs::create_dir(&record_path).expect("a directory blocks the record file");

        let error = host
            .operations()
            .install(&host.request(StartMode::Boot))
            .expect_err("record persistence must fail");

        assert!(matches!(error, ServiceError::Record { .. }), "{error}");
        assert!(
            host.controls.registrations().is_empty(),
            "a failed install must not leave a live unrecorded registration"
        );
        assert!(
            host.controls
                .calls()
                .iter()
                .any(|call| call == "uninstall runner-manager (boot)"),
            "the registration must be explicitly rolled back: {:?}",
            host.controls.calls()
        );
        assert!(
            !host.runner_root.as_path().exists(),
            "the rollback must take the runner root this install created with it; a directory \
             prepared for a registration that does not exist is litter, and on Windows it is \
             litter with a security descriptor"
        );
    }

    // -----------------------------------------------------------------------
    // The runner root (b2)
    // -----------------------------------------------------------------------

    #[test]
    fn the_runner_root_a_boot_registration_needs_admits_only_the_service() {
        use crate::runner_root_access::{RootAdmission, default_root_sddl, grants_broad_write};

        // The mapping `prepare_runner_root` reads, asserted against the same
        // function the registration's own principal comes from — which is the
        // point of deriving it there rather than restating it.
        assert_eq!(
            ServiceAccount::for_definition(DefinitionKind::WindowsService, StartMode::Boot),
            ServiceAccount::LocalSystem
        );
        assert_eq!(
            ServiceAccount::for_definition(DefinitionKind::WindowsScheduledTask, StartMode::Login),
            ServiceAccount::InvokingUser
        );

        let boot = default_root_sddl(&RootAdmission::LocalSystem);
        assert!(!grants_broad_write(&boot), "{boot}");
        assert!(
            !boot.contains("S-1-5-21"),
            "a boot registration runs as LocalSystem, so its root names no operator: {boot}"
        );

        // A login task runs under a *filtered* token — `RunLevel` is
        // `LeastPrivilege`, see `windows_scheduled_task_xml` — in which
        // Administrators is deny-only. Without an ace of its own the account
        // the task runs as would be admitted by nothing at all.
        let login = default_root_sddl(&RootAdmission::Account("S-1-5-21-1-2-3-1001".to_owned()));
        assert!(login.contains("S-1-5-21-1-2-3-1001"), "{login}");
        assert!(!grants_broad_write(&login), "{login}");
    }

    #[test]
    fn an_install_reports_the_runner_root_it_prepared() {
        let host = Host::new();
        let installed = host
            .operations()
            .install(&host.request(StartMode::Boot))
            .expect("an install");
        let rendered = installed.runner_root.to_string();
        assert!(
            !rendered.contains("S-1-5-21"),
            "the report must add no identity to the output: {rendered}"
        );
        if cfg!(windows) {
            assert_eq!(
                installed.runner_root.path(),
                Some(host.runner_root.as_path())
            );
            assert!(
                host.runner_root.as_path().is_dir(),
                "the directory jobs would run in has to exist once the service is registered"
            );
        } else {
            assert_eq!(
                installed.runner_root,
                crate::runner_root_access::RootAccessSummary::NotApplicable,
                "macOS and Linux keep the runtime directory they have always used"
            );
        }
    }

    #[test]
    fn switching_start_mode_reconciles_the_runner_root_for_the_new_account() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install at boot");

        let change = operations
            .set_start_mode(StartMode::Login)
            .expect("a switch to login");

        assert!(change.changed);
        if cfg!(windows) {
            assert_eq!(change.runner_root.path(), Some(host.runner_root.as_path()));
            assert!(
                host.runner_root.as_path().is_dir(),
                "the switch must not remove the directory it reconciled"
            );
        }
        // The operator is told, because the account that may write there has
        // moved with the mode.
        assert!(
            change.to_string().contains("runner root"),
            "{}",
            change.to_string()
        );
    }

    #[test]
    fn switching_to_the_mode_already_in_force_touches_no_runner_root() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install at boot");

        let change = operations
            .set_start_mode(StartMode::Boot)
            .expect("a switch to the mode already in force");

        assert!(!change.changed);
        assert_eq!(
            change.runner_root,
            crate::runner_root_access::RootAccessSummary::NotApplicable,
            "nothing moves, so nothing about the root's access control has to; reconciling here \
             would turn a no-op command into one that can fail on a permission it does not need"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_registration_the_manager_refuses_leaves_no_runner_root_behind() {
        let host = Host::new();
        host.controls
            .fail_next_install(StartMode::Boot, "injected registration failure");

        let error = host
            .operations()
            .install(&host.request(StartMode::Boot))
            .expect_err("the manager refuses the registration");

        assert!(matches!(error, ServiceError::Control { .. }), "{error}");
        assert!(
            !host.runner_root.as_path().exists(),
            "the directory was created for a registration that does not exist"
        );
    }

    #[cfg(windows)]
    #[test]
    fn an_existing_broad_runner_root_refuses_the_install_before_anything_is_registered() {
        let host = Host::new();
        // What a directory created below `C:\` with inheritance left on looks
        // like, built deliberately because a per-account `%TEMP%` never
        // produces one by accident.
        crate::runner_root_access::create_with_descriptor_for_tests(
            host.runner_root.as_path(),
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)",
        )
        .expect("a deliberately open runner root");
        let before = crate::runner_root_access::report(host.runner_root.as_path());

        let error = host
            .operations()
            .install(&host.request(StartMode::Boot))
            .expect_err("an open runner root is refused");

        assert!(matches!(error, ServiceError::RunnerRoot { .. }), "{error}");
        assert!(
            error.to_string().contains("nothing was registered"),
            "{error}"
        );
        assert!(
            host.controls.registrations().is_empty(),
            "the refusal has to come before the platform is asked to register anything: {:?}",
            host.controls.calls()
        );
        assert_eq!(
            crate::runner_root_access::report(host.runner_root.as_path()),
            before,
            "an open directory is refused rather than tightened: its contents cannot be trusted, \
             so adopting it would be worse than declining it"
        );
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_leaves_the_runner_root_exactly_where_it_is() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install");
        assert!(host.runner_root.as_path().is_dir());

        operations.uninstall().expect("an uninstall");

        assert!(
            host.runner_root.as_path().is_dir(),
            "`05-infrastructure.md` item 5: uninstall deregisters and deletes nothing else. A \
             runner root may hold an operator's retained workspaces."
        );
    }

    #[test]
    fn install_reviews_what_it_registered() {
        let host = Host::new();
        let installed = host
            .operations()
            .install(&host.request(StartMode::Boot))
            .expect("an install");
        assert!(
            installed.review.is_least_privilege(),
            "{}",
            installed.review
        );
        assert!(
            !installed.review.controls().is_empty(),
            "a review that confirms nothing proves nothing: {}",
            installed.review
        );
        assert_eq!(
            installed.review.kind(),
            host_definition_kind(StartMode::Boot),
            "the review must be of the definition this host's manager was given"
        );
        assert!(
            !installed.review.account().justification().is_empty(),
            "a privileged account with no stated reason is an unreviewed one"
        );
    }

    // -----------------------------------------------------------------------
    // Uninstall deletes nothing else
    // -----------------------------------------------------------------------

    #[test]
    fn uninstall_leaves_configuration_sqlite_secrets_and_cache_exactly_as_they_were() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install");

        // The files `05-infrastructure.md` says must survive. Written *after*
        // the install so that the snapshot below is of a host in the state an
        // operator's would be in.
        let config = host.paths.config_dir();
        std::fs::write(config.join("runner-manager.db"), b"sqlite fixture").expect("writable");
        std::fs::write(config.join("config.toml"), b"host_capacity = 2").expect("writable");
        std::fs::create_dir_all(host.paths.state_dir().join("packages/2.330.0")).expect("writable");
        std::fs::write(
            host.paths
                .state_dir()
                .join("packages/2.330.0/runner.tar.gz"),
            b"cached package",
        )
        .expect("writable");
        std::fs::create_dir_all(host.paths.state_dir().join("secrets")).expect("writable");
        std::fs::write(
            host.paths.state_dir().join("secrets/user-access-token"),
            b"a stand-in for the stored credential",
        )
        .expect("writable");
        std::fs::write(
            host.paths.logs_dir().join("runner-manager.log.2026-08-22"),
            b"diagnostics",
        )
        .expect("writable");

        let roots: Vec<PathBuf> = host
            .paths
            .all()
            .iter()
            .map(|(_, path)| (*path).to_path_buf())
            .collect();
        let roots: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        let before = snapshot(&roots);

        // Non-vacuity: a comparison of two empty maps would pass whatever
        // `uninstall` did.
        assert!(
            before.len() >= 6,
            "the fixture must actually contain the files this test is about, got {before:#?}"
        );
        let record_path = InstallRecord::path(&host.paths);
        assert!(
            before.contains_key(&record_path),
            "the install record must be present before uninstall"
        );

        let uninstalled = operations.uninstall().expect("an uninstall");
        assert!(uninstalled.removed_registration);
        assert!(uninstalled.removed_record);

        let after = snapshot(&roots);

        // Exactly one thing changed, and it is the registration's own record.
        let mut expected = before.clone();
        expected.remove(&record_path);
        assert_eq!(
            after, expected,
            "uninstall must remove its own record and nothing else"
        );
        assert!(
            !record_path.exists(),
            "the record itself must go, or `uninstall` did nothing at all"
        );
        assert!(
            uninstalled
                .preserved
                .iter()
                .all(|path| roots.contains(&path.as_path())),
            "the preserved list must name the four directories: {uninstalled}"
        );
    }

    #[test]
    fn uninstall_on_a_host_with_no_registration_is_not_a_failure() {
        let host = Host::new();
        let uninstalled = host.operations().uninstall().expect("a no-op uninstall");
        assert!(!uninstalled.removed_registration);
        assert!(!uninstalled.removed_record);
    }

    #[test]
    fn uninstall_removes_a_registration_even_when_the_record_is_gone() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install");
        std::fs::remove_file(InstallRecord::path(&host.paths)).expect("the record is lost");

        let uninstalled = operations.uninstall().expect("an uninstall");
        assert!(
            uninstalled.removed_registration,
            "a lost record must not strand a registration"
        );
        assert!(host.controls.registrations().is_empty());
    }

    // -----------------------------------------------------------------------
    // Switching start mode
    // -----------------------------------------------------------------------

    #[test]
    fn switching_start_mode_reuses_the_recorded_path_and_re_resolves_nothing() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install at boot");

        // The discriminator. If the switch re-resolved the binary the way
        // `install` does, it would either fail here or silently record the test
        // binary instead. Removing the file makes the difference visible.
        std::fs::remove_file(&host.binary).expect("the installed binary goes away");

        let change = operations
            .set_start_mode(StartMode::Login)
            .expect("a switch that does not reinstall the product");
        assert!(change.changed);
        assert_eq!(change.from, StartMode::Boot);
        assert_eq!(change.to, StartMode::Login);
        assert_eq!(change.store_scope, crate::secrets::SecretScope::User);

        let record = InstallRecord::read(&host.paths)
            .expect("readable")
            .expect("a record");
        assert_eq!(record.start_mode, StartMode::Login);
        assert_eq!(
            record.binary, host.binary,
            "the recorded path must survive the switch untouched"
        );

        let registrations = host.controls.registrations();
        assert_eq!(registrations.len(), 1, "{registrations:?}");
        assert_eq!(registrations[0].0, StartMode::Login);
        assert!(
            registrations[0]
                .2
                .command_line
                .contains(&host.binary.to_string_lossy().into_owned()),
            "{:?}",
            registrations[0].2
        );
    }

    #[test]
    fn switching_start_mode_keeps_the_live_registration_when_target_install_fails() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install at boot");
        let record_before = std::fs::read(InstallRecord::path(&host.paths)).expect("the record");
        host.controls
            .fail_next_install(StartMode::Login, "injected target failure");

        let error = operations
            .set_start_mode(StartMode::Login)
            .expect_err("the target manager refuses the install");

        assert!(matches!(error, ServiceError::Control { .. }), "{error}");
        assert_eq!(
            std::fs::read(InstallRecord::path(&host.paths)).expect("the old record survives"),
            record_before
        );
        let registrations = host.controls.registrations();
        assert_eq!(registrations.len(), 1, "{registrations:?}");
        assert_eq!(registrations[0].0, StartMode::Boot);
    }

    #[test]
    fn switching_start_mode_rolls_back_target_when_record_persistence_fails() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install at boot");
        let record_before = std::fs::read(InstallRecord::path(&host.paths)).expect("the record");
        let config = host.paths.config_dir().to_path_buf();
        let hidden = config.with_file_name("config-hidden-by-fault");
        host.controls.hide_directory_after_install(
            StartMode::Login,
            config.clone(),
            hidden.clone(),
        );

        let error = operations
            .set_start_mode(StartMode::Login)
            .expect_err("the injected filesystem fault prevents persistence");

        std::fs::remove_file(&config).expect("remove the injected blocker");
        std::fs::rename(&hidden, &config).expect("restore the record directory");
        assert!(matches!(error, ServiceError::Record { .. }), "{error}");
        assert_eq!(
            std::fs::read(InstallRecord::path(&host.paths)).expect("the old record survives"),
            record_before
        );
        let registrations = host.controls.registrations();
        assert_eq!(registrations.len(), 1, "{registrations:?}");
        assert_eq!(registrations[0].0, StartMode::Boot);
        assert!(
            host.controls
                .calls()
                .iter()
                .any(|call| call == "uninstall runner-manager (login)"),
            "the target must be rolled back: {:?}",
            host.controls.calls()
        );
    }

    #[test]
    fn switching_to_the_mode_already_in_force_registers_nothing_again() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install");
        let before = host.controls.calls().len();

        let change = operations
            .set_start_mode(StartMode::Boot)
            .expect("a no-op switch");
        assert!(!change.changed);
        assert_eq!(
            host.controls.calls().len(),
            before,
            "a no-op switch must not touch the service manager"
        );
    }

    #[test]
    fn switching_start_mode_on_a_host_with_no_registration_is_refused() {
        let host = Host::new();
        let error = host
            .operations()
            .set_start_mode(StartMode::Login)
            .expect_err("there is nothing to switch");
        assert!(
            matches!(error, ServiceError::NotInstalled { .. }),
            "{error}"
        );
    }

    // -----------------------------------------------------------------------
    // Status
    // -----------------------------------------------------------------------

    #[test]
    fn status_reports_the_four_facts_journey_five_asks_for() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install");
        let at = DateTime::parse_from_rfc3339("2026-08-22T09:00:00Z")
            .expect("a valid timestamp")
            .with_timezone(&Utc);
        record_github_contact(&host.paths, at).expect("a heartbeat");

        let status = operations.status().expect("a status");
        assert_eq!(status.start_mode(), Some(StartMode::Boot));
        assert_eq!(
            status.binary().map(BinaryPath::recorded),
            Some(host.binary.as_path())
        );
        assert_eq!(status.log_file(), host.paths.logs_dir().join(LOG_FILE_STEM));
        assert_eq!(status.last_github_contact(), Some(at));
        assert!(status.is_installed());
        assert!(status.is_healthy(), "{status}");

        let printed = status.to_string();
        for fragment in [
            "start mode",
            "diagnostic log",
            "last GitHub contact",
            "binary",
        ] {
            assert!(printed.contains(fragment), "{printed}");
        }
    }

    #[test]
    fn status_reports_a_stale_binary_as_an_error_rather_than_appearing_healthy() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install");

        // The discriminator: healthy first, so a `is_healthy` that always
        // returned false could not pass this test.
        assert!(
            operations.status().expect("a status").is_healthy(),
            "the freshly installed host must be healthy"
        );

        std::fs::remove_file(&host.binary).expect("the binary moves out from under the record");

        let status = operations.status().expect("a status");
        assert!(!status.is_healthy(), "{status}");
        assert!(
            status
                .problems()
                .iter()
                .any(|problem| problem.subject == "binary"),
            "{status}"
        );
        assert!(status.to_string().contains("STALE"), "{status}");
    }

    #[test]
    fn status_reports_a_registration_that_would_not_start_at_boot() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install");
        assert!(operations.status().expect("a status").is_healthy());

        host.controls.edit("runner-manager", |registration| {
            registration.starts_automatically = false;
        });

        let status = operations.status().expect("a status");
        assert!(!status.is_healthy(), "{status}");
        assert!(
            status
                .problems()
                .iter()
                .any(|problem| problem.detail.contains("after a reboot")),
            "{status}"
        );
    }

    #[test]
    fn status_reports_a_restart_policy_something_else_edited() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install");
        assert!(operations.status().expect("a status").is_healthy());

        host.controls.edit("runner-manager", |registration| {
            registration.restart_delay = Some(Duration::from_secs(1));
        });

        let status = operations.status().expect("a status");
        assert!(!status.is_healthy(), "{status}");
        assert!(
            status
                .problems()
                .iter()
                .any(|problem| problem.subject == "restart policy"),
            "{status}"
        );
    }

    #[test]
    fn status_reports_a_registration_naming_a_binary_the_record_does_not() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install");
        let other = host.binary.with_file_name("someone-elses.exe");
        std::fs::write(&other, b"x").expect("writable");

        host.controls.edit("runner-manager", |registration| {
            registration.command_line = quote_argument(&other.to_string_lossy());
        });

        let status = operations.status().expect("a status");
        assert!(!status.is_healthy(), "{status}");
        assert!(
            matches!(status.binary(), Some(BinaryPath::Diverged { .. })),
            "{status}"
        );
    }

    #[test]
    fn status_reports_a_record_no_service_manager_knows_about() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Boot))
            .expect("an install");
        // Something removed the registration behind this product's back.
        for mode in [StartMode::Boot, StartMode::Login] {
            host.controls
                .control(mode)
                .expect("a control")
                .uninstall(&ServiceIdentity::product())
                .expect("removed");
        }

        let status = operations.status().expect("a status");
        assert!(!status.is_healthy(), "{status}");
        assert!(
            status
                .problems()
                .iter()
                .any(|problem| problem.subject == "registration"),
            "{status}"
        );
    }

    #[test]
    fn status_on_a_host_with_nothing_installed_is_neither_healthy_nor_broken() {
        let host = Host::new();
        let status = host.operations().status().expect("a status");
        assert!(!status.is_installed());
        assert!(
            status.is_healthy(),
            "a host that never installed the service has no fault to report: {status}"
        );
        assert!(status.to_string().contains("installed"), "{status}");
    }

    #[test]
    fn status_says_a_login_registration_does_not_resume_after_an_unattended_reboot() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Login))
            .expect("an install at login");
        let status = operations.status().expect("a status");
        assert!(
            status
                .notes()
                .iter()
                .any(|note| note.contains("does not run until the operator signs in")),
            "05-infrastructure.md requires `service status` to say so: {status}"
        );
    }

    // -----------------------------------------------------------------------
    // Start and stop
    // -----------------------------------------------------------------------

    #[test]
    fn start_and_stop_reach_the_domain_that_holds_the_registration() {
        let host = Host::new();
        let operations = host.operations();
        operations
            .install(&host.request(StartMode::Login))
            .expect("an install at login");
        operations.start().expect("a start");
        assert!(operations.status().expect("a status").is_running());
        assert!(operations.stop().expect("a stop"));
        assert!(!operations.status().expect("a status").is_running());
    }

    #[test]
    fn starting_a_host_with_no_registration_is_refused() {
        let host = Host::new();
        let error = host.operations().start().expect_err("nothing to start");
        assert!(
            matches!(error, ServiceError::NotInstalled { .. }),
            "{error}"
        );
    }

    // -----------------------------------------------------------------------
    // The seam with `d2`
    // -----------------------------------------------------------------------

    /// Requirement 2 is *"an account that can **read the secret store**"*, and
    /// on Windows what an account may read is decided by a DACL in a file this
    /// task does not own. Asserting the account name alone would be asserting
    /// this module against itself; this reads `d2`'s protection back off a real
    /// store and checks that it admits the account this installer registers.
    ///
    /// No privileges are needed. `d2` documents that a rooted machine-scoped
    /// store *"is protected and encrypted exactly as the standard one is"* —
    /// the Windows backend picks its DACL from the scope, not from the site —
    /// so a store in a temporary directory carries the access control the real
    /// one does.
    #[cfg(windows)]
    #[test]
    fn the_account_this_installer_registers_is_one_the_stores_own_dacl_admits() {
        use crate::secrets::{PlatformSecretStore, SecretScope, SecretStore as _};

        let root = tempfile::tempdir().expect("a temporary directory");
        let store = PlatformSecretStore::rooted_at(SecretScope::Machine, root.path())
            .expect("a rooted machine-scoped store");
        store
            .store(&secrecy::SecretString::from("a stand-in for the token"))
            .expect("the store accepts a value");
        let protection = store.protection().expect("the DACL can be read back");

        assert!(
            protection.description().contains(";;;SY)"),
            "the machine-scoped store must admit LocalSystem, or a boot-start service cannot \
             read the token. `d2` writes this DACL and it is not this task's to widen. Got: {}",
            protection.description()
        );
        assert_eq!(
            ServiceAccount::for_definition(DefinitionKind::WindowsService, StartMode::Boot),
            ServiceAccount::LocalSystem,
            "and that is the account this installer registers, which is why SY is what matters"
        );
        assert!(
            !protection.readable_by_other_local_users(),
            "the same DACL must still exclude ordinary local users: {}",
            protection.description()
        );

        // The other half of the analysis in `docs/service-account.md`, and the
        // reason LocalService and NetworkService are not used: the DACL names
        // three trustees and neither of them is among them.
        for rejected in [";;;LS)", ";;;NS)"] {
            assert!(
                !protection.description().contains(rejected),
                "if the store ever admitted {rejected}, the least-privilege analysis in \
                 docs/service-account.md would need redoing: {}",
                protection.description()
            );
        }
    }
}
