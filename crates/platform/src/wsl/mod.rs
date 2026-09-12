// owner: a1-wsl-platform-adapter

//! Managing a named WSL2 distribution as a first-class host: discovery,
//! invocation, preflight, artifact install, the Windows lifecycle task, and
//! the non-secret provider record.
//!
//! # What this module is, and what it deliberately is not
//!
//! It is the platform half of the managed WSL host feature — the part that
//! knows about `wsl.exe`, `schtasks.exe`, ext4 renames and UTF-16 console
//! output. The orchestration above it (the `wsl` command surface, the
//! credential broker, the device flow) lives in the CLI, because none of that
//! is platform-specific.
//!
//! `02-target-architecture.md` draws the line in one sentence: *"No PowerShell
//! script, registry mutation, `.wslconfig` rewrite or distribution
//! installation is hidden behind this adapter."* Nothing here writes the
//! registry, edits `.wslconfig`, installs or unregisters a distribution, or
//! runs a shell. The complete list of programs this module can start is
//! `wsl.exe` and `schtasks.exe`, and everything either of them is asked to do
//! is an argument vector built in one place.
//!
//! | Module | What it owns |
//! |---|---|
//! | [`exec`] | Literal-argv invocation, bounded capture, deadline, cancellation, and the anonymous stdin pipe a credential crosses on |
//! | [`discovery`] | Decoding `wsl.exe`'s UTF-16/UTF-8 output, and reading `--list --verbose` into exact names |
//! | [`probe`] | Selecting a distribution and the five preflight questions |
//! | [`artifact`] | Exact-version release selection, SHA-256 verification, and the atomic install inside the distribution |
//! | [`task`] | The per-distribution Windows login task: render, register, query, detach |
//! | [`record`] | The non-secret provider record under the config directory |
//!
//! # Every build has this module; only Windows has a host to run it on
//!
//! `02-target-architecture.md` requires that on a non-Windows build `wsl` and
//! `--host wsl:…` *"fail with an actionable unsupported-platform error rather
//! than disappearing from help"*. A `#[cfg(windows)]` module would give the
//! opposite: a command that exists on one platform and is a compile error to
//! mention on the others.
//!
//! So the model is compiled everywhere and only [`WslHost::on_this_host`]
//! refuses, with [`WslError::UnsupportedPlatform`]. That has a second benefit
//! that is worth as much: the parsing, the rendering, the record and the
//! argument vectors are all exercised by `cargo test` on the Linux and macOS
//! CI legs, rather than by the one leg that has WSL.
//!
//! # Where the credential is, and is not
//!
//! `03-security-and-lifecycle.md` item 3 requires the stored credential
//! document to cross the boundary *only* through an anonymous stdin pipe, and
//! to be absent from argv, environment, provider records, logs, errors, status
//! JSON, temporary files and scheduled-task XML. This module's part of that:
//!
//! * [`exec::PipedInput`] is the only way to give a child bytes, its `Debug`
//!   prints a length, and [`exec::CommandRequest`] has no environment API at
//!   all;
//! * [`exec::CommandRequest::refuse_payload_in_argv`] refuses the launch when
//!   the payload is also in the command line;
//! * [`task::LifecycleTask`] has no field that could hold one, and the only
//!   temporary file this module writes is that task's document;
//! * [`record::WslProviderRecord`] has five non-secret fields and
//!   `deny_unknown_fields`.
//!
//! `crates/platform/tests/no_wsl_credential_outside_child_stdin.rs` is the
//! test that puts a canary through the whole path and looks everywhere else.

pub mod artifact;
pub mod discovery;
pub mod exec;
pub mod probe;
pub mod record;
pub mod recovery;
pub mod task;

use std::fmt;
use std::path::PathBuf;

use exec::{CommandRunner, HostCommandRunner};
use probe::{WslExecutable, WslInvoker};
use task::LifecycleTaskControl;

/// Anything that can go wrong managing a WSL distribution.
///
/// One enum rather than one per module: every variant here is something an
/// operator reads on their own terminal, and a chain of `From` conversions
/// between six error types would add wrapping without adding a single fact.
/// The variants are ordered as the work is: platform, process, discovery,
/// preflight, artifact, task, record.
#[derive(Debug, thiserror::Error)]
pub enum WslError {
    /// This build is not for Windows, so there is no WSL to manage.
    #[error(
        "{operation} is a Windows feature: WSL runs on Windows, and this is a {} build. \
         Manage this host's own operating system with the ordinary commands instead.",
        std::env::consts::OS
    )]
    UnsupportedPlatform {
        /// What the caller was trying to do.
        operation: &'static str,
    },

    /// The program could not be launched at all.
    #[error("cannot start {}: {source}", program.display())]
    Spawn {
        /// The program that could not be launched.
        program: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// Waiting on or killing a child failed.
    #[error("cannot control {}: {source}", program.display())]
    ChildControl {
        /// The program that could not be waited on.
        program: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The stdin payload was about to be visible in a process listing.
    ///
    /// Deliberately does not quote the payload: an error message is one of the
    /// places `03-security-and-lifecycle.md` says it must not appear.
    #[error(
        "refusing to start {}: the value meant for this process's stdin also appears in \
         {location}, which would put it in this machine's process listing. Pass it on stdin \
         only (`03-security-and-lifecycle.md`, item 3).",
        program.display()
    )]
    SecretInCommandLine {
        /// The program that would have been launched.
        program: PathBuf,
        /// Where the payload was found.
        location: String,
    },

    /// A program ran and refused.
    #[error("cannot {what} using {}: {detail}", program.display())]
    CommandFailed {
        /// What was being attempted.
        what: &'static str,
        /// The program that refused.
        program: PathBuf,
        /// Its exit code, when it had one.
        exit_code: Option<i32>,
        /// What it said.
        detail: String,
    },

    /// The distribution name cannot be used at all.
    #[error("{requested:?} is not a usable distribution name: {reason}")]
    InvalidName {
        /// What was asked for.
        requested: String,
        /// Which rule it broke.
        reason: String,
    },

    /// No distribution of that name is installed.
    #[error(
        "no WSL distribution named {requested:?} is installed{}",
        if available.is_empty() {
            ". This host has none.".to_string()
        } else {
            format!(". This host has: {}. Names are matched exactly.", available.join(", "))
        }
    )]
    NotInstalled {
        /// What was asked for.
        requested: String,
        /// What is really there.
        available: Vec<String>,
    },

    /// Two rows carry the name, so there is nothing safe to act on.
    #[error(
        "`wsl --list --verbose` reports {requested:?} twice, so this cannot tell which one \
         was meant. Rename one of them."
    )]
    AmbiguousName {
        /// The name that appeared twice.
        requested: String,
    },

    /// The distribution is not WSL2.
    #[error(
        "{distribution} is WSL version {version}; this feature supports WSL2 only, because a \
         WSL1 distribution has neither systemd nor a Linux kernel. \
         Convert it with `wsl --set-version {distribution} 2`."
    )]
    NotWsl2 {
        /// The distribution.
        distribution: String,
        /// The version WSL reported.
        version: u8,
    },

    /// The distribution does not start as root.
    #[error(
        "{distribution} does not start as root, so the provider cannot install a system \
         service or write /usr/local/bin in it: {detail}"
    )]
    NoRootAccess {
        /// The distribution.
        distribution: String,
        /// What `id -u` said.
        detail: String,
    },

    /// The distribution's architecture has no published artifact.
    #[error(
        "{distribution} reports the architecture {reported:?}, and runner-manager publishes no \
         Linux release for it. Only x86-64 and 64-bit ARM are published."
    )]
    UnsupportedArchitecture {
        /// The distribution.
        distribution: String,
        /// What `uname -m` said.
        reported: String,
    },

    /// systemd is not running the distribution.
    #[error(
        "{distribution} is not running systemd, and the Linux runner-manager service is a \
         systemd unit: {detail}. Enable it with `systemd=true` under `[boot]` in \
         /etc/wsl.conf inside the distribution, then `wsl --terminate {distribution}`."
    )]
    SystemdUnavailable {
        /// The distribution.
        distribution: String,
        /// What `systemctl` said.
        detail: String,
    },

    /// The checksum document could not be read.
    #[error("the release checksum document cannot be used: {detail}")]
    UnreadableChecksums {
        /// Why not.
        detail: String,
    },

    /// The release publishes nothing for this version and architecture.
    #[error(
        "the release publishes no {triple} archive for version {version} (it publishes \
         {published} assets), so there is no Linux binary to install that matches this \
         Windows build."
    )]
    NoSuchArtifact {
        /// The version that was asked for.
        version: String,
        /// The target triple that was asked for.
        triple: String,
        /// How many assets the document did list.
        published: usize,
    },

    /// The release publishes more than one archive for this target.
    #[error(
        "the release publishes {count} {triple} archives for version {version}; refusing to \
         guess which one is meant."
    )]
    AmbiguousArtifact {
        /// The version that was asked for.
        version: String,
        /// The target triple.
        triple: String,
        /// How many matched.
        count: usize,
    },

    /// The archive on disk could not be read.
    #[error("the release archive at {} cannot be used: {detail}", path.display())]
    UnreadableArchive {
        /// The archive.
        path: PathBuf,
        /// Why not.
        detail: String,
    },

    /// The archive is not the one that was published.
    #[error(
        "the release archive at {} hashes to {actual}, and the release says it should be \
         {expected}. Nothing has been installed.",
        path.display()
    )]
    DigestMismatch {
        /// The archive.
        path: PathBuf,
        /// What the release published.
        expected: String,
        /// What it really hashes to.
        actual: String,
    },

    /// The destination path cannot be installed to.
    #[error("{path:?} is not a usable Linux destination: {reason}")]
    InvalidDestination {
        /// What was asked for.
        path: String,
        /// Which rule it broke.
        reason: String,
    },

    /// The unpacked binary is not the version that was selected.
    #[error(
        "the unpacked binary reports {reported:?}, not version {expected}. It has not been \
         installed and the existing binary is untouched."
    )]
    VersionMismatch {
        /// The version that was selected.
        expected: String,
        /// What the binary said about itself.
        reported: String,
    },

    /// A task of the product's name exists and is somebody else's.
    #[error("the scheduled task {name} is not this product's, so it will not be changed: {detail}")]
    ForeignTask {
        /// The task name.
        name: String,
        /// Why it was judged foreign, and what to do.
        detail: String,
    },

    /// There is no such task registered.
    #[error("no scheduled task named {name} is registered on this host")]
    NoSuchTask {
        /// The task name.
        name: String,
    },

    /// Task Scheduler refused.
    #[error("cannot {operation} the scheduled task {name}: {detail}")]
    TaskControl {
        /// What was being attempted.
        operation: &'static str,
        /// The task name.
        name: String,
        /// What `schtasks` said.
        detail: String,
    },

    /// Task Scheduler refused for want of privilege.
    #[error(
        "cannot {operation} the scheduled task {name} without elevation: {detail}. Run this \
         command from an elevated prompt."
    )]
    NeedsElevation {
        /// What was being attempted.
        operation: &'static str,
        /// The task name.
        name: String,
        /// What `schtasks` said.
        detail: String,
    },

    /// A provider record could not be read or written.
    #[error("cannot {operation} the provider record at {}: {detail}", path.display())]
    Record {
        /// What was being attempted.
        operation: &'static str,
        /// The record.
        path: PathBuf,
        /// Why not.
        detail: String,
    },

    /// A provider record was written by a version this one does not know.
    #[error(
        "the provider record at {} was written under schema version {found}, and this build \
         understands version {supported}. Refusing to read it rather than silently dropping \
         what it does not understand; upgrade runner-manager.",
        path.display()
    )]
    RecordSchema {
        /// The record.
        path: PathBuf,
        /// The version in the file.
        found: u32,
        /// The version this build writes.
        supported: u32,
    },
}

impl WslError {
    /// A short, stable token for a status document or a log field.
    ///
    /// Stable across message rewordings, which the prose above is not.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform { .. } => "unsupported_platform",
            Self::Spawn { .. } => "spawn",
            Self::ChildControl { .. } => "child_control",
            Self::SecretInCommandLine { .. } => "secret_in_command_line",
            Self::CommandFailed { .. } => "command_failed",
            Self::InvalidName { .. } => "invalid_name",
            Self::NotInstalled { .. } => "not_installed",
            Self::AmbiguousName { .. } => "ambiguous_name",
            Self::NotWsl2 { .. } => "not_wsl2",
            Self::NoRootAccess { .. } => "no_root_access",
            Self::UnsupportedArchitecture { .. } => "unsupported_architecture",
            Self::SystemdUnavailable { .. } => "systemd_unavailable",
            Self::UnreadableChecksums { .. } => "unreadable_checksums",
            Self::NoSuchArtifact { .. } => "no_such_artifact",
            Self::AmbiguousArtifact { .. } => "ambiguous_artifact",
            Self::UnreadableArchive { .. } => "unreadable_archive",
            Self::DigestMismatch { .. } => "digest_mismatch",
            Self::InvalidDestination { .. } => "invalid_destination",
            Self::VersionMismatch { .. } => "version_mismatch",
            Self::ForeignTask { .. } => "foreign_task",
            Self::NoSuchTask { .. } => "no_such_task",
            Self::TaskControl { .. } => "task_control",
            Self::NeedsElevation { .. } => "needs_elevation",
            Self::Record { .. } => "record",
            Self::RecordSchema { .. } => "record_schema",
        }
    }

    /// Whether this failure happened before anything was changed.
    ///
    /// The column `03-security-and-lifecycle.md`'s failure table is really
    /// about: an operator wants to know whether to clean something up before
    /// rerunning, and for every variant here the answer is "no" — the
    /// mutating steps report [`Self::CommandFailed`], [`Self::TaskControl`] or
    /// [`Self::Record`], and each of those is documented at its call site with
    /// what it left behind.
    #[must_use]
    pub fn is_preflight(&self) -> bool {
        matches!(
            self,
            Self::UnsupportedPlatform { .. }
                | Self::SecretInCommandLine { .. }
                | Self::InvalidName { .. }
                | Self::NotInstalled { .. }
                | Self::AmbiguousName { .. }
                | Self::NotWsl2 { .. }
                | Self::NoRootAccess { .. }
                | Self::UnsupportedArchitecture { .. }
                | Self::SystemdUnavailable { .. }
                | Self::UnreadableChecksums { .. }
                | Self::NoSuchArtifact { .. }
                | Self::AmbiguousArtifact { .. }
                | Self::UnreadableArchive { .. }
                | Self::DigestMismatch { .. }
                | Self::InvalidDestination { .. }
        )
    }
}

/// Whether this build can manage a WSL distribution at all.
///
/// # Errors
///
/// [`WslError::UnsupportedPlatform`] on every build that is not for Windows.
pub fn require_windows(operation: &'static str) -> Result<(), WslError> {
    if cfg!(windows) {
        return Ok(());
    }
    Err(WslError::UnsupportedPlatform { operation })
}

/// The WSL adapter bound to a command runner.
///
/// Production builds one with [`WslHost::on_this_host`], which refuses off
/// Windows. Tests build one with [`WslHost::with_runner`] and drive the whole
/// adapter from a script, on any platform.
pub struct WslHost {
    runner: Box<dyn CommandRunner>,
    executable: WslExecutable,
}

impl WslHost {
    /// The real `wsl.exe` on this host.
    ///
    /// # Errors
    ///
    /// [`WslError::UnsupportedPlatform`] when this is not a Windows build.
    pub fn on_this_host(operation: &'static str) -> Result<Self, WslError> {
        require_windows(operation)?;
        Ok(Self {
            runner: Box::new(HostCommandRunner),
            executable: WslExecutable::locate(),
        })
    }

    /// An adapter over an injected runner, for a test or a fixture.
    #[must_use]
    pub fn with_runner(runner: Box<dyn CommandRunner>, executable: WslExecutable) -> Self {
        Self { runner, executable }
    }

    /// The `wsl.exe` this will run.
    #[must_use]
    pub fn executable(&self) -> &WslExecutable {
        &self.executable
    }

    /// Runs `wsl.exe` and the commands inside a distribution.
    #[must_use]
    pub fn invoker(&self) -> WslInvoker<'_> {
        WslInvoker::new(self.runner.as_ref(), &self.executable)
    }

    /// Registers, reads and removes the Windows lifecycle task.
    #[must_use]
    pub fn tasks(&self) -> LifecycleTaskControl<'_> {
        LifecycleTaskControl::new(self.runner.as_ref())
    }
}

impl fmt::Debug for WslHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WslHost")
            .field("executable", &self.executable)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_windows_build_refuses_with_a_sentence_rather_than_not_compiling() {
        let result = require_windows("`runner-manager wsl install`");
        if cfg!(windows) {
            assert!(result.is_ok());
        } else {
            let error = result.expect_err("not Windows");
            assert_eq!(error.kind(), "unsupported_platform");
            let message = error.to_string();
            assert!(
                message.contains("`runner-manager wsl install`"),
                "{message}"
            );
            assert!(message.contains(std::env::consts::OS), "{message}");
        }
    }

    #[test]
    fn the_whole_model_is_available_on_every_platform() {
        // The point of not `cfg`-gating the module: a non-Windows build can
        // still name the types, render the documents and parse the tables, so
        // the CI legs that are not Windows are really testing this feature.
        let identity = task::LifecycleTaskIdentity::for_distribution("Ubuntu").expect("valid");
        assert!(identity.name().starts_with(task::LIFECYCLE_TASK_PREFIX));
        assert!(!discovery::DistributionTable::parse("  Ubuntu  Running  2\n").is_empty());
        assert_eq!(
            artifact::LinuxBinaryPath::default().as_path(),
            artifact::DEFAULT_LINUX_DESTINATION
        );
    }

    #[test]
    fn every_error_has_a_distinct_stable_kind() {
        // A status document and a log field are written from `kind`, so two
        // variants sharing one token would make two different failures
        // indistinguishable to anything reading them.
        let kinds = [
            WslError::UnsupportedPlatform { operation: "x" }.kind(),
            WslError::InvalidName {
                requested: String::new(),
                reason: String::new(),
            }
            .kind(),
            WslError::NotInstalled {
                requested: String::new(),
                available: Vec::new(),
            }
            .kind(),
            WslError::NotWsl2 {
                distribution: String::new(),
                version: 1,
            }
            .kind(),
            WslError::ForeignTask {
                name: String::new(),
                detail: String::new(),
            }
            .kind(),
            WslError::RecordSchema {
                path: PathBuf::new(),
                found: 2,
                supported: 1,
            }
            .kind(),
        ];
        let mut unique = kinds.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), kinds.len(), "{kinds:?}");
    }

    #[test]
    fn a_preflight_failure_says_it_changed_nothing() {
        assert!(
            WslError::NotWsl2 {
                distribution: "Legacy".to_string(),
                version: 1,
            }
            .is_preflight()
        );
        assert!(
            !WslError::TaskControl {
                operation: "register",
                name: String::new(),
                detail: String::new(),
            }
            .is_preflight()
        );
    }

    #[test]
    fn a_host_over_a_scripted_runner_works_on_any_platform() {
        let runner = exec::ScriptedRunner::new().always(
            "--list --verbose",
            exec::CommandOutput::exited(0, "* Ubuntu   Running   2\n", ""),
        );
        let host = WslHost::with_runner(Box::new(runner), WslExecutable::at("wsl.exe"));
        let table = host.invoker().list().expect("scripted");
        assert_eq!(table.names(), ["Ubuntu"]);
        assert!(format!("{host:?}").contains("wsl.exe"));
    }
}
