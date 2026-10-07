// owner: host-prepare

//! `host doctor`, `host prepare`, `host required-tools`, and the host-fitness
//! preflight the daemon applies before it registers a runner.
//!
//! # Why this exists
//!
//! Every item in [`CHECKS`] is something a real host needed fixing by hand
//! before its runners worked properly: Windows Defender scanning a runner
//! workspace on access (a jsdom test worker took 22 s instead of 2.7 s),
//! `LongPathsEnabled` off and git's own `core.longpaths` unset, a login task
//! whose standard token cannot create symbolic links (`setup-bun` failed with
//! `EPERM`), a Windows PowerShell execution policy of `Restricted` under
//! `SYSTEM`, a macOS LaunchAgent that ran every runner at background priority,
//! a capacity of ten on an 8 GB machine, Spotlight indexing the runner root.
//! The doctor finds them; `host prepare` fixes the ones that can be fixed, and
//! asks for administrator rights only when a fix needs them.
//!
//! # A check is a pure function of facts
//!
//! A check's probe reads [`HostFacts`] and returns an [`Outcome`]; it never
//! reaches the operating system itself. [`SystemFacts`] is the real
//! implementation and the tests use a table. Fixes are the same through
//! [`HostActions`], and every fix returns the [`Change`]s it made, with the
//! value it replaced, so `host prepare --revert <id>` can put it back.
//!
//! # Elevation is asked for once, and only for what needs it
//!
//! A fix that needs administrator rights, in a process that does not have
//! them, is not attempted in-process. The whole batch of such fixes is handed
//! to one elevated copy of this binary — `ShellExecuteExW` `runas` on Windows,
//! `sudo` on a terminal or the system password dialog on macOS — with the plan
//! on its command line and a file to report into. That copy re-probes each
//! check before it changes anything, applies only what is still needed,
//! reports, and exits; it never opens the database or writes the journal, which
//! stays owned by the invoking account. A refused prompt is reported and the
//! rest of the command carries on.
//!
//! # Anything that lowers security needs an explicit yes
//!
//! Excluding a runner root from Defender's real-time scanning and turning on
//! Developer Mode both trade security for function. Neither is applied without
//! a specific flag (`--allow-av-exclusion`, `--allow-developer-mode`) or a
//! question answered on a terminal, and `--yes` alone never implies them.
//!
//! # Required, recommended, informational
//!
//! A **required** check failing means runners on this host cannot work
//! correctly, and the daemon refuses to start any (`host_unfit`). A check whose
//! answer is *unknown* never refuses: a probe that could not run is not
//! evidence that the host is unfit, and refusing on it would stop a working
//! host. **Recommended** checks are reported everywhere and never block.
//! **Informational** ones appear only in `host doctor`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use runner_manager_domain::model::{Host, StartMode, Timestamp};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::Store as _;
use runner_manager_platform::host_fitness::{self, ElevationOutcome};
use runner_manager_platform::runner_env::{self, Inherited, RunnerEnv, RunnerPlatform};
use runner_manager_platform::service::{InstallRecord, LAUNCHD_PROCESS_TYPE, plist_string_value};
use runner_manager_platform::unattended_login::{self, Resume, UnattendedLogin};
use serde::{Deserialize, Serialize};

use super::workspace::{self, HostRoot};
use super::{
    CliError, Context, Failure, HostDoctorArgs, HostPrepareArgs, HostRequiredToolsArgs,
    write_failed,
};

/// The version of the `host doctor --json` document.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// What `host prepare` changed, per check, under `config/`.
pub const JOURNAL_FILE: &str = "host-prepare.json";
const JOURNAL_SCHEMA_VERSION: u32 = 1;

/// The tools every runner on this host must find on its `PATH`, under
/// `config/`.
pub const REQUIRED_TOOLS_FILE: &str = "required-tools.json";

/// Set on the service binary `status` this module starts to read the
/// credential, so that copy does not run the doctor in turn.
pub const SKIP_DOCTOR_VARIABLE: &str = "RUNNER_MANAGER_SKIP_HOST_DOCTOR";

/// How often the daemon re-evaluates the required checks.
pub const DAEMON_RECHECK: Duration = Duration::from_secs(5 * 60);

/// How long the daemon's host-unfit record counts as a refusal in force: three
/// rechecks, so one slow evaluation does not hide it.
const HOST_UNFIT_RECORD_FRESH: Duration = Duration::from_secs(3 * DAEMON_RECHECK.as_secs());

const GIB: u64 = 1024 * 1024 * 1024;
/// The memory one concurrent job is assumed to need when a capacity is
/// recommended. A guide, not a measurement of any particular workload.
const MEMORY_PER_RUNNER_GIB: u64 = 3;

/// A GitHub contact this recent proves the service could read its credential.
const RECENT_CONTACT_SECS: u64 = 15 * 60;

const ALLOW_AV_EXCLUSION: &str = "--allow-av-exclusion";
const ALLOW_DEVELOPER_MODE: &str = "--allow-developer-mode";

const WINDOWS_PWSH: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";
/// The `PATH` systemd gives a unit that sets none.
const SYSTEMD_DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Runners cannot work correctly without it; the daemon refuses to start
    /// any while it fails.
    Required,
    /// Reported everywhere, never blocks.
    Recommended,
    /// Reported by `host doctor` only.
    Info,
}

impl Severity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Recommended => "recommended",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    /// The probe could not answer, for instance without administrator rights.
    Unknown,
    NotApplicable,
}

impl Status {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Unknown => "unknown",
            Self::NotApplicable => "n/a",
        }
    }
}

/// Whose view a probe takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Perspective {
    /// A person's command. Facts about the service's account are inferred from
    /// how the service is (or is about to be) registered.
    Operator,
    /// The daemon itself, which *is* the account runners inherit.
    Daemon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostOs {
    Windows,
    Macos,
    Linux,
}

impl HostOs {
    #[must_use]
    pub const fn current() -> Self {
        match RunnerPlatform::current() {
            RunnerPlatform::Windows => Self::Windows,
            RunnerPlatform::MacOs => Self::Macos,
            RunnerPlatform::Linux => Self::Linux,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckPlatform {
    Windows,
    Macos,
    Any,
}

impl CheckPlatform {
    const fn includes(self, os: HostOs) -> bool {
        matches!(
            (self, os),
            (Self::Any, _) | (Self::Windows, HostOs::Windows) | (Self::Macos, HostOs::Macos)
        )
    }
}

// ---------------------------------------------------------------------------
// What a check is evaluated against
// ---------------------------------------------------------------------------

/// The registered (or about-to-be-registered) service, as far as checks care.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSetup {
    pub start_mode: StartMode,
    pub binary: PathBuf,
    pub definition_path: Option<PathBuf>,
    /// The launchd label, for the restart command a macOS remedy names.
    pub label: String,
    /// Whether the service manager reports the daemon running. `None` when
    /// not asked: the daemon's own view, and a service about to be installed.
    #[serde(default)]
    pub running: Option<bool>,
}

/// Everything about this host's configuration a check reads. Serializable
/// because the elevated copy receives it on its command line rather than
/// opening the database itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSetup {
    pub os: HostOs,
    pub perspective: Perspective,
    pub service: Option<ServiceSetup>,
    /// Where jobs run: the effective host runner root, every persistent
    /// repository root, and the dependency-cache root when no runner root
    /// contains it.
    pub runner_roots: Vec<PathBuf>,
    pub capacity: u16,
    pub required_tools: Vec<String>,
    /// Why the required-tools file could not be read, when it could not: the
    /// check is then unknown rather than "none configured".
    #[serde(default)]
    pub required_tools_error: Option<String>,
    /// The `PATH` a native runner starts with, as well as this process can
    /// tell (exact in the daemon).
    pub runner_path: Option<String>,
    /// A directory this account owns, for the symbolic-link probe.
    pub probe_dir: PathBuf,
    pub data_root: Option<PathBuf>,
    /// How long ago the service last reached GitHub, in seconds, as it
    /// recorded it -- counted only when the contact is newer than the service
    /// binary, see [`current_daemon_contact_age`]. A recent contact by the
    /// binary now installed proves it could read its credential.
    #[serde(default)]
    pub service_contact_age_secs: Option<u64>,
    /// Whether the daemon recorded that it cannot read its stored credential:
    /// its own answer, from the session it runs in.
    #[serde(default)]
    pub service_credential_unreadable: bool,
    /// Whether this process reads the login-mode credential itself, to tell a
    /// credential the service binary cannot read from a keychain this whole
    /// session cannot read. `None` when not asked (not a macOS login service).
    #[serde(default)]
    pub own_keychain_readable: Option<bool>,
    /// Why the daemon starts no runner, from its own record or a stuck WSL
    /// launch fence. See [`runner_manager_platform::launch_health`].
    #[serde(default)]
    pub launches_blocked: Option<runner_manager_platform::launch_health::LaunchesBlocked>,
    /// The account the service runs as, or would run as, on macOS.
    #[serde(default)]
    pub service_account: Option<String>,
    /// That account's home folder, on macOS.
    #[serde(default)]
    pub service_home: Option<PathBuf>,
}

impl HostSetup {
    fn start_mode(&self) -> Option<StartMode> {
        self.service.as_ref().map(|service| service.start_mode)
    }
}

// ---------------------------------------------------------------------------
// Facts and actions
// ---------------------------------------------------------------------------

/// The registry values checks read, by meaning. A closed set so that nothing
/// in a plan or a journal can name an arbitrary key for the elevated copy to
/// write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegValue {
    LongPathsEnabled,
    DeveloperMode,
    ExecutionPolicy,
    ExecutionPolicyGroupPolicy,
    InstallationType,
    DefenderServiceRunning,
    DefenderPassiveMode,
    DefenderRealtimeOff,
    DefenderRealtimeOffPolicy,
    MachinePath,
}

impl RegValue {
    /// `(subkey under HKLM, value name)`.
    #[must_use]
    pub const fn location(self) -> (&'static str, &'static str) {
        match self {
            Self::LongPathsEnabled => (
                r"SYSTEM\CurrentControlSet\Control\FileSystem",
                "LongPathsEnabled",
            ),
            Self::DeveloperMode => (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock",
                "AllowDevelopmentWithoutDevLicense",
            ),
            Self::ExecutionPolicy => (
                r"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
                "ExecutionPolicy",
            ),
            Self::ExecutionPolicyGroupPolicy => (
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell",
                "ExecutionPolicy",
            ),
            Self::InstallationType => (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "InstallationType",
            ),
            Self::DefenderServiceRunning => {
                (r"SOFTWARE\Microsoft\Windows Defender", "IsServiceRunning")
            }
            Self::DefenderPassiveMode => (r"SOFTWARE\Microsoft\Windows Defender", "PassiveMode"),
            Self::DefenderRealtimeOff => (
                r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
                "DisableRealtimeMonitoring",
            ),
            Self::DefenderRealtimeOffPolicy => (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                "DisableRealtimeMonitoring",
            ),
            Self::MachinePath => (
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                "Path",
            ),
        }
    }

    /// Whether `host prepare` (or its revert) may ever write this value.
    const fn writable(self) -> bool {
        matches!(
            self,
            Self::LongPathsEnabled | Self::DeveloperMode | Self::ExecutionPolicy
        )
    }
}

/// What reading the service binary's credential found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialProbe {
    Readable,
    Absent,
    Unreadable(String),
}

/// Read-only facts about this host. Every method is safe without privilege.
pub trait HostFacts {
    fn elevated(&self) -> bool;
    fn dword(&self, value: RegValue) -> Result<Option<u32>, String>;
    fn string(&self, value: RegValue) -> Result<Option<String>, String>;
    /// `Ok(None)` when this token may not read the list.
    fn defender_exclusions(&self) -> Result<Option<Vec<String>>, String>;
    fn git_system_value(&self, git: &Path, name: &str) -> Result<Option<String>, String>;
    fn symlink_allowed(&self, directory: &Path) -> Result<bool, String>;
    fn find_tool(&self, tool: &str, path: Option<&str>) -> Option<PathBuf>;
    fn file_exists(&self, path: &Path) -> bool;
    fn memory_bytes(&self) -> Option<u64>;
    fn cpu_count(&self) -> usize;
    /// `Ok(None)` when Spotlight gave no answer for this volume (a mount point).
    fn spotlight_indexing(&self, volume: &Path) -> Result<Option<bool>, String>;
    fn mount_point(&self, path: &Path) -> Option<PathBuf>;
    /// A bounded `stat` and one-entry listing of `directory`.
    fn directory_responds(&self, directory: &Path) -> host_fitness::Responsiveness;
    fn launchd_process_type(&self, plist: &Path) -> Result<Option<String>, String>;
    fn throttled_runner_processes(&self) -> Result<usize, String>;
    fn service_credential(
        &self,
        binary: &Path,
        data_root: Option<&Path>,
    ) -> Result<CredentialProbe, String>;
    /// macOS's power settings in use now (`pmset -g`), by name. `Ok(None)` on
    /// a platform without them.
    fn power_settings(&self) -> Result<Option<BTreeMap<String, u32>>, String> {
        Ok(None)
    }
    /// Automatic login and FileVault. `None` on a platform without them.
    fn unattended_login(&self) -> Option<UnattendedLogin> {
        None
    }
}

/// The writes fixes and reverts make.
pub trait HostActions {
    fn set_dword(&self, value: RegValue, data: Option<u32>) -> Result<(), String>;
    fn set_string(&self, value: RegValue, data: Option<&str>) -> Result<(), String>;
    fn set_git_system_value(
        &self,
        git: &Path,
        name: &str,
        value: Option<&str>,
    ) -> Result<(), String>;
    fn add_defender_exclusions(&self, paths: &[String]) -> Result<(), String>;
    fn remove_defender_exclusions(&self, paths: &[String]) -> Result<(), String>;
    fn set_spotlight(&self, volume: &Path, enabled: bool) -> Result<(), String>;
    /// `pmset -a NAME VALUE`, for one of [`POWER_SETTINGS`].
    fn set_power_setting(&self, name: &str, _value: u32) -> Result<(), String> {
        Err(format!("cannot set {name}: power settings exist only on macOS"))
    }
}

/// One change a fix made, with what it replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    RegistryDword {
        value: RegValue,
        previous: Option<u32>,
        applied: u32,
    },
    RegistryString {
        value: RegValue,
        previous: Option<String>,
        applied: String,
    },
    GitSystemConfig {
        git: PathBuf,
        name: String,
        previous: Option<String>,
        applied: String,
    },
    DefenderExclusions {
        added: Vec<String>,
    },
    SpotlightIndexingOff {
        volume: PathBuf,
    },
    PowerSetting {
        name: String,
        previous: Option<u32>,
        applied: u32,
    },
}

/// The power settings a fix may write, with the largest value a revert may
/// restore. A closed set, as with [`RegValue`]: the journal is a plain file.
const POWER_SETTINGS: [(&str, u32); 4] = [
    ("sleep", 24 * 60),
    ("disksleep", 24 * 60),
    ("autorestart", 1),
    ("womp", 1),
];

/// The only execution policies a revert may restore.
const EXECUTION_POLICIES: [&str; 6] = [
    "Restricted",
    "AllSigned",
    "RemoteSigned",
    "Unrestricted",
    "Bypass",
    "Undefined",
];
const GIT_LONG_PATHS: &str = "core.longpaths";

impl Change {
    /// Identifies what was changed, so a second `prepare` of the same check
    /// does not replace the value the first one recorded.
    fn key(&self) -> String {
        match self {
            Self::RegistryDword { value, .. } | Self::RegistryString { value, .. } => {
                format!("registry:{value:?}")
            }
            Self::GitSystemConfig { name, .. } => format!("git:{name}"),
            Self::DefenderExclusions { added } => format!("defender:{}", added.join(";")),
            Self::SpotlightIndexingOff { volume } => format!("spotlight:{}", volume.display()),
            Self::PowerSetting { name, .. } => format!("pmset:{name}"),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::RegistryDword {
                value,
                previous,
                applied,
            } => format!(
                "{} = {applied} (was {})",
                value.location().1,
                previous.map_or_else(|| "not set".to_owned(), |v| v.to_string())
            ),
            Self::RegistryString {
                value,
                previous,
                applied,
            } => format!(
                "{} = {applied} (was {})",
                value.location().1,
                previous.as_deref().unwrap_or("not set")
            ),
            Self::GitSystemConfig {
                name,
                previous,
                applied,
                ..
            } => format!(
                "git config --system {name} {applied} (was {})",
                previous.as_deref().unwrap_or("not set")
            ),
            Self::DefenderExclusions { added } => {
                format!("Defender exclusion added: {}", added.join(", "))
            }
            Self::SpotlightIndexingOff { volume } => {
                format!("Spotlight indexing off for {}", volume.display())
            }
            Self::PowerSetting {
                name,
                previous,
                applied,
            } => format!(
                "pmset -a {name} {applied} (was {})",
                previous.map_or_else(|| "not set".to_owned(), |v| v.to_string())
            ),
        }
    }

    /// Puts back what this change replaced. Refuses anything outside the
    /// closed set a fix can produce, because a journal is an ordinary file.
    fn revert(&self, actions: &dyn HostActions) -> Result<(), String> {
        match self {
            Self::RegistryDword {
                value, previous, ..
            } if value.writable() => actions.set_dword(*value, *previous),
            Self::RegistryString {
                value, previous, ..
            } if value.writable()
                && previous.as_deref().is_none_or(|text| {
                    EXECUTION_POLICIES
                        .iter()
                        .any(|p| p.eq_ignore_ascii_case(text))
                }) =>
            {
                actions.set_string(*value, previous.as_deref())
            }
            Self::GitSystemConfig {
                git,
                name,
                previous,
                ..
            } if name == GIT_LONG_PATHS => {
                actions.set_git_system_value(git, name, previous.as_deref())
            }
            Self::DefenderExclusions { added } => actions.remove_defender_exclusions(added),
            Self::SpotlightIndexingOff { volume } => actions.set_spotlight(volume, true),
            Self::PowerSetting {
                name,
                previous: Some(previous),
                ..
            } if POWER_SETTINGS
                .iter()
                .any(|(known, most)| known == name && previous <= most) =>
            {
                actions.set_power_setting(name, *previous)
            }
            _ => Err(format!(
                "the journal records a change `host prepare` never makes ({}); it was not reverted",
                self.key()
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// What a probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    pub detail: String,
    /// The manual action, when there is one worth naming.
    pub remedy: Option<String>,
    /// `false` when the check's automatic fix cannot help in this situation
    /// (a Group Policy setting, a startup volume).
    pub fixable: bool,
}

impl Outcome {
    fn new(status: Status, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
            remedy: None,
            fixable: true,
        }
    }

    fn remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }

    fn not_fixable(mut self) -> Self {
        self.fixable = false;
        self
    }
}

fn pass(detail: impl Into<String>) -> Outcome {
    Outcome::new(Status::Pass, detail)
}
fn fail(detail: impl Into<String>) -> Outcome {
    Outcome::new(Status::Fail, detail)
}
fn unknown(detail: impl Into<String>) -> Outcome {
    Outcome::new(Status::Unknown, detail)
}
fn not_applicable(detail: impl Into<String>) -> Outcome {
    Outcome::new(Status::NotApplicable, detail)
}

type Probe = fn(&HostSetup, &dyn HostFacts) -> Outcome;
type Apply = fn(&HostSetup, &dyn HostFacts, &dyn HostActions) -> Result<Vec<Change>, String>;

/// An automatic fix.
pub struct FixSpec {
    pub needs_admin: bool,
    /// The flag that consents to a fix that lowers security; `None` for one
    /// that does not.
    pub consent_flag: Option<&'static str>,
    /// What it will do, in a phrase.
    pub action: &'static str,
    apply: Apply,
}

/// One check.
pub struct CheckSpec {
    pub id: &'static str,
    pub title: &'static str,
    pub platform: CheckPlatform,
    pub severity: Severity,
    probe: Probe,
    pub fix: Option<FixSpec>,
}

/// Every check, in the order they are reported.
pub const CHECKS: &[CheckSpec] = &[
    CheckSpec {
        id: "windows.symlink_privilege",
        title: "Symbolic links for the runner account",
        platform: CheckPlatform::Windows,
        severity: Severity::Required,
        probe: probe_symlink,
        fix: Some(FixSpec {
            needs_admin: true,
            consent_flag: Some(ALLOW_DEVELOPER_MODE),
            action: "turn on Developer Mode (lets every account create symbolic links and sideload apps)",
            apply: |_, facts, actions| set_dword(facts, actions, RegValue::DeveloperMode, 1),
        }),
    },
    CheckSpec {
        id: "windows.long_paths",
        title: "Win32 long paths (LongPathsEnabled)",
        platform: CheckPlatform::Windows,
        severity: Severity::Recommended,
        probe: probe_long_paths,
        fix: Some(FixSpec {
            needs_admin: true,
            consent_flag: None,
            action: "set LongPathsEnabled = 1",
            apply: |_, facts, actions| set_dword(facts, actions, RegValue::LongPathsEnabled, 1),
        }),
    },
    CheckSpec {
        id: "windows.git_long_paths",
        title: "git core.longpaths (system configuration)",
        platform: CheckPlatform::Windows,
        severity: Severity::Recommended,
        probe: probe_git_long_paths,
        fix: Some(FixSpec {
            needs_admin: true,
            consent_flag: None,
            action: "git config --system core.longpaths true",
            apply: apply_git_long_paths,
        }),
    },
    CheckSpec {
        id: "windows.defender_exclusion",
        title: "Runner roots excluded from Defender real-time scanning",
        platform: CheckPlatform::Windows,
        severity: Severity::Recommended,
        probe: probe_defender,
        fix: Some(FixSpec {
            needs_admin: true,
            consent_flag: Some(ALLOW_AV_EXCLUSION),
            action: "Add-MpPreference -ExclusionPath <each runner root> (files there are no longer scanned on access)",
            apply: apply_defender,
        }),
    },
    CheckSpec {
        id: "windows.execution_account",
        title: "Service account can run unattended",
        platform: CheckPlatform::Windows,
        severity: Severity::Recommended,
        probe: probe_execution_account,
        fix: None,
    },
    CheckSpec {
        id: "windows.execution_policy",
        title: "Windows PowerShell execution policy",
        platform: CheckPlatform::Windows,
        severity: Severity::Recommended,
        probe: probe_execution_policy,
        fix: Some(FixSpec {
            needs_admin: true,
            consent_flag: None,
            action: "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine",
            apply: apply_execution_policy,
        }),
    },
    CheckSpec {
        id: "windows.pwsh",
        title: "PowerShell 7 (pwsh) on the runners' PATH",
        platform: CheckPlatform::Windows,
        severity: Severity::Info,
        probe: probe_pwsh,
        fix: None,
    },
    CheckSpec {
        id: "macos.launchd_priority",
        title: "Service and runners at normal priority",
        platform: CheckPlatform::Macos,
        severity: Severity::Recommended,
        probe: probe_launchd_priority,
        fix: None,
    },
    CheckSpec {
        id: "macos.spotlight",
        title: "Spotlight does not index the runner roots",
        platform: CheckPlatform::Macos,
        severity: Severity::Recommended,
        probe: probe_spotlight,
        fix: Some(FixSpec {
            needs_admin: true,
            consent_flag: None,
            action: "mdutil -i off <the volume holding the runner root> (Spotlight stops indexing that whole volume)",
            apply: apply_spotlight,
        }),
    },
    CheckSpec {
        id: "macos.sleep",
        title: "The Mac does not go to sleep",
        platform: CheckPlatform::Macos,
        severity: Severity::Recommended,
        probe: probe_sleep,
        fix: Some(FixSpec {
            needs_admin: true,
            consent_flag: None,
            action: "pmset -a sleep 0 (the Mac stops sleeping when nobody uses it; the display \
                     still turns off)",
            apply: apply_sleep,
        }),
    },
    CheckSpec {
        id: "macos.disk_sleep",
        title: "Disks do not sleep",
        platform: CheckPlatform::Macos,
        severity: Severity::Recommended,
        probe: probe_disk_sleep,
        fix: Some(FixSpec {
            needs_admin: true,
            consent_flag: None,
            action: "pmset -a disksleep 0",
            apply: apply_disk_sleep,
        }),
    },
    CheckSpec {
        id: "macos.autorestart",
        title: "The Mac starts again after a power failure",
        platform: CheckPlatform::Macos,
        severity: Severity::Recommended,
        probe: probe_autorestart,
        fix: Some(FixSpec {
            needs_admin: true,
            consent_flag: None,
            action: "pmset -a autorestart 1",
            apply: apply_autorestart,
        }),
    },
    CheckSpec {
        id: "macos.wake_on_lan",
        title: "The Mac wakes for network access",
        platform: CheckPlatform::Macos,
        severity: Severity::Info,
        probe: probe_wake_on_lan,
        fix: Some(FixSpec {
            needs_admin: true,
            consent_flag: None,
            action: "pmset -a womp 1",
            apply: apply_wake_on_lan,
        }),
    },
    CheckSpec {
        id: "macos.unattended_login",
        title: "The service comes back after an unattended restart",
        platform: CheckPlatform::Macos,
        severity: Severity::Recommended,
        probe: probe_unattended_login,
        // Automatic login and FileVault are security settings: reported with
        // the steps, never changed by `host prepare`.
        fix: None,
    },
    CheckSpec {
        id: "macos.runner_root_location",
        title: "Runner roots have no spaces and are outside the service account's home",
        platform: CheckPlatform::Macos,
        severity: Severity::Recommended,
        probe: probe_runner_root_location,
        fix: None,
    },
    CheckSpec {
        id: "macos.keychain_credential",
        title: "Service binary can read its GitHub credential",
        platform: CheckPlatform::Macos,
        severity: Severity::Required,
        probe: probe_keychain_credential,
        fix: None,
    },
    CheckSpec {
        id: "host.runner_root_responsive",
        title: "Runner roots respond",
        platform: CheckPlatform::Any,
        severity: Severity::Required,
        probe: probe_runner_root_responsive,
        fix: None,
    },
    CheckSpec {
        id: "host.capacity",
        title: "Capacity fits this machine's memory and cores",
        platform: CheckPlatform::Any,
        severity: Severity::Recommended,
        probe: probe_capacity,
        fix: None,
    },
    CheckSpec {
        id: "host.required_tools",
        title: "Required tools on the runners' PATH",
        platform: CheckPlatform::Any,
        severity: Severity::Required,
        probe: probe_required_tools,
        fix: None,
    },
    // Recommended, not Required: a Required failure makes the daemon refuse
    // every launch, and this check reports exactly that refusal.
    CheckSpec {
        id: "host.launches",
        title: "The service can start runners",
        platform: CheckPlatform::Any,
        severity: Severity::Recommended,
        probe: probe_launches,
        fix: None,
    },
];

fn check(id: &str) -> Option<&'static CheckSpec> {
    CHECKS.iter().find(|check| check.id == id)
}

fn fix(id: &str) -> Option<&'static FixSpec> {
    check(id).and_then(|check| check.fix.as_ref())
}

fn fix_needs_admin(id: &str) -> bool {
    fix(id).is_some_and(|fix| fix.needs_admin)
}

/// Whether the fix for `id` lowers security and so needs explicit consent.
#[must_use]
pub fn lowers_security(id: &str) -> bool {
    fix(id).is_some_and(|fix| fix.consent_flag.is_some())
}

fn set_dword(
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
    value: RegValue,
    data: u32,
) -> Result<Vec<Change>, String> {
    let previous = facts.dword(value)?;
    actions.set_dword(value, Some(data))?;
    Ok(vec![Change::RegistryDword {
        value,
        previous,
        applied: data,
    }])
}

// -- windows.symlink_privilege ----------------------------------------------

const SYMLINK_CONSEQUENCE: &str =
    "`npm`, `pnpm` and `setup-bun` then fail in jobs with EPERM when they link a file";

fn probe_symlink(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    let boot_remedy = "or run the service as LocalSystem instead: runner-manager service install \
                       --start-at boot (from an elevated terminal)";
    let measured =
        |facts: &dyn HostFacts, account: &str| match facts.symlink_allowed(&setup.probe_dir) {
            Ok(true) => pass(format!("{account} can create symbolic links")),
            Ok(false) => fail(format!(
                "{account} cannot create symbolic links; {SYMLINK_CONSEQUENCE}"
            ))
            .remedy(boot_remedy),
            Err(error) => unknown(format!("the symbolic-link probe could not run: {error}")),
        };
    if setup.perspective == Perspective::Daemon {
        return measured(facts, "this daemon's account");
    }
    if facts.dword(RegValue::DeveloperMode) == Ok(Some(1)) {
        return pass("Developer Mode is on, so every account can create symbolic links");
    }
    match setup.start_mode() {
        Some(StartMode::Boot) => {
            pass("the boot service runs as LocalSystem, which holds the symbolic-link privilege")
        }
        Some(StartMode::Login) if !facts.elevated() => measured(
            facts,
            "this account (the login service runs as it, unelevated)",
        ),
        Some(StartMode::Login) => fail(format!(
            "the login service runs with this user's standard (unelevated) token, which cannot \
             create symbolic links while Developer Mode is off; {SYMLINK_CONSEQUENCE}"
        ))
        .remedy(boot_remedy),
        None => measured(facts, "this account"),
    }
}

// -- windows.long_paths -------------------------------------------------------

fn probe_long_paths(_: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    match facts.dword(RegValue::LongPathsEnabled) {
        Ok(Some(1)) => pass("LongPathsEnabled is 1"),
        Ok(found) => fail(format!(
            "LongPathsEnabled is {}, so programs that opt in still stop at 260 characters in deep \
             node_modules and build trees",
            found.map_or_else(|| "not set".to_owned(), |value| value.to_string())
        )),
        Err(error) => unknown(format!("LongPathsEnabled could not be read: {error}")),
    }
}

// -- windows.git_long_paths ---------------------------------------------------

fn runner_git(setup: &HostSetup, facts: &dyn HostFacts) -> Option<PathBuf> {
    facts.find_tool("git", setup.runner_path.as_deref())
}

fn probe_git_long_paths(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    let Some(git) = runner_git(setup, facts) else {
        return not_applicable("git is not on the runners' PATH");
    };
    match facts.git_system_value(&git, GIT_LONG_PATHS) {
        Ok(Some(value)) if value.trim().eq_ignore_ascii_case("true") => pass(format!(
            "{} reads core.longpaths = true from its system configuration",
            git.display()
        )),
        Ok(found) => fail(format!(
            "core.longpaths is {} in {}'s system configuration. Git does not honour \
             LongPathsEnabled, so a checkout holding a path over 260 characters fails",
            found.as_deref().unwrap_or("not set"),
            git.display()
        )),
        Err(error) => unknown(format!(
            "git's system configuration could not be read: {error}"
        )),
    }
}

fn apply_git_long_paths(
    setup: &HostSetup,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
) -> Result<Vec<Change>, String> {
    let git = runner_git(setup, facts).ok_or("git is not on the runners' PATH")?;
    let previous = facts.git_system_value(&git, GIT_LONG_PATHS)?;
    actions.set_git_system_value(&git, GIT_LONG_PATHS, Some("true"))?;
    Ok(vec![Change::GitSystemConfig {
        git,
        name: GIT_LONG_PATHS.to_owned(),
        previous,
        applied: "true".to_owned(),
    }])
}

// -- windows.defender_exclusion -----------------------------------------------

/// Why Defender is not the scanner to worry about, when it is not.
fn defender_inactive(facts: &dyn HostFacts) -> Option<&'static str> {
    if facts.dword(RegValue::DefenderRealtimeOffPolicy) == Ok(Some(1))
        || facts.dword(RegValue::DefenderRealtimeOff) == Ok(Some(1))
    {
        return Some("Defender real-time protection is turned off");
    }
    if facts.dword(RegValue::DefenderPassiveMode) == Ok(Some(1)) {
        return Some("Defender runs in passive mode behind another antivirus product");
    }
    if facts.dword(RegValue::DefenderServiceRunning) == Ok(Some(0)) {
        return Some("the Defender service is not running");
    }
    None
}

/// Expands `%NAME%` references from this process's environment, leaving
/// unknown ones as they are.
fn expand_environment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(value) => out.push_str(&value),
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn normalised_windows_path(text: &str) -> String {
    expand_environment(text)
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

/// The runner roots no exclusion covers. An exclusion covers its own path and
/// everything under it.
fn uncovered_roots(roots: &[PathBuf], exclusions: &[String]) -> Vec<String> {
    let exclusions: Vec<String> = exclusions
        .iter()
        .map(|e| normalised_windows_path(e))
        .collect();
    roots
        .iter()
        .map(|root| root.display().to_string())
        .filter(|root| {
            let root_key = normalised_windows_path(root);
            !exclusions.iter().any(|exclusion| {
                !exclusion.is_empty()
                    && (root_key == *exclusion
                        || root_key
                            .strip_prefix(exclusion.as_str())
                            .is_some_and(|tail| tail.starts_with('\\')))
            })
        })
        .collect()
}

fn probe_defender(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    if setup.runner_roots.is_empty() {
        return not_applicable("no runner root could be resolved");
    }
    if let Some(reason) = defender_inactive(facts) {
        return not_applicable(reason);
    }
    match facts.defender_exclusions() {
        Ok(Some(exclusions)) => {
            let missing = uncovered_roots(&setup.runner_roots, &exclusions);
            if missing.is_empty() {
                pass("every runner root is excluded from real-time scanning")
            } else {
                fail(format!(
                    "Defender scans every file jobs read and write under {} on access, which \
                     makes installs and test start-up several times slower (measured: 22 s \
                     instead of 2.7 s per jsdom test worker)",
                    missing.join(", ")
                ))
            }
        }
        Ok(None) => unknown(
            "only an administrator can read Defender's exclusion list; run `runner-manager host \
             doctor` from an elevated terminal to see it",
        ),
        Err(error) => unknown(format!(
            "Defender's exclusion list could not be read: {error}"
        )),
    }
}

fn apply_defender(
    setup: &HostSetup,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
) -> Result<Vec<Change>, String> {
    let exclusions = facts
        .defender_exclusions()?
        .ok_or("Defender's exclusion list cannot be read even with administrator rights")?;
    let missing = uncovered_roots(&setup.runner_roots, &exclusions);
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    actions.add_defender_exclusions(&missing)?;
    Ok(vec![Change::DefenderExclusions { added: missing }])
}

// -- windows.execution_account ------------------------------------------------

fn probe_execution_account(setup: &HostSetup, _: &dyn HostFacts) -> Outcome {
    match setup.start_mode() {
        Some(StartMode::Boot) => pass(
            "the boot service runs as LocalSystem: it needs no signed-in session and nothing it \
             starts waits on a prompt",
        ),
        Some(StartMode::Login) => fail(
            "the login service runs with this user's standard token. Windows Firewall prompts for \
             tools that listen on the network (Node.js from a fresh per-job path) wait for a \
             person who is not there, and anything that needs administrator rights fails",
        )
        .remedy(
            "for an autonomous host: runner-manager service install --start-at boot (from an \
             elevated terminal)",
        ),
        None => not_applicable("no service is installed"),
    }
}

// -- windows.execution_policy -------------------------------------------------

fn probe_execution_policy(_: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    let read = |value| facts.string(value);
    let (policy, source, managed) = match read(RegValue::ExecutionPolicyGroupPolicy) {
        Ok(Some(policy)) => (policy, "Group Policy", true),
        Err(error) => return unknown(format!("the execution policy could not be read: {error}")),
        Ok(None) => match read(RegValue::ExecutionPolicy) {
            Ok(Some(policy)) if !policy.eq_ignore_ascii_case("Undefined") => {
                (policy, "LocalMachine", false)
            }
            Err(error) => {
                return unknown(format!("the execution policy could not be read: {error}"));
            }
            Ok(_) => {
                let server = read(RegValue::InstallationType)
                    .ok()
                    .flatten()
                    .is_some_and(|kind| kind.to_ascii_lowercase().contains("server"));
                let default = if server { "RemoteSigned" } else { "Restricted" };
                (default.to_owned(), "the Windows default", false)
            }
        },
    };
    let blocks = ["Restricted", "AllSigned"]
        .iter()
        .any(|blocking| policy.eq_ignore_ascii_case(blocking));
    if !blocks {
        return pass(format!("{policy} ({source})"));
    }
    let outcome = fail(format!(
        "Windows PowerShell's execution policy is {policy} ({source}), so `shell: powershell` \
         steps that run a .ps1 script under the service account are refused"
    ));
    if managed {
        outcome
            .not_fixable()
            .remedy("Group Policy sets it; change the policy where it is managed")
    } else {
        outcome
    }
}

fn apply_execution_policy(
    _: &HostSetup,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
) -> Result<Vec<Change>, String> {
    if facts
        .string(RegValue::ExecutionPolicyGroupPolicy)?
        .is_some()
    {
        return Err(
            "Group Policy sets the execution policy; a local change would not apply".into(),
        );
    }
    let previous = facts.string(RegValue::ExecutionPolicy)?;
    actions.set_string(RegValue::ExecutionPolicy, Some("RemoteSigned"))?;
    Ok(vec![Change::RegistryString {
        value: RegValue::ExecutionPolicy,
        previous,
        applied: "RemoteSigned".to_owned(),
    }])
}

// -- windows.pwsh -------------------------------------------------------------

fn probe_pwsh(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    if let Some(found) = facts.find_tool("pwsh", setup.runner_path.as_deref()) {
        return pass(found.display().to_string());
    }
    let install = "winget install --id Microsoft.PowerShell --source winget --scope machine";
    if facts.file_exists(Path::new(WINDOWS_PWSH)) {
        fail(format!(
            "PowerShell 7 is installed at {WINDOWS_PWSH} but is not on the runners' PATH, so \
             `shell: pwsh` steps fail"
        ))
        .remedy("add its directory with `runner-manager host env set PATH=...`")
    } else {
        fail("PowerShell 7 is not installed, so `shell: pwsh` steps fail").remedy(install)
    }
}

// -- macos.launchd_priority ---------------------------------------------------

fn probe_launchd_priority(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    let mut problems = Vec::new();
    let plist = setup
        .service
        .as_ref()
        .and_then(|service| service.definition_path.as_ref());
    if let Some(plist) = plist {
        // The same rule `service status` applies to the plist it rendered.
        match facts.launchd_process_type(plist) {
            Ok(Some(kind)) if kind == LAUNCHD_PROCESS_TYPE => {}
            Ok(kind) => problems.push(format!(
                "{} sets ProcessType = {}, not {LAUNCHD_PROCESS_TYPE}, so launchd runs the daemon \
                 and every runner it starts below normal priority",
                plist.display(),
                kind.as_deref().unwrap_or("nothing (Standard)")
            )),
            Err(error) => {
                return unknown(format!("{} could not be read: {error}", plist.display()));
            }
        }
    }
    match facts.throttled_runner_processes() {
        Ok(0) => {}
        Ok(count) => problems.push(format!(
            "{count} runner process(es) are running at background priority"
        )),
        Err(error) if problems.is_empty() => {
            return unknown(format!("runner priorities could not be read: {error}"));
        }
        Err(_) => {}
    }
    if !problems.is_empty() {
        let restart = match setup.service.as_ref() {
            Some(service) if service.start_mode == StartMode::Boot => {
                format!("sudo launchctl kickstart -k system/{}", service.label)
            }
            Some(service) => format!("launchctl kickstart -k gui/$(id -u)/{}", service.label),
            None => "runner-manager service install".to_owned(),
        };
        return fail(problems.join("; ")).remedy(format!(
            "the daemon (0.4.32 and later; `runner-manager update`) rewrites the plist with \
             ProcessType = Interactive and reloads itself when it starts with no runner; to do \
             it now, restart the service while no job runs: {restart}"
        ));
    }
    if plist.is_none() {
        return not_applicable("no LaunchAgent or LaunchDaemon is installed");
    }
    if setup.service.as_ref().and_then(|service| service.running) == Some(false) {
        return unknown(
            "the plist asks for normal priority, but the service is not running, so the \
             priority it runs at cannot be seen; `runner-manager service status` says why",
        );
    }
    pass("the service runs at normal priority and no runner is throttled")
}

// -- macos.spotlight ----------------------------------------------------------

fn is_noindex(root: &Path) -> bool {
    root.components()
        .any(|part| part.as_os_str().to_string_lossy().ends_with(".noindex"))
}

/// The volumes macOS boots from, where turning Spotlight off would disable
/// search for the whole machine.
fn is_startup_volume(volume: &Path) -> bool {
    volume == Path::new("/") || volume == Path::new("/System/Volumes/Data")
}

/// The indexed runner roots and the volume each lives on.
///
/// Spotlight answers per volume: `mdutil -s` on a folder inside a volume says
/// "unknown indexing state" (measured on the Mac mini), so the question is put
/// to the root's mount point. A volume it gives no answer for is an error, not
/// a pass.
fn indexed_roots(
    setup: &HostSetup,
    facts: &dyn HostFacts,
) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let mut indexed = Vec::new();
    // Roots usually share a volume; ask Spotlight about each volume once.
    let mut answers: BTreeMap<PathBuf, Option<bool>> = BTreeMap::new();
    for root in setup.runner_roots.iter().filter(|root| !is_noindex(root)) {
        // `df` and `mdutil` on a hung volume would hang this whole check.
        if facts.directory_responds(root) != host_fitness::Responsiveness::Responds {
            return Err(format!("{} does not respond", root.display()));
        }
        let volume = facts
            .mount_point(root)
            .ok_or_else(|| format!("the volume holding {} could not be found", root.display()))?;
        let answer = match answers.get(&volume) {
            Some(answer) => *answer,
            None => {
                let answer = facts.spotlight_indexing(&volume)?;
                answers.insert(volume.clone(), answer);
                answer
            }
        };
        match answer {
            Some(true) => indexed.push((root.clone(), volume)),
            Some(false) => {}
            None => return Err(format!("Spotlight gave no answer for {}", volume.display())),
        }
    }
    Ok(indexed)
}

fn probe_spotlight(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    if setup.runner_roots.is_empty() {
        return not_applicable("no runner root could be resolved");
    }
    let indexed = match indexed_roots(setup, facts) {
        Ok(indexed) => indexed,
        Err(error) => return unknown(format!("Spotlight's status could not be read: {error}")),
    };
    if indexed.is_empty() {
        return pass("Spotlight does not index the volumes holding the runner roots");
    }
    let names = indexed
        .iter()
        .map(|(root, _)| root.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let outcome = fail(format!(
        "Spotlight indexes {names}, re-reading every file jobs write there"
    ));
    // The fix turns indexing off per volume and never on a startup volume, so
    // a root there needs the manual remedy even when another root is fixable.
    let Some((startup_root, _)) = indexed.iter().find(|(_, volume)| is_startup_volume(volume))
    else {
        return outcome;
    };
    let remedy = format!(
        "{} is on the startup volume: move it into a folder whose name ends in `.noindex`, has \
         no spaces and is outside your home folder (runner-manager host set-runtime-root --path \
         {MACOS_RUNNER_ROOT}), or add it to System Settings > Spotlight > Search Privacy",
        startup_root.display(),
    );
    let outcome = outcome.remedy(remedy);
    if indexed.iter().all(|(_, volume)| is_startup_volume(volume)) {
        outcome.not_fixable()
    } else {
        outcome
    }
}

fn apply_spotlight(
    setup: &HostSetup,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
) -> Result<Vec<Change>, String> {
    let mut changes = Vec::new();
    let mut volumes: Vec<PathBuf> = indexed_roots(setup, facts)?
        .into_iter()
        .map(|(_, volume)| volume)
        .filter(|volume| !is_startup_volume(volume))
        .collect();
    volumes.sort();
    volumes.dedup();
    if volumes.is_empty() {
        return Err("every indexed runner root is on the startup volume; see the remedy".into());
    }
    for volume in volumes {
        actions.set_spotlight(&volume, false)?;
        changes.push(Change::SpotlightIndexingOff { volume });
    }
    Ok(changes)
}

// -- macos.sleep, macos.disk_sleep, macos.autorestart, macos.wake_on_lan --------

/// A runner root a Mac can always use: no spaces, outside every home folder,
/// and named `.noindex` so Spotlight leaves it alone. Jobs that broke under
/// `~/Library/Application Support` pass there, measured on the runner Macs.
const MACOS_RUNNER_ROOT: &str = "/Users/Shared/rman.noindex";

/// Reads `pmset -g`: every setting it lists, by name. A name can contain
/// spaces (`Sleep On Power Button 1`) and a value can carry a note (`sleep 0
/// (sleep prevented by powerd)`), so the value is the first number on the line
/// and the name is everything before it.
fn power_settings_in(output: &str) -> BTreeMap<String, u32> {
    let mut settings = BTreeMap::new();
    for line in output.lines().filter(|line| line.starts_with(char::is_whitespace)) {
        let words: Vec<&str> = line.split_whitespace().collect();
        if let Some(at) = words.iter().position(|word| word.parse::<u32>().is_ok())
            && at > 0
            && let Ok(value) = words[at].parse()
        {
            settings.insert(words[..at].join(" "), value);
        }
    }
    settings
}

/// One power setting against the value a runner host wants.
fn power_probe(
    facts: &dyn HostFacts,
    name: &str,
    wanted: u32,
    good: &str,
    bad: impl Fn(u32) -> String,
) -> Outcome {
    match facts.power_settings() {
        Err(error) => unknown(format!("`pmset -g` could not be read: {error}")),
        Ok(None) => not_applicable("this platform has no power settings to check"),
        Ok(Some(settings)) => match settings.get(name) {
            None => not_applicable(format!("this Mac has no `{name}` power setting")),
            Some(&value) if value == wanted => pass(good),
            Some(&value) => fail(bad(value)),
        },
    }
}

fn apply_power(
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
    name: &str,
    wanted: u32,
) -> Result<Vec<Change>, String> {
    let previous = facts
        .power_settings()?
        .and_then(|settings| settings.get(name).copied());
    actions.set_power_setting(name, wanted)?;
    Ok(vec![Change::PowerSetting {
        name: name.to_owned(),
        previous,
        applied: wanted,
    }])
}

fn probe_sleep(_: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    if let Ok(Some(settings)) = facts.power_settings()
        && settings.get("SleepDisabled") == Some(&1)
    {
        return pass("sleep is disabled for the whole system");
    }
    power_probe(facts, "sleep", 0, "the Mac does not sleep on its own", |minutes| {
        format!(
            "the Mac sleeps after {minutes} minute(s) nobody uses it, and a sleeping Mac freezes \
             the job it is running; GitHub fails a job whose runner stops answering"
        )
    })
}

fn apply_sleep(
    _: &HostSetup,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
) -> Result<Vec<Change>, String> {
    apply_power(facts, actions, "sleep", 0)
}

fn probe_disk_sleep(_: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    power_probe(facts, "disksleep", 0, "disks do not sleep", |minutes| {
        format!(
            "disks sleep after {minutes} minute(s) idle, so the first read after a quiet spell \
             waits for a disk to wake"
        )
    })
}

fn apply_disk_sleep(
    _: &HostSetup,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
) -> Result<Vec<Change>, String> {
    apply_power(facts, actions, "disksleep", 0)
}

fn probe_autorestart(_: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    power_probe(
        facts,
        "autorestart",
        1,
        "the Mac starts again by itself after a power failure",
        |_| {
            "after a power failure the Mac stays off until somebody presses its power button"
                .to_owned()
        },
    )
}

fn apply_autorestart(
    _: &HostSetup,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
) -> Result<Vec<Change>, String> {
    apply_power(facts, actions, "autorestart", 1)
}

fn probe_wake_on_lan(_: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    power_probe(
        facts,
        "womp",
        1,
        "the Mac wakes when the network asks it to",
        |_| "Wake for network access is off, so the Mac cannot be woken remotely".to_owned(),
    )
}

fn apply_wake_on_lan(
    _: &HostSetup,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
) -> Result<Vec<Change>, String> {
    apply_power(facts, actions, "womp", 1)
}

// -- macos.unattended_login ---------------------------------------------------

fn probe_unattended_login(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    let Some(service) = &setup.service else {
        return not_applicable("no service is installed");
    };
    let Some(found) = facts.unattended_login() else {
        return not_applicable("automatic login and FileVault could not be probed here");
    };
    let account = setup
        .service_account
        .as_deref()
        .unwrap_or("the service account");
    let verdict = unattended_login::resume(&found, service.start_mode, account);
    let detail = verdict.detail(account).unwrap_or_default();
    match (&verdict, verdict.remedy()) {
        (Resume::Resumes, _) => pass(match service.start_mode {
            StartMode::Login => format!(
                "automatic login signs {account} in and FileVault is off, so the service starts \
                 again after a restart"
            ),
            StartMode::Boot => "FileVault is off, so the service starts at boot".to_owned(),
        }),
        (Resume::Unknown(_), _) => unknown(detail),
        (_, Some(remedy)) => fail(detail).remedy(remedy),
        (_, None) => fail(detail),
    }
}

// -- macos.runner_root_location -----------------------------------------------

fn probe_runner_root_location(setup: &HostSetup, _: &dyn HostFacts) -> Outcome {
    if setup.runner_roots.is_empty() {
        return not_applicable("no runner root could be resolved");
    }
    let home = setup
        .service_home
        .as_deref()
        .filter(|home| *home != Path::new("/"));
    let mut found = Vec::new();
    for root in &setup.runner_roots {
        if root.to_string_lossy().chars().any(char::is_whitespace) {
            found.push(format!(
                "{} has a space in its path, which breaks job scripts that do not quote paths",
                root.display()
            ));
        }
        if let Some(home) = home
            && root.starts_with(home)
        {
            found.push(format!(
                "{} is inside {}, the home folder of the account the service runs as, and so is \
                 every job's TMPDIR; a test that builds a stand-in home folder under TMPDIR then \
                 nests it inside the real one",
                root.display(),
                home.display()
            ));
        }
    }
    if found.is_empty() {
        pass("no runner root has a space in its path or is inside the service account's home")
    } else {
        fail(found.join("; ")).remedy(format!(
            "move the runner root to a folder with no spaces outside every home folder: \
             runner-manager host set-runtime-root --path {MACOS_RUNNER_ROOT}"
        ))
    }
}


// -- macos.keychain_credential ------------------------------------------------

fn probe_keychain_credential(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    if setup.perspective == Perspective::Daemon {
        return not_applicable("the daemon reads its own credential directly");
    }
    let Some(service) = &setup.service else {
        return not_applicable("no service is installed");
    };
    if service.start_mode == StartMode::Boot {
        return not_applicable(
            "a boot service keeps its credential in the System Keychain, which only root reads",
        );
    }
    let sign_in = || {
        format!(
            "{}{} (sign in again with the service binary; never switch to --start-at boot for \
             this)",
            super::update::force::auth_command_line(
                setup.data_root.as_deref(),
                StartMode::Login,
                &service.binary
            ),
            runner_manager_platform::service::MACOS_LOGIN_PLACE
        )
    };
    if setup.service_credential_unreadable {
        return fail(
            "the service recorded that it cannot read its stored GitHub credential, so it starts \
             no runner",
        )
        .remedy(sign_in());
    }
    if let Some(age) = setup
        .service_contact_age_secs
        .filter(|age| *age <= RECENT_CONTACT_SECS)
    {
        return pass(format!(
            "the service binary now installed reached GitHub {} minute(s) ago, so it reads its \
             credential",
            age / 60
        ));
    }
    match facts.service_credential(&service.binary, setup.data_root.as_deref()) {
        Ok(CredentialProbe::Readable) => {
            pass("the service binary reads its GitHub credential from the login keychain")
        }
        Ok(CredentialProbe::Absent) => not_applicable(
            "no GitHub credential is stored yet (`runner-manager auth login --start-at login`)",
        ),
        // If this process cannot read it either, the session is the problem
        // (an SSH session cannot unlock the login keychain), not the service
        // binary's grant.
        Ok(CredentialProbe::Unreadable(_)) if setup.own_keychain_readable != Some(true) => unknown(
            "this session cannot read the login keychain at all (an SSH session cannot unlock \
                 it), so the service binary's own access cannot be told apart; run `runner-manager \
                 host doctor` in a Terminal on this Mac",
        ),
        Ok(CredentialProbe::Unreadable(reason)) => fail(format!(
            "the service binary {} cannot read its GitHub credential ({reason}). The login \
             keychain ties an item to the exact build that wrote it; the daemon hands the \
             credential to the new build when it updates, so this is an item written by a build \
             that did not: the first update to 0.4.34 or later, or a binary replaced by hand",
            service.binary.display()
        ))
        .remedy(sign_in()),
        Err(error) => unknown(format!("the service binary could not be asked: {error}")),
    }
}

// -- host.runner_root_responsive ----------------------------------------------

/// How long a runner root has to answer a `stat` and a one-entry listing.
pub const RUNNER_ROOT_DEADLINE: Duration = Duration::from_secs(5);

/// A hung volume under a runner root -- seen on the Mac mini, whose external
/// `/Volumes/NVME` stopped answering `ls` -- wedges every runner placed there
/// and leaves a slot held by an attempt with no process. Required, so the
/// daemon registers no runner while it lasts.
fn probe_runner_root_responsive(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    if setup.runner_roots.is_empty() {
        return not_applicable("no runner root could be resolved");
    }
    let mut hung = Vec::new();
    let mut errors = Vec::new();
    for root in &setup.runner_roots {
        match facts.directory_responds(root) {
            host_fitness::Responsiveness::Responds => {}
            host_fitness::Responsiveness::Hung => hung.push(root.display().to_string()),
            host_fitness::Responsiveness::Failed(error) => {
                errors.push(format!("{}: {error}", root.display()));
            }
        }
    }
    if !hung.is_empty() {
        return fail(format!(
            "runner root not responding: {} did not answer within {} seconds, so a runner \
             placed there would hang",
            hung.join(", "),
            RUNNER_ROOT_DEADLINE.as_secs()
        ))
        .remedy("check the volume holding it (a stalled external disk or network mount); a reboot or reconnect usually clears it");
    }
    if !errors.is_empty() {
        return unknown(format!(
            "a runner root could not be read: {}",
            errors.join("; ")
        ));
    }
    pass("every runner root answers")
}

// -- host.capacity ------------------------------------------------------------

/// About [`MEMORY_PER_RUNNER_GIB`] of memory and one core per concurrent job.
#[must_use]
pub fn recommended_capacity(memory_bytes: u64, cores: usize) -> u16 {
    let by_memory = memory_bytes / GIB / MEMORY_PER_RUNNER_GIB;
    let by_cores = u64::try_from(cores).unwrap_or(u64::MAX);
    u16::try_from(by_memory.min(by_cores).max(1)).unwrap_or(u16::MAX)
}

fn probe_capacity(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    let Some(memory) = facts.memory_bytes() else {
        return unknown("this machine's memory could not be read");
    };
    let cores = facts.cpu_count();
    let recommended = recommended_capacity(memory, cores);
    let machine = format!("{} GiB of memory and {cores} cores", memory / GIB);
    if setup.capacity <= recommended {
        return pass(format!(
            "capacity {} on {machine} (up to {recommended} fits)",
            setup.capacity
        ));
    }
    fail(format!(
        "capacity {} on {machine}; at about {MEMORY_PER_RUNNER_GIB} GiB and one core per \
         concurrent job, {recommended} is what fits without memory pressure (other runners on \
         this machine need room too)",
        setup.capacity
    ))
    .remedy(format!("runner-manager host set-capacity {recommended}"))
}

// -- host.launches ------------------------------------------------------------

fn probe_launches(setup: &HostSetup, _facts: &dyn HostFacts) -> Outcome {
    match &setup.launches_blocked {
        None => pass("no blocked launches recorded"),
        Some(blocked) => fail(format!("the service has started no runner {blocked}"))
            .remedy(blocked.remedy.clone()),
    }
}

// -- host.required_tools ------------------------------------------------------

fn probe_required_tools(setup: &HostSetup, facts: &dyn HostFacts) -> Outcome {
    if let Some(error) = &setup.required_tools_error {
        return unknown(format!("the required tools could not be read: {error}"))
            .remedy("runner-manager host required-tools --set <TOOLS> (rewrites the file)");
    }
    if setup.required_tools.is_empty() {
        return not_applicable(
            "no required tools are configured (runner-manager host required-tools --set git,node)",
        );
    }
    let missing: Vec<&str> = setup
        .required_tools
        .iter()
        .filter(|tool| {
            facts
                .find_tool(tool, setup.runner_path.as_deref())
                .is_none()
        })
        .map(String::as_str)
        .collect();
    if missing.is_empty() {
        return pass(format!(
            "found on the runners' PATH: {}",
            setup.required_tools.join(", ")
        ));
    }
    fail(format!("not on the runners' PATH: {}", missing.join(", ")))
        .remedy("install them, or add their directory with `runner-manager host env set PATH=...`")
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// What a fix would do, as the report shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixView {
    pub action: &'static str,
    pub needs_admin: bool,
    /// The flag that consents to it, when it lowers security.
    pub consent_flag: Option<&'static str>,
    pub revert: String,
}

/// One evaluated check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub title: &'static str,
    pub platform: CheckPlatform,
    pub severity: Severity,
    pub status: Status,
    pub detail: String,
    /// `null` when there is no automatic fix, or it cannot help here.
    pub fix: Option<FixView>,
    pub remedy: Option<String>,
}

impl Finding {
    /// Failing or unknown, with an automatic fix that can help.
    fn wants_fix(&self) -> bool {
        matches!(self.status, Status::Fail | Status::Unknown) && self.fix.is_some()
    }

    /// Failing, and not merely informational.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.status == Status::Fail && self.severity != Severity::Info
    }
}

/// The `host doctor --json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub os: HostOs,
    pub perspective: Perspective,
    pub elevated: bool,
    pub findings: Vec<Finding>,
}

impl Report {
    /// The ids of the required checks that fail. Unknown never counts.
    #[must_use]
    pub fn required_failing(&self) -> Vec<String> {
        self.with(Severity::Required, Status::Fail)
            .map(|finding| finding.id.to_owned())
            .collect()
    }

    /// The findings of one severity in one status.
    fn with(&self, severity: Severity, status: Status) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(move |finding| finding.severity == severity && finding.status == status)
    }
}

impl Finding {
    /// `id  status (severity): detail`, the line every report prints.
    fn line(&self, width: usize) -> String {
        format!(
            "{:<width$}  {} ({}): {}",
            self.id,
            self.status.as_str(),
            self.severity.as_str(),
            self.detail
        )
    }
}

/// Evaluates every check that applies to `setup.os`.
#[must_use]
pub fn evaluate(setup: &HostSetup, facts: &dyn HostFacts) -> Report {
    let findings = CHECKS
        .iter()
        .filter(|check| check.platform.includes(setup.os))
        .map(|check| {
            let outcome = (check.probe)(setup, facts);
            Finding {
                id: check.id,
                title: check.title,
                platform: check.platform,
                severity: check.severity,
                status: outcome.status,
                detail: outcome.detail,
                fix: check
                    .fix
                    .as_ref()
                    .filter(|_| outcome.fixable)
                    .map(|fix| FixView {
                        action: fix.action,
                        needs_admin: fix.needs_admin,
                        consent_flag: fix.consent_flag,
                        revert: format!("runner-manager host prepare --revert {}", check.id),
                    }),
                remedy: outcome.remedy,
            }
        })
        .collect();
    Report {
        schema_version: REPORT_SCHEMA_VERSION,
        os: setup.os,
        perspective: setup.perspective,
        elevated: facts.elevated(),
        findings,
    }
}

/// The plain report `host doctor` prints.
fn write_report(out: &mut dyn Write, report: &Report) -> io::Result<()> {
    let os = match report.os {
        HostOs::Windows => "windows",
        HostOs::Macos => "macos",
        HostOs::Linux => "linux",
    };
    let view = match report.perspective {
        Perspective::Operator => "operator view",
        Perspective::Daemon => "daemon view",
    };
    let elevated = if report.elevated {
        "elevated"
    } else {
        "not elevated"
    };
    writeln!(out, "Host doctor ({os}, {view}, {elevated})")?;
    let widest = report
        .findings
        .iter()
        .map(|finding| finding.id.len())
        .max()
        .unwrap_or(0);
    for finding in &report.findings {
        writeln!(out, "  {}", finding.line(widest))?;
        if finding.status == Status::Pass || finding.status == Status::NotApplicable {
            continue;
        }
        if let Some(fix) = &finding.fix {
            let mut conditions = Vec::new();
            if fix.needs_admin {
                conditions.push("administrator rights".to_owned());
            }
            if let Some(flag) = fix.consent_flag {
                conditions.push(format!("lowers security, needs {flag}"));
            }
            let conditions = if conditions.is_empty() {
                String::new()
            } else {
                format!(" [{}]", conditions.join("; "))
            };
            writeln!(out, "      fix: {}{conditions}", fix.action)?;
        }
        if let Some(remedy) = &finding.remedy {
            writeln!(
                out,
                "      {}: {remedy}",
                if finding.fix.is_some() { "or" } else { "do" }
            )?;
        }
    }
    writeln!(out)?;
    writeln!(out, "Summary")?;
    for severity in [Severity::Required, Severity::Recommended] {
        writeln!(
            out,
            "  {:<12}{} failing, {} unknown",
            severity.as_str(),
            report.with(severity, Status::Fail).count(),
            report.with(severity, Status::Unknown).count()
        )?;
    }
    let fixable = report.findings.iter().filter(|f| f.wants_fix()).count();
    let next = if fixable == 0 {
        "nothing `host prepare` can fix".to_owned()
    } else {
        format!(
            "runner-manager host prepare (fixes {fixable}; asks for administrator rights once if needed)"
        )
    };
    writeln!(out, "  {:<12}{next}", "next")
}

// ---------------------------------------------------------------------------
// The setup, from this host's configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct RequiredToolsFile {
    schema_version: u32,
    tools: Vec<String>,
}

const REQUIRED_TOOLS_SCHEMA_VERSION: u32 = 1;

fn required_tools_path(context: &Context) -> PathBuf {
    context.paths().config_dir().join(REQUIRED_TOOLS_FILE)
}

/// The configured required tools; empty when none are.
///
/// # Errors
/// [`Failure::LocalState`] when the file exists and cannot be read.
pub fn required_tools(context: &Context) -> Result<Vec<String>, CliError> {
    read_json_or(&required_tools_path(context), RequiredToolsFile::default).map(|file| file.tools)
}

fn validate_tool(tool: &str) -> Result<(), CliError> {
    let valid = !tool.is_empty()
        && tool.len() <= 64
        && tool
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'));
    if valid {
        Ok(())
    } else {
        Err(CliError::with_remedy(
            Failure::InvalidArgument,
            format!(
                "{tool:?} is not a tool name: use the bare command name, such as `git` or `pwsh`, \
                 with no path"
            ),
            "runner-manager host required-tools --set git,pwsh,node",
        ))
    }
}

/// `PATH` as a boot service on this platform inherits it, before runner
/// defaults and `runner.env` are applied.
fn service_inherited_path(os: HostOs, mode: Option<StartMode>) -> Option<OsString> {
    match (os, mode) {
        (HostOs::Windows, Some(StartMode::Boot)) => {
            let (subkey, value) = RegValue::MachinePath.location();
            host_fitness::read_registry_string(subkey, value)
                .ok()
                .flatten()
                .map(|path| OsString::from(expand_environment(&path)))
                .or_else(|| std::env::var_os("PATH"))
        }
        (HostOs::Macos, Some(_)) => Some(OsString::from(runner_env::MACOS_SYSTEM_PATH)),
        (HostOs::Linux, Some(_)) => Some(OsString::from(SYSTEMD_DEFAULT_PATH)),
        _ => std::env::var_os("PATH"),
    }
}

/// The `PATH` a native runner starts with: `runner.env`'s, else the platform
/// defaults over what the daemon inherits.
fn runner_path(
    context: &Context,
    perspective: Perspective,
    mode: Option<StartMode>,
) -> Option<String> {
    let file =
        RunnerEnv::load(&runner_env::path_in(context.paths().config_dir())).unwrap_or_default();
    if let Some(path) = file.get("PATH") {
        return Some(path.to_owned());
    }
    let inherited = match perspective {
        Perspective::Daemon => std::env::var_os("PATH"),
        Perspective::Operator => service_inherited_path(HostOs::current(), mode),
    };
    let defaults = runner_env::platform_defaults(
        RunnerPlatform::current(),
        Path::new(""),
        &Inherited {
            path: inherited.clone(),
            has_locale: true,
        },
        Path::exists,
    );
    defaults
        .into_iter()
        .find(|(name, _)| *name == "PATH")
        .map(|(_, value)| value)
        .or(inherited)
        .map(|path| path.to_string_lossy().into_owned())
}

/// How long ago the daemon now installed reached GitHub, if it has.
///
/// The contact file is written by whichever daemon ran last. Straight after an
/// upgrade that is the *previous* binary, which kept reaching GitHub through
/// its drain -- so its contact said nothing about whether the new binary can
/// read the credential, and the keychain check passed while every start of the
/// new daemon failed with `-25293` (watched on the 0.4.33 rollout). A contact
/// counts only when it is newer than the moment the service binary was put in
/// place, which the old daemon cannot have reached.
fn current_daemon_contact_age(
    contact: Option<chrono::DateTime<chrono::Utc>>,
    binary_replaced_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<u64> {
    let contact = contact?;
    if binary_replaced_at.is_some_and(|replaced| contact <= replaced) {
        return None;
    }
    u64::try_from((now - contact).num_seconds()).ok()
}

/// When `binary` was put in place: its status-change time, which a copy or a
/// rename sets and nothing can set back (a copy may keep the source's
/// modification time). The modification time where there is no such field.
fn replaced_at(binary: &Path) -> Option<chrono::DateTime<chrono::Utc>> {
    let metadata = std::fs::metadata(binary).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let nanos = u32::try_from(metadata.ctime_nsec()).unwrap_or(0);
        chrono::DateTime::from_timestamp(metadata.ctime(), nanos)
    }
    #[cfg(not(unix))]
    {
        metadata.modified().ok().map(chrono::DateTime::from)
    }
}

/// Builds the setup from values the caller has already read.
///
/// `service` overrides the installed registration; `service install` passes
/// the one it is about to make, because that is the account runners will use.
fn setup_from_parts(
    context: &Context,
    perspective: Perspective,
    host: Option<&Host>,
    policies: &[ScalePolicy],
    runner_root: &HostRoot,
    service: Option<ServiceSetup>,
) -> HostSetup {
    let service = service.or_else(|| {
        InstallRecord::read(context.paths())
            .ok()
            .flatten()
            .map(|record| ServiceSetup {
                start_mode: record.start_mode,
                binary: record.binary,
                definition_path: record.definition_path,
                label: super::service::identity().launchd_label(),
                running: (perspective == Perspective::Operator)
                    .then(|| super::service::operations(context).status().ok())
                    .flatten()
                    .map(|status| status.is_running()),
            })
    });
    let mut runner_roots: Vec<PathBuf> = runner_root
        .effective
        .iter()
        .map(|root| PathBuf::from(root.as_str()))
        .collect();
    for policy in policies {
        if let Some(root) = policy.workspace_policy().root() {
            let root = PathBuf::from(root.as_str());
            if !runner_roots.contains(&root) {
                runner_roots.push(root);
            }
        }
    }
    // Jobs read and write the dependency-cache root as much as their own
    // workspace, so it gets the same Defender, Spotlight and responsiveness
    // checks, and `host prepare` excludes it with the runner roots. Only when it
    // exists and no runner root already contains it, which the default
    // (`<runner root>/_cache`) always is.
    if let Some(cache_root) = super::cache::active_root(context, host)
        && cache_root.is_dir()
        && !runner_roots.iter().any(|root| cache_root.starts_with(root))
    {
        runner_roots.push(cache_root);
    }
    let mode = service.as_ref().map(|service| service.start_mode);
    let (service_account, service_home) = service_account_and_home(perspective, mode);
    let (required_tools, required_tools_error) = match required_tools(context) {
        Ok(tools) => (tools, None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    HostSetup {
        os: HostOs::current(),
        perspective,
        runner_roots,
        capacity: host.map_or(super::DEFAULT_HOST_CAPACITY, Host::host_capacity),
        required_tools,
        required_tools_error,
        runner_path: runner_path(context, perspective, mode),
        probe_dir: context.paths().state_dir().to_path_buf(),
        data_root: context.data_root.clone(),
        service_contact_age_secs: current_daemon_contact_age(
            runner_manager_platform::service::last_github_contact(context.paths())
                .ok()
                .flatten(),
            service
                .as_ref()
                .and_then(|service| replaced_at(&service.binary)),
            context.clock().now(),
        ),
        service_credential_unreadable:
            runner_manager_platform::service::credential_unreadable_since(context.paths())
                .is_ok_and(|since| since.is_some()),
        own_keychain_readable: (HostOs::current() == HostOs::Macos
            && perspective == Perspective::Operator
            && mode == Some(StartMode::Login))
        .then(|| {
            context
                .secret_store(StartMode::Login)
                .is_ok_and(|store| store.load().is_ok())
        }),
        launches_blocked: runner_manager_platform::launch_health::launches_blocked(
            context.paths(),
            context.clock().now(),
        ),
        service_account,
        service_home,
        service,
    }
}

/// The account the service runs as on macOS, and its home folder: root's for
/// a boot service seen by an operator, and otherwise this process's own (a
/// login service runs as the account that installed it, and the daemon is the
/// service). `(None, None)` elsewhere, where nothing reads them.
fn service_account_and_home(
    perspective: Perspective,
    mode: Option<StartMode>,
) -> (Option<String>, Option<PathBuf>) {
    if HostOs::current() != HostOs::Macos {
        return (None, None);
    }
    if perspective == Perspective::Operator && mode == Some(StartMode::Boot) {
        return (Some("root".into()), Some(PathBuf::from("/var/root")));
    }
    (
        unattended_login::current_account(),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

/// Builds the setup by reading this host's configuration.
///
/// # Errors
/// [`Failure::LocalState`] when the database cannot be read.
pub fn setup(
    context: &Context,
    perspective: Perspective,
    service: Option<ServiceSetup>,
) -> Result<HostSetup, CliError> {
    let store = context.store()?;
    let host = super::host::local_host(&store)?;
    let policies = store.policies().map_err(|source| {
        CliError::new(
            Failure::LocalState,
            format!("cannot read this host's policies: {source}"),
        )
    })?;
    let root = workspace::host_root(context.paths(), host.as_ref());
    Ok(setup_from_parts(
        context,
        perspective,
        host.as_ref(),
        &policies,
        &root,
        service,
    ))
}

// ---------------------------------------------------------------------------
// The real facts and actions
// ---------------------------------------------------------------------------

/// [`HostFacts`] read from this machine.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemFacts;

fn run_capture(program: &Path, args: &[&str]) -> Result<std::process::Output, String> {
    std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("{} could not be started: {error}", program.display()))
}

#[cfg(windows)]
fn windows_powershell() -> PathBuf {
    host_fitness::system_directory()
        .map_or_else(|_| PathBuf::from(r"C:\Windows\System32"), PathBuf::from)
        .join(r"WindowsPowerShell\v1.0\powershell.exe")
}

#[cfg(windows)]
fn run_windows_powershell(script: &str) -> Result<(), String> {
    let encoded: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let output = std::process::Command::new(windows_powershell())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &crate::tui::shell::base64(&encoded),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("Windows PowerShell could not be started: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Windows PowerShell failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// A PowerShell array literal of single-quoted strings.
#[cfg(any(windows, test))]
fn powershell_list(paths: &[String]) -> String {
    let quoted: Vec<String> = paths
        .iter()
        .map(|path| format!("'{}'", path.replace('\'', "''")))
        .collect();
    format!("@({})", quoted.join(","))
}

impl HostFacts for SystemFacts {
    fn elevated(&self) -> bool {
        host_fitness::is_elevated()
    }

    fn dword(&self, value: RegValue) -> Result<Option<u32>, String> {
        let (subkey, name) = value.location();
        host_fitness::read_registry_dword(subkey, name).map_err(|error| error.to_string())
    }

    fn string(&self, value: RegValue) -> Result<Option<String>, String> {
        let (subkey, name) = value.location();
        host_fitness::read_registry_string(subkey, name).map_err(|error| error.to_string())
    }

    fn defender_exclusions(&self) -> Result<Option<Vec<String>>, String> {
        match host_fitness::registry_value_names(
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        ) {
            Ok(names) => Ok(Some(names)),
            Err(host_fitness::RegistryError::AccessDenied) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn git_system_value(&self, git: &Path, name: &str) -> Result<Option<String>, String> {
        let output = run_capture(git, &["config", "--system", "--get", name])?;
        match output.status.code() {
            Some(0) => Ok(Some(
                String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            )),
            // 1: the key is not set.
            Some(1) => Ok(None),
            _ => Err(String::from_utf8_lossy(&output.stderr).trim().to_owned()),
        }
    }

    fn symlink_allowed(&self, directory: &Path) -> Result<bool, String> {
        host_fitness::can_create_symlink(directory).map_err(|error| error.to_string())
    }

    fn find_tool(&self, tool: &str, path: Option<&str>) -> Option<PathBuf> {
        host_fitness::find_on_path(tool, &OsString::from(path?))
    }

    fn file_exists(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn memory_bytes(&self) -> Option<u64> {
        host_fitness::physical_memory_bytes()
    }

    fn cpu_count(&self) -> usize {
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
    }

    fn power_settings(&self) -> Result<Option<BTreeMap<String, u32>>, String> {
        if !cfg!(target_os = "macos") {
            return Ok(None);
        }
        let output = run_capture(Path::new("/usr/bin/pmset"), &["-g"])?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
        }
        Ok(Some(power_settings_in(&String::from_utf8_lossy(
            &output.stdout,
        ))))
    }

    fn unattended_login(&self) -> Option<UnattendedLogin> {
        unattended_login::probe()
    }

    fn spotlight_indexing(&self, volume: &Path) -> Result<Option<bool>, String> {
        let output = run_capture(
            Path::new("/usr/bin/mdutil"),
            &["-s", &volume.to_string_lossy()],
        )?;
        let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        Ok(if text.contains("indexing enabled") {
            Some(true)
        } else if text.contains("indexing disabled")
            || text.contains("indexing and searching disabled")
        {
            Some(false)
        } else {
            None
        })
    }

    fn directory_responds(&self, directory: &Path) -> host_fitness::Responsiveness {
        host_fitness::directory_responds(directory, RUNNER_ROOT_DEADLINE)
    }

    fn mount_point(&self, path: &Path) -> Option<PathBuf> {
        let existing = path.ancestors().find(|ancestor| ancestor.exists())?;
        let output =
            run_capture(Path::new("/bin/df"), &["-P", &existing.to_string_lossy()]).ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let line = text.lines().nth(1)?;
        // `df -P`'s sixth column; a mount point may contain spaces, so it is
        // everything after the fifth.
        let mount = line
            .split_whitespace()
            .skip(5)
            .collect::<Vec<_>>()
            .join(" ");
        (!mount.is_empty()).then(|| PathBuf::from(mount))
    }

    fn launchd_process_type(&self, plist: &Path) -> Result<Option<String>, String> {
        let text = std::fs::read_to_string(plist).map_err(|error| error.to_string())?;
        Ok(plist_string_value(&text, "ProcessType"))
    }

    fn throttled_runner_processes(&self) -> Result<usize, String> {
        let output = run_capture(Path::new("/bin/ps"), &["-axo", "pri=,comm="])?;
        Ok(throttled_runners_in(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }

    fn service_credential(
        &self,
        binary: &Path,
        data_root: Option<&Path>,
    ) -> Result<CredentialProbe, String> {
        let mut command = std::process::Command::new(binary);
        if let Some(root) = data_root {
            command.arg("--data-dir").arg(root);
        }
        command
            .args(["status", "--json"])
            .env(SKIP_DOCTOR_VARIABLE, "1")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| format!("{} could not be started: {error}", binary.display()))?;
        // Read on a thread so a large document can never fill the pipe and
        // stall the child, and so the answer is taken the moment it is ready.
        let mut stdout = child.stdout.take().ok_or("the child had no stdout")?;
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = sender.send(io::Read::read_to_end(&mut stdout, &mut bytes).map(|_| bytes));
        });
        let Ok(read) = receiver.recv_timeout(Duration::from_secs(20)) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("it did not answer within 20 seconds".into());
        };
        let _ = child.wait();
        let bytes = read.map_err(|error| error.to_string())?;
        let document: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("its status document did not parse: {error}"))?;
        let credential = &document["credential"];
        Ok(match credential["unreadable"].as_str() {
            Some(reason) => CredentialProbe::Unreadable(reason.to_owned()),
            None if credential["present"].as_bool() == Some(true) => CredentialProbe::Readable,
            None => CredentialProbe::Absent,
        })
    }
}

/// Runner processes in `ps -axo pri=,comm=` output at background priority.
fn throttled_runners_in(listing: &str) -> usize {
    listing
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (priority, command) = line.split_once(char::is_whitespace)?;
            Some((priority.parse::<i32>().ok()?, command.trim()))
        })
        .filter(|(priority, command)| {
            *priority <= 4
                && (command.ends_with("Runner.Listener") || command.ends_with("Runner.Worker"))
        })
        .count()
}

/// [`HostActions`] carried out on this machine.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemActions;

impl HostActions for SystemActions {
    fn set_dword(&self, value: RegValue, data: Option<u32>) -> Result<(), String> {
        if !value.writable() {
            return Err(format!("{value:?} is not a value host prepare writes"));
        }
        let (subkey, name) = value.location();
        host_fitness::write_registry_dword(subkey, name, data).map_err(|error| error.to_string())
    }

    fn set_string(&self, value: RegValue, data: Option<&str>) -> Result<(), String> {
        if !value.writable() {
            return Err(format!("{value:?} is not a value host prepare writes"));
        }
        let (subkey, name) = value.location();
        host_fitness::write_registry_string(subkey, name, data).map_err(|error| error.to_string())
    }

    fn set_git_system_value(
        &self,
        git: &Path,
        name: &str,
        value: Option<&str>,
    ) -> Result<(), String> {
        let output = match value {
            Some(value) => run_capture(git, &["config", "--system", name, value])?,
            None => run_capture(git, &["config", "--system", "--unset", name])?,
        };
        // `--unset` of a key that is not set exits 5; that is the goal state.
        if output.status.success() || (value.is_none() && output.status.code() == Some(5)) {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
        }
    }

    #[cfg(windows)]
    fn add_defender_exclusions(&self, paths: &[String]) -> Result<(), String> {
        run_windows_powershell(&format!(
            "$ErrorActionPreference='Stop'; Add-MpPreference -ExclusionPath {}",
            powershell_list(paths)
        ))
    }

    #[cfg(windows)]
    fn remove_defender_exclusions(&self, paths: &[String]) -> Result<(), String> {
        run_windows_powershell(&format!(
            "$ErrorActionPreference='Stop'; Remove-MpPreference -ExclusionPath {}",
            powershell_list(paths)
        ))
    }

    #[cfg(not(windows))]
    fn add_defender_exclusions(&self, _: &[String]) -> Result<(), String> {
        Err("Defender exists only on Windows".into())
    }

    #[cfg(not(windows))]
    fn remove_defender_exclusions(&self, _: &[String]) -> Result<(), String> {
        Err("Defender exists only on Windows".into())
    }

    fn set_spotlight(&self, volume: &Path, enabled: bool) -> Result<(), String> {
        let flag = if enabled { "on" } else { "off" };
        let output = run_capture(
            Path::new("/usr/bin/mdutil"),
            &["-i", flag, &volume.to_string_lossy()],
        )?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
        }
    }

    fn set_power_setting(&self, name: &str, value: u32) -> Result<(), String> {
        if !POWER_SETTINGS.iter().any(|(known, _)| *known == name) {
            return Err(format!("{name} is not a power setting `host prepare` changes"));
        }
        let output = run_capture(
            Path::new("/usr/bin/pmset"),
            &["-a", name, &value.to_string()],
        )?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
        }
    }
}

// ---------------------------------------------------------------------------
// Applying fixes
// ---------------------------------------------------------------------------

/// How one fix (or revert) went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum FixOutcome {
    Applied {
        changes: Vec<Change>,
    },
    /// The re-probe found nothing left to do.
    AlreadyDone,
    Reverted,
    Failed {
        error: String,
    },
    NotAttempted {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixResult {
    pub id: String,
    #[serde(flatten)]
    pub outcome: FixOutcome,
}

/// What the elevated copy is asked to do. Carried on its command line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElevatedRequest {
    pub setup: HostSetup,
    pub apply: Vec<String>,
    pub revert: Vec<(String, Vec<Change>)>,
}

/// Why no elevated copy reported back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevationFailure {
    Refused,
    Unavailable(String),
    Failed(String),
}

impl ElevationFailure {
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::Refused => "administrator rights were refused".to_owned(),
            Self::Unavailable(detail) => {
                format!("administrator rights could not be asked for: {detail}")
            }
            Self::Failed(detail) => format!("the elevated step failed: {detail}"),
        }
    }
}

/// Runs a request with administrator rights.
pub trait Elevator {
    fn elevate(&self, request: &ElevatedRequest) -> Result<Vec<FixResult>, ElevationFailure>;
}

/// Relaunches this binary through [`host_fitness::run_elevated`].
#[derive(Debug, Clone, Copy)]
pub struct SystemElevator {
    /// Whether a password may be asked for on this terminal (`sudo`); `false`
    /// uses the system dialog.
    pub terminal: bool,
}

impl Elevator for SystemElevator {
    fn elevate(&self, request: &ElevatedRequest) -> Result<Vec<FixResult>, ElevationFailure> {
        let plan = serde_json::to_string(request)
            .map_err(|error| ElevationFailure::Failed(error.to_string()))?;
        run_elevated_reporting(
            |result| {
                vec![
                    OsString::from("host"),
                    OsString::from("prepare"),
                    OsString::from("--elevated-request"),
                    OsString::from(plan),
                    OsString::from("--elevated-result"),
                    result.as_os_str().to_owned(),
                ]
            },
            self.terminal,
        )
    }
}

/// Runs one elevated copy of this binary with the arguments `args` builds
/// around the file it is to report into, waits for it, and reads that
/// report back. The elevated window is hidden, so the file is its only voice.
///
/// # Errors
/// [`ElevationFailure::Refused`] or [`ElevationFailure::Unavailable`] when no
/// elevated copy ran, and [`ElevationFailure::Failed`] when one ran and left
/// no readable report.
pub(crate) fn run_elevated_reporting<T: serde::de::DeserializeOwned>(
    args: impl FnOnce(&Path) -> Vec<OsString>,
    terminal: bool,
) -> Result<T, ElevationFailure> {
    let failed = |error: String| ElevationFailure::Failed(error);
    let program = std::env::current_exe().map_err(|error| failed(error.to_string()))?;
    let directory = tempfile::tempdir().map_err(|error| failed(error.to_string()))?;
    let result = directory.path().join("result.json");
    match host_fitness::run_elevated(&program, &args(&result), terminal) {
        ElevationOutcome::Refused => Err(ElevationFailure::Refused),
        ElevationOutcome::Unavailable(detail) => Err(ElevationFailure::Unavailable(detail)),
        ElevationOutcome::Exited(code) => {
            let text = std::fs::read_to_string(&result).map_err(|error| {
                failed(format!("it exited {code} and wrote no result ({error})"))
            })?;
            serde_json::from_str(&text).map_err(|error| failed(error.to_string()))
        }
    }
}

fn apply_one(
    id: &str,
    setup: &HostSetup,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
) -> FixResult {
    let outcome = match check(id) {
        Some(CheckSpec {
            probe,
            fix: Some(fix),
            ..
        }) => {
            let before = probe(setup, facts);
            if matches!(before.status, Status::Pass | Status::NotApplicable) {
                FixOutcome::AlreadyDone
            } else {
                match (fix.apply)(setup, facts, actions) {
                    Ok(changes) if changes.is_empty() => FixOutcome::AlreadyDone,
                    Ok(changes) => FixOutcome::Applied { changes },
                    Err(error) => FixOutcome::Failed { error },
                }
            }
        }
        _ => FixOutcome::NotAttempted {
            reason: "no automatic fix exists for this check".into(),
        },
    };
    FixResult {
        id: id.to_owned(),
        outcome,
    }
}

fn revert_one(id: &str, changes: &[Change], actions: &dyn HostActions) -> FixResult {
    // Newest first, so a check that changed two things unwinds in order.
    let outcome = changes
        .iter()
        .rev()
        .try_for_each(|change| change.revert(actions))
        .map_or_else(
            |error| FixOutcome::Failed { error },
            |()| FixOutcome::Reverted,
        );
    FixResult {
        id: id.to_owned(),
        outcome,
    }
}

/// Carries out `request` in this process.
fn run_request(
    request: &ElevatedRequest,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
) -> Vec<FixResult> {
    let mut results: Vec<FixResult> = request
        .apply
        .iter()
        .map(|id| apply_one(id, &request.setup, facts, actions))
        .collect();
    results.extend(
        request
            .revert
            .iter()
            .map(|(id, changes)| revert_one(id, changes, actions)),
    );
    results
}

/// Applies (or reverts) in-process what needs no elevation, and hands the rest
/// to one elevated run.
fn execute(
    request: ElevatedRequest,
    facts: &dyn HostFacts,
    actions: &dyn HostActions,
    elevator: &dyn Elevator,
) -> Vec<FixResult> {
    let elevated = facts.elevated();
    let (admin_apply, local_apply): (Vec<String>, Vec<String>) = request
        .apply
        .into_iter()
        .partition(|id| !elevated && fix_needs_admin(id));
    // Every kind of `Change` is a machine-wide setting, so undoing one needs
    // the same rights making it did.
    let (admin_revert, local_revert): (Vec<_>, Vec<_>) =
        request.revert.into_iter().partition(|_| !elevated);
    let mut results = run_request(
        &ElevatedRequest {
            setup: request.setup.clone(),
            apply: local_apply,
            revert: local_revert,
        },
        facts,
        actions,
    );
    if admin_apply.is_empty() && admin_revert.is_empty() {
        return results;
    }
    let ids: Vec<String> = admin_apply
        .iter()
        .cloned()
        .chain(admin_revert.iter().map(|(id, _)| id.clone()))
        .collect();
    let elevated_request = ElevatedRequest {
        setup: request.setup,
        apply: admin_apply,
        revert: admin_revert,
    };
    match elevator.elevate(&elevated_request) {
        Ok(reported) => {
            // Anything the elevated copy did not mention is reported as such
            // rather than silently dropped.
            for id in ids {
                match reported.iter().find(|result| result.id == id) {
                    Some(result) => results.push(result.clone()),
                    None => results.push(FixResult {
                        id,
                        outcome: FixOutcome::NotAttempted {
                            reason: "the elevated step did not report it".into(),
                        },
                    }),
                }
            }
        }
        Err(failure) => results.extend(ids.into_iter().map(|id| FixResult {
            id,
            outcome: FixOutcome::NotAttempted {
                reason: failure.reason(),
            },
        })),
    }
    results
}

// ---------------------------------------------------------------------------
// The journal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Journal {
    schema_version: u32,
    entries: BTreeMap<String, JournalEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JournalEntry {
    applied_at: Timestamp,
    by_version: String,
    changes: Vec<Change>,
}

fn journal_path(context: &Context) -> PathBuf {
    context.paths().config_dir().join(JOURNAL_FILE)
}

/// A JSON file under `config/`, or `missing()` when there is none.
fn read_json_or<T: serde::de::DeserializeOwned>(
    path: &Path,
    missing: impl FnOnce() -> T,
) -> Result<T, CliError> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|error| {
            CliError::new(
                Failure::LocalState,
                format!("{} is not valid: {error}", path.display()),
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(missing()),
        Err(error) => Err(CliError::new(
            Failure::LocalState,
            format!("cannot read {}: {error}", path.display()),
        )),
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), CliError> {
    serde_json::to_vec_pretty(value)
        .map_err(io::Error::other)
        .and_then(|bytes| host_fitness::write_atomically(path, &bytes))
        .map_err(|error| {
            CliError::new(
                Failure::LocalState,
                format!("cannot write {}: {error}", path.display()),
            )
        })
}

fn read_journal(path: &Path) -> Result<Journal, CliError> {
    read_json_or(path, || Journal {
        schema_version: JOURNAL_SCHEMA_VERSION,
        entries: BTreeMap::new(),
    })
}

/// Records applied changes and forgets reverted checks. A change already
/// recorded for the same thing keeps its original `previous` value, so a
/// revert always returns to the state before the first `prepare`.
fn update_journal(journal: &mut Journal, results: &[FixResult], now: Timestamp) {
    for result in results {
        match &result.outcome {
            FixOutcome::Applied { changes } => {
                let entry =
                    journal
                        .entries
                        .entry(result.id.clone())
                        .or_insert_with(|| JournalEntry {
                            applied_at: now,
                            by_version: env!("CARGO_PKG_VERSION").to_owned(),
                            changes: Vec::new(),
                        });
                for change in changes {
                    if !entry
                        .changes
                        .iter()
                        .any(|known| known.key() == change.key())
                    {
                        entry.changes.push(change.clone());
                    }
                }
            }
            FixOutcome::Reverted => {
                journal.entries.remove(&result.id);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Asking the person
// ---------------------------------------------------------------------------

/// A yes/no question to the person running the command, when there is one.
pub trait Prompt {
    /// `None` when nobody can be asked.
    fn confirm(&mut self, question: &str) -> Option<bool>;
}

/// Nobody to ask: the daemon, the TUI's one-key fix, a script.
pub struct NoPrompt;

impl Prompt for NoPrompt {
    fn confirm(&mut self, _: &str) -> Option<bool> {
        None
    }
}

/// A terminal: the question on `err`, the answer from `input`.
pub struct TerminalPrompt<'a> {
    pub input: &'a mut dyn BufRead,
    pub err: &'a mut dyn Write,
}

impl Prompt for TerminalPrompt<'_> {
    fn confirm(&mut self, question: &str) -> Option<bool> {
        let _ = write!(self.err, "{question} [y/N] ");
        let _ = self.err.flush();
        let mut answer = String::new();
        self.input.read_line(&mut answer).ok()?;
        Some(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }
}

/// What the person allowed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Consent {
    pub assume_yes: bool,
    pub allow_av_exclusion: bool,
    pub allow_developer_mode: bool,
}

impl Consent {
    fn grants(&self, flag: &str) -> bool {
        match flag {
            ALLOW_AV_EXCLUSION => self.allow_av_exclusion,
            ALLOW_DEVELOPER_MODE => self.allow_developer_mode,
            _ => false,
        }
    }
}

/// Which fixes to apply, and which were held back and why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub apply: Vec<&'static str>,
    pub held: Vec<(&'static str, String)>,
}

/// Chooses the fixes to apply from a report.
///
/// A fix that lowers security is included only with its flag or an explicit
/// yes on a terminal; everything else is included and then confirmed as a
/// batch, unless `--yes`.
pub fn plan(report: &Report, only: &[String], consent: &Consent, prompt: &mut dyn Prompt) -> Plan {
    let mut plan = Plan::default();
    for finding in report
        .findings
        .iter()
        .filter(|finding| finding.wants_fix())
        .filter(|finding| only.is_empty() || only.iter().any(|id| id == finding.id))
    {
        let fix = finding.fix.as_ref().expect("wants_fix implies a fix");
        if let Some(flag) = fix.consent_flag
            && !consent.grants(flag)
        {
            let question = format!(
                "{}: {} -- this lowers security. Apply it?",
                finding.id, fix.action
            );
            match prompt.confirm(&question) {
                Some(true) => {}
                Some(false) => {
                    plan.held.push((finding.id, "declined".into()));
                    continue;
                }
                None => {
                    plan.held.push((
                        finding.id,
                        format!("lowers security; pass {flag} to apply it"),
                    ));
                    continue;
                }
            }
        }
        plan.apply.push(finding.id);
    }
    plan
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// `host doctor [--json]`. Exits [`Failure::HostUnfit`] when a required check
/// fails, after printing the whole report.
///
/// # Errors
/// [`Failure::HostUnfit`], or the local-state failures of reading the setup.
pub fn doctor(
    context: &Context,
    args: &HostDoctorArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this host check");
    let setup = setup(context, Perspective::Operator, None)?;
    let report = evaluate(&setup, &SystemFacts);
    if args.json {
        serde_json::to_writer_pretty(&mut *out, &report)
            .map_err(|error| io::Error::other(error.to_string()))
            .and_then(|()| writeln!(out))
            .map_err(failed)?;
    } else {
        write_report(out, &report).map_err(failed)?;
    }
    unfit_failure(&report)
}

fn unfit_failure(report: &Report) -> Result<(), CliError> {
    let failing = report.required_failing();
    if failing.is_empty() {
        return Ok(());
    }
    Err(CliError::with_remedy(
        Failure::HostUnfit,
        format!(
            "required host check(s) fail: {}; the daemon starts no runner until they pass",
            failing.join(", ")
        ),
        "runner-manager host prepare",
    ))
}

fn known_ids(ids: &[String]) -> Result<(), CliError> {
    if let Some(unknown) = ids.iter().find(|id| check(id).is_none()) {
        let known: Vec<&str> = CHECKS.iter().map(|check| check.id).collect();
        return Err(CliError::with_remedy(
            Failure::InvalidArgument,
            format!(
                "{unknown:?} is not a host check; the checks are {}",
                known.join(", ")
            ),
            "runner-manager host doctor",
        ));
    }
    Ok(())
}

fn describe_result(result: &FixResult) -> String {
    match &result.outcome {
        FixOutcome::Applied { changes } => format!(
            "applied: {}",
            changes
                .iter()
                .map(Change::describe)
                .collect::<Vec<_>>()
                .join("; ")
        ),
        FixOutcome::AlreadyDone => "nothing to change".into(),
        FixOutcome::Reverted => "reverted".into(),
        FixOutcome::Failed { error } => format!("failed: {error}"),
        FixOutcome::NotAttempted { reason } => format!("not attempted: {reason}"),
    }
}

/// Everything `host prepare`, `service install` and the TUI share.
pub struct PrepareRun<'a> {
    pub context: &'a Context,
    pub setup: HostSetup,
    pub facts: &'a dyn HostFacts,
    pub actions: &'a dyn HostActions,
    pub elevator: &'a dyn Elevator,
    pub prompt: &'a mut dyn Prompt,
    pub consent: Consent,
}

/// The outcome of a prepare run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareOutcome {
    pub results: Vec<FixResult>,
    pub held: Vec<(&'static str, String)>,
    pub after: Report,
    /// `true` when nothing was applied because the batch was not confirmed.
    pub cancelled: bool,
}

/// Plans, confirms, applies, journals and re-probes.
///
/// # Errors
/// [`Failure::InvalidArgument`] for an unknown id, or a non-interactive run
/// without `--yes`; [`Failure::LocalState`] when the journal cannot be written.
pub fn prepare(
    run: PrepareRun<'_>,
    only: &[String],
    out: &mut dyn Write,
) -> Result<PrepareOutcome, CliError> {
    known_ids(only)?;
    let failed = write_failed("this host preparation");
    let before = evaluate(&run.setup, run.facts);
    let plan = plan(&before, only, &run.consent, run.prompt);
    if plan.apply.is_empty() {
        writeln!(out, "Nothing to apply.").map_err(failed)?;
    } else {
        writeln!(out, "Host prepare will apply:").map_err(failed)?;
        for id in &plan.apply {
            let fix = fix(id).expect("planned ids have fixes");
            let admin = if fix.needs_admin && !run.facts.elevated() {
                " (administrator)"
            } else {
                ""
            };
            writeln!(out, "  {id}  {}{admin}", fix.action).map_err(failed)?;
        }
    }
    for (id, reason) in &plan.held {
        writeln!(out, "  held back: {id} ({reason})").map_err(failed)?;
    }
    out.flush().map_err(failed)?;
    if plan.apply.is_empty() {
        return Ok(PrepareOutcome {
            results: Vec::new(),
            held: plan.held,
            after: before,
            cancelled: false,
        });
    }
    if !run.consent.assume_yes {
        let question = format!("Apply {} change(s)?", plan.apply.len());
        match run.prompt.confirm(&question) {
            Some(true) => {}
            Some(false) => {
                writeln!(out, "Nothing was changed.").map_err(failed)?;
                return Ok(PrepareOutcome {
                    results: Vec::new(),
                    held: plan.held,
                    after: before,
                    cancelled: true,
                });
            }
            None => {
                return Err(CliError::with_remedy(
                    Failure::InvalidArgument,
                    "host prepare changes machine settings and there is no terminal to confirm \
                     on; nothing was changed",
                    "runner-manager host prepare --yes",
                ));
            }
        }
    }
    if !run.facts.elevated() && plan.apply.iter().any(|id| fix_needs_admin(id)) {
        writeln!(
            out,
            "Asking for administrator rights once for the changes that need them..."
        )
        .map_err(failed)?;
        out.flush().map_err(failed)?;
    }
    let results = apply_and_report(
        run.context,
        ElevatedRequest {
            setup: run.setup.clone(),
            apply: plan.apply.iter().map(|id| (*id).to_owned()).collect(),
            revert: Vec::new(),
        },
        (run.facts, run.actions, run.elevator),
        out,
    )?;
    let after = evaluate(&run.setup, run.facts);
    Ok(PrepareOutcome {
        results,
        held: plan.held,
        after,
        cancelled: false,
    })
}

/// Carries out `request` (elevating what needs it), journals what changed,
/// and prints one line per check.
fn apply_and_report(
    context: &Context,
    request: ElevatedRequest,
    (facts, actions, elevator): (&dyn HostFacts, &dyn HostActions, &dyn Elevator),
    out: &mut dyn Write,
) -> Result<Vec<FixResult>, CliError> {
    let results = execute(request, facts, actions, elevator);
    if results
        .iter()
        .any(|r| matches!(r.outcome, FixOutcome::Applied { .. } | FixOutcome::Reverted))
    {
        let path = journal_path(context);
        let mut journal = read_journal(&path)?;
        update_journal(&mut journal, &results, context.clock().now());
        write_json(&path, &journal)?;
    }
    for result in &results {
        writeln!(out, "  {}  {}", result.id, describe_result(result))
            .map_err(write_failed("this host preparation"))?;
    }
    Ok(results)
}

/// `host prepare [--yes] [--only ID]... [--allow-…] | --revert ID...`.
///
/// # Errors
/// See [`prepare`]; [`Failure::HostUnfit`] when a required check still fails
/// afterwards; [`Failure::NotFound`] for a revert nothing was recorded for.
pub fn prepare_command(
    context: &Context,
    args: &HostPrepareArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this host preparation");
    let terminal = io::stdin().is_terminal() && io::stderr().is_terminal();
    let setup = setup(context, Perspective::Operator, None)?;
    let elevator = SystemElevator { terminal };
    if !args.revert.is_empty() {
        return revert_command(context, setup, &args.revert, &elevator, out);
    }
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stderr = io::stderr();
    let mut terminal_prompt = TerminalPrompt {
        input: &mut input,
        err: &mut stderr,
    };
    let mut no_prompt = NoPrompt;
    let prompt: &mut dyn Prompt = if terminal {
        &mut terminal_prompt
    } else {
        &mut no_prompt
    };
    let outcome = prepare(
        PrepareRun {
            context,
            setup,
            facts: &SystemFacts,
            actions: &SystemActions,
            elevator: &elevator,
            prompt,
            consent: Consent {
                assume_yes: args.yes,
                allow_av_exclusion: args.allow_av_exclusion,
                allow_developer_mode: args.allow_developer_mode,
            },
        },
        &args.only,
        out,
    )?;
    writeln!(out).map_err(failed)?;
    write_report(out, &outcome.after).map_err(failed)?;
    unfit_failure(&outcome.after)
}

fn revert_command(
    context: &Context,
    setup: HostSetup,
    ids: &[String],
    elevator: &dyn Elevator,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    known_ids(ids)?;
    let journal = read_journal(&journal_path(context))?;
    let mut revert = Vec::new();
    for id in ids {
        let Some(entry) = journal.entries.get(id) else {
            return Err(CliError::with_remedy(
                Failure::NotFound,
                format!(
                    "host prepare has recorded no change for {id} on this host, so there is \
                     nothing to revert"
                ),
                "runner-manager host doctor",
            ));
        };
        revert.push((id.clone(), entry.changes.clone()));
    }
    let results = apply_and_report(
        context,
        ElevatedRequest {
            setup,
            apply: Vec::new(),
            revert,
        },
        (&SystemFacts, &SystemActions, elevator),
        out,
    )?;
    if results.iter().all(|r| r.outcome == FixOutcome::Reverted) {
        Ok(())
    } else {
        Err(CliError::new(
            Failure::Unclassified,
            "not every change could be reverted; the journal still records the rest",
        ))
    }
}

/// `host required-tools [--set a,b | --clear]`.
///
/// # Errors
/// [`Failure::InvalidArgument`] for a name that is not a bare command;
/// [`Failure::LocalState`] when the file cannot be read or written.
pub fn required_tools_command(
    context: &Context,
    args: &HostRequiredToolsArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("the required tools");
    let path = required_tools_path(context);
    if args.clear {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(CliError::new(
                    Failure::LocalState,
                    format!("cannot remove {}: {error}", path.display()),
                ));
            }
        }
    } else if let Some(tools) = &args.set {
        let mut list: Vec<String> = Vec::new();
        for tool in tools
            .iter()
            .map(|tool| tool.trim())
            .filter(|tool| !tool.is_empty())
        {
            validate_tool(tool)?;
            if !list.iter().any(|known| known == tool) {
                list.push(tool.to_owned());
            }
        }
        write_json(
            &path,
            &RequiredToolsFile {
                schema_version: REQUIRED_TOOLS_SCHEMA_VERSION,
                tools: list,
            },
        )?;
    }
    let tools = required_tools(context)?;
    writeln!(out, "Required tools").map_err(failed)?;
    writeln!(
        out,
        "  tools     {}",
        if tools.is_empty() {
            "none".to_owned()
        } else {
            tools.join(", ")
        }
    )
    .map_err(failed)?;
    writeln!(out, "  file      {}", path.display()).map_err(failed)?;
    writeln!(
        out,
        "  effect    the daemon starts no runner while one of them is missing from the runners' PATH"
    )
    .map_err(failed)
}

/// The elevated copy: reads the plan from its own command line, carries it
/// out, writes the results, and exits. Opens no database and no log, because
/// as root on macOS either would leave files the invoking account cannot
/// write.
#[must_use]
pub fn run_elevated_child(request: &str, result: &Path) -> ExitCode {
    let request: ElevatedRequest = match serde_json::from_str(request) {
        Ok(request) => request,
        Err(_) => return ExitCode::from(2),
    };
    let results = run_request(&request, &SystemFacts, &SystemActions);
    match serde_json::to_string(&results)
        .map_err(io::Error::other)
        .and_then(|text| std::fs::write(result, text))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(2),
    }
}

// ---------------------------------------------------------------------------
// Where it runs automatically
// ---------------------------------------------------------------------------

/// A failing check, as `status`, `service status` and the TUI show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingSummary {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub remedy: Option<String>,
    /// Whether `host prepare` can fix it.
    pub fixable: bool,
    pub needs_admin: bool,
    pub consent_flag: Option<String>,
}

/// The daemon's refusal, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostUnfitSummary {
    pub since: Timestamp,
    pub checks: Vec<String>,
}

/// The `doctor` block of `status --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorSummary {
    /// How many checks were evaluated; `0` when the doctor was skipped.
    pub checked: usize,
    /// Required and recommended checks that fail.
    pub failing: Vec<FindingSummary>,
    /// Checks that could not be answered.
    pub unknown: Vec<String>,
    /// The daemon's recorded refusal to start runners, if any.
    pub daemon_host_unfit: Option<HostUnfitSummary>,
}

impl DoctorSummary {
    fn of(report: Option<&Report>, context: &Context) -> Self {
        let findings = report.map_or(&[][..], |report| report.findings.as_slice());
        Self {
            checked: findings.len(),
            failing: findings
                .iter()
                .filter(|finding| finding.needs_attention())
                .map(|finding| FindingSummary {
                    id: finding.id.to_owned(),
                    severity: finding.severity,
                    title: finding.title.to_owned(),
                    detail: finding.detail.clone(),
                    remedy: finding.remedy.clone(),
                    fixable: finding.fix.is_some(),
                    needs_admin: finding.fix.as_ref().is_some_and(|fix| fix.needs_admin),
                    consent_flag: finding
                        .fix
                        .as_ref()
                        .and_then(|fix| fix.consent_flag)
                        .map(str::to_owned),
                })
                .collect(),
            unknown: findings
                .iter()
                .filter(|finding| {
                    finding.status == Status::Unknown && finding.severity != Severity::Info
                })
                .map(|finding| finding.id.to_owned())
                .collect(),
            daemon_host_unfit: host_fitness::host_unfit(context.paths())
                .ok()
                .flatten()
                // A running daemon re-stamps the record every recheck, so one
                // it has not touched for several is left behind by a daemon
                // that stopped (or was uninstalled) while refusing, not a
                // refusal in force.
                .filter(|record| {
                    (context.clock().now() - record.checked_at)
                        .to_std()
                        .is_ok_and(|age| age <= HOST_UNFIT_RECORD_FRESH)
                })
                .map(|record| HostUnfitSummary {
                    since: record.since,
                    checks: record.checks,
                }),
        }
    }

    /// One line for `status` and `service status`.
    #[must_use]
    pub fn line(&self) -> String {
        if self.checked == 0 {
            return "not checked".to_owned();
        }
        let required = self
            .failing
            .iter()
            .filter(|finding| finding.severity == Severity::Required)
            .count();
        let recommended = self.failing.len() - required;
        if self.failing.is_empty() {
            return format!("ok ({} checks)", self.checked);
        }
        let ids: Vec<&str> = self
            .failing
            .iter()
            .map(|finding| finding.id.as_str())
            .collect();
        format!(
            "{required} required, {recommended} recommended failing ({}); runner-manager host doctor",
            ids.join(", ")
        )
    }
}

/// The doctor summary for `status`, from values `status` already read.
#[must_use]
pub fn status_summary(
    context: &Context,
    host: Option<&Host>,
    policies: &[ScalePolicy],
    runner_root: &HostRoot,
) -> DoctorSummary {
    if std::env::var_os(SKIP_DOCTOR_VARIABLE).is_some() {
        return DoctorSummary::of(None, context);
    }
    let setup = setup_from_parts(
        context,
        Perspective::Operator,
        host,
        policies,
        runner_root,
        None,
    );
    DoctorSummary::of(Some(&evaluate(&setup, &SystemFacts)), context)
}

/// A summary with no checks run yet, still carrying the daemon's recorded
/// refusal.
#[must_use]
pub fn pending_summary(context: &Context) -> DoctorSummary {
    DoctorSummary::of(None, context)
}

/// The doctor summary read fresh from this host's configuration, for a
/// caller that has nothing to hand it: `service status`, and the TUI's own
/// doctor thread. `Err` when the configuration could not be read.
///
/// # Errors
/// The local-state failure of reading the configuration.
pub fn current_summary(context: &Context) -> Result<DoctorSummary, CliError> {
    let setup = setup(context, Perspective::Operator, None)?;
    Ok(DoctorSummary::of(
        Some(&evaluate(&setup, &SystemFacts)),
        context,
    ))
}

/// The doctor summary for `service status`.
#[must_use]
pub fn service_status_line(context: &Context) -> String {
    current_summary(context).map_or_else(
        |error| format!("not checked ({error})"),
        |summary| summary.line(),
    )
}

/// Run by `service install` before it registers anything: reports the
/// checks that matter for the account the service is about to run as, and on
/// a terminal offers to fix them.
///
/// Never fails the install: a host that is not ready yet can still have its
/// service installed, and the daemon refuses runners until it is.
///
/// # Errors
/// Only when `out` cannot be written.
pub fn before_service_install(
    context: &Context,
    start_mode: StartMode,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this service installation");
    let binary = std::env::current_exe().unwrap_or_default();
    let Ok(setup) = setup(
        context,
        Perspective::Operator,
        Some(ServiceSetup {
            start_mode,
            binary,
            definition_path: None,
            label: super::service::identity().launchd_label(),
            running: None,
        }),
    ) else {
        return Ok(());
    };
    let report = evaluate(&setup, &SystemFacts);
    let attention: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.needs_attention())
        .collect();
    if attention.is_empty() {
        return Ok(());
    }
    writeln!(out, "Host checks for a {start_mode} service").map_err(failed)?;
    for finding in &attention {
        writeln!(out, "  {}", finding.line(0)).map_err(failed)?;
    }
    let interactive = io::stdin().is_terminal() && io::stderr().is_terminal();
    let fixable = report.findings.iter().any(Finding::wants_fix);
    if interactive && fixable {
        // The offer goes to stderr: `out` is buffered for decoration and a
        // question nobody can see is not an offer.
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let mut stderr = io::stderr();
        let mut prompt = TerminalPrompt {
            input: &mut input,
            err: &mut stderr,
        };
        if prompt.confirm("Fix what can be fixed before installing?") == Some(true) {
            let mut err = io::stderr();
            let _ = prepare(
                PrepareRun {
                    context,
                    setup,
                    facts: &SystemFacts,
                    actions: &SystemActions,
                    elevator: &SystemElevator { terminal: true },
                    prompt: &mut prompt,
                    consent: Consent {
                        assume_yes: true,
                        ..Consent::default()
                    },
                },
                &[],
                &mut err,
            );
            return Ok(());
        }
    }
    writeln!(
        out,
        "  next  runner-manager host prepare (asks for administrator rights only if needed)"
    )
    .map_err(failed)?;
    writeln!(out).map_err(failed)
}

/// The TUI's one-key fix: applies the fixes for `checks` -- the ones the
/// dialog named, never another -- that the person consented to, asking for
/// administrator rights through the system's own dialog, and returns one line
/// describing what happened.
#[must_use]
pub fn prepare_from_tui(
    context: &Context,
    checks: &[String],
    allow_security_tradeoffs: bool,
) -> String {
    // An empty `only` means every check to `prepare`; here it means none.
    if checks.is_empty() {
        return "Host prepare: nothing was chosen to fix.".into();
    }
    let setup = match setup(context, Perspective::Operator, None) {
        Ok(setup) => setup,
        Err(error) => return format!("host prepare could not start: {error}"),
    };
    let mut sink = Vec::new();
    match prepare(
        PrepareRun {
            context,
            setup,
            facts: &SystemFacts,
            actions: &SystemActions,
            elevator: &SystemElevator { terminal: false },
            prompt: &mut NoPrompt,
            consent: Consent {
                assume_yes: true,
                allow_av_exclusion: allow_security_tradeoffs,
                allow_developer_mode: allow_security_tradeoffs,
            },
        },
        checks,
        &mut sink,
    ) {
        Ok(outcome) => tui_summary(&outcome),
        Err(error) => format!("host prepare failed: {error}"),
    }
}

fn tui_summary(outcome: &PrepareOutcome) -> String {
    let count = |predicate: fn(&FixOutcome) -> bool| {
        outcome
            .results
            .iter()
            .filter(|r| predicate(&r.outcome))
            .count()
    };
    let applied = count(|o| matches!(o, FixOutcome::Applied { .. } | FixOutcome::AlreadyDone));
    let mut parts = vec![format!("{applied} fixed")];
    let not_done: Vec<String> = outcome
        .results
        .iter()
        .filter_map(|r| match &r.outcome {
            FixOutcome::Failed { error } => Some(format!("{}: {error}", r.id)),
            FixOutcome::NotAttempted { reason } => Some(format!("{}: {reason}", r.id)),
            _ => None,
        })
        .collect();
    if !not_done.is_empty() {
        parts.push(format!("not fixed: {}", not_done.join("; ")));
    }
    if !outcome.held.is_empty() {
        let held: Vec<&str> = outcome.held.iter().map(|(id, _)| *id).collect();
        parts.push(format!("held back: {}", held.join(", ")));
    }
    let remaining = outcome
        .after
        .findings
        .iter()
        .filter(|f| f.needs_attention())
        .count();
    parts.push(format!("{remaining} still need attention"));
    format!("Host prepare: {}.", parts.join("; "))
}

/// What the daemon's preflight found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DaemonVerdict {
    /// Failing required checks: while this is non-empty no runner starts.
    pub required: Vec<String>,
    /// Failing recommended checks, for the log.
    pub recommended: Vec<String>,
}

/// The daemon's preflight: evaluates every check from the daemon's own point
/// of view, off the runtime thread, and records or clears the refusal `status`
/// and the TUI read. Never prompts, and never refuses on a check it could not
/// evaluate.
///
/// # Errors
/// A description of why the checks could not run at all; the caller then
/// holds nothing back.
pub async fn daemon_preflight(context: &Context) -> Result<DaemonVerdict, String> {
    let setup = setup(context, Perspective::Daemon, None).map_err(|error| error.to_string())?;
    let report = tokio::task::spawn_blocking(move || evaluate(&setup, &SystemFacts))
        .await
        .map_err(|error| error.to_string())?;
    let verdict = DaemonVerdict {
        required: report.required_failing(),
        recommended: report
            .with(Severity::Recommended, Status::Fail)
            .map(|f| f.id.to_owned())
            .collect(),
    };
    let recorded = if verdict.required.is_empty() {
        host_fitness::clear_host_unfit(context.paths())
    } else {
        host_fitness::record_host_unfit(context.paths(), &verdict.required, context.clock().now())
    };
    // The refusal itself does not depend on the record; only what `status`
    // can show does.
    if let Err(error) = recorded {
        tracing::warn!(
            event = "host_unfit_unrecorded",
            "the host-fitness record could not be written: {error}"
        );
    }
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;

    /// A table of facts. Anything not set answers "absent".
    #[derive(Default)]
    struct Facts {
        elevated: bool,
        dwords: HashMap<RegValue, Result<Option<u32>, String>>,
        strings: HashMap<RegValue, Option<String>>,
        exclusions: Option<Vec<String>>,
        git: Option<PathBuf>,
        git_values: RefCell<HashMap<String, String>>,
        symlinks: bool,
        tools: Vec<&'static str>,
        files: Vec<PathBuf>,
        memory: Option<u64>,
        cores: usize,
        /// Volumes Spotlight indexes; any other volume answers "disabled".
        indexed: Vec<PathBuf>,
        /// Volumes Spotlight gives no answer for.
        unanswered: Vec<PathBuf>,
        mounts: HashMap<PathBuf, PathBuf>,
        /// Directories that do not answer.
        hung: Vec<PathBuf>,
        process_type: Option<String>,
        throttled: usize,
        credential: Option<CredentialProbe>,
        power: Option<BTreeMap<String, u32>>,
        unattended: Option<UnattendedLogin>,
    }

    impl HostFacts for Facts {
        fn elevated(&self) -> bool {
            self.elevated
        }
        fn dword(&self, value: RegValue) -> Result<Option<u32>, String> {
            self.dwords.get(&value).cloned().unwrap_or(Ok(None))
        }
        fn string(&self, value: RegValue) -> Result<Option<String>, String> {
            Ok(self.strings.get(&value).cloned().flatten())
        }
        fn defender_exclusions(&self) -> Result<Option<Vec<String>>, String> {
            Ok(self.exclusions.clone())
        }
        fn git_system_value(&self, _: &Path, name: &str) -> Result<Option<String>, String> {
            Ok(self.git_values.borrow().get(name).cloned())
        }
        fn symlink_allowed(&self, _: &Path) -> Result<bool, String> {
            Ok(self.symlinks)
        }
        fn find_tool(&self, tool: &str, _: Option<&str>) -> Option<PathBuf> {
            if tool == "git" {
                return self.git.clone();
            }
            self.tools
                .contains(&tool)
                .then(|| PathBuf::from(format!("/bin/{tool}")))
        }
        fn file_exists(&self, path: &Path) -> bool {
            self.files.iter().any(|file| file == path)
        }
        fn memory_bytes(&self) -> Option<u64> {
            self.memory
        }
        fn cpu_count(&self) -> usize {
            self.cores
        }
        fn spotlight_indexing(&self, volume: &Path) -> Result<Option<bool>, String> {
            if self.unanswered.iter().any(|v| v == volume) {
                return Ok(None);
            }
            Ok(Some(self.indexed.iter().any(|v| v == volume)))
        }
        fn directory_responds(&self, directory: &Path) -> host_fitness::Responsiveness {
            if self.hung.iter().any(|hung| hung == directory) {
                host_fitness::Responsiveness::Hung
            } else {
                host_fitness::Responsiveness::Responds
            }
        }
        fn mount_point(&self, path: &Path) -> Option<PathBuf> {
            self.mounts.get(path).cloned()
        }
        fn launchd_process_type(&self, _: &Path) -> Result<Option<String>, String> {
            Ok(self.process_type.clone())
        }
        fn throttled_runner_processes(&self) -> Result<usize, String> {
            Ok(self.throttled)
        }
        fn service_credential(
            &self,
            _: &Path,
            _: Option<&Path>,
        ) -> Result<CredentialProbe, String> {
            self.credential.clone().ok_or_else(|| "no answer".into())
        }
        fn power_settings(&self) -> Result<Option<BTreeMap<String, u32>>, String> {
            Ok(self.power.clone())
        }
        fn unattended_login(&self) -> Option<UnattendedLogin> {
            self.unattended.clone()
        }
    }

    /// Records every write, and applies git writes to the facts.
    #[derive(Default)]
    struct Actions<'a> {
        log: RefCell<Vec<String>>,
        git: Option<&'a Facts>,
    }

    impl HostActions for Actions<'_> {
        fn set_dword(&self, value: RegValue, data: Option<u32>) -> Result<(), String> {
            self.log
                .borrow_mut()
                .push(format!("dword {value:?}={data:?}"));
            Ok(())
        }
        fn set_string(&self, value: RegValue, data: Option<&str>) -> Result<(), String> {
            self.log
                .borrow_mut()
                .push(format!("string {value:?}={data:?}"));
            Ok(())
        }
        fn set_git_system_value(
            &self,
            _: &Path,
            name: &str,
            value: Option<&str>,
        ) -> Result<(), String> {
            self.log.borrow_mut().push(format!("git {name}={value:?}"));
            if let Some(facts) = self.git {
                let mut values = facts.git_values.borrow_mut();
                match value {
                    Some(value) => values.insert(name.to_owned(), value.to_owned()),
                    None => values.remove(name),
                };
            }
            Ok(())
        }
        fn add_defender_exclusions(&self, paths: &[String]) -> Result<(), String> {
            self.log
                .borrow_mut()
                .push(format!("defender add {}", paths.join("|")));
            Ok(())
        }
        fn remove_defender_exclusions(&self, paths: &[String]) -> Result<(), String> {
            self.log
                .borrow_mut()
                .push(format!("defender remove {}", paths.join("|")));
            Ok(())
        }
        fn set_spotlight(&self, volume: &Path, enabled: bool) -> Result<(), String> {
            self.log
                .borrow_mut()
                .push(format!("spotlight {} {enabled}", volume.display()));
            Ok(())
        }
        fn set_power_setting(&self, name: &str, value: u32) -> Result<(), String> {
            self.log.borrow_mut().push(format!("pmset {name} {value}"));
            Ok(())
        }
    }

    fn windows_setup() -> HostSetup {
        HostSetup {
            os: HostOs::Windows,
            perspective: Perspective::Operator,
            service: Some(ServiceSetup {
                start_mode: StartMode::Boot,
                binary: PathBuf::from(r"C:\rm\runner-manager.exe"),
                definition_path: None,
                label: "rm".into(),
                running: None,
            }),
            runner_roots: vec![PathBuf::from(r"C:\rman")],
            capacity: 2,
            required_tools: Vec::new(),
            required_tools_error: None,
            runner_path: Some(r"C:\Windows\System32".into()),
            probe_dir: PathBuf::from(r"C:\state"),
            data_root: None,
            service_contact_age_secs: None,
            service_credential_unreadable: false,
            own_keychain_readable: None,
            launches_blocked: None,
            service_account: None,
            service_home: None,
        }
    }

    fn macos_setup() -> HostSetup {
        HostSetup {
            os: HostOs::Macos,
            service: Some(ServiceSetup {
                start_mode: StartMode::Login,
                binary: PathBuf::from("/Users/me/rm/runner-manager"),
                definition_path: Some(PathBuf::from("/Users/me/Library/LaunchAgents/rm.plist")),
                label: "io.github.IvanMurzak.runner-manager".into(),
                running: None,
            }),
            runner_roots: vec![PathBuf::from("/Volumes/NVME/rman")],
            runner_path: Some("/usr/bin".into()),
            probe_dir: PathBuf::from("/tmp/state"),
            service_account: Some("me".into()),
            service_home: Some(PathBuf::from("/Users/me")),
            ..windows_setup()
        }
    }

    fn finding<'a>(report: &'a Report, id: &str) -> &'a Finding {
        report
            .findings
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("{id} missing"))
    }

    fn status_of(setup: &HostSetup, facts: &Facts, id: &str) -> Status {
        finding(&evaluate(setup, facts), id).status
    }

    /// `pmset -g` on the runner Mac that was set up with the defaults.
    const SLEEPY_MAC_PMSET: &str = "System-wide power settings:\n\
                                    Currently in use:\n \
                                    standby              0\n \
                                    Sleep On Power Button 1\n \
                                    autorestart          0\n \
                                    powernap             1\n \
                                    disksleep            10\n \
                                    sleep                1 (sleep prevented by powerd)\n \
                                    womp                 1\n";

    #[test]
    fn power_settings_are_read_the_way_pmset_prints_them() {
        let settings = power_settings_in(SLEEPY_MAC_PMSET);
        assert_eq!(settings.get("sleep"), Some(&1));
        assert_eq!(settings.get("disksleep"), Some(&10));
        assert_eq!(settings.get("autorestart"), Some(&0));
        assert_eq!(settings.get("womp"), Some(&1));
        assert_eq!(settings.get("Sleep On Power Button"), Some(&1));
        assert!(!settings.contains_key("Currently in use:"));
    }

    #[test]
    fn a_mac_that_sleeps_or_stays_off_after_a_power_failure_is_fixed_with_pmset() {
        let setup = macos_setup();
        let mut facts = Facts {
            power: Some(power_settings_in(SLEEPY_MAC_PMSET)),
            ..Facts::default()
        };
        let report = evaluate(&setup, &facts);
        for id in ["macos.sleep", "macos.disk_sleep", "macos.autorestart"] {
            let found = finding(&report, id);
            assert_eq!(found.status, Status::Fail, "{id}");
            assert_eq!(found.severity, Severity::Recommended, "{id}");
            let fix = found.fix.as_ref().expect("fixable");
            assert!(fix.needs_admin, "{id}");
            assert!(fix.consent_flag.is_none(), "{id}");
        }
        assert_eq!(finding(&report, "macos.wake_on_lan").status, Status::Pass);

        let actions = Actions::default();
        for (id, expected) in [
            ("macos.sleep", ("sleep", Some(1), 0)),
            ("macos.disk_sleep", ("disksleep", Some(10), 0)),
            ("macos.autorestart", ("autorestart", Some(0), 1)),
        ] {
            let (name, previous, applied) = expected;
            assert_eq!(
                apply_one(id, &setup, &facts, &actions).outcome,
                FixOutcome::Applied {
                    changes: vec![Change::PowerSetting {
                        name: name.into(),
                        previous,
                        applied,
                    }]
                },
                "{id}"
            );
        }
        assert_eq!(
            *actions.log.borrow(),
            ["pmset sleep 0", "pmset disksleep 0", "pmset autorestart 1"]
        );

        // A revert puts back exactly what was there, and nothing outside the
        // closed set a journal could name.
        let reverting = Actions::default();
        Change::PowerSetting {
            name: "disksleep".into(),
            previous: Some(10),
            applied: 0,
        }
        .revert(&reverting)
        .unwrap();
        assert_eq!(*reverting.log.borrow(), ["pmset disksleep 10"]);
        for tampered in [
            Change::PowerSetting {
                name: "hibernatemode".into(),
                previous: Some(0),
                applied: 3,
            },
            Change::PowerSetting {
                name: "autorestart".into(),
                previous: Some(7),
                applied: 1,
            },
        ] {
            assert!(tampered.revert(&reverting).is_err(), "{tampered:?}");
        }

        facts.power = Some(power_settings_in(
            "Currently in use:\n sleep 0\n disksleep 0\n autorestart 1\n womp 0\n",
        ));
        for id in ["macos.sleep", "macos.disk_sleep", "macos.autorestart"] {
            assert_eq!(status_of(&setup, &facts, id), Status::Pass, "{id}");
        }
        let womp = finding(&evaluate(&setup, &facts), "macos.wake_on_lan").clone();
        assert_eq!((womp.status, womp.severity), (Status::Fail, Severity::Info));
        assert!(!womp.needs_attention(), "wake-on-LAN is optional");
        facts.power = None;
        assert_eq!(
            status_of(&setup, &facts, "macos.sleep"),
            Status::NotApplicable
        );
    }

    #[test]
    fn unattended_login_is_reported_with_its_steps_and_never_fixed() {
        use runner_manager_platform::unattended_login::AutoLogin;
        let id = "macos.unattended_login";
        let mut setup = macos_setup();
        let mut facts = Facts {
            unattended: Some(UnattendedLogin {
                auto_login: AutoLogin::As("me".into()),
                filevault_on: Some(false),
            }),
            ..Facts::default()
        };
        assert_eq!(status_of(&setup, &facts, id), Status::Pass);

        facts.unattended = Some(UnattendedLogin {
            auto_login: AutoLogin::Off,
            filevault_on: Some(false),
        });
        let report = evaluate(&setup, &facts);
        let off = finding(&report, id);
        assert_eq!(off.status, Status::Fail);
        assert!(off.fix.is_none(), "automatic login is never changed for you");
        assert!(off.detail.contains("waits for me to sign in"), "{}", off.detail);
        assert!(
            off.remedy
                .as_deref()
                .unwrap()
                .contains("System Settings > Users & Groups"),
            "{off:?}"
        );

        facts.unattended = Some(UnattendedLogin {
            auto_login: AutoLogin::As("me".into()),
            filevault_on: Some(true),
        });
        let report = evaluate(&setup, &facts);
        let locked = finding(&report, id);
        assert_eq!(locked.status, Status::Fail);
        assert!(locked.fix.is_none(), "FileVault is never changed for you");
        assert!(
            locked
                .remedy
                .as_deref()
                .unwrap()
                .contains("Privacy & Security > FileVault"),
            "{locked:?}"
        );

        setup.service = None;
        assert_eq!(status_of(&setup, &facts, id), Status::NotApplicable);
    }

    #[test]
    fn a_runner_root_with_a_space_or_inside_the_service_home_is_reported() {
        let id = "macos.runner_root_location";
        let mut setup = macos_setup();
        let facts = Facts::default();
        assert_eq!(status_of(&setup, &facts, id), Status::Pass);

        // The default root on a login-mode Mac: both problems at once.
        setup.runner_roots = vec![PathBuf::from(
            "/Users/me/Library/Application Support/io.github.IvanMurzak.runner-manager/runtime",
        )];
        let report = evaluate(&setup, &facts);
        let found = finding(&report, id);
        assert_eq!(found.status, Status::Fail);
        assert!(found.detail.contains("has a space"), "{}", found.detail);
        assert!(found.detail.contains("inside /Users/me"), "{}", found.detail);
        let remedy = found.remedy.as_deref().unwrap();
        assert!(remedy.contains(MACOS_RUNNER_ROOT), "{remedy}");
        assert!(!MACOS_RUNNER_ROOT.contains(' '));

        setup.runner_roots = vec![PathBuf::from("/Users/me/rman.noindex")];
        let found = finding(&evaluate(&setup, &facts), id).clone();
        assert_eq!(found.status, Status::Fail);
        assert!(!found.detail.contains("has a space"), "{}", found.detail);

        setup.runner_roots = vec![PathBuf::from(MACOS_RUNNER_ROOT)];
        assert_eq!(status_of(&setup, &facts, id), Status::Pass);
    }

    #[test]
    fn the_spotlight_remedy_names_a_root_with_no_spaces() {
        let mut setup = macos_setup();
        let root = PathBuf::from(
            "/Users/me/Library/Application Support/io.github.IvanMurzak.runner-manager/runtime",
        );
        setup.runner_roots = vec![root.clone()];
        let mut facts = Facts::default();
        facts.mounts.insert(root, PathBuf::from("/System/Volumes/Data"));
        facts.indexed = vec![PathBuf::from("/System/Volumes/Data")];
        let report = evaluate(&setup, &facts);
        let remedy = finding(&report, "macos.spotlight").remedy.clone().unwrap();
        assert!(
            remedy.contains(&format!("--path {MACOS_RUNNER_ROOT})")),
            "{remedy}"
        );
        assert!(!remedy.contains("runtime.noindex"), "{remedy}");
    }

    #[test]
    fn check_ids_are_unique_and_every_security_tradeoff_needs_a_flag() {
        let mut ids: Vec<&str> = CHECKS.iter().map(|c| c.id).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before);
        for id in ["windows.defender_exclusion", "windows.symlink_privilege"] {
            assert!(
                check(id)
                    .unwrap()
                    .fix
                    .as_ref()
                    .unwrap()
                    .consent_flag
                    .is_some(),
                "{id}"
            );
        }
    }

    #[test]
    fn only_this_platforms_checks_are_evaluated() {
        let facts = Facts::default();
        let windows = evaluate(&windows_setup(), &facts);
        assert!(
            windows
                .findings
                .iter()
                .all(|f| f.platform != CheckPlatform::Macos)
        );
        assert!(
            windows
                .findings
                .iter()
                .any(|f| f.id == "windows.long_paths")
        );
        let linux = evaluate(
            &HostSetup {
                os: HostOs::Linux,
                ..windows_setup()
            },
            &facts,
        );
        assert!(
            linux
                .findings
                .iter()
                .all(|f| f.platform == CheckPlatform::Any)
        );
    }

    #[test]
    fn long_paths_pass_only_at_one() {
        let setup = windows_setup();
        let mut facts = Facts::default();
        assert_eq!(
            status_of(&setup, &facts, "windows.long_paths"),
            Status::Fail
        );
        facts.dwords.insert(RegValue::LongPathsEnabled, Ok(Some(0)));
        assert_eq!(
            status_of(&setup, &facts, "windows.long_paths"),
            Status::Fail
        );
        facts.dwords.insert(RegValue::LongPathsEnabled, Ok(Some(1)));
        assert_eq!(
            status_of(&setup, &facts, "windows.long_paths"),
            Status::Pass
        );
        facts
            .dwords
            .insert(RegValue::LongPathsEnabled, Err("access denied".into()));
        assert_eq!(
            status_of(&setup, &facts, "windows.long_paths"),
            Status::Unknown
        );
    }

    #[test]
    fn git_long_paths_reads_the_system_scope_of_the_runners_git() {
        let setup = windows_setup();
        let mut facts = Facts::default();
        assert_eq!(
            status_of(&setup, &facts, "windows.git_long_paths"),
            Status::NotApplicable
        );
        facts.git = Some(PathBuf::from(r"C:\Git\cmd\git.exe"));
        assert_eq!(
            status_of(&setup, &facts, "windows.git_long_paths"),
            Status::Fail
        );
        facts
            .git_values
            .borrow_mut()
            .insert(GIT_LONG_PATHS.into(), "true".into());
        assert_eq!(
            status_of(&setup, &facts, "windows.git_long_paths"),
            Status::Pass
        );
    }

    #[test]
    fn a_defender_exclusion_covers_its_own_path_and_everything_below_it() {
        let roots = vec![
            PathBuf::from(r"C:\rman"),
            PathBuf::from(r"C:\ProgramData\rm\runner-workspaces"),
            PathBuf::from(r"D:\rmanx"),
        ];
        let exclusions = vec![
            r"c:\RMAN\".to_owned(),
            r"C:\ProgramData".to_owned(),
            r"D:\rman".to_owned(),
        ];
        assert_eq!(uncovered_roots(&roots, &exclusions), [r"D:\rmanx"]);
        assert_eq!(uncovered_roots(&roots, &[]).len(), 3);
    }

    #[test]
    fn defender_is_unknown_without_admin_and_not_applicable_when_off() {
        let setup = windows_setup();
        let mut facts = Facts::default();
        assert_eq!(
            status_of(&setup, &facts, "windows.defender_exclusion"),
            Status::Unknown
        );
        facts.exclusions = Some(vec![r"C:\rman".into()]);
        assert_eq!(
            status_of(&setup, &facts, "windows.defender_exclusion"),
            Status::Pass
        );
        facts.exclusions = Some(vec![r"C:\other".into()]);
        assert_eq!(
            status_of(&setup, &facts, "windows.defender_exclusion"),
            Status::Fail
        );
        facts
            .dwords
            .insert(RegValue::DefenderPassiveMode, Ok(Some(1)));
        assert_eq!(
            status_of(&setup, &facts, "windows.defender_exclusion"),
            Status::NotApplicable
        );
    }

    #[test]
    fn symlink_privilege_follows_the_execution_account() {
        let mut setup = windows_setup();
        let mut facts = Facts::default();
        assert_eq!(
            status_of(&setup, &facts, "windows.symlink_privilege"),
            Status::Pass,
            "boot"
        );
        setup.service.as_mut().unwrap().start_mode = StartMode::Login;
        facts.elevated = true;
        assert_eq!(
            status_of(&setup, &facts, "windows.symlink_privilege"),
            Status::Fail,
            "login"
        );
        facts.dwords.insert(RegValue::DeveloperMode, Ok(Some(1)));
        assert_eq!(
            status_of(&setup, &facts, "windows.symlink_privilege"),
            Status::Pass,
            "dev mode"
        );
        facts.dwords.remove(&RegValue::DeveloperMode);
        facts.elevated = false;
        facts.symlinks = true;
        assert_eq!(
            status_of(&setup, &facts, "windows.symlink_privilege"),
            Status::Pass,
            "an unelevated login account that measurably can"
        );
        setup.perspective = Perspective::Daemon;
        setup.service.as_mut().unwrap().start_mode = StartMode::Boot;
        facts.symlinks = false;
        assert_eq!(
            status_of(&setup, &facts, "windows.symlink_privilege"),
            Status::Fail,
            "the daemon measures rather than infers"
        );
    }

    #[test]
    fn execution_policy_defaults_to_restricted_on_a_client_and_respects_group_policy() {
        let setup = windows_setup();
        let mut facts = Facts::default();
        let id = "windows.execution_policy";
        assert_eq!(status_of(&setup, &facts, id), Status::Fail);
        facts
            .strings
            .insert(RegValue::InstallationType, Some("Server".into()));
        assert_eq!(status_of(&setup, &facts, id), Status::Pass);
        facts
            .strings
            .insert(RegValue::InstallationType, Some("Client".into()));
        facts
            .strings
            .insert(RegValue::ExecutionPolicy, Some("RemoteSigned".into()));
        assert_eq!(status_of(&setup, &facts, id), Status::Pass);
        facts.strings.insert(
            RegValue::ExecutionPolicyGroupPolicy,
            Some("AllSigned".into()),
        );
        let report = evaluate(&setup, &facts);
        let managed = finding(&report, id);
        assert_eq!(managed.status, Status::Fail);
        assert!(
            managed.fix.is_none(),
            "a Group Policy setting has no local fix"
        );
    }

    #[test]
    fn pwsh_and_execution_account_report_without_fixing() {
        let mut setup = windows_setup();
        let mut facts = Facts::default();
        assert_eq!(status_of(&setup, &facts, "windows.pwsh"), Status::Fail);
        facts.files.push(PathBuf::from(WINDOWS_PWSH));
        let report = evaluate(&setup, &facts);
        assert!(
            finding(&report, "windows.pwsh")
                .detail
                .contains("not on the runners' PATH")
        );
        facts.tools.push("pwsh");
        assert_eq!(status_of(&setup, &facts, "windows.pwsh"), Status::Pass);
        assert_eq!(
            status_of(&setup, &facts, "windows.execution_account"),
            Status::Pass
        );
        setup.service.as_mut().unwrap().start_mode = StartMode::Login;
        let report = evaluate(&setup, &facts);
        let account = finding(&report, "windows.execution_account");
        assert_eq!(account.status, Status::Fail);
        assert!(
            account
                .remedy
                .as_deref()
                .unwrap()
                .contains("--start-at boot")
        );
        setup.service = None;
        assert_eq!(
            status_of(&setup, &facts, "windows.execution_account"),
            Status::NotApplicable
        );
    }

    #[test]
    fn a_background_launch_agent_or_a_throttled_runner_fails_the_priority_check() {
        let setup = macos_setup();
        let mut facts = Facts::default();
        let id = "macos.launchd_priority";
        facts.process_type = Some(LAUNCHD_PROCESS_TYPE.into());
        assert_eq!(status_of(&setup, &facts, id), Status::Pass);
        facts.process_type = None;
        assert_eq!(
            status_of(&setup, &facts, id),
            Status::Fail,
            "no ProcessType is Standard, below normal priority, as `service status` judges it"
        );
        facts.process_type = Some("Background".into());
        let report = evaluate(&setup, &facts);
        assert_eq!(finding(&report, id).status, Status::Fail);
        assert!(
            finding(&report, id).remedy.as_deref().unwrap().ends_with(
                "launchctl kickstart -k gui/$(id -u)/io.github.IvanMurzak.runner-manager"
            ),
            "{:?}",
            finding(&report, id).remedy
        );
        facts.process_type = Some("Interactive".into());
        facts.throttled = 2;
        assert_eq!(status_of(&setup, &facts, id), Status::Fail);
    }

    #[test]
    fn throttled_runners_are_counted_from_ps_output() {
        let listing = "  4 /Users/me/rman/a/bin/Runner.Listener\n 31 /Users/me/rman/b/bin/Runner.Listener\n  4 /usr/libexec/other\n  4 /x/bin/Runner.Worker\n";
        assert_eq!(throttled_runners_in(listing), 2);
    }

    #[test]
    fn spotlight_is_fixable_only_off_the_startup_volume() {
        let mut setup = macos_setup();
        let mut facts = Facts::default();
        let id = "macos.spotlight";
        assert_eq!(
            status_of(&setup, &facts, id),
            Status::Unknown,
            "a root whose volume cannot be found is not a pass"
        );
        facts.mounts.insert(
            PathBuf::from("/Volumes/NVME/rman"),
            PathBuf::from("/Volumes/NVME"),
        );
        facts.unanswered.push(PathBuf::from("/Volumes/NVME"));
        assert_eq!(
            status_of(&setup, &facts, id),
            Status::Unknown,
            "mdutil's `unknown indexing state` is not a pass"
        );
        facts.unanswered.clear();
        assert_eq!(status_of(&setup, &facts, id), Status::Pass);
        facts.indexed.push(PathBuf::from("/Volumes/NVME"));
        let report = evaluate(&setup, &facts);
        assert_eq!(finding(&report, id).status, Status::Fail);
        assert!(finding(&report, id).fix.is_some());
        let actions = Actions::default();
        let result = apply_one(id, &setup, &facts, &actions);
        assert_eq!(
            result.outcome,
            FixOutcome::Applied {
                changes: vec![Change::SpotlightIndexingOff {
                    volume: PathBuf::from("/Volumes/NVME")
                }]
            }
        );
        setup.runner_roots = vec![PathBuf::from("/Users/me/rman")];
        facts.indexed = vec![PathBuf::from("/System/Volumes/Data")];
        facts.mounts.insert(
            PathBuf::from("/Users/me/rman"),
            PathBuf::from("/System/Volumes/Data"),
        );
        let report = evaluate(&setup, &facts);
        assert!(finding(&report, id).fix.is_none());
        assert!(
            finding(&report, id)
                .remedy
                .as_deref()
                .unwrap()
                .contains(".noindex")
        );
        setup.runner_roots = vec![PathBuf::from("/Users/me/rman.noindex/x")];
        assert_eq!(
            status_of(&setup, &facts, id),
            Status::Pass,
            "a `.noindex` folder is skipped even on an indexed volume"
        );
    }

    #[test]
    fn an_unreadable_keychain_credential_names_the_exact_login_command() {
        let mut setup = macos_setup();
        setup.own_keychain_readable = Some(true);
        let mut facts = Facts {
            credential: Some(CredentialProbe::Unreadable(
                "errSecInteractionNotAllowed".into(),
            )),
            ..Facts::default()
        };
        let report = evaluate(&setup, &facts);
        let keychain = finding(&report, "macos.keychain_credential");
        assert_eq!(keychain.status, Status::Fail);
        let remedy = keychain.remedy.as_deref().unwrap();
        assert!(
            remedy.contains("/Users/me/rm/runner-manager")
                && remedy.contains(" auth login --start-at login")
                && !remedy.contains("sudo"),
            "{remedy}"
        );
        assert_eq!(report.required_failing(), ["macos.keychain_credential"]);

        // A session that cannot read the keychain at all (SSH) is not the
        // service binary's fault: measured on the Mac mini, both binaries
        // answered -25293 over SSH while the daemon was serving jobs.
        setup.own_keychain_readable = Some(false);
        assert_eq!(
            status_of(&setup, &facts, "macos.keychain_credential"),
            Status::Unknown
        );
        // And a service that reached GitHub minutes ago read its credential
        // to do it.
        let recent = HostSetup {
            service_contact_age_secs: Some(120),
            ..setup.clone()
        };
        assert_eq!(
            status_of(&recent, &facts, "macos.keychain_credential"),
            Status::Pass
        );
        facts.credential = Some(CredentialProbe::Readable);
        assert_eq!(
            status_of(&setup, &facts, "macos.keychain_credential"),
            Status::Pass
        );
        let daemon = HostSetup {
            perspective: Perspective::Daemon,
            ..setup
        };
        assert_eq!(
            status_of(&daemon, &facts, "macos.keychain_credential"),
            Status::NotApplicable
        );
    }

    /// The 0.4.33 rollout: right after the binary swap every start of the new
    /// daemon failed with `-25293`, and the check passed on the contact the
    /// *old* daemon had made during its drain, "0 minute(s) ago".
    #[test]
    fn a_contact_made_before_the_binary_was_replaced_proves_nothing() {
        let now = chrono::Utc::now();
        let swapped = now - chrono::Duration::seconds(20);
        let old_daemon_contact = Some(swapped - chrono::Duration::seconds(5));
        assert_eq!(
            current_daemon_contact_age(old_daemon_contact, Some(swapped), now),
            None,
            "the previous binary's contact is not the installed binary's"
        );
        let new_daemon_contact = Some(swapped + chrono::Duration::seconds(10));
        assert_eq!(
            current_daemon_contact_age(new_daemon_contact, Some(swapped), now),
            Some(10)
        );
        assert_eq!(
            current_daemon_contact_age(new_daemon_contact, None, now),
            Some(10),
            "a binary whose time cannot be read does not discard a contact"
        );

        // End to end through the check: the stale contact is gone, so the
        // service binary is asked, and it cannot read the item.
        let mut setup = macos_setup();
        setup.own_keychain_readable = Some(true);
        setup.service_contact_age_secs =
            current_daemon_contact_age(old_daemon_contact, Some(swapped), now);
        let facts = Facts {
            credential: Some(CredentialProbe::Unreadable("-25293".into())),
            ..Facts::default()
        };
        assert_eq!(
            status_of(&setup, &facts, "macos.keychain_credential"),
            Status::Fail
        );
    }

    #[test]
    fn the_daemons_own_unreadable_record_fails_the_check_whatever_else_says() {
        let setup = HostSetup {
            service_credential_unreadable: true,
            service_contact_age_secs: Some(0),
            ..macos_setup()
        };
        let facts = Facts {
            credential: Some(CredentialProbe::Readable),
            ..Facts::default()
        };
        let report = evaluate(&setup, &facts);
        let keychain = finding(&report, "macos.keychain_credential");
        assert_eq!(keychain.status, Status::Fail);
        assert!(
            keychain
                .remedy
                .as_deref()
                .unwrap()
                .contains(" auth login --start-at login"),
            "{keychain:?}"
        );
    }

    #[test]
    fn a_stopped_service_is_not_reported_as_running_at_normal_priority() {
        let mut setup = macos_setup();
        let facts = Facts {
            process_type: Some(LAUNCHD_PROCESS_TYPE.to_string()),
            ..Facts::default()
        };
        setup.service.as_mut().unwrap().running = Some(true);
        assert_eq!(
            status_of(&setup, &facts, "macos.launchd_priority"),
            Status::Pass
        );
        setup.service.as_mut().unwrap().running = Some(false);
        assert_eq!(
            status_of(&setup, &facts, "macos.launchd_priority"),
            Status::Unknown
        );
    }

    #[test]
    fn capacity_is_recommended_from_memory_and_cores() {
        assert_eq!(recommended_capacity(8 * GIB, 8), 2);
        assert_eq!(recommended_capacity(64 * GIB, 16), 16);
        assert_eq!(recommended_capacity(GIB, 4), 1);
        let setup = HostSetup {
            capacity: 10,
            ..macos_setup()
        };
        let facts = Facts {
            memory: Some(8 * GIB),
            cores: 8,
            ..Facts::default()
        };
        let report = evaluate(&setup, &facts);
        let capacity = finding(&report, "host.capacity");
        assert_eq!(capacity.status, Status::Fail);
        assert_eq!(
            capacity.remedy.as_deref(),
            Some("runner-manager host set-capacity 2")
        );
        assert!(
            capacity.fix.is_none(),
            "capacity is never changed automatically"
        );
    }

    /// A hung runner volume is a required failure (the daemon refuses
    /// runners), and the Spotlight check does not call `df` or `mdutil` on it.
    #[test]
    fn a_hung_runner_root_is_unfit_and_spotlight_does_not_touch_it() {
        let setup = macos_setup();
        let mut facts = Facts::default();
        facts.mounts.insert(
            PathBuf::from("/Volumes/NVME/rman"),
            PathBuf::from("/Volumes/NVME"),
        );
        let id = "host.runner_root_responsive";
        assert_eq!(status_of(&setup, &facts, id), Status::Pass);
        assert_eq!(status_of(&setup, &facts, "macos.spotlight"), Status::Pass);

        facts.hung.push(PathBuf::from("/Volumes/NVME/rman"));
        let report = evaluate(&setup, &facts);
        let root = finding(&report, id);
        assert_eq!(root.status, Status::Fail);
        assert!(
            root.detail.starts_with("runner root not responding"),
            "{}",
            root.detail
        );
        assert!(report.required_failing().contains(&id.to_owned()));
        assert_eq!(finding(&report, "macos.spotlight").status, Status::Unknown);
    }

    #[test]
    fn required_tools_fail_by_name() {
        let mut setup = windows_setup();
        let facts = Facts {
            tools: vec!["node"],
            ..Facts::default()
        };
        assert_eq!(
            status_of(&setup, &facts, "host.required_tools"),
            Status::NotApplicable
        );
        setup.required_tools = vec!["node".into(), "pwsh".into()];
        let report = evaluate(&setup, &facts);
        assert_eq!(
            finding(&report, "host.required_tools").detail,
            "not on the runners' PATH: pwsh"
        );
        assert_eq!(report.required_failing(), ["host.required_tools"]);

        // A file that cannot be read is not "none configured".
        setup.required_tools = Vec::new();
        setup.required_tools_error = Some("required-tools.json is not valid".into());
        assert_eq!(
            status_of(&setup, &facts, "host.required_tools"),
            Status::Unknown
        );
    }

    /// Blocked launches fail the doctor with the reason and the remedy, and
    /// never as a Required check: that would make the daemon refuse launches
    /// because launches are refused.
    #[test]
    fn blocked_launches_fail_with_their_remedy_but_never_make_the_host_unfit() {
        let mut setup = windows_setup();
        let facts = Facts::default();
        assert_eq!(status_of(&setup, &facts, "host.launches"), Status::Pass);
        setup.launches_blocked = Some(runner_manager_platform::launch_health::LaunchesBlocked {
            since: chrono::DateTime::from_timestamp(1_790_000_000, 0).unwrap(),
            reason: "a runner launch by process 189 has held the WSL launch fence".into(),
            remedy: "restart the service".into(),
        });
        let report = evaluate(&setup, &facts);
        let launches = finding(&report, "host.launches");
        assert_eq!(launches.status, Status::Fail);
        assert!(
            launches.detail.contains("process 189"),
            "{}",
            launches.detail
        );
        assert_eq!(launches.remedy.as_deref(), Some("restart the service"));
        assert!(
            !report
                .required_failing()
                .contains(&"host.launches".to_owned())
        );
    }

    #[test]
    fn unknown_never_counts_as_unfit() {
        let setup = HostSetup {
            perspective: Perspective::Daemon,
            ..windows_setup()
        };
        struct Broken;
        impl HostFacts for Broken {
            fn elevated(&self) -> bool {
                false
            }
            fn dword(&self, _: RegValue) -> Result<Option<u32>, String> {
                Err("x".into())
            }
            fn string(&self, _: RegValue) -> Result<Option<String>, String> {
                Err("x".into())
            }
            fn defender_exclusions(&self) -> Result<Option<Vec<String>>, String> {
                Err("x".into())
            }
            fn git_system_value(&self, _: &Path, _: &str) -> Result<Option<String>, String> {
                Err("x".into())
            }
            fn symlink_allowed(&self, _: &Path) -> Result<bool, String> {
                Err("x".into())
            }
            fn find_tool(&self, _: &str, _: Option<&str>) -> Option<PathBuf> {
                None
            }
            fn file_exists(&self, _: &Path) -> bool {
                false
            }
            fn memory_bytes(&self) -> Option<u64> {
                None
            }
            fn cpu_count(&self) -> usize {
                1
            }
            fn spotlight_indexing(&self, _: &Path) -> Result<Option<bool>, String> {
                Err("x".into())
            }
            fn directory_responds(&self, _: &Path) -> host_fitness::Responsiveness {
                host_fitness::Responsiveness::Failed("x".into())
            }
            fn mount_point(&self, _: &Path) -> Option<PathBuf> {
                None
            }
            fn launchd_process_type(&self, _: &Path) -> Result<Option<String>, String> {
                Err("x".into())
            }
            fn throttled_runner_processes(&self) -> Result<usize, String> {
                Err("x".into())
            }
            fn service_credential(
                &self,
                _: &Path,
                _: Option<&Path>,
            ) -> Result<CredentialProbe, String> {
                Err("x".into())
            }
        }
        let report = evaluate(&setup, &Broken);
        assert_eq!(
            finding(&report, "windows.symlink_privilege").status,
            Status::Unknown
        );
        assert!(report.required_failing().is_empty());
    }

    struct Scripted {
        answers: Vec<bool>,
        asked: Vec<String>,
    }

    impl Prompt for Scripted {
        fn confirm(&mut self, question: &str) -> Option<bool> {
            self.asked.push(question.to_owned());
            Some(self.answers.remove(0))
        }
    }

    fn report_needing_everything() -> Report {
        let mut setup = windows_setup();
        setup.service.as_mut().unwrap().start_mode = StartMode::Login;
        let facts = Facts {
            elevated: true,
            exclusions: Some(Vec::new()),
            git: Some(PathBuf::from(r"C:\Git\cmd\git.exe")),
            ..Facts::default()
        };
        evaluate(&setup, &facts)
    }

    #[test]
    fn a_security_tradeoff_is_never_planned_without_its_flag_or_a_yes() {
        let report = report_needing_everything();
        let plan_without = plan(
            &report,
            &[],
            &Consent {
                assume_yes: true,
                ..Consent::default()
            },
            &mut NoPrompt,
        );
        assert!(!plan_without.apply.contains(&"windows.defender_exclusion"));
        assert!(!plan_without.apply.contains(&"windows.symlink_privilege"));
        assert!(plan_without.apply.contains(&"windows.long_paths"));
        assert!(
            plan_without
                .held
                .iter()
                .any(|(id, reason)| *id == "windows.defender_exclusion"
                    && reason.contains(ALLOW_AV_EXCLUSION))
        );

        let flagged = plan(
            &report,
            &[],
            &Consent {
                allow_av_exclusion: true,
                ..Consent::default()
            },
            &mut NoPrompt,
        );
        assert!(flagged.apply.contains(&"windows.defender_exclusion"));
        assert!(!flagged.apply.contains(&"windows.symlink_privilege"));

        let mut prompt = Scripted {
            answers: vec![false, true],
            asked: Vec::new(),
        };
        let asked = plan(&report, &[], &Consent::default(), &mut prompt);
        assert_eq!(prompt.asked.len(), 2);
        assert!(asked.apply.contains(&"windows.defender_exclusion"));
        assert!(
            asked
                .held
                .iter()
                .any(|(id, _)| *id == "windows.symlink_privilege")
        );
    }

    #[test]
    fn only_restricts_the_plan() {
        let report = report_needing_everything();
        let plan = plan(
            &report,
            &["windows.long_paths".into()],
            &Consent::default(),
            &mut NoPrompt,
        );
        assert_eq!(plan.apply, ["windows.long_paths"]);
    }

    struct FakeElevator<'a> {
        facts: &'a Facts,
        actions: &'a Actions<'a>,
        refuse: bool,
        requests: RefCell<Vec<ElevatedRequest>>,
    }

    impl Elevator for FakeElevator<'_> {
        fn elevate(&self, request: &ElevatedRequest) -> Result<Vec<FixResult>, ElevationFailure> {
            self.requests.borrow_mut().push(request.clone());
            if self.refuse {
                return Err(ElevationFailure::Refused);
            }
            Ok(run_request(request, self.facts, self.actions))
        }
    }

    #[test]
    fn admin_fixes_go_to_one_elevated_run_and_a_refusal_is_reported_per_check() {
        let setup = windows_setup();
        let facts = Facts::default();
        let actions = Actions::default();
        let elevator = FakeElevator {
            facts: &facts,
            actions: &actions,
            refuse: false,
            requests: RefCell::default(),
        };
        let request = ElevatedRequest {
            setup: setup.clone(),
            apply: vec![
                "windows.long_paths".into(),
                "windows.execution_policy".into(),
            ],
            revert: Vec::new(),
        };
        let results = execute(request.clone(), &facts, &actions, &elevator);
        assert_eq!(
            elevator.requests.borrow().len(),
            1,
            "one prompt for the batch"
        );
        assert_eq!(elevator.requests.borrow()[0].apply.len(), 2);
        assert!(
            results
                .iter()
                .all(|r| matches!(r.outcome, FixOutcome::Applied { .. }))
        );
        assert_eq!(
            *actions.log.borrow(),
            [
                "dword LongPathsEnabled=Some(1)",
                "string ExecutionPolicy=Some(\"RemoteSigned\")"
            ]
        );

        let refusing = FakeElevator {
            refuse: true,
            ..elevator
        };
        let results = execute(request, &facts, &actions, &refusing);
        assert!(results.iter().all(|r| matches!(
            &r.outcome,
            FixOutcome::NotAttempted { reason } if reason.contains("refused")
        )));
    }

    #[test]
    fn an_elevated_process_applies_in_process_and_never_relaunches() {
        let setup = windows_setup();
        let facts = Facts {
            elevated: true,
            ..Facts::default()
        };
        let actions = Actions::default();
        let elevator = FakeElevator {
            facts: &facts,
            actions: &actions,
            refuse: true,
            requests: RefCell::default(),
        };
        let results = execute(
            ElevatedRequest {
                setup,
                apply: vec!["windows.long_paths".into()],
                revert: Vec::new(),
            },
            &facts,
            &actions,
            &elevator,
        );
        assert!(elevator.requests.borrow().is_empty());
        assert!(matches!(results[0].outcome, FixOutcome::Applied { .. }));
    }

    #[test]
    fn a_fix_re_probes_first_and_changes_nothing_that_already_passes() {
        let setup = windows_setup();
        let mut facts = Facts::default();
        facts.dwords.insert(RegValue::LongPathsEnabled, Ok(Some(1)));
        let actions = Actions::default();
        assert_eq!(
            apply_one("windows.long_paths", &setup, &facts, &actions).outcome,
            FixOutcome::AlreadyDone
        );
        assert!(actions.log.borrow().is_empty());
    }

    #[test]
    fn a_revert_restores_exactly_what_the_fix_replaced() {
        let setup = windows_setup();
        let mut facts = Facts {
            git: Some(PathBuf::from(r"C:\Git\cmd\git.exe")),
            ..Facts::default()
        };
        facts
            .git_values
            .borrow_mut()
            .insert(GIT_LONG_PATHS.into(), "false".into());
        facts.dwords.insert(RegValue::LongPathsEnabled, Ok(Some(0)));
        let actions = Actions {
            git: Some(&facts),
            ..Actions::default()
        };
        let fixed = run_request(
            &ElevatedRequest {
                setup: setup.clone(),
                apply: vec!["windows.long_paths".into(), "windows.git_long_paths".into()],
                revert: Vec::new(),
            },
            &facts,
            &actions,
        );
        let mut journal = Journal::default();
        update_journal(&mut journal, &fixed, chrono::Utc::now());
        assert_eq!(journal.entries.len(), 2);
        let revert: Vec<(String, Vec<Change>)> = journal
            .entries
            .iter()
            .map(|(id, entry)| (id.clone(), entry.changes.clone()))
            .collect();
        actions.log.borrow_mut().clear();
        let reverted = run_request(
            &ElevatedRequest {
                setup,
                apply: Vec::new(),
                revert,
            },
            &facts,
            &actions,
        );
        assert!(reverted.iter().all(|r| r.outcome == FixOutcome::Reverted));
        assert_eq!(
            *actions.log.borrow(),
            [
                "git core.longpaths=Some(\"false\")",
                "dword LongPathsEnabled=Some(0)"
            ]
        );
        update_journal(&mut journal, &reverted, chrono::Utc::now());
        assert!(journal.entries.is_empty());
    }

    #[test]
    fn a_second_prepare_keeps_the_first_previous_value() {
        let now = chrono::Utc::now();
        let first = FixResult {
            id: "windows.long_paths".into(),
            outcome: FixOutcome::Applied {
                changes: vec![Change::RegistryDword {
                    value: RegValue::LongPathsEnabled,
                    previous: Some(0),
                    applied: 1,
                }],
            },
        };
        let second = FixResult {
            id: "windows.long_paths".into(),
            outcome: FixOutcome::Applied {
                changes: vec![Change::RegistryDword {
                    value: RegValue::LongPathsEnabled,
                    previous: Some(1),
                    applied: 1,
                }],
            },
        };
        let mut journal = Journal::default();
        update_journal(&mut journal, &[first, second], now);
        assert_eq!(
            journal.entries["windows.long_paths"].changes,
            [Change::RegistryDword {
                value: RegValue::LongPathsEnabled,
                previous: Some(0),
                applied: 1
            }]
        );
    }

    #[test]
    fn a_tampered_journal_cannot_make_a_revert_write_an_arbitrary_value() {
        let actions = Actions::default();
        for change in [
            Change::RegistryDword {
                value: RegValue::MachinePath,
                previous: Some(0),
                applied: 1,
            },
            Change::RegistryString {
                value: RegValue::ExecutionPolicy,
                previous: Some("Anything; Evil".into()),
                applied: "RemoteSigned".into(),
            },
            Change::GitSystemConfig {
                git: PathBuf::from("git"),
                name: "core.sshCommand".into(),
                previous: Some("evil".into()),
                applied: "x".into(),
            },
        ] {
            assert!(change.revert(&actions).is_err(), "{change:?}");
        }
        assert!(actions.log.borrow().is_empty());
    }

    #[test]
    fn the_elevated_request_round_trips_through_its_command_line() {
        let request = ElevatedRequest {
            setup: macos_setup(),
            apply: vec!["macos.spotlight".into()],
            revert: vec![(
                "windows.defender_exclusion".into(),
                vec![Change::DefenderExclusions {
                    added: vec![r"C:\r m\'x".into()],
                }],
            )],
        };
        let text = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<ElevatedRequest>(&text).unwrap(),
            request
        );
    }

    #[test]
    fn environment_references_expand_and_unknown_ones_survive() {
        // SAFETY-free: reads a variable every process has on its platform.
        let path = std::env::var("PATH").unwrap();
        assert_eq!(expand_environment("%PATH%;x"), format!("{path};x"));
        assert_eq!(
            expand_environment("%NO_SUCH_RM_VAR%\\a"),
            "%NO_SUCH_RM_VAR%\\a"
        );
        assert_eq!(expand_environment("100%"), "100%");
    }

    #[test]
    fn powershell_lists_escape_single_quotes() {
        assert_eq!(
            powershell_list(&[r"C:\a".into(), "it's".into()]),
            r"@('C:\a','it''s')"
        );
    }

    fn rooted_context(root: &Path) -> Context {
        let endpoints =
            runner_manager_github::Endpoints::for_test_server("http://127.0.0.1:9").unwrap();
        Context::rooted_against(root, endpoints).unwrap()
    }

    /// The whole prepare path against fakes: nothing is applied without a yes
    /// and with nobody to ask, and with one the batch goes to one elevated
    /// run and every change lands in the journal with what it replaced.
    #[test]
    fn prepare_needs_a_yes_then_elevates_once_and_journals_what_it_changed() {
        let root = tempfile::tempdir().unwrap();
        let context = rooted_context(root.path());
        let setup = windows_setup();
        let facts = Facts {
            exclusions: Some(Vec::new()),
            ..Facts::default()
        };
        let actions = Actions::default();
        let elevator = FakeElevator {
            facts: &facts,
            actions: &actions,
            refuse: false,
            requests: RefCell::default(),
        };
        let run = |consent: Consent, out: &mut Vec<u8>| {
            prepare(
                PrepareRun {
                    context: &context,
                    setup: setup.clone(),
                    facts: &facts,
                    actions: &actions,
                    elevator: &elevator,
                    prompt: &mut NoPrompt,
                    consent,
                },
                &[],
                out,
            )
        };

        let refused = run(Consent::default(), &mut Vec::new()).unwrap_err();
        assert_eq!(refused.class(), Failure::InvalidArgument);
        assert!(
            actions.log.borrow().is_empty(),
            "nothing may change without a yes"
        );
        assert!(elevator.requests.borrow().is_empty());
        assert!(!journal_path(&context).exists());

        let mut out = Vec::new();
        let outcome = run(
            Consent {
                assume_yes: true,
                ..Consent::default()
            },
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(elevator.requests.borrow().len(), 1, "{text}");
        assert!(
            outcome
                .held
                .iter()
                .any(|(id, _)| *id == "windows.defender_exclusion"),
            "--yes alone never applies a security trade-off: {text}"
        );
        assert!(
            !actions
                .log
                .borrow()
                .iter()
                .any(|line| line.starts_with("defender"))
        );
        let journal = read_journal(&journal_path(&context)).unwrap();
        assert_eq!(
            journal.entries["windows.long_paths"].changes,
            [Change::RegistryDword {
                value: RegValue::LongPathsEnabled,
                previous: None,
                applied: 1
            }]
        );
    }

    #[test]
    fn the_summary_line_counts_by_severity() {
        let failing = |id: &str, severity| FindingSummary {
            id: id.into(),
            severity,
            title: String::new(),
            detail: String::new(),
            remedy: None,
            fixable: true,
            needs_admin: true,
            consent_flag: None,
        };
        let summary = DoctorSummary {
            checked: 9,
            failing: vec![
                failing("a", Severity::Required),
                failing("b", Severity::Recommended),
            ],
            unknown: Vec::new(),
            daemon_host_unfit: None,
        };
        assert_eq!(
            summary.line(),
            "1 required, 1 recommended failing (a, b); runner-manager host doctor"
        );
        let clean = DoctorSummary {
            failing: Vec::new(),
            ..summary
        };
        assert_eq!(clean.line(), "ok (9 checks)");
    }
}
