// owner: a1-wsl-platform-adapter

//! Selecting a distribution and asking it the five questions that decide
//! whether the product may manage it.
//!
//! # One invocation shape, and only one
//!
//! Every Linux command this adapter runs is
//!
//! ```text
//! wsl.exe --distribution <NAME> --user <USER> --exec <PROGRAM> [ARG ...]
//! ```
//!
//! as an argument *vector* — [`LinuxCommand::wsl_arguments`] builds it, and it
//! is the only thing that does. `--exec` is what makes that true end to end:
//! Microsoft documents it as *"execute the specified command without using the
//! default Linux shell"*, so the arguments reach `execvp` as they were written
//! and no `;`, `&&`, `$(…)` or quote in a distribution name, a path or a
//! version string is ever interpreted by anything
//! (<https://learn.microsoft.com/en-us/windows/wsl/basic-commands>).
//!
//! The Windows half is the same story: [`super::exec::CommandRequest`] holds a
//! `Vec<OsString>` and `std::process::Command` quotes each element for
//! `CommandLineToArgvW`. There is no point in the chain at which a string is
//! split back into arguments.
//!
//! # The five preflight questions
//!
//! `02-target-architecture.md` step 1 is *"validate that `NAME` is installed as
//! WSL2, starts as root, and runs systemd"*, and `03-security-and-lifecycle.md`
//! adds the architecture row to the failure table. [`probe_readiness`] asks
//! them in the order in which a failing answer is most useful:
//!
//! 1. **Installed, exactly.** `wsl --list --verbose`, matched case-sensitively.
//! 2. **WSL2.** A WSL1 distribution has no systemd and no separate kernel;
//!    refusing here is `Compatibility`'s "explicit preflight failure".
//! 3. **Root.** `id -u` must answer `0`. The provider installs a system
//!    service and writes `/usr/local/bin`; discovering that it cannot halfway
//!    through is the failure mode this question removes.
//! 4. **A supported Linux architecture.** `uname -m`, mapped to the
//!    architectures the release actually publishes.
//! 5. **systemd.** `systemctl is-system-running`. WSL runs systemd only when
//!    the distribution opts in and the WSL build is 0.67.6 or newer
//!    (<https://learn.microsoft.com/en-us/windows/wsl/systemd>), and the Linux
//!    daemon is a system unit.
//!
//! **No question in this list mutates anything.** That is what
//! `03-security-and-lifecycle.md`'s "WSL/systemd preflight — no mutation and no
//! device login" means in code: a failure here happens before a credential has
//! been issued, before a byte has been written into the distribution, and
//! before a Windows task exists.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use runner_manager_domain::model::Arch;

use super::WslError;
use super::discovery::{DistributionTable, validate_distribution_name};
use super::exec::{ChildInput, CommandOutput, CommandRequest, CommandRunner, OutputLimits};

/// The Linux account every managed command runs as.
///
/// Fixed rather than configurable. The provider's whole job — installing a
/// binary under `/usr/local/bin`, registering a system unit, writing a machine
/// secret store — is root's, and a second account would mean a second set of
/// permissions to reason about for no gain
/// (`02-target-architecture.md`: `--user root`).
pub const LINUX_USER: &str = "root";

/// `wsl.exe`, as found on this host or as a test says it is.
///
/// # Why `%SystemRoot%` is used here and refused in [`crate::runner_root`]
///
/// `runner_root` derives the default runner root from `GetSystemDirectoryW`
/// and says explicitly that it will not read `%SystemDrive%`, because that
/// value *decides where an ACL'd directory is created* — a wrong answer there
/// is a security-relevant mistake that nothing downstream would notice.
///
/// This is the weaker question of where one well-known executable is, and its
/// wrong answer is loud: `wsl.exe` is either at the path or it is not, and a
/// missing program is a [`WslError::Spawn`] naming the path it tried. So the
/// environment is used as a *hint*, with a documented fallback to a bare
/// `wsl.exe`, which resolves through `PATH` exactly as it would in an
/// operator's own shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WslExecutable(PathBuf);

impl WslExecutable {
    /// Where `wsl.exe` is on this host.
    ///
    /// `%SystemRoot%\System32\wsl.exe` when `%SystemRoot%` names a directory
    /// that has it, and a bare `wsl.exe` otherwise.
    #[must_use]
    pub fn locate() -> Self {
        Self(locate_in_system32("wsl.exe"))
    }

    /// A named executable, for a test or for a caller that already knows.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// The path that will be launched.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Default for WslExecutable {
    fn default() -> Self {
        Self::locate()
    }
}

impl fmt::Display for WslExecutable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// `%SystemRoot%` + `System32` + the program, when that file is really there,
/// and a bare program name -- resolved through `PATH` -- otherwise.
///
/// Shared by [`WslExecutable`] and by [`crate::wsl::task`]'s `schtasks.exe`,
/// which need the same lookup under the same reasoning.
pub(crate) fn locate_in_system32(program: &str) -> PathBuf {
    locate_from(std::env::var_os("SystemRoot").map(PathBuf::from), program)
}

/// The pure half of [`locate_in_system32`], so both branches are testable on a
/// machine that has neither `%SystemRoot%` nor the program.
fn locate_from(system_root: Option<PathBuf>, program: &str) -> PathBuf {
    if let Some(root) = system_root {
        let candidate = root.join("System32").join(program);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from(program)
}

// ---------------------------------------------------------------------------
// One Linux command
// ---------------------------------------------------------------------------

/// A program to run inside a named distribution, as a literal argument vector.
#[derive(Debug)]
pub struct LinuxCommand {
    distribution: String,
    user: String,
    program: String,
    arguments: Vec<String>,
    input: ChildInput,
    timeout: Duration,
    limits: OutputLimits,
}

impl LinuxCommand {
    /// Runs `program` in `distribution`, as root, with no arguments.
    #[must_use]
    pub fn new(distribution: impl Into<String>, program: impl Into<String>) -> Self {
        Self {
            distribution: distribution.into(),
            user: LINUX_USER.to_string(),
            program: program.into(),
            arguments: Vec::new(),
            input: ChildInput::Empty,
            timeout: super::exec::DEFAULT_TIMEOUT,
            limits: OutputLimits::default(),
        }
    }

    /// Appends arguments, verbatim and in order.
    #[must_use]
    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    /// Gives the Linux process something on its stdin.
    #[must_use]
    pub fn with_input(mut self, input: ChildInput) -> Self {
        self.input = input;
        self
    }

    /// Replaces the default deadline.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replaces the default capture bounds.
    #[must_use]
    pub fn with_limits(mut self, limits: OutputLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The distribution this runs in.
    #[must_use]
    pub fn distribution(&self) -> &str {
        &self.distribution
    }

    /// The Linux program.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The argument vector handed to `wsl.exe`.
    ///
    /// The single place the invocation shape is written down, and therefore
    /// the single thing a test has to assert to know that no shell is
    /// involved anywhere.
    #[must_use]
    pub fn wsl_arguments(&self) -> Vec<String> {
        let mut argv = vec![
            "--distribution".to_string(),
            self.distribution.clone(),
            "--user".to_string(),
            self.user.clone(),
            "--exec".to_string(),
            self.program.clone(),
        ];
        argv.extend(self.arguments.iter().cloned());
        argv
    }
}

// ---------------------------------------------------------------------------
// The invoker
// ---------------------------------------------------------------------------

/// Runs `wsl.exe`, through whatever [`CommandRunner`] it was given.
#[derive(Debug, Clone, Copy)]
pub struct WslInvoker<'runner> {
    runner: &'runner dyn CommandRunner,
    executable: &'runner WslExecutable,
}

impl<'runner> WslInvoker<'runner> {
    /// Binds a runner and an executable.
    #[must_use]
    pub fn new(runner: &'runner dyn CommandRunner, executable: &'runner WslExecutable) -> Self {
        Self { runner, executable }
    }

    /// The executable it will launch.
    #[must_use]
    pub fn executable(&self) -> &WslExecutable {
        self.executable
    }

    /// `wsl.exe --list --verbose`.
    ///
    /// # Errors
    ///
    /// [`WslError::Spawn`] when `wsl.exe` is not there — which on a Windows
    /// host without WSL is the honest answer — and
    /// [`WslError::CommandFailed`] when it ran and refused.
    pub fn list(&self) -> Result<DistributionTable, WslError> {
        let request = CommandRequest::new(self.executable.path())
            .arg("--list")
            .arg("--verbose");
        let output = self.runner.run(&request)?;
        if !output.success() {
            // `wsl --list` exits non-zero when WSL is installed but has no
            // distributions, and the table is then legitimately empty. That is
            // told apart from a real failure by whether anything parsed.
            let table = DistributionTable::from_console_output(output.stdout());
            if table.is_empty() && table.unreadable().is_empty() {
                return Err(WslError::CommandFailed {
                    what: "list the installed WSL distributions",
                    program: self.executable.path().to_path_buf(),
                    exit_code: output.exit_code(),
                    detail: output.diagnostic(),
                });
            }
            return Ok(table);
        }
        Ok(DistributionTable::from_console_output(output.stdout()))
    }

    /// Runs one command inside a distribution.
    ///
    /// Takes the command **by value**, which is not an accident: a
    /// [`ChildInput`] is deliberately not `Clone`, so moving it into the
    /// request is the only way to run it. That both prevents a credential from
    /// being duplicated on the heap by a stray `clone()` and keeps the
    /// artifact installer from copying a fifteen-megabyte archive on its way
    /// to the pipe.
    ///
    /// A non-zero exit is returned as a [`CommandOutput`], not as an error:
    /// several callers here treat "it said no" as information rather than as a
    /// failure.
    ///
    /// # Errors
    ///
    /// [`WslError::InvalidName`] before anything is launched;
    /// [`WslError::Spawn`], [`WslError::SecretInCommandLine`] or
    /// [`WslError::ChildControl`] from the runner.
    pub fn exec(&self, command: LinuxCommand) -> Result<CommandOutput, WslError> {
        validate_distribution_name(&command.distribution)?;
        let request = CommandRequest::new(self.executable.path())
            .args(command.wsl_arguments())
            .with_timeout(command.timeout)
            .with_limits(command.limits)
            .with_input(command.input);
        self.runner.run(&request)
    }

    /// Runs one command and refuses anything but a clean exit.
    ///
    /// # Errors
    ///
    /// As [`WslInvoker::exec`], plus [`WslError::CommandFailed`] when the
    /// Linux program exited non-zero, timed out, or was cancelled.
    pub fn exec_ok(
        &self,
        what: &'static str,
        command: LinuxCommand,
    ) -> Result<CommandOutput, WslError> {
        let program = PathBuf::from(command.program());
        let output = self.exec(command)?;
        if output.success() {
            return Ok(output);
        }
        Err(WslError::CommandFailed {
            what,
            program,
            exit_code: output.exit_code(),
            detail: output.diagnostic(),
        })
    }
}

// ---------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------

/// What `systemctl is-system-running` said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemdState {
    /// Fully up.
    Running,
    /// Up, with at least one failed unit. Usable: the product's own unit is
    /// what matters, and `service status` reports it separately.
    Degraded,
    /// Still coming up. Usable for the same reason, and the alternative —
    /// refusing during the first seconds after a cold start — would make the
    /// preflight flaky rather than strict.
    Starting,
    /// Not systemd, or systemd is not the init here. Refused.
    Unavailable(String),
}

impl SystemdState {
    /// Reads the one word `systemctl is-system-running` prints.
    #[must_use]
    pub fn from_report(word: &str) -> Self {
        match word.trim() {
            "running" => Self::Running,
            "degraded" => Self::Degraded,
            "initializing" | "starting" => Self::Starting,
            "" => Self::Unavailable("it said nothing".to_string()),
            other => Self::Unavailable(other.to_string()),
        }
    }

    /// Whether the Linux service manager can be used.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Running | Self::Degraded | Self::Starting)
    }
}

impl fmt::Display for SystemdState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => f.write_str("running"),
            Self::Degraded => f.write_str("degraded"),
            Self::Starting => f.write_str("starting"),
            Self::Unavailable(word) => write!(f, "unavailable ({word})"),
        }
    }
}

/// Maps `uname -m` onto the architectures the release publishes.
///
/// `Arch::Arm32` is deliberately absent: `crates/app/src/cli/update.rs`'s
/// target table publishes `x86_64-unknown-linux-gnu` and
/// `aarch64-unknown-linux-gnu` and nothing else, so a 32-bit ARM distribution
/// has no artifact and must be refused here rather than fail at download.
///
/// # Errors
///
/// [`WslError::UnsupportedArchitecture`] naming what the distribution said.
pub fn architecture_from_uname(distribution: &str, machine: &str) -> Result<Arch, WslError> {
    match machine.trim() {
        "x86_64" | "amd64" => Ok(Arch::X64),
        "aarch64" | "arm64" => Ok(Arch::Arm64),
        other => Err(WslError::UnsupportedArchitecture {
            distribution: distribution.to_string(),
            reported: other.to_string(),
        }),
    }
}

/// Everything the preflight established about one distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionReadiness {
    name: String,
    wsl_version: u8,
    default: bool,
    architecture: Arch,
    machine: String,
    systemd: SystemdState,
}

impl DistributionReadiness {
    /// The exact name, as WSL spells it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Always 2 — [`probe_readiness`] refuses anything else — but carried so a
    /// status line can state it rather than assert it.
    #[must_use]
    pub fn wsl_version(&self) -> u8 {
        self.wsl_version
    }

    /// Whether WSL marks it as the default distribution.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.default
    }

    /// The architecture the release artifact must match.
    #[must_use]
    pub fn architecture(&self) -> Arch {
        self.architecture
    }

    /// What `uname -m` actually said, for a status line.
    #[must_use]
    pub fn machine(&self) -> &str {
        &self.machine
    }

    /// The service manager's state.
    #[must_use]
    pub fn systemd(&self) -> &SystemdState {
        &self.systemd
    }
}

/// Asks the five preflight questions. Mutates nothing.
///
/// # Errors
///
/// [`WslError::InvalidName`], [`WslError::NotInstalled`],
/// [`WslError::AmbiguousName`], [`WslError::NotWsl2`],
/// [`WslError::NoRootAccess`], [`WslError::UnsupportedArchitecture`] or
/// [`WslError::SystemdUnavailable`] — each naming the one thing an operator
/// would have to change — plus anything [`WslInvoker::exec`] can report.
pub fn probe_readiness(
    invoker: &WslInvoker<'_>,
    name: &str,
) -> Result<DistributionReadiness, WslError> {
    validate_distribution_name(name)?;
    let table = invoker.list()?;
    let installed = table.exactly(name)?;
    installed.require_wsl2()?;
    let wsl_version = installed.wsl_version();
    let default = installed.is_default();

    // Root. `id -u` rather than `whoami`, because the answer is a number in
    // every locale and `whoami`'s is a name that a localised system may
    // translate.
    let identity = invoker.exec(LinuxCommand::new(name, "id").args(["-u"]))?;
    if !identity.success() {
        // A failed `wsl.exe --user root --exec id -u` does not establish
        // anything about root. In particular, WSL service/VM startup errors
        // are returned as this command's stderr and used to be mislabeled as
        // a permanently ineligible distribution. Preserve the transport
        // failure as a retryable provisioning error instead.
        return Err(WslError::CommandFailed {
            what: "verify root access in the distribution",
            program: PathBuf::from("id"),
            exit_code: identity.exit_code(),
            detail: identity.diagnostic(),
        });
    }
    let reported = identity.stdout_text();
    if reported != "0" {
        return Err(WslError::NoRootAccess {
            distribution: name.to_string(),
            detail: format!("`id -u` answered {reported}, not 0"),
        });
    }

    let uname = invoker.exec_ok(
        "read the distribution's architecture",
        LinuxCommand::new(name, "uname").args(["-m"]),
    )?;
    let machine = uname.stdout_text();
    let architecture = architecture_from_uname(name, &machine)?;

    // `is-system-running` exits non-zero for `degraded` and for `starting`,
    // both of which are usable, so the word is read rather than the code.
    let systemd_report =
        invoker.exec(LinuxCommand::new(name, "systemctl").args(["is-system-running"]))?;
    let systemd = SystemdState::from_report(&systemd_report.stdout_text());
    if !systemd.is_usable() {
        return Err(WslError::SystemdUnavailable {
            distribution: name.to_string(),
            detail: match &systemd {
                SystemdState::Unavailable(word) => {
                    let stderr = systemd_report.stderr_text();
                    if stderr.is_empty() {
                        format!("`systemctl is-system-running` answered `{word}`")
                    } else {
                        format!("`systemctl is-system-running` answered `{word}`: {stderr}")
                    }
                }
                other => other.to_string(),
            },
        });
    }

    Ok(DistributionReadiness {
        name: name.to_string(),
        wsl_version,
        default,
        architecture,
        machine,
        systemd,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wsl::exec::{PipedInput, ScriptedRunner};
    use secrecy::{ExposeSecret, SecretString};

    fn executable() -> WslExecutable {
        WslExecutable::at("wsl.exe")
    }

    fn table() -> CommandOutput {
        CommandOutput::exited(
            0,
            concat!(
                "  NAME       STATE       VERSION\n",
                "* Ubuntu     Running     2\n",
                "  Legacy     Stopped     1\n",
            ),
            "",
        )
    }

    /// A runner that answers every preflight question the way a healthy
    /// `Ubuntu` would.
    fn healthy() -> ScriptedRunner {
        ScriptedRunner::new()
            .always("--list --verbose", table())
            .always("--exec id -u", CommandOutput::exited(0, "0\n", ""))
            .always("--exec uname -m", CommandOutput::exited(0, "x86_64\n", ""))
            .always(
                "--exec systemctl is-system-running",
                CommandOutput::exited(0, "running\n", ""),
            )
    }

    // -- The invocation shape ------------------------------------------------

    #[test]
    fn a_linux_command_is_an_argument_vector_with_no_shell_in_it() {
        let command = LinuxCommand::new("Debian GNU/Linux 12", "/usr/local/bin/runner-manager")
            .args(["service", "install", "--start-at", "boot"]);
        assert_eq!(
            command.wsl_arguments(),
            vec![
                "--distribution",
                "Debian GNU/Linux 12",
                "--user",
                "root",
                "--exec",
                "/usr/local/bin/runner-manager",
                "service",
                "install",
                "--start-at",
                "boot",
            ]
        );
    }

    #[test]
    fn a_hostile_distribution_name_stays_one_argument() {
        let command = LinuxCommand::new("Ubuntu; rm -rf /", "id").args(["-u"]);
        let argv = command.wsl_arguments();
        assert_eq!(argv[1], "Ubuntu; rm -rf /");
        assert!(
            argv.iter().all(|argument| argument != "rm"),
            "the name must never become its own argument: {argv:?}"
        );
        // And `--exec` is present, which is what keeps the Linux side from
        // handing it to a shell.
        assert!(argv.contains(&"--exec".to_string()));
    }

    #[test]
    fn the_invoker_passes_the_vector_through_untouched() {
        let runner = healthy();
        let executable = executable();
        let invoker = WslInvoker::new(&runner, &executable);
        invoker
            .exec(LinuxCommand::new("Ubuntu", "id").args(["-u"]))
            .expect("scripted");
        let recorded = runner.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].arguments,
            vec![
                "--distribution",
                "Ubuntu",
                "--user",
                "root",
                "--exec",
                "id",
                "-u"
            ]
        );
    }

    #[test]
    fn a_name_that_reads_as_an_option_is_refused_before_anything_is_launched() {
        let runner = ScriptedRunner::new();
        let executable = executable();
        let invoker = WslInvoker::new(&runner, &executable);
        let error = invoker
            .exec(LinuxCommand::new("--shutdown", "id"))
            .expect_err("refused");
        assert!(matches!(error, WslError::InvalidName { .. }), "{error:?}");
        assert_eq!(runner.call_count(), 0, "nothing may be launched");
    }

    #[test]
    fn a_piped_payload_reaches_the_child_and_no_argument() {
        let secret = SecretString::from(format!("{}{}", "ghu_", "a1ProbeFixtureNotARealToken0000"));
        let runner = ScriptedRunner::new();
        let executable = executable();
        let invoker = WslInvoker::new(&runner, &executable);
        invoker
            .exec(
                LinuxCommand::new("Ubuntu", "/usr/local/bin/runner-manager")
                    .args(["auth", "receive", "--start-at", "boot"])
                    .with_input(ChildInput::Piped(PipedInput::from_secret_text(&secret))),
            )
            .expect("scripted");
        assert_eq!(runner.piped_input(), secret.expose_secret().as_bytes());
        assert!(
            runner
                .command_lines()
                .iter()
                .all(|line| !line.contains(secret.expose_secret())),
            "the canary must not be in any command line"
        );
    }

    // -- Readiness -----------------------------------------------------------

    #[test]
    fn a_healthy_distribution_reports_every_fact_it_established() {
        let runner = healthy();
        let executable = executable();
        let ready =
            probe_readiness(&WslInvoker::new(&runner, &executable), "Ubuntu").expect("healthy");
        assert_eq!(ready.name(), "Ubuntu");
        assert_eq!(ready.wsl_version(), 2);
        assert!(ready.is_default());
        assert_eq!(ready.architecture(), Arch::X64);
        assert_eq!(ready.machine(), "x86_64");
        assert_eq!(ready.systemd(), &SystemdState::Running);
    }

    #[test]
    fn a_wsl1_distribution_is_refused_before_any_linux_command_runs() {
        let runner = healthy();
        let executable = executable();
        let error =
            probe_readiness(&WslInvoker::new(&runner, &executable), "Legacy").expect_err("WSL1");
        assert!(matches!(error, WslError::NotWsl2 { .. }), "{error:?}");
        assert_eq!(
            runner.call_count(),
            1,
            "only `--list` should have run: {:?}",
            runner.command_lines()
        );
    }

    #[test]
    fn a_distribution_that_is_not_installed_lists_the_ones_that_are() {
        let runner = healthy();
        let executable = executable();
        let error =
            probe_readiness(&WslInvoker::new(&runner, &executable), "Fedora").expect_err("absent");
        assert!(error.to_string().contains("Ubuntu"), "{error}");
    }

    #[test]
    fn a_distribution_that_does_not_start_as_root_is_refused() {
        let runner = ScriptedRunner::new()
            .always("--list --verbose", table())
            .always("--exec id -u", CommandOutput::exited(0, "1000\n", ""));
        let executable = executable();
        let error = probe_readiness(&WslInvoker::new(&runner, &executable), "Ubuntu")
            .expect_err("not root");
        let WslError::NoRootAccess { detail, .. } = &error else {
            panic!("unexpected error: {error:?}");
        };
        assert!(detail.contains("1000"), "{detail}");
    }

    #[test]
    fn a_wsl_startup_failure_is_not_mislabeled_as_missing_root_access() {
        let diagnostic = concat!(
            "A connection attempt failed because the connected party did not respond.\n",
            "Error code: Wsl/Service/0x8007274c\n",
        );
        let runner = ScriptedRunner::new()
            .always("--list --verbose", table())
            .always("--exec id -u", CommandOutput::exited(-1, "", diagnostic));
        let executable = executable();
        let error = probe_readiness(&WslInvoker::new(&runner, &executable), "Ubuntu")
            .expect_err("WSL startup failed");

        let WslError::CommandFailed {
            what,
            exit_code,
            detail,
            ..
        } = &error
        else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(*what, "verify root access in the distribution");
        assert_eq!(*exit_code, Some(-1));
        assert!(detail.contains("Wsl/Service/0x8007274c"), "{detail}");
        assert!(
            !error.to_string().contains("does not start as root"),
            "{error}"
        );
    }

    #[test]
    fn an_unsupported_architecture_names_what_the_distribution_said() {
        let runner = ScriptedRunner::new()
            .always("--list --verbose", table())
            .always("--exec id -u", CommandOutput::exited(0, "0\n", ""))
            .always("--exec uname -m", CommandOutput::exited(0, "armv7l\n", ""));
        let executable = executable();
        let error = probe_readiness(&WslInvoker::new(&runner, &executable), "Ubuntu")
            .expect_err("armv7l has no published artifact");
        assert!(
            matches!(&error, WslError::UnsupportedArchitecture { reported, .. } if reported == "armv7l"),
            "{error:?}"
        );
        assert!(error.to_string().contains("armv7l"));
    }

    #[test]
    fn architecture_mapping_covers_both_published_linux_targets_and_nothing_else() {
        assert_eq!(
            architecture_from_uname("d", "x86_64").expect("x64"),
            Arch::X64
        );
        assert_eq!(
            architecture_from_uname("d", "amd64").expect("x64"),
            Arch::X64
        );
        assert_eq!(
            architecture_from_uname("d", "aarch64").expect("arm64"),
            Arch::Arm64
        );
        assert_eq!(
            architecture_from_uname("d", "arm64\n").expect("arm64"),
            Arch::Arm64
        );
        for machine in ["armv7l", "i686", "riscv64", "s390x", ""] {
            assert!(
                architecture_from_uname("d", machine).is_err(),
                "{machine} has no published Linux artifact"
            );
        }
    }

    #[test]
    fn a_distribution_without_systemd_is_refused_with_what_it_answered() {
        let runner = ScriptedRunner::new()
            .always("--list --verbose", table())
            .always("--exec id -u", CommandOutput::exited(0, "0\n", ""))
            .always("--exec uname -m", CommandOutput::exited(0, "x86_64\n", ""))
            .always(
                "--exec systemctl is-system-running",
                CommandOutput::exited(1, "offline\n", ""),
            );
        let executable = executable();
        let error = probe_readiness(&WslInvoker::new(&runner, &executable), "Ubuntu")
            .expect_err("no systemd");
        let WslError::SystemdUnavailable { detail, .. } = &error else {
            panic!("unexpected error: {error:?}");
        };
        assert!(detail.contains("offline"), "{detail}");
    }

    #[test]
    fn degraded_and_starting_systemd_are_usable_because_the_products_own_unit_is_what_matters() {
        for word in ["degraded", "starting", "initializing"] {
            let runner = ScriptedRunner::new()
                .always("--list --verbose", table())
                .always("--exec id -u", CommandOutput::exited(0, "0\n", ""))
                .always("--exec uname -m", CommandOutput::exited(0, "x86_64\n", ""))
                .always(
                    "--exec systemctl is-system-running",
                    CommandOutput::exited(1, format!("{word}\n"), ""),
                );
            let executable = executable();
            let ready = probe_readiness(&WslInvoker::new(&runner, &executable), "Ubuntu")
                .unwrap_or_else(|error| panic!("{word} should be usable: {error}"));
            assert!(ready.systemd().is_usable());
        }
    }

    #[test]
    fn the_preflight_mutates_nothing() {
        // Every command it runs is a read. Stated as a test because the
        // failure table's first row -- "no mutation and no device login" -- is
        // otherwise a property of a code path nobody re-reads.
        let runner = healthy();
        let executable = executable();
        probe_readiness(&WslInvoker::new(&runner, &executable), "Ubuntu").expect("healthy");
        for line in runner.command_lines() {
            assert!(
                [
                    "--list --verbose",
                    "id -u",
                    "uname -m",
                    "systemctl is-system-running"
                ]
                .iter()
                .any(|read| line.contains(read)),
                "the preflight ran something that is not a read: {line}"
            );
        }
    }

    // -- Locating wsl.exe ----------------------------------------------------

    #[test]
    fn a_missing_system_root_falls_back_to_the_path_lookup() {
        assert_eq!(locate_from(None, "wsl.exe"), PathBuf::from("wsl.exe"));
        assert_eq!(
            locate_from(Some(PathBuf::from("Q:\\NoSuchWindows")), "wsl.exe"),
            PathBuf::from("wsl.exe")
        );
    }

    #[test]
    fn a_system_root_that_really_holds_the_executable_is_used() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let system32 = root.path().join("System32");
        std::fs::create_dir_all(&system32).expect("create System32");
        std::fs::write(system32.join("wsl.exe"), b"not really an executable")
            .expect("write the stand-in");
        assert_eq!(
            locate_from(Some(root.path().to_path_buf()), "wsl.exe"),
            system32.join("wsl.exe")
        );
    }
}
