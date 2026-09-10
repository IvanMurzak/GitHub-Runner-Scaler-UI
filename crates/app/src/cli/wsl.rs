// owner: b2-wsl-cli-orchestration

//! `wsl list/install/status/detach`, `--host wsl:NAME`, and the hidden
//! `wsl-host hold` — the public half of the managed WSL host feature.
//!
//! # What is here and what is one layer down
//!
//! `crates/platform`'s [`runner_manager_platform::wsl`] module knows about
//! `wsl.exe`, `schtasks.exe`, UTF-16 console output and ext4 renames. It is
//! deliberately ignorant of *when* to do any of it. This module is the
//! orchestration: the ordered, convergent install transaction of
//! `02-target-architecture.md`, the command surface an operator types, the
//! status document a script parses, and the proxy that carries an existing
//! command into the distribution.
//!
//! | Section | What it owns |
//! |---|---|
//! | [`ProxyPlan`] | The argument vector `--host wsl:NAME` forwards, and the child that inherits this process's three streams |
//! | [`WslSecretSink`] | The one door a credential document goes through: the stdin of `auth receive` inside the distribution |
//! | [`Provisioner`] | The eight-stage install transaction, in order, and what each stage leaves behind when it fails |
//! | [`probe`] | Every fact `status` reports, read from the distribution rather than from the record |
//! | [`hold`] | The Linux side of the Windows lifecycle task |
//!
//! # Two properties this module exists to make structural
//!
//! **Nothing mutates before the preflight is complete.**
//! `03-security-and-lifecycle.md`'s failure table opens with *"WSL/systemd
//! preflight → no mutation and no device login"*, and
//! [`Provisioner::install`] is written so that every question is asked before
//! the first answer is acted on: [`Stage::Preflight`] runs
//! [`probe_readiness`] **and** the foreign-task check, and only then does
//! anything download, install, authenticate or register.
//!
//! **Health is read from the host, never from the record.** The provider
//! record is advisory — `02-target-architecture.md` says so in as many words —
//! so [`probe`] asks `wsl.exe`, `systemctl` and the Linux binary itself, and
//! the record contributes exactly one thing to the answer:
//! [`WslStatusDocument::drift`], a list of the places where what was recorded
//! and what is true disagree.
//!
//! # The credential never touches this machine's disk
//!
//! `--host wsl:NAME auth login` runs the device flow **here**, because that is
//! where the browser is, and hands the resulting document straight to
//! [`WslSecretSink`], which writes it to the stdin of `auth receive` inside the
//! distribution. There is no staging store to clean up because
//! [`super::auth::broker_user_credential`] is not given one — see its
//! documentation. This module's contribution to the same guarantee is that the
//! sink's only output is a pipe, and that
//! [`runner_manager_platform::wsl::exec::CommandRequest::refuse_payload_in_argv`]
//! refuses the launch if the document were ever also in the command line.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use chrono::{DateTime, Utc};
use runner_manager_domain::model::Clock;
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::service::TaskPrincipal;
use runner_manager_platform::wsl::artifact::{
    BinaryInstaller, DEFAULT_LINUX_DESTINATION, LinuxBinaryPath, PublishedArtifact, ReleaseTarget,
    linux_target, select_exact_release,
};
use runner_manager_platform::wsl::discovery::validate_distribution_name;
use runner_manager_platform::wsl::exec::{ChildInput, PipedInput};
use runner_manager_platform::wsl::probe::{
    DistributionReadiness, LinuxCommand, SystemdState, WslExecutable, WslInvoker, probe_readiness,
};
use runner_manager_platform::wsl::record::WslProviderRecord;
use runner_manager_platform::wsl::task::{
    LifecycleTask, LifecycleTaskIdentity, PRODUCT_MARKER, RegisteredTask,
};
use runner_manager_platform::wsl::{WslError, WslHost};
use secrecy::SecretString;
use serde::Serialize;

use super::auth::{BrokeredCredential, SecretSink, SecretSinkError, broker_user_credential};
use super::update::{AssetSource, fetch_file, fetch_text};
use super::{
    AuthCommand, Cli, CliError, Command, Context, Failure, HOST_OPTION, StartAt, Styling,
    WslCommand, WslDetachArgs, WslHostCommand, WslInstallArgs, WslStatusArgs, write_failed,
};

/// `--host=` — the other spelling clap accepts for the same option.
///
/// Named beside [`HOST_OPTION`] because [`forwarded_arguments`] has to strip
/// **both**: a selector left in the vector is a `--host` the Linux binary would
/// read as addressing a third host, and clap accepts either form.
const HOST_OPTION_EQUALS: &str = "--host=";

/// The version of the `wsl status --json` document.
///
/// Same contract as `status --json`'s [`super::status::SCHEMA_VERSION`]: adding
/// a field is compatible and leaves this alone; removing or renaming one is
/// not, and moves it.
pub const WSL_STATUS_SCHEMA_VERSION: u32 = 1;

/// How long `docker info` is given before it is reported as unavailable.
///
/// Short, and deliberately: Docker is a **diagnostic** here, not a gate, and a
/// distribution whose Docker daemon is wedged must not be able to make
/// `wsl status` hang. `03-security-and-lifecycle.md` never lists Docker among
/// the things provisioning depends on; `02-target-architecture.md` lists it
/// among *"workload prerequisite diagnostics"*.
const DOCKER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// How long the Linux `service install` is given.
///
/// Longer than the default: it writes a unit, reloads systemd and starts a
/// daemon that opens a database.
const SERVICE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// The first release whose private service copy watches its source binary and
/// performs the unbounded, journal-backed upgrade drain itself.
///
/// A WSL installer must never substitute `systemctl stop` for that protocol:
/// systemd's ordinary stop is a bounded shutdown and can signal the runner
/// child with the service cgroup. Versions before this one cannot be asked to
/// hand over safely, so an active one is left alone.
const FIRST_COOPERATIVE_SERVICE_HANDOVER: [u64; 3] = [0, 1, 8];

/// The controller only observes a handover. The daemon owns its duration,
/// waiting on its local journal without a deadline; this modest pause prevents
/// observation from turning that wait into a tight WSL process loop.
#[cfg(not(test))]
const HANDOVER_OBSERVE_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(test)]
const HANDOVER_OBSERVE_INTERVAL: Duration = Duration::ZERO;

// ---------------------------------------------------------------------------
// Turning a platform failure into an operator-facing one
// ---------------------------------------------------------------------------

/// Maps a [`WslError`] onto the CLI's exit-code taxonomy.
///
/// The mapping is by **what the operator has to do**, not by which module
/// raised it, which is why it is here rather than on `WslError`:
///
/// * a distribution that is WSL1, has no systemd, no root, or an architecture
///   the release does not publish is [`Failure::UnsupportedHost`] — the host is
///   not eligible, and rerunning unchanged will refuse again;
/// * a name that cannot be used at all is [`Failure::InvalidArgument`], and one
///   that is simply not installed is [`Failure::NotFound`];
/// * a task somebody else owns, or a name two rows claim, is
///   [`Failure::Conflict`] — there is something here to resolve by hand;
/// * a release document or archive that will not do is
///   [`Failure::UnusableResponse`], the same class `update` raises for the same
///   evidence;
/// * everything that ran and refused is [`Failure::WslProvisioning`], the class
///   whose remedy is "fix what this names and run `wsl install` again".
pub fn wsl_failure(source: &WslError) -> CliError {
    let message = source.to_string();
    match source {
        WslError::UnsupportedPlatform { .. } => CliError::new(Failure::UnsupportedHost, message),
        WslError::InvalidName { .. } | WslError::InvalidDestination { .. } => {
            CliError::with_remedy(Failure::InvalidArgument, message, "runner-manager wsl list")
        }
        WslError::NotInstalled { .. } => {
            CliError::with_remedy(Failure::NotFound, message, "runner-manager wsl list")
        }
        WslError::NoSuchTask { .. } => CliError::new(Failure::NotFound, message),
        WslError::AmbiguousName { .. } | WslError::AmbiguousArtifact { .. } => {
            CliError::new(Failure::Conflict, message)
        }
        WslError::ForeignTask { .. } => CliError::with_remedy(
            Failure::Conflict,
            message,
            "taskschd.msc   (inspect it, then rename or remove it yourself)",
        ),
        WslError::NotWsl2 { .. }
        | WslError::NoRootAccess { .. }
        | WslError::UnsupportedArchitecture { .. }
        | WslError::SystemdUnavailable { .. }
        | WslError::NoSuchArtifact { .. } => CliError::new(Failure::UnsupportedHost, message),
        WslError::UnreadableChecksums { .. }
        | WslError::UnreadableArchive { .. }
        | WslError::DigestMismatch { .. }
        | WslError::VersionMismatch { .. } => CliError::new(Failure::UnusableResponse, message),
        // The payload was about to be in a process listing. `d2`'s class, and
        // for the same reason: this is a secret-handling refusal.
        WslError::SecretInCommandLine { .. } => CliError::new(Failure::SecretStore, message),
        WslError::Record { .. } | WslError::RecordSchema { .. } => {
            CliError::new(Failure::LocalState, message)
        }
        WslError::NeedsElevation { .. } => CliError::with_remedy(
            Failure::WslProvisioning,
            message,
            "run this command from an elevated prompt",
        ),
        WslError::Spawn { .. }
        | WslError::ChildControl { .. }
        | WslError::CommandFailed { .. }
        | WslError::TaskControl { .. } => CliError::new(Failure::WslProvisioning, message),
    }
}

/// Builds the adapter for this host, refusing off Windows.
///
/// # Errors
/// [`Failure::UnsupportedHost`] on a non-Windows build.
fn host_adapter(operation: &'static str) -> Result<WslHost, CliError> {
    WslHost::on_this_host(operation).map_err(|source| wsl_failure(&source))
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// `runner-manager wsl …`.
///
/// # Errors
/// Every class [`wsl_failure`] names, plus [`Failure::Unclassified`] when the
/// report cannot be written.
pub fn dispatch(
    context: &Context,
    command: &WslCommand,
    styling: Styling,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        WslCommand::List => list(context, out),
        WslCommand::Install(args) => install(context, args, styling, out),
        WslCommand::Status(args) => status(context, args, out),
        WslCommand::Detach(args) => detach(context, args, out),
    }
}

/// `runner-manager wsl-host hold`, inside the distribution.
///
/// # Errors
/// [`Failure::UnsupportedHost`] anywhere but Linux, and
/// [`Failure::WslProvisioning`] when systemd is not usable or will not start
/// the unit.
pub fn dispatch_wsl_host(command: &WslHostCommand, out: &mut dyn Write) -> Result<(), CliError> {
    match command {
        WslHostCommand::Hold => {
            require_linux()?;
            let unit = super::service::identity().systemd_unit();
            let mut wait = wait_for_a_stop_signal;
            hold(&HostSystemd, &unit, out, &mut wait)
        }
    }
}

/// Refuses `wsl-host` anywhere but inside a Linux distribution.
///
/// # Errors
/// [`Failure::UnsupportedHost`], naming this build's OS.
fn require_linux() -> Result<(), CliError> {
    if cfg!(target_os = "linux") {
        return Ok(());
    }
    Err(CliError::with_remedy(
        Failure::UnsupportedHost,
        format!(
            "`wsl-host hold` runs inside a WSL2 distribution and starts its systemd unit; \
             this is a {} build, which has no such unit. It is not a command to type: the \
             Windows lifecycle task `runner-manager wsl install` registers is what runs it.",
            std::env::consts::OS
        ),
        "runner-manager wsl install --distribution NAME",
    ))
}

// ---------------------------------------------------------------------------
// `--host wsl:NAME`
// ---------------------------------------------------------------------------

/// Everything `--host wsl:NAME` does, including owning the exit code.
///
/// # Why this returns the child's exit code through [`std::process::exit`]
///
/// `02-target-architecture.md` requires the proxy to preserve the command's
/// result, and [`ExitCode`] carries a `u8`. A Windows process exit code is a
/// full 32-bit value and a Unix one can be `128 + signal`, so narrowing here
/// would silently rewrite the answer the operator's script branches on. The
/// streams this process holds are the child's own — nothing is buffered here —
/// so exiting without unwinding loses nothing.
#[must_use]
pub fn dispatch_to_selected_host(cli: &Cli, distribution: &str, argv: &[OsString]) -> ExitCode {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();

    match run_on_selected_host(cli, distribution, argv, &mut out, &mut err) {
        Ok(code) => {
            let _ = out.flush();
            let _ = err.flush();
            std::process::exit(code)
        }
        Err(failure) => {
            let _ = out.flush();
            let _ = failure.render(&mut err);
            let _ = err.flush();
            ExitCode::from(failure.class().code())
        }
    }
}

/// The routable half of [`dispatch_to_selected_host`].
///
/// # Errors
/// [`Failure::InvalidArgument`] when the command is one that can only run on
/// this machine, and everything the brokered login or the proxy reports.
fn run_on_selected_host(
    cli: &Cli,
    distribution: &str,
    argv: &[OsString],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32, CliError> {
    refuse_a_command_that_cannot_be_proxied(&cli.command)?;
    let host = host_adapter("`--host wsl:...`")?;
    validate_distribution_name(distribution).map_err(|source| wsl_failure(&source))?;

    // -----------------------------------------------------------------------
    // `auth login` IS THE ONE COMMAND THAT IS NOT FORWARDED.
    // -----------------------------------------------------------------------
    // `02-target-architecture.md`: "Windows owns the interactive device flow
    // and uses the private credential handoff, because that is both more
    // reliable for browser interaction and the only design that can guarantee
    // a new, independent token pair without a staging store." Forwarding it
    // would run the device flow inside the distribution, where there is no
    // browser to open and no operator watching.
    if let Command::Auth(AuthCommand::Login(args)) = &cli.command {
        let context = Context::resolve(cli.data_dir.as_deref(), err)?;
        brokered_login(
            &context,
            &host,
            distribution,
            args,
            Styling::for_stdout(),
            out,
        )?;
        return Ok(0);
    }

    // -----------------------------------------------------------------------
    // `update` ON A WSL HOST IS CARRIED OUT BY WINDOWS
    // -----------------------------------------------------------------------
    // The user typed `runner-manager --host wsl:<NAME> update`.
    // The Windows host owns the version matching; updating the Linux binary
    // directly leaves the Windows host behind and does not restart the service.
    // Instead, this is translated to `runner-manager wsl install --distribution <NAME>`.
    if let Command::Update(_) = &cli.command {
        let context = Context::resolve(cli.data_dir.as_deref(), err)?;
        let install_args = WslInstallArgs {
            distribution: distribution.to_string(),
            capacity: None,
        };
        dispatch(&context, &WslCommand::Install(install_args), Styling::for_stdout(), out)?;
        return Ok(0);
    }

    let plan = ProxyPlan::new(
        host.executable(),
        distribution,
        DEFAULT_LINUX_DESTINATION,
        forwarded_arguments(argv),
    )?;
    HostProxyRunner.run(&plan)
}

/// The two families that address this machine by construction.
///
/// # Errors
/// [`Failure::InvalidArgument`], naming the command that was meant.
fn refuse_a_command_that_cannot_be_proxied(command: &Command) -> Result<(), CliError> {
    let (what, remedy) = match command {
        Command::Wsl(_) => (
            "`wsl` manages a distribution from the Windows side — it drives `wsl.exe` and \
             Task Scheduler, neither of which exists inside the distribution",
            "runner-manager wsl status --distribution NAME",
        ),
        Command::WslHost(_) => (
            "`wsl-host` is the Linux end of the lifecycle task and is started by that task, \
             not by an operator",
            "runner-manager wsl install --distribution NAME",
        ),
        _ => return Ok(()),
    };
    Err(CliError::with_remedy(
        Failure::InvalidArgument,
        format!("{what}, so `--host wsl:...` cannot carry it."),
        remedy,
    ))
}

/// The arguments to forward, which are the ones the operator typed minus the
/// selector.
///
/// # Both spellings, and nothing else
///
/// clap accepts `--host wsl:Ubuntu` and `--host=wsl:Ubuntu`, and this removes
/// either. Nothing else is touched — not `--data-dir`, not a flag this build
/// has never heard of — because the design says *"the original arguments"*, and
/// a proxy that edited them would be a second, undocumented command surface.
///
/// A short option is not stripped because there is none: `--host` is declared
/// without one, so `-h` is still clap's help.
#[must_use]
pub fn forwarded_arguments(argv: &[OsString]) -> Vec<OsString> {
    let mut forwarded = Vec::new();
    let mut skip_a_value = false;
    for argument in argv.iter().skip(1) {
        if skip_a_value {
            skip_a_value = false;
            continue;
        }
        if argument == HOST_OPTION {
            skip_a_value = true;
            continue;
        }
        if argument
            .to_str()
            .is_some_and(|text| text.starts_with(HOST_OPTION_EQUALS))
        {
            continue;
        }
        forwarded.push(argument.clone());
    }
    forwarded
}

/// The exact program and argument vector a proxied command becomes.
///
/// Built as a value rather than assembled at the spawn, so that the whole of
/// *"proxied to the exact Linux binary … with the original arguments"* is one
/// thing a test can read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPlan {
    program: PathBuf,
    arguments: Vec<OsString>,
}

impl ProxyPlan {
    /// `wsl.exe --distribution NAME --user root --exec <binary> <forwarded…>`.
    ///
    /// # Errors
    /// [`Failure::InvalidArgument`] for a distribution name that cannot be
    /// used at all.
    pub fn new(
        wsl: &WslExecutable,
        distribution: &str,
        linux_binary: &str,
        forwarded: Vec<OsString>,
    ) -> Result<Self, CliError> {
        validate_distribution_name(distribution).map_err(|source| wsl_failure(&source))?;
        let mut arguments: Vec<OsString> = [
            "--distribution",
            distribution,
            "--user",
            runner_manager_platform::wsl::probe::LINUX_USER,
            "--exec",
            linux_binary,
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        arguments.extend(forwarded);
        Ok(Self {
            program: wsl.path().to_path_buf(),
            arguments,
        })
    }

    /// The program that will be started.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The literal argument vector.
    #[must_use]
    #[allow(
        dead_code,
        reason = "read by the argument-vector proof in this file's tests, which is the                   whole of what `the original arguments` means"
    )]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// The child, configured.
    ///
    /// # The three streams are configured by NOT being configured
    ///
    /// [`std::process::Command`] defaults every stream to
    /// [`std::process::Stdio::inherit`] for `spawn`/`status`, so a command this
    /// function has not touched hands the child *this process's own* stdin,
    /// stdout and stderr. That is the requirement — "inherited stdin/stdout/
    /// stderr" — and it is met by the absence of three calls, which is why
    /// `the_proxy_configures_no_stream_of_its_own` reads this file and asserts
    /// no `Stdio` appears in it. A `piped()` here would not merely capture the
    /// output: it would deadlock any proxied command that writes more than a
    /// pipe buffer, because nothing in this process is reading.
    ///
    /// Nothing sets an environment variable or a working directory either, and
    /// [`std::process::Command::get_envs`] is empty as a result — the child
    /// inherits this process's environment unchanged, exactly as it would if
    /// the operator had typed `wsl.exe` themselves.
    #[must_use]
    pub fn command(&self) -> std::process::Command {
        let mut command = std::process::Command::new(&self.program);
        command.args(&self.arguments);
        command
    }
}

/// Runs a [`ProxyPlan`] and reports the child's exit code.
///
/// A trait so that the argument vector can be asserted without starting
/// `wsl.exe`, which no CI leg but the Windows one has.
pub trait ProxyRunner: fmt::Debug {
    /// Runs it.
    ///
    /// # Errors
    /// [`Failure::WslProvisioning`] when the program cannot be started or
    /// waited on.
    fn run(&self, plan: &ProxyPlan) -> Result<i32, CliError>;
}

/// Really starts the child, with this process's three streams.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostProxyRunner;

impl ProxyRunner for HostProxyRunner {
    fn run(&self, plan: &ProxyPlan) -> Result<i32, CliError> {
        let status = plan.command().status().map_err(|source| {
            CliError::with_remedy(
                Failure::WslProvisioning,
                format!(
                    "cannot start {} to carry this command into the distribution: {source}",
                    plan.program().display()
                ),
                "runner-manager wsl list",
            )
        })?;
        Ok(exit_code_of(&status))
    }
}

/// The number a proxied command exited with.
///
/// A child killed by a signal has no code of its own, and the shell convention
/// — `128 + signal` — is the one every script that reads `$?` already assumes.
/// Without this, a proxied command killed by `SIGTERM` would be reported as a
/// success, because `ExitStatus::code` is `None` there.
#[must_use]
fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    i32::from(Failure::WslProvisioning.code())
}

// ---------------------------------------------------------------------------
// The credential sink
// ---------------------------------------------------------------------------

/// Delivers one credential document to `auth receive` inside a distribution.
///
/// # The only door, and it is a pipe
///
/// `03-security-and-lifecycle.md` item 3: the document *"crosses the
/// Windows/Linux boundary only through an anonymous stdin pipe. It is absent
/// from argv, environment, provider records, logs, errors, status JSON,
/// temporary files and scheduled-task XML."* This type is where that is either
/// true or not, and three things make it true rather than reviewed:
///
/// * the document reaches the child only as
///   [`PipedInput::from_secret_text`], which is the sole way
///   [`runner_manager_platform::wsl::exec`] will give a child bytes;
/// * the argument vector is built here, from constants, and never from the
///   document — and `refuse_payload_in_argv` refuses the launch if the two ever
///   coincided;
/// * neither [`SecretSinkError`] variant this raises carries any part of it:
///   the `reason` is the child's own diagnostic, and `auth receive` prints
///   nothing about the value it was given.
#[derive(Debug)]
pub struct WslSecretSink<'invoker> {
    invoker: WslInvoker<'invoker>,
    distribution: String,
    binary: String,
    start_at: StartAt,
    /// How many documents were handed over. Read by the install transaction so
    /// that its report can say whether a credential was issued or adopted.
    delivered: usize,
}

impl<'invoker> WslSecretSink<'invoker> {
    /// A sink pointed at one distribution's `auth receive`.
    #[must_use]
    pub fn new(
        invoker: WslInvoker<'invoker>,
        distribution: impl Into<String>,
        binary: impl Into<String>,
        start_at: StartAt,
    ) -> Self {
        Self {
            invoker,
            distribution: distribution.into(),
            binary: binary.into(),
            start_at,
            delivered: 0,
        }
    }

    /// How many documents this delivered.
    #[must_use]
    pub fn delivered(&self) -> usize {
        self.delivered
    }

    /// What the destination is called, for a failure message.
    fn destination(&self) -> String {
        format!("{} in {}", self.binary, self.distribution)
    }

    /// The `--start-at` value `auth receive` is given.
    ///
    /// Spelled here, once, rather than at the call site: `receive` writes the
    /// store this names *and* records the start mode, so a value that
    /// disagreed with the `service install --start-at boot` two stages later
    /// would leave a credential the Linux daemon never reads.
    fn start_at_token(&self) -> &'static str {
        match self.start_at {
            StartAt::Boot => "boot",
            StartAt::Login => "login",
        }
    }
}

impl SecretSink for WslSecretSink<'_> {
    fn send(&mut self, document: &SecretString) -> Result<(), SecretSinkError> {
        let command = LinuxCommand::new(self.distribution.clone(), self.binary.clone())
            .args(["auth", "receive", "--start-at", self.start_at_token()])
            .with_input(ChildInput::Piped(PipedInput::from_secret_text(document)));

        let output = self.invoker.exec(command).map_err(|source| {
            // `source.to_string()` is safe to carry: no `WslError` variant
            // quotes a piped payload, and `SecretInCommandLine` documents that
            // it deliberately does not.
            SecretSinkError::Undeliverable {
                destination: self.destination(),
                reason: source.to_string(),
            }
        })?;

        if !output.success() {
            return Err(SecretSinkError::Refused {
                destination: self.destination(),
                reason: output.diagnostic(),
            });
        }
        self.delivered += 1;
        Ok(())
    }
}

/// `--host wsl:NAME auth login`.
///
/// # Errors
/// Everything the preflight and the device flow report.
fn brokered_login(
    context: &Context,
    host: &WslHost,
    distribution: &str,
    args: &super::AuthLoginArgs,
    styling: Styling,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this sign-in");
    let invoker = host.invoker();

    // The preflight comes first here for the same reason it does in the
    // install transaction: `03-security-and-lifecycle.md` requires that a
    // distribution which cannot hold the credential never causes one to be
    // issued. A refusal here has cost GitHub nothing and the operator nothing.
    let readiness =
        probe_readiness(&invoker, distribution).map_err(|source| wsl_failure(&source))?;

    // `boot` unless the operator says otherwise: a managed WSL host runs its
    // daemon from a systemd system unit, which has no login session to read a
    // user-scoped store from.
    let start_at = args.start_at.unwrap_or(StartAt::Boot);
    let mut sink = WslSecretSink::new(
        invoker,
        readiness.name(),
        DEFAULT_LINUX_DESTINATION,
        start_at,
    );

    writeln!(
        out,
        "Signing in for the WSL host {}. The credential this issues is independent of \
         this machine's own: GitHub invalidates both halves of a pair when either renews, \
         so two daemons cannot share one.",
        readiness.name()
    )
    .map_err(failed)?;
    out.flush().map_err(failed)?;

    let brokered = broker_user_credential(context, styling, out, &mut sink)?;
    report_brokered_credential(&brokered, readiness.name(), out)
}

/// The metadata half of a completed handoff, and nothing more.
///
/// # Errors
/// [`Failure::Unclassified`] when the report cannot be written.
fn report_brokered_credential(
    brokered: &BrokeredCredential,
    distribution: &str,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this sign-in");
    writeln!(out).map_err(failed)?;
    writeln!(
        out,
        "Stored in {distribution}'s own machine credential store. {brokered}"
    )
    .map_err(failed)?;
    writeln!(
        out,
        "Nothing was written on this machine: the document went straight to the \
         distribution's `auth receive` on a pipe."
    )
    .map_err(failed)
}

// ---------------------------------------------------------------------------
// Release assets
// ---------------------------------------------------------------------------

/// Where the exact-version Linux archive and its `SHA256SUMS` come from.
///
/// A seam, so that the install transaction's stage ordering can be asserted on
/// a CI leg with no network: the production implementation is the same
/// `SHA256SUMS`-then-archive pair `update` uses, and a test hands over a
/// document it wrote itself.
pub trait ReleaseAssets: fmt::Debug {
    /// Where these assets are, for a report and for a failure message.
    fn describe(&self) -> String;

    /// The release's `SHA256SUMS`.
    ///
    /// # Errors
    /// [`Failure::GithubUnavailable`] and [`Failure::UnusableResponse`].
    fn checksums(&self) -> Result<String, CliError>;

    /// Streams one asset to `into`.
    ///
    /// # Errors
    /// [`Failure::GithubUnavailable`] and [`Failure::LocalState`].
    fn download(&self, asset: &str, into: &Path) -> Result<(), CliError>;
}

/// The release GitHub published under `v<version>`.
#[derive(Debug)]
pub struct PublishedReleaseAssets {
    source: AssetSource,
    runtime: tokio::runtime::Runtime,
}

impl PublishedReleaseAssets {
    /// The assets of one exact version.
    ///
    /// # Errors
    /// [`Failure::InvalidArgument`] when the release-assets override is not
    /// usable, and [`Failure::Unclassified`] when the async runtime will not
    /// start.
    pub fn for_version(version: &str, err: &mut dyn Write) -> Result<Self, CliError> {
        Ok(Self {
            source: AssetSource::for_version(version, err)?,
            runtime: super::runtime()?,
        })
    }
}

impl ReleaseAssets for PublishedReleaseAssets {
    fn describe(&self) -> String {
        self.source.to_string()
    }

    fn checksums(&self) -> Result<String, CliError> {
        self.runtime
            .block_on(fetch_text(&self.source, "SHA256SUMS"))
    }

    fn download(&self, asset: &str, into: &Path) -> Result<(), CliError> {
        self.runtime.block_on(fetch_file(&self.source, asset, into))
    }
}

// ---------------------------------------------------------------------------
// The credential issuer
// ---------------------------------------------------------------------------

/// Runs the interactive device flow and hands the result to a sink.
///
/// A seam for the same reason [`ReleaseAssets`] is one: the install
/// transaction's ordering has to be assertable, and a real device flow needs a
/// person and a browser.
pub trait CredentialIssuer: fmt::Debug {
    /// Issues one **new** credential and delivers it.
    ///
    /// # Errors
    /// Every device-flow class, and [`Failure::SecretStore`] when the sink
    /// would not take the document.
    fn issue(
        &self,
        out: &mut dyn Write,
        sink: &mut dyn SecretSink,
    ) -> Result<BrokeredCredential, CliError>;
}

/// The real GitHub device flow, in this interactive Windows process.
#[derive(Debug)]
pub struct DeviceFlowIssuer<'context> {
    context: &'context Context,
    styling: Styling,
}

impl<'context> DeviceFlowIssuer<'context> {
    /// Binds the published App registration and this process's endpoints.
    #[must_use]
    pub fn new(context: &'context Context, styling: Styling) -> Self {
        Self { context, styling }
    }
}

impl CredentialIssuer for DeviceFlowIssuer<'_> {
    fn issue(
        &self,
        out: &mut dyn Write,
        sink: &mut dyn SecretSink,
    ) -> Result<BrokeredCredential, CliError> {
        broker_user_credential(self.context, self.styling, out, sink)
    }
}

// ---------------------------------------------------------------------------
// What `status` reports
// ---------------------------------------------------------------------------

/// One managed distribution's real state, as `wsl status --json` emits it.
///
/// Every field below is read from the distribution, from Task Scheduler, or
/// from the release this build belongs to. [`Self::provider_record`] is the one
/// exception and it is **advisory**: it contributes to [`Self::drift`] and to
/// nothing else, because `02-target-architecture.md` says a missing record
/// never licenses deletion and a present one never licenses a health claim.
#[derive(Debug, Clone, Serialize)]
pub struct WslStatusDocument {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub distribution: String,
    /// Whether this host can accept jobs: WSL2 up, the exact binary installed,
    /// a credential in its own store, the unit active, and the lifecycle task
    /// registered to this product and enabled.
    pub healthy: bool,
    /// The version this Windows build provisions, which is its own.
    pub expected_version: String,
    pub provider_record: Option<ProviderRecordSnapshot>,
    pub wsl: WslSnapshot,
    pub binary: BinarySnapshot,
    pub credential: CredentialSnapshot,
    pub service: ServiceSnapshot,
    pub lifecycle_task: TaskSnapshot,
    /// The Linux host's runner ceiling, when the Linux binary could report it.
    pub capacity: Option<u16>,
    /// Workload prerequisites that are not provisioning failures. Docker is
    /// the one this build knows about.
    pub diagnostics: Vec<Diagnostic>,
    /// Where the record and the host disagree. Empty when they agree, and
    /// empty when there is no record — an absent record is not drift.
    pub drift: Vec<String>,
    /// The constraint `02-target-architecture.md` requires status to state
    /// explicitly, rather than leave an operator to discover after a reboot.
    pub availability: &'static str,
}

/// The sentence every status document carries about when this host exists.
///
/// `02-target-architecture.md`: WSL distributions are registered per user, so
/// "this feature promises unattended Linux availability after that user's
/// logon, not before any interactive logon after a Windows reboot. Status
/// states that constraint explicitly."
pub const AVAILABILITY_NOTE: &str = "This host is available after the owning Windows account logs on, because a WSL \
     distribution is registered per user. It does not come up between a Windows reboot and \
     the first interactive logon.";

#[derive(Debug, Clone, Serialize)]
pub struct ProviderRecordSnapshot {
    pub schema_version: u32,
    pub distribution: String,
    pub task_name: String,
    pub installed_version: String,
    pub last_verified: DateTime<Utc>,
}

impl From<&WslProviderRecord> for ProviderRecordSnapshot {
    fn from(record: &WslProviderRecord) -> Self {
        Self {
            schema_version: record.schema_version,
            distribution: record.distribution.clone(),
            task_name: record.task_name.clone(),
            installed_version: record.installed_version.clone(),
            last_verified: record.last_verified,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WslSnapshot {
    /// Whether the distribution is installed, WSL2, root-capable and running
    /// systemd — everything the provisioning preflight asks.
    pub ready: bool,
    pub installed: bool,
    pub wsl_version: Option<u8>,
    pub default: Option<bool>,
    pub architecture: Option<String>,
    pub machine: Option<String>,
    pub systemd: Option<String>,
    /// Why `ready` is false, in the words of the check that refused.
    pub problem: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinarySnapshot {
    pub path: String,
    pub installed: bool,
    pub version: Option<String>,
    /// Whether the installed version is the one this Windows build provisions.
    pub matches_expected: bool,
    pub problem: Option<String>,
}

/// Whether the **distribution's own** store holds a credential.
///
/// Never this machine's: nothing here loads the Windows store, and the value
/// is a boolean read out of the Linux binary's `status --json`, which is
/// itself documented to report presence rather than the token.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialSnapshot {
    pub present: bool,
    pub unreadable: Option<String>,
    pub store_scope: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceSnapshot {
    pub unit: String,
    /// `systemctl is-enabled` in its own word, or null when it could not be
    /// asked.
    pub enabled: Option<String>,
    /// `systemctl is-active` in its own word.
    pub active: Option<String>,
    /// The version reported by the product-owned binary registered for the
    /// service, when the Linux status command could inspect it.
    pub binary_version: Option<String>,
    pub matches_expected: bool,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskSnapshot {
    pub name: String,
    pub registered: bool,
    /// Whether the registration carries this product's marker. A task of this
    /// name that does not is never changed and never removed.
    pub product_owned: bool,
    pub enabled: bool,
    pub running: bool,
    pub command: Option<String>,
    pub arguments: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub name: String,
    pub available: bool,
    pub detail: String,
}

impl WslStatusDocument {
    /// The one line an operator reads first.
    #[must_use]
    pub fn headline(&self) -> String {
        if self.healthy {
            format!("{} is a healthy managed runner host.", self.distribution)
        } else {
            format!(
                "{} is not ready to accept jobs. Every line below is read from the \
                 distribution, not from this machine's record.",
                self.distribution
            )
        }
    }

    /// The named parts that are not yet in place, for a failure message.
    ///
    /// # A distribution that is not ready reports one problem, not six
    ///
    /// When the preflight refuses — WSL1, no systemd, no root — nothing else
    /// was asked, so every other field is at its default and reporting them
    /// would list five fabricated failures beside the one real one. An
    /// operator who reads "no credential, no service, no binary" about a WSL1
    /// distribution goes looking for four problems that do not exist.
    #[must_use]
    pub fn unhealthy_parts(&self) -> Vec<String> {
        let mut parts = Vec::new();
        if !self.wsl.ready {
            parts.push(format!(
                "WSL: {}",
                self.wsl.problem.as_deref().unwrap_or("not ready")
            ));
            return parts;
        }
        if !self.binary.installed {
            parts.push(format!(
                "the Linux binary at {}: {}",
                self.binary.path,
                self.binary.problem.as_deref().unwrap_or("not installed")
            ));
        } else if !self.binary.matches_expected {
            parts.push(format!(
                "the Linux binary is {} and this build provisions {}",
                self.binary.version.as_deref().unwrap_or("unknown"),
                self.expected_version
            ));
        }
        if !self.credential.present {
            parts.push(match &self.credential.unreadable {
                Some(why) => format!("the distribution's credential store: {why}"),
                None => "the distribution holds no credential of its own".to_string(),
            });
        }
        if !self.service.healthy {
            parts.push(format!(
                "the systemd unit {} is {}; its binary is {} (expected {})",
                self.service.unit,
                self.service.active.as_deref().unwrap_or("not readable"),
                self.service
                    .binary_version
                    .as_deref()
                    .unwrap_or("not readable"),
                self.expected_version,
            ));
        }
        if !self.lifecycle_task.registered {
            parts.push(format!(
                "the Windows lifecycle task {} is not registered",
                self.lifecycle_task.name
            ));
        } else if !self.lifecycle_task.product_owned {
            parts.push(format!(
                "the task {} is not this product's ({PRODUCT_MARKER})",
                self.lifecycle_task.name
            ));
        } else if !self.lifecycle_task.enabled {
            parts.push(format!("the task {} is disabled", self.lifecycle_task.name));
        }
        parts
    }
}

// ---------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------

/// The fields `wsl status` reads out of the Linux binary's own `status --json`.
///
/// A narrow mirror rather than a shared type: `status --json` is a
/// compatibility surface with its own version, the Linux binary answering may
/// be a different build from this one, and `deny_unknown_fields` here would
/// turn every additive change over there into a failure over here.
#[derive(Debug, Clone, serde::Deserialize)]
struct LinuxStatus {
    product: LinuxProduct,
    credential: LinuxCredential,
    host: LinuxHost,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct LinuxProduct {
    version: String,
    #[serde(default)]
    service_binary_version: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct LinuxCredential {
    present: bool,
    unreadable: Option<String>,
    store_scope: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct LinuxHost {
    capacity: u16,
}

/// Everything `wsl status` and the install read-back report.
///
/// Tolerant by construction: a distribution that is not installed, or has no
/// binary in it, produces a document that says so rather than an error. The
/// caller decides whether an unhealthy answer is a failure — `status` prints
/// it and exits zero, `install` prints it and exits
/// [`Failure::WslProvisioning`].
///
/// # Errors
/// [`Failure::LocalState`] when the provider record exists and cannot be read,
/// and [`Failure::InvalidArgument`] for a name that cannot be used at all.
/// Nothing else: every probe failure is *reported* rather than raised.
pub fn probe(
    host: &WslHost,
    paths: &AppPaths,
    distribution: &str,
    linux_binary: &str,
    unit: &str,
    expected_version: &str,
    now: DateTime<Utc>,
) -> Result<WslStatusDocument, CliError> {
    validate_distribution_name(distribution).map_err(|source| wsl_failure(&source))?;
    let record =
        WslProviderRecord::read(paths, distribution).map_err(|source| wsl_failure(&source))?;
    let identity = LifecycleTaskIdentity::for_distribution(distribution)
        .map_err(|source| wsl_failure(&source))?;

    let invoker = host.invoker();
    let readiness = probe_readiness(&invoker, distribution);
    let wsl = wsl_snapshot(&invoker, distribution, &readiness);

    let mut binary = BinarySnapshot {
        path: linux_binary.to_string(),
        installed: false,
        version: None,
        matches_expected: false,
        problem: None,
    };
    let mut credential = CredentialSnapshot {
        present: false,
        unreadable: None,
        store_scope: None,
    };
    let mut service = ServiceSnapshot {
        unit: unit.to_string(),
        enabled: None,
        active: None,
        binary_version: None,
        matches_expected: false,
        healthy: false,
    };
    let mut capacity = None;
    let mut diagnostics = Vec::new();

    if wsl.ready {
        match linux_status(&invoker, distribution, linux_binary) {
            Ok(LinuxAnswer::Reported(status)) => {
                binary.installed = true;
                binary.matches_expected = status.product.version == expected_version;
                binary.version = Some(status.product.version);
                service.matches_expected =
                    status.product.service_binary_version.as_deref() == Some(expected_version);
                service.binary_version = status.product.service_binary_version;
                credential.present = status.credential.present;
                credential.unreadable = status.credential.unreadable;
                credential.store_scope = status.credential.store_scope;
                capacity = Some(status.host.capacity);
            }
            // The child's diagnostic, not a claim about the file: a binary
            // that is there and refused would otherwise be reported as absent,
            // and the operator sent to reinstall something already installed.
            Ok(LinuxAnswer::Unusable(why)) => {
                binary.problem = Some(format!(
                    "there is no usable runner-manager at {linux_binary} inside \
                     {distribution}: {why}"
                ));
            }
            Err(problem) => binary.problem = Some(problem),
        }

        service.enabled = systemctl_word(&invoker, distribution, &["is-enabled", unit]);
        service.active = systemctl_word(&invoker, distribution, &["is-active", unit]);
        service.healthy = service.active.as_deref() == Some("active") && service.matches_expected;

        diagnostics.push(docker_diagnostic(&invoker, distribution));
    }

    let task = host.tasks().query(&identity);
    let lifecycle_task =
        task_snapshot(identity.name(), task.as_ref().ok().and_then(Option::as_ref));

    let healthy = wsl.ready
        && binary.installed
        && binary.matches_expected
        && credential.present
        && service.healthy
        && lifecycle_task.registered
        && lifecycle_task.product_owned
        && lifecycle_task.enabled;

    let drift = drift_between(
        record.as_ref(),
        wsl.ready,
        &binary,
        &lifecycle_task,
        distribution,
    );

    Ok(WslStatusDocument {
        schema_version: WSL_STATUS_SCHEMA_VERSION,
        generated_at: now,
        distribution: distribution.to_string(),
        healthy,
        expected_version: expected_version.to_string(),
        provider_record: record.as_ref().map(ProviderRecordSnapshot::from),
        wsl,
        binary,
        credential,
        service,
        lifecycle_task,
        capacity,
        diagnostics,
        drift,
        availability: AVAILABILITY_NOTE,
    })
}

/// The distribution half of the document.
fn wsl_snapshot(
    invoker: &WslInvoker<'_>,
    distribution: &str,
    readiness: &Result<DistributionReadiness, WslError>,
) -> WslSnapshot {
    match readiness {
        Ok(ready) => WslSnapshot {
            ready: true,
            installed: true,
            wsl_version: Some(ready.wsl_version()),
            default: Some(ready.is_default()),
            architecture: Some(format!("{:?}", ready.architecture()).to_lowercase()),
            machine: Some(ready.machine().to_string()),
            systemd: Some(ready.systemd().to_string()),
            problem: None,
        },
        Err(problem) => {
            // The table is read again rather than inferred from the error: a
            // distribution can be installed and still fail the preflight — WSL1
            // is exactly that — and "installed: false" would be a lie about it.
            let installed = invoker
                .list()
                .map(|table| table.exactly(distribution).is_ok())
                .unwrap_or(false);
            WslSnapshot {
                ready: false,
                installed,
                wsl_version: None,
                default: None,
                architecture: None,
                machine: None,
                systemd: None,
                problem: Some(problem.to_string()),
            }
        }
    }
}

/// What the Linux binary said when it was asked for `status --json`.
///
/// # Why `Unusable` carries a sentence rather than being an absence
///
/// A missing program and a program that ran and refused are the same exit
/// status to this process, and a caller that read either as "there is no
/// runner-manager here" would state, about a binary that is plainly installed,
/// that it is not. The child's own diagnostic is the only thing that tells the
/// two apart, so it is carried rather than dropped: every caller reports it,
/// and [`Provisioner::settle_the_credential`] refuses on it instead of reading
/// "could not ask" as "holds no credential".
#[derive(Debug)]
enum LinuxAnswer {
    /// It answered, and this build could read the answer.
    Reported(LinuxStatus),
    /// There is no usable runner-manager there, in the child's own words.
    Unusable(String),
}

/// The Linux binary's own `status --json`.
///
/// # Errors
/// A sentence for [`BinarySnapshot::problem`] when the binary is there and its
/// answer could not be used.
fn linux_status(
    invoker: &WslInvoker<'_>,
    distribution: &str,
    binary: &str,
) -> Result<LinuxAnswer, String> {
    let command = LinuxCommand::new(distribution, binary).args(["status", "--json"]);
    let output = match invoker.exec(command) {
        Ok(output) => output,
        Err(source) => return Err(source.to_string()),
    };
    if !output.success() {
        return Ok(LinuxAnswer::Unusable(output.diagnostic()));
    }
    serde_json::from_slice::<LinuxStatus>(output.stdout())
        .map(LinuxAnswer::Reported)
        .map_err(|source| {
            format!(
                "the runner-manager at {binary} in {distribution} answered `status --json` with \
             something this build cannot read: {source}"
            )
        })
}

/// One word from `systemctl`, whatever its exit code.
///
/// `is-enabled` and `is-active` both exit non-zero for perfectly informative
/// answers — `disabled`, `inactive`, `failed` — so the word is read and the
/// code is not.
fn systemctl_word(
    invoker: &WslInvoker<'_>,
    distribution: &str,
    arguments: &[&str],
) -> Option<String> {
    let command = LinuxCommand::new(distribution, "systemctl").args(arguments.iter().copied());
    let output = invoker.exec(command).ok()?;
    let word = output.stdout_text();
    if word.is_empty() {
        let stderr = output.stderr_text();
        return (!stderr.is_empty()).then_some(stderr);
    }
    Some(word)
}

/// The version of systemd's main service process, not merely the executable
/// currently registered for the next start.
///
/// During a cooperative handover the daemon replaces its private executable
/// just before it exits. Looking only at `status --json` can therefore observe
/// the new file while the old daemon is still the unit's main process. `/proc`
/// follows the live process and makes the controller wait for systemd's restart
/// before it says the host resumed service.
fn service_main_version(
    invoker: &WslInvoker<'_>,
    distribution: &str,
    unit: &str,
) -> Option<String> {
    let pid = systemctl_word(
        invoker,
        distribution,
        &["show", "--property=MainPID", "--value", unit],
    )?
    .parse::<u32>()
    .ok()
    .filter(|pid| *pid != 0)?;
    let output = invoker
        .exec(LinuxCommand::new(distribution, format!("/proc/{pid}/exe")).args(["--version"]))
        .ok()?;
    if !output.success() {
        return None;
    }
    output
        .stdout_text()
        .split_whitespace()
        .last()
        .map(str::to_owned)
}

/// Whether a release contains the daemon's source-watch handover protocol.
///
/// Status reports release versions, which are normal SemVer releases here.
/// Unknown forms are intentionally treated as legacy: guessing that an active
/// daemon can drain would be less safe than declining the update.
fn supports_cooperative_service_handover(version: Option<&str>) -> bool {
    let Some(version) = version else {
        return false;
    };
    let core = version.split(['-', '+']).next().unwrap_or_default();
    if core != version {
        return false;
    }
    let mut parts = core.split('.');
    let parsed = [
        parts.next().and_then(|part| part.parse::<u64>().ok()),
        parts.next().and_then(|part| part.parse::<u64>().ok()),
        parts.next().and_then(|part| part.parse::<u64>().ok()),
    ];
    if parts.next().is_some() {
        return false;
    }
    let [Some(major), Some(minor), Some(patch)] = parsed else {
        return false;
    };
    [major, minor, patch] >= FIRST_COOPERATIVE_SERVICE_HANDOVER
}

/// Whether Docker can run a container in this distribution.
///
/// **A diagnostic and never a gate.** Nothing in the provisioning transaction
/// consults it: a runner host with no Docker still accepts every job that does
/// not use a container, and refusing to provision one would be this tool
/// deciding what workloads its operator is allowed to run.
fn docker_diagnostic(invoker: &WslInvoker<'_>, distribution: &str) -> Diagnostic {
    let command = LinuxCommand::new(distribution, "docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .with_timeout(DOCKER_TIMEOUT);
    let (available, detail) = match invoker.exec(command) {
        Ok(output) if output.success() => (true, format!("engine {}", output.stdout_text())),
        Ok(output) => (
            false,
            format!(
                "not usable here, so container jobs would fail while ordinary jobs run: {}",
                output.diagnostic()
            ),
        ),
        Err(source) => (false, format!("could not be asked: {source}")),
    };
    Diagnostic {
        name: "docker".to_string(),
        available,
        detail,
    }
}

/// The Task Scheduler half of the document.
fn task_snapshot(name: &str, task: Option<&RegisteredTask>) -> TaskSnapshot {
    match task {
        Some(task) => TaskSnapshot {
            name: name.to_string(),
            registered: true,
            product_owned: task.is_product_owned(),
            enabled: task.enabled(),
            running: task.running(),
            command: Some(task.command().to_string()),
            arguments: Some(task.arguments().to_string()),
        },
        None => TaskSnapshot {
            name: name.to_string(),
            registered: false,
            product_owned: false,
            enabled: false,
            running: false,
            command: None,
            arguments: None,
        },
    }
}

/// Where the record and the host disagree.
///
/// An absent record is **not** drift: `wsl status` on an unmanaged
/// distribution is a legitimate question with a legitimate answer, and a
/// record is never the authority for anything here.
///
/// Neither is a question that was never asked. `wsl_ready` is
/// [`WslSnapshot::ready`], and when it is false the distribution was never
/// interrogated about its binary — so an absent [`BinarySnapshot::version`]
/// says nothing about the host. Reporting it as drift is the same fabrication
/// [`WslStatusDocument::unhealthy_parts`] exists to avoid: it would tell the
/// operator of a WSL1 or systemd-less distribution that their Linux binary is
/// gone, which nothing here has looked for.
fn drift_between(
    record: Option<&WslProviderRecord>,
    wsl_ready: bool,
    binary: &BinarySnapshot,
    task: &TaskSnapshot,
    distribution: &str,
) -> Vec<String> {
    let Some(record) = record else {
        return Vec::new();
    };
    let mut drift = Vec::new();
    if record.distribution != distribution {
        drift.push(format!(
            "the record names the distribution {:?} and this asked about {distribution:?}",
            record.distribution
        ));
    }
    if record.task_name != task.name {
        drift.push(format!(
            "the record names the task {:?} and this build derives {:?}",
            record.task_name, task.name
        ));
    }
    if !task.registered {
        drift.push(format!(
            "the record says this host is managed and no task named {} is registered",
            task.name
        ));
    }
    match &binary.version {
        Some(version) if *version != record.installed_version => drift.push(format!(
            "the record says runner-manager {} was installed and the distribution reports {version}",
            record.installed_version
        )),
        None if wsl_ready => drift.push(format!(
            "the record says runner-manager {} was installed and the distribution has no \
             readable binary at {}",
            record.installed_version, binary.path
        )),
        _ => {}
    }
    drift
}

// ---------------------------------------------------------------------------
// The install transaction
// ---------------------------------------------------------------------------

/// The ordered stages of `wsl install`.
///
/// Named rather than implied so that a failure can say which one it happened
/// in, and so that the ordering test asserts a sequence rather than a shape.
/// The order is `02-target-architecture.md`'s, one stage per numbered step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// WSL2, root, architecture, systemd, and the task's ownership. Mutates
    /// nothing and issues no credential.
    Preflight,
    /// `SHA256SUMS`, the exact-version archive, and its digest.
    Artifact,
    /// The atomic replacement of the Linux binary.
    Binary,
    /// An existing Linux credential is preserved; an absent one is issued here
    /// and delivered on a pipe.
    Credential,
    /// Only when `--capacity` was supplied.
    Capacity,
    /// The Linux systemd unit.
    Service,
    /// The Windows login task.
    LifecycleTask,
    /// The provider record and the read-back that decides whether this
    /// succeeded.
    Verification,
}

impl Stage {
    /// Every stage, in the order they run.
    ///
    /// `Failure::ALL`'s reasoning, one layer up: the sequence is the contract
    /// `02-target-architecture.md` fixes, and a test that iterates it is what
    /// keeps a ninth stage from arriving without a label of its own.
    #[allow(
        dead_code,
        reason = "read by the stage-label proof in this file's tests"
    )]
    pub const ALL: &'static [Stage] = &[
        Stage::Preflight,
        Stage::Artifact,
        Stage::Binary,
        Stage::Credential,
        Stage::Capacity,
        Stage::Service,
        Stage::LifecycleTask,
        Stage::Verification,
    ];

    /// The word a progress line and a failure both use.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Artifact => "release artifact",
            Self::Binary => "Linux binary",
            Self::Credential => "credential",
            Self::Capacity => "capacity",
            Self::Service => "Linux service",
            Self::LifecycleTask => "Windows lifecycle task",
            Self::Verification => "verification",
        }
    }
}

/// What one run of the transaction did, for the report and for the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    /// The version installed inside the distribution.
    pub version: String,
    /// Whether the Linux binary was replaced, or was already this version.
    pub binary_replaced: bool,
    /// Whether a new credential was issued, or an existing one adopted.
    pub credential_issued: bool,
    /// Whether `host set-capacity` ran.
    pub capacity_set: Option<u16>,
    /// Whether `service install` ran, or an enabled unit was adopted.
    pub service_installed: bool,
}

/// The eight-stage convergent install transaction.
///
/// # Convergent, which is a stronger promise than idempotent
///
/// Every stage either finds the host already in the state it wants and leaves
/// it alone, or moves it there. So a rerun after any failure is safe and is the
/// documented remedy — `03-security-and-lifecycle.md`'s failure table is a
/// table of exactly that. In particular a rerun never issues a second
/// credential over a healthy one, never reinstalls an enabled unit, and never
/// changes a capacity that was not asked for.
#[derive(Debug)]
pub struct Provisioner<'a> {
    /// The WSL adapter, real or scripted.
    pub host: &'a WslHost,
    /// Where the exact-version archive comes from.
    pub assets: &'a dyn ReleaseAssets,
    /// Who runs the device flow when a credential has to be issued.
    pub issuer: &'a dyn CredentialIssuer,
    /// This machine's config directory, for the provider record.
    pub paths: &'a AppPaths,
    /// The Windows account the login task is registered for.
    pub principal: TaskPrincipal,
    /// The version to install, which is this build's own.
    pub version: String,
    /// Where the binary goes inside the distribution.
    pub linux_binary: String,
    /// The systemd unit the Linux service registers.
    pub unit: String,
    /// When this ran.
    pub now: DateTime<Utc>,
}

impl Provisioner<'_> {
    /// Runs every stage, in order, and reports the state it left behind.
    ///
    /// # Errors
    /// The class of whichever stage refused. A [`Stage::Preflight`] failure
    /// means nothing was changed; every later one names what it left behind in
    /// its own message, and rerunning is safe in all of them.
    pub fn install(
        &self,
        args: &WslInstallArgs,
        out: &mut dyn Write,
    ) -> Result<(WslStatusDocument, InstallOutcome), CliError> {
        let failed = write_failed("this install");
        let invoker = self.host.invoker();

        // -- Stage 1: preflight --------------------------------------------
        // Every question, before the first answer is acted on.
        let readiness = probe_readiness(&invoker, &args.distribution)
            .map_err(|source| self.stage_failure(Stage::Preflight, &source))?;
        let distribution = readiness.name().to_string();
        let identity = LifecycleTaskIdentity::for_distribution(&distribution)
            .map_err(|source| self.stage_failure(Stage::Preflight, &source))?;
        refuse_a_foreign_task(self.host, &identity)
            .map_err(|source| self.stage_failure(Stage::Preflight, &source))?;

        writeln!(out, "runner-manager wsl install").map_err(failed)?;
        writeln!(out, "  distribution              {distribution}").map_err(failed)?;
        writeln!(
            out,
            "  preflight                 WSL{}, {} ({}), systemd {}",
            readiness.wsl_version(),
            format!("{:?}", readiness.architecture()).to_lowercase(),
            readiness.machine(),
            readiness.systemd()
        )
        .map_err(failed)?;
        writeln!(out, "  version to install        {}", self.version).map_err(failed)?;
        writeln!(
            out,
            "  release assets            {}",
            self.assets.describe()
        )
        .map_err(failed)?;
        out.flush().map_err(failed)?;

        // -- Stage 2: the exact-version artifact ---------------------------
        let (target, artifact, archive, _work) = self.resolve_artifact(&readiness)?;

        // -- Stage 3: the binary -------------------------------------------
        // Asked *before* the install so the report can say "already 0.4.0"
        // rather than describe a replacement that replaced nothing.
        let installed_before = match linux_status(&invoker, &distribution, &self.linux_binary) {
            Ok(LinuxAnswer::Reported(status)) => Some(status),
            // Nothing usable answered, so there is nothing to leave alone.
            Ok(LinuxAnswer::Unusable(_)) | Err(_) => None,
        };
        let binary_replaced = installed_before
            .as_ref()
            .is_none_or(|status| status.product.version != self.version);
        let service_was_active =
            systemctl_word(&invoker, &distribution, &["is-active", &self.unit]).as_deref()
                == Some("active");
        let service_version = installed_before
            .as_ref()
            .and_then(|status| status.product.service_binary_version.as_deref());
        // A version present before the source is changed is enough to reject a
        // known legacy service without changing anything in the distribution.
        // Older source binaries did not report the private-copy version at
        // all, so that case is re-checked after their source is atomically
        // updated below. Updating the source cannot signal or stop a legacy
        // service and is safe to leave in place when its private copy is
        // subsequently refused.
        if service_was_active
            && service_version.is_some_and(|version| version != self.version)
            && !supports_cooperative_service_handover(service_version)
        {
            return Err(CliError::with_remedy(
                Failure::WslProvisioning,
                format!(
                    "the active systemd unit {} runs service binary {} which predates the \
                     cooperative upgrade handover. It was not stopped, and neither the Linux \
                     binary nor its service copy was replaced.",
                    self.unit,
                    service_version.unwrap_or("of an unknown version"),
                ),
                "runner-manager wsl status --distribution <NAME>",
            ));
        }

        if binary_replaced {
            writeln!(out, "Installing {} into {distribution}", artifact.asset()).map_err(failed)?;
            out.flush().map_err(failed)?;
            BinaryInstaller::new(
                &invoker,
                distribution.clone(),
                LinuxBinaryPath::parse(&self.linux_binary)
                    .map_err(|source| self.stage_failure(Stage::Binary, &source))?,
            )
            .install(&archive, &artifact, &target)
            .map_err(|source| self.stage_failure(Stage::Binary, &source))?;
        } else {
            writeln!(
                out,
                "{distribution} already runs runner-manager {}; the binary is left alone.",
                self.version
            )
            .map_err(failed)?;
        }

        let service_needs_handover = if service_was_active {
            let service_version = match linux_status(&invoker, &distribution, &self.linux_binary) {
                Ok(LinuxAnswer::Reported(status)) => status.product.service_binary_version,
                Ok(LinuxAnswer::Unusable(why)) => {
                    return Err(CliError::with_remedy(
                        Failure::WslProvisioning,
                        format!(
                            "{}: the updated Linux binary would not report the active service \
                             copy, so this cannot prove that it supports a safe handover: {why}",
                            stage_prefix(Stage::Service)
                        ),
                        "runner-manager wsl status --distribution <NAME>",
                    ));
                }
                Err(why) => {
                    return Err(CliError::with_remedy(
                        Failure::WslProvisioning,
                        format!(
                            "{}: cannot read the active service copy after replacing the Linux \
                             source binary: {why}",
                            stage_prefix(Stage::Service)
                        ),
                        "runner-manager wsl status --distribution <NAME>",
                    ));
                }
            };
            if service_version.as_deref() == Some(self.version.as_str()) {
                false
            } else if !supports_cooperative_service_handover(service_version.as_deref()) {
                return Err(CliError::with_remedy(
                    Failure::WslProvisioning,
                    format!(
                        "the active systemd unit {} runs service binary {} which predates the \
                         cooperative upgrade handover. It was not stopped and its private copy \
                         was not replaced; the Linux source binary is safe to leave in place.",
                        self.unit,
                        service_version
                            .as_deref()
                            .unwrap_or("of an unknown version"),
                    ),
                    "runner-manager wsl status --distribution <NAME>",
                ));
            } else {
                true
            }
        } else {
            false
        };

        // An active private service copy upgrades itself: replacing its source
        // causes the daemon to stop admitting jobs, wait for the local attempt
        // journal to become empty with no deadline, replace its own copy and
        // exit for systemd to restart it. This controller deliberately never
        // uses `systemctl stop`; that is a different, sixty-second shutdown
        // path and systemd may signal the runner child in the service cgroup.
        if service_needs_handover {
            self.wait_for_cooperative_service_handover(&invoker, &distribution, out)?;
        }

        // -- Stage 4: the credential ---------------------------------------
        let credential_issued = self.settle_the_credential(&invoker, &distribution, out)?;

        // -- Stage 5: capacity ---------------------------------------------
        // ONLY when it was supplied. A capacity comes from an observed
        // workload measurement; inferring one here would overwrite a number
        // its operator chose.
        if let Some(capacity) = args.capacity {
            invoker
                .exec_ok(
                    "set the Linux host's capacity",
                    self.linux(&distribution)
                        .args(["host", "set-capacity", &capacity.to_string()]),
                )
                .map_err(|source| self.stage_failure(Stage::Capacity, &source))?;
            writeln!(out, "Capacity set to {capacity}.").map_err(failed)?;
        }

        // -- Stage 6: the Linux service ------------------------------------
        let service_installed = self.settle_the_service(&invoker, &distribution, out)?;

        // -- Stage 7: the Windows lifecycle task ---------------------------
        let task = LifecycleTask::new(
            identity.clone(),
            self.principal.clone(),
            self.host.executable(),
            self.linux_binary.clone(),
        );
        let tasks = self.host.tasks();
        tasks
            .register(&task)
            .map_err(|source| self.stage_failure(Stage::LifecycleTask, &source))?;
        // Started now as well as at logon: the operator asked for a runner
        // host, and one that only exists after the next sign-out would look
        // broken for the rest of today.
        tasks
            .start(&identity)
            .map_err(|source| self.stage_failure(Stage::LifecycleTask, &source))?;
        writeln!(
            out,
            "Lifecycle task {} registered and started.",
            identity.name()
        )
        .map_err(failed)?;
        out.flush().map_err(failed)?;

        // -- Stage 8: the record, then the read-back -----------------------
        // The record is written before the read-back so that a host which is
        // provisioned but unhealthy is still one `wsl detach` can clean up.
        // It claims nothing about health: `last_verified` is when this looked,
        // and `probe` never consults it for an answer.
        WslProviderRecord::new(
            distribution.clone(),
            identity.name(),
            self.version.clone(),
            self.now,
        )
        .write(self.paths)
        .map_err(|source| self.stage_failure(Stage::Verification, &source))?;

        let document = probe(
            self.host,
            self.paths,
            &distribution,
            &self.linux_binary,
            &self.unit,
            &self.version,
            self.now,
        )?;

        Ok((
            document,
            InstallOutcome {
                version: self.version.clone(),
                binary_replaced,
                credential_issued,
                capacity_set: args.capacity,
                service_installed,
            },
        ))
    }

    /// Stage 2, whole: the checksum document, the exact release, and the
    /// downloaded archive.
    ///
    /// The [`tempfile::TempDir`] is returned with the path because dropping it
    /// deletes the archive, and the caller needs it alive until the install has
    /// read it.
    #[allow(
        clippy::type_complexity,
        reason = "four values that belong to one stage"
    )]
    fn resolve_artifact(
        &self,
        readiness: &DistributionReadiness,
    ) -> Result<(ReleaseTarget, PublishedArtifact, PathBuf, tempfile::TempDir), CliError> {
        let target = linux_target(readiness.name(), readiness.architecture())
            .map_err(|source| self.stage_failure(Stage::Artifact, &source))?;
        let document = self
            .assets
            .checksums()
            .map_err(|failure| in_stage(Stage::Artifact, failure))?;
        let artifact = select_exact_release(&document, &target, &self.version)
            .map_err(|source| self.stage_failure(Stage::Artifact, &source))?;

        let work = tempfile::tempdir().map_err(|source| {
            CliError::new(
                Failure::LocalState,
                format!("cannot create a temporary directory to download into: {source}"),
            )
        })?;
        let archive = work.path().join(artifact.asset());
        self.assets
            .download(artifact.asset(), &archive)
            .map_err(|failure| in_stage(Stage::Artifact, failure))?;
        Ok((target, artifact, archive, work))
    }

    /// Stage 4: adopt a credential the distribution already has, or issue one.
    ///
    /// # A healthy Linux store is never replaced
    ///
    /// `03-security-and-lifecycle.md` guarantee 1: *"A WSL host receives a
    /// newly issued credential unless its own Linux machine store is already
    /// authenticated."* So this asks the distribution first, and the device
    /// flow only happens on the `false` branch — which is also why re-running
    /// `wsl install` on a working host never sends its operator to a browser.
    ///
    /// The Windows store is not read on either branch. It is not reachable
    /// from here: the issuer is handed a sink and nothing else.
    fn settle_the_credential(
        &self,
        invoker: &WslInvoker<'_>,
        distribution: &str,
        out: &mut dyn Write,
    ) -> Result<bool, CliError> {
        let failed = write_failed("this install");
        let answer =
            linux_status(invoker, distribution, &self.linux_binary).map_err(|problem| {
                CliError::new(
                    Failure::WslProvisioning,
                    format!("{}: {problem}", stage_prefix(Stage::Credential)),
                )
            })?;

        // The binary landed one stage ago, so a refusal here is not "there is
        // no host to ask" -- it is "the host would not say". Guarantee 1 is
        // about not issuing over a credential this cannot see, and a status
        // that never answered hides one exactly as an unreadable store does.
        // Reading it as absence would mint a second credential and, because
        // GitHub invalidates both halves of a pair when either renews, destroy
        // the one the distribution was already working with.
        let status = match answer {
            LinuxAnswer::Reported(status) => status,
            LinuxAnswer::Unusable(why) => {
                return Err(CliError::with_remedy(
                    Failure::WslProvisioning,
                    format!(
                        "{}: the runner-manager at {} in {distribution} would not answer \
                         `status --json`, so this cannot tell whether the distribution already \
                         holds a credential and will not issue one blind: {why}",
                        stage_prefix(Stage::Credential),
                        self.linux_binary
                    ),
                    "runner-manager wsl status --distribution <NAME>",
                ));
            }
        };

        if status.credential.present {
            writeln!(
                out,
                "{distribution} already holds its own credential; it is left untouched."
            )
            .map_err(failed)?;
            return Ok(false);
        }
        if let Some(why) = status.credential.unreadable {
            return Err(CliError::with_remedy(
                Failure::SecretStore,
                format!(
                    "{}: {distribution}'s credential store could not be read, so this cannot \
                     tell whether it already holds a credential and will not issue one over a \
                     value it cannot see: {why}",
                    stage_prefix(Stage::Credential)
                ),
                "runner-manager wsl status --distribution <NAME>",
            ));
        }

        let mut sink = WslSecretSink::new(
            *invoker,
            distribution,
            self.linux_binary.clone(),
            StartAt::Boot,
        );
        writeln!(
            out,
            "{distribution} holds no credential of its own, so this signs in for it now. \
             The credential is issued to the distribution and is never stored here."
        )
        .map_err(failed)?;
        out.flush().map_err(failed)?;

        let brokered = self
            .issuer
            .issue(out, &mut sink)
            .map_err(|failure| in_stage(Stage::Credential, failure))?;
        writeln!(out, "Credential delivered. {brokered}").map_err(failed)?;
        // The sink's own count, not `true`: what the report claims about this
        // host's credential is what the receiver actually took.
        Ok(sink.delivered() > 0)
    }

    /// Waits until systemd is running the replacement after its daemon-owned
    /// cooperative handover.
    ///
    /// The service's source-file watch is the request and its `Upgrade` drain
    /// is the acknowledgement. It waits on the local journal in the daemon;
    /// this observer has no deadline because no timeout is worth terminating a
    /// workflow. The running-process check is necessary because the private
    /// file changes immediately before the old daemon exits.
    fn wait_for_cooperative_service_handover(
        &self,
        invoker: &WslInvoker<'_>,
        distribution: &str,
        out: &mut dyn Write,
    ) -> Result<(), CliError> {
        let failed = write_failed("this install");
        writeln!(
            out,
            "The active service copy is taking its cooperative upgrade handover: it accepts \
             no new jobs and waits for its local journal to drain before systemd restarts it."
        )
        .map_err(failed)?;
        out.flush().map_err(failed)?;

        loop {
            let status =
                linux_status(invoker, distribution, &self.linux_binary).map_err(|source| {
                    CliError::new(
                        Failure::WslProvisioning,
                        format!(
                            "{}: cannot observe the cooperative service handover: {source}",
                            stage_prefix(Stage::Service)
                        ),
                    )
                })?;
            let active = systemctl_word(invoker, distribution, &["is-active", &self.unit]);
            if active.as_deref() == Some("failed") {
                return Err(CliError::with_remedy(
                    Failure::WslProvisioning,
                    format!(
                        "{}: the cooperative handover stopped {} but systemd reported it \
                         failed before the replacement could resume. No forced stop was used.",
                        stage_prefix(Stage::Service),
                        self.unit
                    ),
                    "runner-manager wsl status --distribution <NAME>",
                ));
            }
            if let LinuxAnswer::Reported(status) = status
                && status.product.service_binary_version.as_deref() == Some(self.version.as_str())
                && active.as_deref() == Some("active")
                && service_main_version(invoker, distribution, &self.unit).as_deref()
                    == Some(self.version.as_str())
            {
                writeln!(
                    out,
                    "The service drained, replaced its private copy, and systemd restarted it."
                )
                .map_err(failed)?;
                return Ok(());
            }
            std::thread::sleep(HANDOVER_OBSERVE_INTERVAL);
        }
    }

    /// Stage 6: adopt an active unit, or install and start the Linux service.
    ///
    /// # Why an enabled unit is adopted rather than reinstalled
    ///
    /// `service install` takes this host's single-instance lock, and an active
    /// unit holds it. Reinstalling one would refuse and, more importantly,
    /// would be an attempt to replace a daemon that is deliberately managing
    /// its own drain. A disabled-but-active unit is still active: it is
    /// re-enabled after adoption rather than treated as safe to replace.
    fn settle_the_service(
        &self,
        invoker: &WslInvoker<'_>,
        distribution: &str,
        out: &mut dyn Write,
    ) -> Result<bool, CliError> {
        let failed = write_failed("this install");
        let enabled = systemctl_word(invoker, distribution, &["is-enabled", &self.unit]);
        let active = systemctl_word(invoker, distribution, &["is-active", &self.unit]);
        if active.as_deref() == Some("active") {
            if enabled.as_deref() != Some("enabled") {
                invoker
                    .exec_ok(
                        "enable the adopted Linux service",
                        LinuxCommand::new(distribution, "systemctl")
                            .args(["enable", self.unit.as_str()])
                            .with_timeout(SERVICE_TIMEOUT),
                    )
                    .map_err(|source| self.stage_failure(Stage::Service, &source))?;
                writeln!(
                    out,
                    "The active systemd unit {} was adopted and enabled at boot.",
                    self.unit
                )
                .map_err(failed)?;
            } else {
                writeln!(
                    out,
                    "The systemd unit {} is already enabled and active; it is adopted rather than \
                     reinstalled.",
                    self.unit
                )
                .map_err(failed)?;
            }
            return Ok(false);
        }

        if enabled.as_deref() == Some("enabled") {
            invoker
                .exec_ok(
                    "start the adopted Linux service",
                    LinuxCommand::new(distribution, "systemctl")
                        .args(["start", self.unit.as_str()])
                        .with_timeout(SERVICE_TIMEOUT),
                )
                .map_err(|source| self.stage_failure(Stage::Service, &source))?;
            writeln!(
                out,
                "The systemd unit {} was already enabled but not active; it was adopted and started.",
                self.unit
            )
            .map_err(failed)?;
            return Ok(false);
        }

        invoker
            .exec_ok(
                "install the Linux service",
                self.linux(distribution)
                    .args(["service", "install", "--start-at", "boot"])
                    .with_timeout(SERVICE_TIMEOUT),
            )
            .map_err(|source| self.stage_failure(Stage::Service, &source))?;
        invoker
            .exec_ok(
                "start the installed Linux service",
                LinuxCommand::new(distribution, "systemctl")
                    .args(["start", self.unit.as_str()])
                    .with_timeout(SERVICE_TIMEOUT),
            )
            .map_err(|source| self.stage_failure(Stage::Service, &source))?;
        writeln!(out, "Linux service installed and started at boot.").map_err(failed)?;
        Ok(true)
    }

    /// One command run by the installed Linux binary.
    fn linux(&self, distribution: &str) -> LinuxCommand {
        LinuxCommand::new(distribution.to_string(), self.linux_binary.clone())
    }

    /// A failure that names the stage it happened in.
    ///
    /// The stage is what tells an operator whether anything was changed, which
    /// is the column `03-security-and-lifecycle.md`'s failure table is really
    /// about.
    fn stage_failure(&self, stage: Stage, source: &WslError) -> CliError {
        in_stage(stage, wsl_failure(source))
    }
}

/// Puts a stage's sentence in front of a failure, keeping its class and remedy.
///
/// Applied to every failure the transaction can raise — the platform's, the
/// release's, and the device flow's — because *"was anything changed, and is a
/// rerun safe"* is the same question whichever of them refused, and an
/// operator should not have to know which layer produced the words.
#[must_use]
fn in_stage(stage: Stage, failure: CliError) -> CliError {
    let prefix = stage_prefix(stage);
    let message = format!("{prefix}: {failure}");
    match failure.remedy() {
        Some(remedy) => CliError::with_remedy(failure.class(), message, remedy.to_string()),
        None => CliError::with_remedy(
            failure.class(),
            message,
            "runner-manager wsl status --distribution <NAME>",
        ),
    }
}

/// The sentence every staged failure opens with.
///
/// It answers the only question an operator has at that moment — *was anything
/// changed?* — and it is one function rather than one string per call site
/// because [`Provisioner::settle_the_credential`] raises failures of its own
/// that are not [`WslError`]s and owe the same sentence.
#[must_use]
fn stage_prefix(stage: Stage) -> String {
    match stage {
        Stage::Preflight => format!(
            "{} failed, so nothing has been changed and no credential was issued",
            stage.label()
        ),
        other => format!(
            "the {} stage failed; earlier stages stand and `wsl install` is safe to run \
             again once this is fixed",
            other.label()
        ),
    }
}

/// Refuses before anything is changed when the task name is somebody else's.
///
/// [`runner_manager_platform::wsl::task::LifecycleTaskControl::register`]
/// refuses a foreign task too, and that is the guard that matters — but it is
/// stage 7, by which time a binary has been installed and a credential may have
/// been issued. Asking in the preflight turns "provisioned a host it then could
/// not keep alive" into "changed nothing".
///
/// # Errors
/// [`WslError::ForeignTask`].
fn refuse_a_foreign_task(host: &WslHost, identity: &LifecycleTaskIdentity) -> Result<(), WslError> {
    match host.tasks().query(identity)? {
        Some(existing) if !existing.is_product_owned() => Err(WslError::ForeignTask {
            name: identity.name().to_string(),
            detail: format!(
                "a task of this name already exists, its description does not identify it as \
                 this product's ({PRODUCT_MARKER}), and it starts `{}`. Nothing has been \
                 changed. Rename or remove it yourself if it is the hand-created keep-alive \
                 this feature replaces.",
                existing.command()
            ),
        }),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// The commands
// ---------------------------------------------------------------------------

/// The systemd unit the Linux host runs, as named from the Windows side.
///
/// # Why this is the product's name and `wsl-host hold` resolves its own
///
/// [`super::service::identity`] reads `RUNNER_MANAGER_SERVICE_NAME_TAG`, which
/// is a test seam for *this* process's machine — it moves which registration
/// the local `service` commands act on. The unit inside a WSL distribution is
/// a different machine's, chosen by the copy of runner-manager installed there
/// and by the environment that copy runs in, so honouring a Windows-side tag
/// here would make `wsl status` ask about `runner-manager-selftest-….service`
/// and report the operator's real, healthy service as absent.
///
/// `wsl-host hold` is the opposite case and calls [`super::service::identity`]
/// deliberately: it runs *inside* the distribution, in the same process
/// environment as the `service install` that registered the unit, so the two
/// have to agree.
#[must_use]
fn linux_unit() -> String {
    runner_manager_platform::service::ServiceIdentity::product().systemd_unit()
}

/// `runner-manager wsl list`.
///
/// # Errors
/// [`Failure::UnsupportedHost`] off Windows, [`Failure::WslProvisioning`] when
/// `wsl.exe` cannot be run.
pub fn list(context: &Context, out: &mut dyn Write) -> Result<(), CliError> {
    let host = host_adapter("`runner-manager wsl list`")?;
    list_with(&host, context.paths(), out)
}

/// [`list`] over an adapter and a config directory, so it can be driven by a
/// scripted host.
///
/// # Errors
/// As [`list`].
fn list_with(host: &WslHost, paths: &AppPaths, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("this distribution list");
    let table = host
        .invoker()
        .list()
        .map_err(|source| wsl_failure(&source))?;

    writeln!(out, "WSL distributions").map_err(failed)?;
    if table.is_empty() && table.unreadable().is_empty() {
        writeln!(out).map_err(failed)?;
        writeln!(out, "This machine has no WSL distributions installed.").map_err(failed)?;
        return Ok(());
    }

    for entry in table.entries() {
        // Read per entry rather than listed once: `WslProviderRecord::all`
        // would report a record whose distribution has since been
        // unregistered, and this column is about the rows WSL really has.
        let managed = match WslProviderRecord::read(paths, entry.name()) {
            Ok(Some(record)) => format!("managed, runner-manager {}", record.installed_version),
            Ok(None) => "not managed".to_string(),
            // Reported in its row rather than raised. `wsl list` is the remedy
            // every other failure in this module points an operator at, and a
            // record is advisory in any case -- one file this build cannot
            // parse must not be able to hide every distribution the machine
            // has, which is the one thing this command exists to say.
            Err(source) => format!("record unreadable: {source}"),
        };
        let default = if entry.is_default() { ", default" } else { "" };
        writeln!(
            out,
            "  {}  WSL{}, {}{default} ({managed})",
            entry.name(),
            entry.wsl_version(),
            entry.state(),
        )
        .map_err(failed)?;
    }
    for unreadable in table.unreadable() {
        writeln!(out, "  <unreadable>  {unreadable}").map_err(failed)?;
    }
    writeln!(out).map_err(failed)?;
    writeln!(
        out,
        "Names are matched exactly. `runner-manager wsl install --distribution NAME` makes \
         one a second runner host."
    )
    .map_err(failed)
}

/// `runner-manager wsl install`.
///
/// # Errors
/// The class of whichever stage refused, and [`Failure::WslProvisioning`] when
/// the read-back finds the host only partly provisioned.
pub fn install(
    context: &Context,
    args: &WslInstallArgs,
    styling: Styling,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let host = host_adapter("`runner-manager wsl install`")?;
    let mut err = io::stderr();
    let version = env!("CARGO_PKG_VERSION").to_string();
    let assets = PublishedReleaseAssets::for_version(&version, &mut err)?;
    let issuer = DeviceFlowIssuer::new(context, styling);
    let principal = TaskPrincipal::current().map_err(|source| {
        CliError::with_remedy(
            Failure::WslProvisioning,
            format!("cannot decide which Windows account the lifecycle task runs as: {source}"),
            "runner-manager wsl install --distribution NAME   (from an interactive session)",
        )
    })?;

    let provisioner = Provisioner {
        host: &host,
        assets: &assets,
        issuer: &issuer,
        paths: context.paths(),
        principal,
        version,
        linux_binary: DEFAULT_LINUX_DESTINATION.to_string(),
        unit: linux_unit(),
        now: context.clock().now(),
    };

    let (document, outcome) = provisioner.install(args, out)?;
    write_install_report(&document, &outcome, out)?;
    refuse_a_partial_host(&document)
}

/// `runner-manager wsl status`.
///
/// # Errors
/// [`Failure::UnsupportedHost`] off Windows and [`Failure::LocalState`] when
/// the record cannot be read. An **unhealthy** host is not an error: the
/// document says so and the command exits zero, because "tell me what is
/// wrong" is what it was asked.
pub fn status(
    context: &Context,
    args: &WslStatusArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let host = host_adapter("`runner-manager wsl status`")?;
    let document = probe(
        &host,
        context.paths(),
        &args.distribution,
        DEFAULT_LINUX_DESTINATION,
        &linux_unit(),
        env!("CARGO_PKG_VERSION"),
        context.clock().now(),
    )?;

    if args.json {
        return write_json(out, &document);
    }
    write_status_text(&document, out)
}

/// `runner-manager wsl detach`.
///
/// # Errors
/// [`Failure::Conflict`] when the task is not this product's, and
/// [`Failure::WslProvisioning`] when Task Scheduler refused.
pub fn detach(
    context: &Context,
    args: &WslDetachArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let host = host_adapter("`runner-manager wsl detach`")?;
    detach_with(&host, context.paths(), &args.distribution, out)
}

/// [`detach`] over an adapter and a config directory, so it can be driven by a
/// scripted host.
///
/// # Errors
/// As [`detach`].
fn detach_with(
    host: &WslHost,
    paths: &AppPaths,
    distribution: &str,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this detach");
    let identity = LifecycleTaskIdentity::for_distribution(distribution)
        .map_err(|source| wsl_failure(&source))?;

    // Stopped before it is removed, so the hold process is not left running
    // against a task that no longer exists. A task that is not there at all is
    // not an error: `detach` is convergent too.
    let tasks = host.tasks();
    let stopped = match tasks.stop(&identity) {
        Ok(stopped) => stopped,
        Err(WslError::NoSuchTask { .. }) => false,
        Err(source) => return Err(wsl_failure(&source)),
    };
    let detached = tasks
        .detach(&identity)
        .map_err(|source| wsl_failure(&source))?;
    let record_removed =
        WslProviderRecord::remove(paths, distribution).map_err(|source| wsl_failure(&source))?;

    writeln!(out, "runner-manager wsl detach").map_err(failed)?;
    writeln!(out, "  distribution              {distribution}").map_err(failed)?;
    writeln!(
        out,
        "  lifecycle task            {} ({})",
        detached.name,
        if detached.removed {
            if stopped {
                "stopped and removed"
            } else {
                "removed"
            }
        } else {
            "was not registered"
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  provider record           {}",
        if record_removed {
            "removed"
        } else {
            "was not there"
        }
    )
    .map_err(failed)?;
    writeln!(out).map_err(failed)?;
    write_what_detach_left_alone(distribution, out)
}

/// The half of `detach` that is a promise rather than an action.
///
/// `03-security-and-lifecycle.md`: *"`wsl detach` is intentionally
/// non-destructive … The WSL distribution, Linux service, credentials,
/// policies, workspaces and packages remain. Output names explicit Linux
/// commands an operator may run separately."*
fn write_what_detach_left_alone(distribution: &str, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("this detach");
    writeln!(
        out,
        "Nothing inside {distribution} was changed. Its runner-manager, its systemd unit, its \
         credential, its policies and its workspaces are all still there, and the \
         distribution itself is still registered with WSL."
    )
    .map_err(failed)?;
    writeln!(out).map_err(failed)?;
    writeln!(out, "To undo the Linux half as well, run these inside it:").map_err(failed)?;
    writeln!(
        out,
        "  wsl --distribution {distribution} --user root -- runner-manager service uninstall"
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  wsl --distribution {distribution} --user root -- runner-manager auth logout"
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  wsl --distribution {distribution} --user root -- rm {DEFAULT_LINUX_DESTINATION}"
    )
    .map_err(failed)
}

/// Exits non-zero when the read-back found a host that cannot take jobs.
///
/// # Errors
/// [`Failure::WslProvisioning`], naming every part that is not in place.
fn refuse_a_partial_host(document: &WslStatusDocument) -> Result<(), CliError> {
    if document.healthy {
        return Ok(());
    }
    Err(CliError::with_remedy(
        Failure::WslProvisioning,
        format!(
            "{} is provisioned only in part, so this will not claim it is a working runner \
             host: {}. Everything that did land stands; fix what is named and run this \
             again.",
            document.distribution,
            document.unhealthy_parts().join("; ")
        ),
        format!(
            "runner-manager wsl status --distribution {}",
            document.distribution
        ),
    ))
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The `--json` document, pretty-printed with a trailing newline.
///
/// # Errors
/// [`Failure::Unclassified`] when it cannot be serialised or written.
fn write_json(out: &mut dyn Write, document: &WslStatusDocument) -> Result<(), CliError> {
    let failed = write_failed("this status document");
    let text = serde_json::to_string_pretty(document).map_err(|source| {
        CliError::new(
            Failure::Unclassified,
            format!("cannot render this status document: {source}"),
        )
    })?;
    writeln!(out, "{text}").map_err(failed)
}

/// The text report, in the two-column shape `ui::Ui::decorate` aligns.
///
/// # Errors
/// [`Failure::Unclassified`] when it cannot be written.
fn write_status_text(document: &WslStatusDocument, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("this status report");
    writeln!(out, "runner-manager wsl status").map_err(failed)?;
    writeln!(out, "  distribution              {}", document.distribution).map_err(failed)?;
    writeln!(
        out,
        "  provider record           {}",
        match &document.provider_record {
            Some(record) => format!(
                "runner-manager {}, last verified {}",
                record.installed_version, record.last_verified
            ),
            None => "none on this machine (advisory only)".to_string(),
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  wsl                       {}",
        match (&document.wsl.problem, document.wsl.wsl_version) {
            (Some(problem), _) => problem.clone(),
            (None, Some(version)) => format!(
                "WSL{version}, {} ({}), systemd {}",
                document.wsl.architecture.as_deref().unwrap_or("unknown"),
                document.wsl.machine.as_deref().unwrap_or("unknown"),
                document.wsl.systemd.as_deref().unwrap_or("unknown")
            ),
            (None, None) => "not readable".to_string(),
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  linux binary              {}",
        match (&document.binary.version, &document.binary.problem) {
            (Some(version), _) => format!(
                "{version} at {}{}",
                document.binary.path,
                if document.binary.matches_expected {
                    String::new()
                } else {
                    format!(" (this build provisions {})", document.expected_version)
                }
            ),
            (None, Some(problem)) => problem.clone(),
            (None, None) => format!("not installed at {}", document.binary.path),
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  credential                {}",
        match (&document.credential.unreadable, document.credential.present) {
            (Some(why), _) => format!("store unreadable: {why}"),
            (None, true) => format!(
                "present in the distribution's own {} store",
                document
                    .credential
                    .store_scope
                    .as_deref()
                    .unwrap_or("machine")
            ),
            (None, false) => "none: this host has not been signed in".to_string(),
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  linux service             {} is {}; binary {}{}",
        document.service.unit,
        document.service.active.as_deref().unwrap_or("not readable"),
        document
            .service
            .binary_version
            .as_deref()
            .unwrap_or("not readable"),
        if document.service.matches_expected {
            String::new()
        } else {
            format!(" (expected {})", document.expected_version)
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  lifecycle task            {}",
        describe_task(&document.lifecycle_task)
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  capacity                  {}",
        match document.capacity {
            Some(capacity) => capacity.to_string(),
            None => "not readable".to_string(),
        }
    )
    .map_err(failed)?;
    for diagnostic in &document.diagnostics {
        writeln!(
            out,
            "  {:<25} {}",
            diagnostic.name,
            if diagnostic.available {
                diagnostic.detail.clone()
            } else {
                format!("unavailable — {}", diagnostic.detail)
            }
        )
        .map_err(failed)?;
    }

    writeln!(out).map_err(failed)?;
    writeln!(out, "{}", document.headline()).map_err(failed)?;
    if !document.drift.is_empty() {
        writeln!(out).map_err(failed)?;
        writeln!(out, "Drift between this machine's record and the host:").map_err(failed)?;
        for line in &document.drift {
            writeln!(out, "  - {line}").map_err(failed)?;
        }
    }
    writeln!(out).map_err(failed)?;
    writeln!(out, "{AVAILABILITY_NOTE}").map_err(failed)
}

/// One phrase for the lifecycle task's four states.
fn describe_task(task: &TaskSnapshot) -> String {
    if !task.registered {
        return format!("{} is not registered", task.name);
    }
    if !task.product_owned {
        return format!(
            "{} exists and is NOT this product's ({PRODUCT_MARKER}); it will not be changed",
            task.name
        );
    }
    format!(
        "{} is registered, {}, and {}",
        task.name,
        if task.enabled { "enabled" } else { "DISABLED" },
        if task.running {
            "running"
        } else {
            "not reported as running"
        }
    )
}

/// The closing lines of `wsl install`.
///
/// # Errors
/// [`Failure::Unclassified`] when it cannot be written.
fn write_install_report(
    document: &WslStatusDocument,
    outcome: &InstallOutcome,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this install");
    writeln!(out).map_err(failed)?;
    writeln!(out, "What this run did").map_err(failed)?;
    writeln!(
        out,
        "  linux binary              {}",
        if outcome.binary_replaced {
            format!("installed {}", outcome.version)
        } else {
            format!("already {}", outcome.version)
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  credential                {}",
        if outcome.credential_issued {
            "issued independently and delivered on a pipe"
        } else {
            "the distribution's existing one was preserved"
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  capacity                  {}",
        match outcome.capacity_set {
            Some(capacity) => format!("set to {capacity}"),
            None => "unchanged (none was supplied)".to_string(),
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  linux service             {}",
        if outcome.service_installed {
            "installed"
        } else {
            "the enabled unit was adopted"
        }
    )
    .map_err(failed)?;
    writeln!(out).map_err(failed)?;
    write_status_text(document, out)
}

// ---------------------------------------------------------------------------
// `wsl-host hold`
// ---------------------------------------------------------------------------

/// The program the hold drives. Never a shell.
pub const SYSTEMCTL: &str = "systemctl";

/// One `systemctl` invocation, as a literal argument vector.
///
/// A function rather than an inline builder so that
/// `the_hold_never_builds_a_shell_command` can read the program and the
/// arguments back: `02-target-architecture.md` requires the hold to start the
/// unit *"by argument-vector process execution"* and says *"No shell text is
/// constructed"*, and this is where that is either true or not.
#[must_use]
pub fn systemctl_command(arguments: &[&str]) -> std::process::Command {
    let mut command = std::process::Command::new(SYSTEMCTL);
    command.args(arguments);
    command
}

/// Runs `systemctl` inside the distribution the hold is holding.
///
/// A seam so that the hold's sequence — verify, then start, then wait — can be
/// asserted on a machine with no systemd.
pub trait Systemd: fmt::Debug {
    /// Runs one invocation and captures it.
    ///
    /// # Errors
    /// Whatever the operating system says about starting `systemctl`.
    fn run(&self, arguments: &[&str]) -> io::Result<std::process::Output>;
}

/// The real `systemctl` on this Linux host.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostSystemd;

impl Systemd for HostSystemd {
    fn run(&self, arguments: &[&str]) -> io::Result<std::process::Output> {
        systemctl_command(arguments).output()
    }
}

/// Why the hold ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldStop {
    /// The operating system asked this process to stop, and named how.
    ///
    /// Constructed by the Unix signal handler below. The Windows build carries
    /// this type because it *renders* the task whose action runs the hold, and
    /// has no signals to construct one with.
    #[allow(
        dead_code,
        reason = "constructed on Unix, where the hold actually runs"
    )]
    Signal(&'static str),
}

/// The Linux end of the Windows lifecycle task.
///
/// # What it is for, and what it deliberately is not
///
/// WSL retires a distribution when nothing is running in it. The Windows task
/// starts this process at logon so that something always is — that is the whole
/// of its job. It is **not** a supervisor: `02-target-architecture.md` is
/// explicit that *"the Linux systemd service remains the daemon authority and
/// restart supervisor"*, so this starts the unit once and then does nothing
/// but stay alive and answer signals. It does not poll it, restart it, or stop
/// it on the way out — stopping it would take the runner host down every time
/// the operator logged off, which is the opposite of what the task is for.
///
/// # Errors
/// [`Failure::WslProvisioning`] when systemd is not usable here or will not
/// start the unit, and [`Failure::Unclassified`] when the log line cannot be
/// written.
pub fn hold(
    systemd: &dyn Systemd,
    unit: &str,
    out: &mut dyn Write,
    wait: &mut dyn FnMut() -> Result<HoldStop, CliError>,
) -> Result<(), CliError> {
    let failed = write_failed("this hold");

    // Verify. The unit is a systemd unit, so a distribution without systemd
    // has nothing to start and saying so is more use than a failed `start`.
    let report = run_systemctl(systemd, &["is-system-running"])?;
    let state = SystemdState::from_report(&report);
    if !state.is_usable() {
        return Err(CliError::with_remedy(
            Failure::WslProvisioning,
            format!(
                "this distribution is not running systemd ({state}), so there is no {unit} to \
                 start and no daemon for this hold to keep alive."
            ),
            "add `systemd=true` under `[boot]` in /etc/wsl.conf, then terminate the \
             distribution so it restarts",
        ));
    }

    // Start. `systemctl start` is idempotent — a unit that is already running
    // is left running — so the hold restarting after a Windows logoff does not
    // bounce the daemon.
    let started = systemd
        .run(&["start", unit])
        .map_err(cannot_run_systemctl)?;
    if !started.status.success() {
        return Err(CliError::with_remedy(
            Failure::WslProvisioning,
            format!(
                "cannot start {unit}: {}",
                String::from_utf8_lossy(&started.stderr).trim()
            ),
            "runner-manager service status",
        ));
    }

    writeln!(
        out,
        "runner-manager: {unit} is started; holding this distribution open until this \
         process is stopped."
    )
    .map_err(failed)?;
    out.flush().map_err(failed)?;

    let HoldStop::Signal(name) = wait()?;
    writeln!(
        out,
        "runner-manager: {name} received; releasing this distribution. {unit} is left running \
         and systemd remains its supervisor."
    )
    .map_err(failed)?;
    out.flush().map_err(failed)
}

/// One word out of `systemctl`, whatever it exited with.
///
/// # Errors
/// [`Failure::WslProvisioning`] when `systemctl` cannot be started at all.
fn run_systemctl(systemd: &dyn Systemd, arguments: &[&str]) -> Result<String, CliError> {
    let output = systemd.run(arguments).map_err(cannot_run_systemctl)?;
    let word = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if word.is_empty() {
        return Ok(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(word)
}

fn cannot_run_systemctl(source: io::Error) -> CliError {
    CliError::with_remedy(
        Failure::WslProvisioning,
        format!("cannot run `{SYSTEMCTL}` in this distribution: {source}"),
        "runner-manager wsl status --distribution NAME",
    )
}

/// Blocks until the operating system asks this process to stop.
///
/// # Why three signals and not `ctrl_c` alone
///
/// Task Scheduler's `/End`, and WSL's own shutdown, terminate the process
/// group rather than send an interrupt. `SIGHUP` is what a closing WSL session
/// delivers. A hold that only listened for `SIGINT` would be killed rather than
/// asked, and the log would never say why it stopped.
///
/// # Errors
/// [`Failure::WslProvisioning`] when a handler cannot be installed, and
/// [`Failure::Unclassified`] when the runtime will not start.
#[cfg(unix)]
fn wait_for_a_stop_signal() -> Result<HoldStop, CliError> {
    use tokio::signal::unix::{SignalKind, signal};

    let runtime = super::runtime()?;
    runtime.block_on(async {
        let handler = |kind: SignalKind, name: &'static str| {
            signal(kind).map_err(|source| {
                CliError::new(
                    Failure::WslProvisioning,
                    format!("cannot listen for {name} in this distribution: {source}"),
                )
            })
        };
        let mut terminate = handler(SignalKind::terminate(), "SIGTERM")?;
        let mut interrupt = handler(SignalKind::interrupt(), "SIGINT")?;
        let mut hangup = handler(SignalKind::hangup(), "SIGHUP")?;
        Ok(tokio::select! {
            _ = terminate.recv() => HoldStop::Signal("SIGTERM"),
            _ = interrupt.recv() => HoldStop::Signal("SIGINT"),
            _ = hangup.recv() => HoldStop::Signal("SIGHUP"),
        })
    })
}

/// Unreachable: [`require_linux`] refuses before this is called.
///
/// It exists so that the whole module compiles on the Windows leg, which is the
/// leg that has to *render* the task whose action invokes it.
#[cfg(not(unix))]
fn wait_for_a_stop_signal() -> Result<HoldStop, CliError> {
    Err(CliError::new(
        Failure::UnsupportedHost,
        "`wsl-host hold` waits on Unix signals and this is not a Unix build",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use clap::Parser as _;
    use runner_manager_platform::wsl::exec::{
        CommandOutput, CommandRequest, CommandRunner, ScriptedRunner,
    };

    use crate::cli::HostSelector;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// The version this build provisions, which is the only one it accepts.
    fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    const DISTRIBUTION: &str = "Ubuntu";
    const UNIT: &str = "runner-manager.service";
    const TRIPLE: &str = "x86_64-unknown-linux-gnu";

    /// Shaped like a stored credential document and unmistakably not one.
    ///
    /// Assembled at run time so the literal is in no source file and in no
    /// compiled artifact — the same reasoning `d2`'s fixtures give, and what
    /// makes `the_credential_crosses_only_on_the_childs_stdin` mean something
    /// when it scans everything else for it.
    fn canary() -> String {
        format!(
            "{{\"access_token\":\"{}{}\",\"refresh_token\":\"{}{}\"}}",
            "ghu_", "b2WslCanaryNotARealToken00000000", "ghr_", "b2WslCanaryRefreshNotARealOne000"
        )
    }

    /// An ordered log of everything the transaction did, across all three
    /// seams.
    ///
    /// `ScriptedRunner` records the commands and nothing else, so a download
    /// and a device flow would be invisible to it and "the credential was
    /// issued only after the binary landed" would be unassertable. One journal,
    /// shared by the runner, the assets and the issuer, makes the whole
    /// transaction one readable sequence.
    #[derive(Debug, Default, Clone)]
    struct Journal(Arc<Mutex<Vec<String>>>);

    impl Journal {
        fn note(&self, entry: impl Into<String>) {
            self.0
                .lock()
                .expect("the journal is not shared across a panic")
                .push(entry.into());
        }

        fn entries(&self) -> Vec<String> {
            self.0
                .lock()
                .expect("the journal is not shared across a panic")
                .clone()
        }

        fn position(&self, needle: &str) -> Option<usize> {
            self.0
                .lock()
                .expect("the journal is not shared across a panic")
                .iter()
                .position(|entry| entry.contains(needle))
        }

        /// Where something happened, or a failure that prints the whole log.
        fn at(&self, needle: &str) -> usize {
            self.position(needle).unwrap_or_else(|| {
                panic!(
                    "{needle:?} never happened. The journal was:\n{:#?}",
                    self.entries()
                )
            })
        }

        fn never(&self, needle: &str) {
            assert!(
                self.position(needle).is_none(),
                "{needle:?} must not have happened. The journal was:\n{:#?}",
                self.entries()
            );
        }

        /// Asserts the log reads in this order, naming the pair that did not.
        fn in_order(&self, steps: &[&str]) {
            for pair in steps.windows(2) {
                let (before, after) = (pair[0], pair[1]);
                assert!(
                    self.at(before) < self.at(after),
                    "{before:?} must happen before {after:?}. The journal was:\n{:#?}",
                    self.entries()
                );
            }
        }
    }

    /// A [`CommandRunner`] that answers from a script and writes to the shared
    /// journal on the way through.
    #[derive(Debug, Clone)]
    struct FakeRunner {
        inner: Arc<ScriptedRunner>,
        journal: Journal,
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, request: &CommandRequest) -> Result<CommandOutput, WslError> {
            let mut line = request
                .program()
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            for argument in request.argument_strings() {
                line.push(' ');
                line.push_str(&argument);
            }
            self.journal.note(line);
            self.inner.run(request)
        }
    }

    /// A release whose `SHA256SUMS` really does describe the bytes it serves.
    #[derive(Debug)]
    struct FakeAssets {
        journal: Journal,
        document: String,
        archive: Vec<u8>,
        refuse: Option<String>,
    }

    impl FakeAssets {
        /// A release publishing exactly this build's version for x86-64 Linux.
        fn publishing(journal: Journal) -> Self {
            let archive = b"a stand-in for a release archive".to_vec();
            let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&archive));
            Self {
                journal,
                document: format!("{digest}  runner-manager-{}-{TRIPLE}.tar.gz\n", version()),
                archive,
                refuse: None,
            }
        }

        fn asset(&self) -> String {
            format!("runner-manager-{}-{TRIPLE}.tar.gz", version())
        }

        fn refusing(mut self, why: &str) -> Self {
            self.refuse = Some(why.to_string());
            self
        }
    }

    impl ReleaseAssets for FakeAssets {
        fn describe(&self) -> String {
            "a fixture release".to_string()
        }

        fn checksums(&self) -> Result<String, CliError> {
            self.journal.note("assets SHA256SUMS");
            match &self.refuse {
                Some(why) => Err(CliError::new(Failure::GithubUnavailable, why.clone())),
                None => Ok(self.document.clone()),
            }
        }

        fn download(&self, asset: &str, into: &Path) -> Result<(), CliError> {
            self.journal.note(format!("assets download {asset}"));
            std::fs::write(into, &self.archive).map_err(|source| {
                CliError::new(
                    Failure::LocalState,
                    format!("cannot write the fixture archive: {source}"),
                )
            })
        }
    }

    /// A device flow that runs without a browser, and says so in the journal.
    #[derive(Debug)]
    struct FakeIssuer {
        journal: Journal,
        document: String,
        refuse: Option<String>,
    }

    impl FakeIssuer {
        fn issuing(journal: Journal) -> Self {
            Self {
                journal,
                document: canary(),
                refuse: None,
            }
        }

        fn refusing(mut self, why: &str) -> Self {
            self.refuse = Some(why.to_string());
            self
        }
    }

    impl CredentialIssuer for FakeIssuer {
        fn issue(
            &self,
            _out: &mut dyn Write,
            sink: &mut dyn SecretSink,
        ) -> Result<BrokeredCredential, CliError> {
            self.journal.note("device flow");
            if let Some(why) = &self.refuse {
                return Err(CliError::new(Failure::AuthenticationDeclined, why.clone()));
            }
            sink.send(&SecretString::from(self.document.clone()))
                .map_err(|source| CliError::new(Failure::SecretStore, source.to_string()))?;
            Ok(BrokeredCredential {
                renewable: true,
                access_expires_at: None,
                refresh_expires_at: None,
            })
        }
    }

    /// `status --json` as the Linux binary would answer it.
    fn linux_status_json(credential: bool, capacity: u16, reported: &str) -> String {
        linux_status_json_with_service(credential, capacity, reported, reported)
    }

    fn linux_status_json_with_service(
        credential: bool,
        capacity: u16,
        reported: &str,
        service_reported: &str,
    ) -> String {
        format!(
            "{{\"schema_version\":1,\"product\":{{\"name\":\"runner-manager\",\
             \"version\":\"{reported}\",\"service_binary_version\":\"{service_reported}\"}},\
             \"credential\":{{\"present\":{credential},\
             \"unreadable\":null,\"store_scope\":\"machine\"}},\
             \"host\":{{\"capacity\":{capacity}}}}}"
        )
    }

    fn ok(stdout: &str) -> CommandOutput {
        CommandOutput::exited(0, stdout, "")
    }

    fn refused(stderr: &str) -> CommandOutput {
        CommandOutput::exited(1, "", stderr)
    }

    fn identity_of(distribution: &str) -> LifecycleTaskIdentity {
        LifecycleTaskIdentity::for_distribution(distribution).expect("a usable fixture name")
    }

    /// The document Task Scheduler would export for the product's own task.
    fn our_task_xml(distribution: &str) -> String {
        LifecycleTask::new(
            identity_of(distribution),
            TaskPrincipal::named("FIXTURE\\ivan"),
            &WslExecutable::at("wsl.exe"),
            DEFAULT_LINUX_DESTINATION,
        )
        .xml()
    }

    /// A task of the same name that somebody made by hand.
    fn foreign_task_xml() -> String {
        "<?xml version=\"1.0\"?><Task><RegistrationInfo><Description>A keep-alive I made by \
         hand.</Description></RegistrationInfo><Actions><Exec><Command>wsl.exe</Command>\
         <Arguments>-d Ubuntu -- sleep infinity</Arguments></Exec></Actions></Task>"
            .to_string()
    }

    /// The four answers a complete preflight asks for, in the order it asks.
    ///
    /// One function rather than one copy per script: every test below that is
    /// *not* about a refusing preflight needs exactly these four, and a fifth
    /// transcription of them is a fifth chance to spell `x86_64` wrongly. The
    /// deliberately truncated scripts in the refusal table are still written
    /// out, because each of those omits a rule on purpose.
    fn preflight_script() -> ScriptedRunner {
        ScriptedRunner::new()
            .always("--list --verbose", ok("* Ubuntu   Running   2\n"))
            .always("--exec id -u", ok("0\n"))
            .always("--exec uname -m", ok("x86_64\n"))
            .always("--exec systemctl is-system-running", ok("running\n"))
    }

    /// A distribution that is WSL2, root-capable, x86-64 and running systemd.
    ///
    /// The `/XML ONE` and `/FO CSV` sequences are the interaction the
    /// transaction really has with Task Scheduler, in order: absent when the
    /// preflight looks, absent again when `register` looks and looks a second
    /// time without an export, and this product's own from then on.
    fn base_script() -> ScriptedRunner {
        preflight_script()
            .always("--exec systemctl is-enabled", ok("disabled\n"))
            .sequence(
                "--exec systemctl is-active",
                vec![ok("inactive\n"), ok("inactive\n"), ok("active\n")],
            )
            .always("--exec docker info", ok("27.1.1\n"))
            .always("--version", ok(&format!("runner-manager {}\n", version())))
            .sequence(
                "/XML ONE",
                vec![
                    refused("ERROR: The system cannot find the file specified."),
                    refused("ERROR: The system cannot find the file specified."),
                    ok(&our_task_xml(DISTRIBUTION)),
                ],
            )
            .sequence(
                "/FO CSV",
                vec![
                    refused("ERROR: The system cannot find the file specified."),
                    ok("\"task\",\"N/A\",\"Running\"\n"),
                ],
            )
    }

    /// [`base_script`] over a distribution that has never been provisioned.
    fn fresh_script() -> ScriptedRunner {
        base_script().sequence(
            "status --json",
            vec![
                // Before the install there is no binary at all.
                refused("/usr/local/bin/runner-manager: not found"),
                // After it, a host that holds no credential of its own.
                ok(&linux_status_json(false, 1, version())),
                // After the handoff, what the read-back sees.
                ok(&linux_status_json(true, 8, version())),
            ],
        )
    }

    /// A distribution that is already a healthy managed runner host.
    ///
    /// Layered onto [`preflight_script`] and never onto [`base_script`],
    /// because `ScriptedRunner` answers from the FIRST rule that matches: a
    /// second rule for the same command line is never reached, so an
    /// "override" appended to a base script would silently keep the base's
    /// answer. The preflight is shared precisely because this script agrees
    /// with it; every rule that differs is spelled out below.
    fn provisioned_script(docker: CommandOutput) -> ScriptedRunner {
        preflight_script()
            .always("--exec systemctl is-enabled", ok("enabled\n"))
            .always("--exec systemctl is-active", ok("active\n"))
            .always("--exec docker info", docker)
            .always("--version", ok(&format!("runner-manager {}\n", version())))
            .always("status --json", ok(&linux_status_json(true, 8, version())))
            .always("/XML ONE", ok(&our_task_xml(DISTRIBUTION)))
            .always("/FO CSV", ok("\"task\",\"N/A\",\"Running\"\n"))
    }

    /// A previously installed unit that systemd knows about but is not
    /// running yet. The first two answers see the inactive unit before the
    /// adoption stage starts it; the third is the install read-back.
    fn provisioned_inactive_script() -> ScriptedRunner {
        preflight_script()
            .always("--exec systemctl is-enabled", ok("enabled\n"))
            .sequence(
                "--exec systemctl is-active",
                vec![ok("inactive\n"), ok("inactive\n"), ok("active\n")],
            )
            .always("--exec docker info", ok("27.1.1\n"))
            .always("--version", ok(&format!("runner-manager {}\n", version())))
            .always("status --json", ok(&linux_status_json(true, 8, version())))
            .always("/XML ONE", ok(&our_task_xml(DISTRIBUTION)))
            .always("/FO CSV", ok("\"task\",\"N/A\",\"Running\"\n"))
    }

    fn wrap(scripted: ScriptedRunner, journal: &Journal) -> (WslHost, Arc<ScriptedRunner>) {
        let inner = Arc::new(scripted);
        let runner = FakeRunner {
            inner: Arc::clone(&inner),
            journal: journal.clone(),
        };
        (
            WslHost::with_runner(Box::new(runner), WslExecutable::at("wsl.exe")),
            inner,
        )
    }

    /// Plants the record `probe` will read, claiming `version` was installed.
    ///
    /// The version is the only thing the five call sites differ in, and it is
    /// the thing each of them is about -- `9.9.9` over a host that has nothing
    /// is what makes the drift assertions mean something.
    fn write_record(paths: &AppPaths, version: &str) {
        WslProviderRecord::new(
            DISTRIBUTION,
            identity_of(DISTRIBUTION).name(),
            version,
            Utc::now(),
        )
        .write(paths)
        .expect("a record");
    }

    fn fixture_paths() -> (tempfile::TempDir, AppPaths) {
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(root.path());
        paths.create_all().expect("the fixture directories");
        (root, paths)
    }

    /// Everything one install needs, wired together.
    struct Fixture {
        journal: Journal,
        host: WslHost,
        runner: Arc<ScriptedRunner>,
        assets: FakeAssets,
        issuer: FakeIssuer,
        _root: tempfile::TempDir,
        paths: AppPaths,
        out: Vec<u8>,
    }

    impl Fixture {
        fn over(script: ScriptedRunner) -> Self {
            let journal = Journal::default();
            let (host, runner) = wrap(script, &journal);
            let (root, paths) = fixture_paths();
            Self {
                assets: FakeAssets::publishing(journal.clone()),
                issuer: FakeIssuer::issuing(journal.clone()),
                journal,
                host,
                runner,
                _root: root,
                paths,
                out: Vec::new(),
            }
        }

        fn fresh() -> Self {
            Self::over(fresh_script())
        }

        fn install(
            &mut self,
            capacity: Option<u16>,
        ) -> Result<(WslStatusDocument, InstallOutcome), CliError> {
            let provisioner = Provisioner {
                host: &self.host,
                assets: &self.assets,
                issuer: &self.issuer,
                paths: &self.paths,
                principal: TaskPrincipal::named("FIXTURE\\ivan"),
                version: version().to_string(),
                linux_binary: DEFAULT_LINUX_DESTINATION.to_string(),
                unit: UNIT.to_string(),
                now: DateTime::from_timestamp(1_800_000_000, 0).expect("a fixed instant"),
            };
            let outcome = provisioner.install(
                &WslInstallArgs {
                    distribution: DISTRIBUTION.to_string(),
                    capacity,
                },
                &mut self.out,
            );
            // The closing report is `install`'s, not the transaction's, and
            // the tests that read it are reading what an operator would see.
            if let Ok((document, outcome)) = &outcome {
                write_install_report(document, outcome, &mut self.out)
                    .expect("a report can always be written to a buffer");
            }
            outcome
        }

        fn output(&self) -> String {
            String::from_utf8_lossy(&self.out).into_owned()
        }
    }

    /// Probes a scripted host the way `wsl status` does.
    ///
    /// The [`tempfile::TempDir`] is handed back because dropping it deletes
    /// the config directory the document was read against; the [`AppPaths`]
    /// inside it is not, because no caller has anything left to ask it.
    fn probe_scripted(script: ScriptedRunner) -> (Journal, tempfile::TempDir, WslStatusDocument) {
        let journal = Journal::default();
        let (host, _) = wrap(script, &journal);
        let (root, paths) = fixture_paths();
        let document = probe(
            &host,
            &paths,
            DISTRIBUTION,
            DEFAULT_LINUX_DESTINATION,
            UNIT,
            version(),
            Utc::now(),
        )
        .expect("a readable host");
        (journal, root, document)
    }

    // -----------------------------------------------------------------------
    // The `--host` selector
    // -----------------------------------------------------------------------

    #[test]
    fn local_is_the_default_so_every_existing_invocation_is_unchanged() {
        let cli = Cli::try_parse_from(["runner-manager", "status"]).expect("an ordinary command");
        assert_eq!(cli.host, HostSelector::Local);
        assert_eq!(cli.host.distribution(), None);
        assert_eq!(cli.host.to_string(), "local");

        let explicit = Cli::try_parse_from(["runner-manager", "--host", "local", "status"])
            .expect("the default, spelled out");
        assert_eq!(explicit.host, HostSelector::Local);
    }

    #[test]
    fn a_wsl_selector_carries_the_exact_name_however_it_is_spelled() {
        // Several distributions, independently addressable, in the shapes WSL
        // really allows: spaces, punctuation, and names that differ only in
        // case.
        for name in [
            "Ubuntu",
            "Ubuntu-24.04",
            "Debian GNU Linux",
            "ubuntu",
            "openSUSE-Tumbleweed",
        ] {
            let cli =
                Cli::try_parse_from(["runner-manager", "--host", &format!("wsl:{name}"), "status"])
                    .unwrap_or_else(|error| panic!("`wsl:{name}` must parse: {error}"));
            assert_eq!(cli.host, HostSelector::Wsl(name.to_string()));
            assert_eq!(cli.host.distribution(), Some(name));
            assert_eq!(cli.host.to_string(), format!("wsl:{name}"));
        }
    }

    #[test]
    fn the_selector_is_global_so_it_may_follow_the_subcommand() {
        let cli = Cli::try_parse_from(["runner-manager", "repo", "list", "--host=wsl:Ubuntu"])
            .expect("a global option after the subcommand");
        assert_eq!(cli.host.distribution(), Some("Ubuntu"));
    }

    #[test]
    fn an_unspellable_host_is_refused_with_a_sentence_that_names_both_forms() {
        let refusal = HostSelector::parse("ubuntu").expect_err("not a selector");
        assert!(refusal.contains("local"), "{refusal}");
        assert!(refusal.contains("wsl:"), "{refusal}");
        assert!(refusal.contains("wsl list"), "{refusal}");

        let empty = HostSelector::parse("wsl:").expect_err("no name after the prefix");
        assert!(empty.contains("Ubuntu"), "{empty}");

        assert!(
            Cli::try_parse_from(["runner-manager", "--host", "kvm:box", "status"]).is_err(),
            "an unknown host kind is a usage error, not a silent local run"
        );
    }

    // -----------------------------------------------------------------------
    // The proxy
    // -----------------------------------------------------------------------

    fn argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_proxy_forwards_the_original_arguments_and_removes_only_the_selector() {
        assert_eq!(
            forwarded_arguments(&argv(&[
                "runner-manager",
                "--host",
                "wsl:Ubuntu",
                "repo",
                "list"
            ])),
            argv(&["repo", "list"])
        );
        assert_eq!(
            forwarded_arguments(&argv(&[
                "runner-manager",
                "repo",
                "list",
                "--host=wsl:Ubuntu"
            ])),
            argv(&["repo", "list"])
        );

        // `--host-label` is `repo add`'s own option and shares five characters
        // with the selector. Stripping it would silently drop the routing label
        // the policy is created with.
        assert_eq!(
            forwarded_arguments(&argv(&[
                "runner-manager",
                "--host=wsl:Ubuntu",
                "repo",
                "add",
                "owner/repo",
                "--host-label",
                "ivanpc",
                "--max-capacity",
                "4",
            ])),
            argv(&[
                "repo",
                "add",
                "owner/repo",
                "--host-label",
                "ivanpc",
                "--max-capacity",
                "4"
            ])
        );

        // Nothing else is touched -- not `--data-dir`, not a flag this build
        // has never heard of.
        assert_eq!(
            forwarded_arguments(&argv(&[
                "runner-manager",
                "--data-dir",
                "/tmp/x",
                "--host",
                "wsl:Ubuntu",
                "status",
                "--json",
            ])),
            argv(&["--data-dir", "/tmp/x", "status", "--json"])
        );
    }

    #[test]
    fn the_proxy_builds_the_exact_argument_vector_for_each_distribution() {
        for name in ["Ubuntu", "Debian GNU Linux", "Ubuntu-24.04"] {
            let plan = ProxyPlan::new(
                &WslExecutable::at("C:\\Windows\\System32\\wsl.exe"),
                name,
                DEFAULT_LINUX_DESTINATION,
                argv(&["status", "--json"]),
            )
            .expect("a usable name");

            assert_eq!(plan.program(), Path::new("C:\\Windows\\System32\\wsl.exe"));
            assert_eq!(
                plan.arguments(),
                [
                    "--distribution",
                    name,
                    "--user",
                    "root",
                    "--exec",
                    DEFAULT_LINUX_DESTINATION,
                    "status",
                    "--json",
                ]
                .map(OsString::from)
            );
        }
    }

    #[test]
    fn a_name_that_cannot_be_used_is_refused_before_anything_is_started() {
        let refusal = ProxyPlan::new(
            &WslExecutable::at("wsl.exe"),
            "Ubuntu\nDebian",
            DEFAULT_LINUX_DESTINATION,
            Vec::new(),
        )
        .expect_err("a name with a newline in it");
        assert_eq!(refusal.class(), Failure::InvalidArgument);
    }

    #[test]
    fn the_proxy_sets_no_environment_and_no_working_directory() {
        let plan = ProxyPlan::new(
            &WslExecutable::at("wsl.exe"),
            DISTRIBUTION,
            DEFAULT_LINUX_DESTINATION,
            argv(&["status"]),
        )
        .expect("a usable name");
        let command = plan.command();

        assert_eq!(command.get_program(), std::ffi::OsStr::new("wsl.exe"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            plan.arguments()
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&std::ffi::OsStr>>()
        );
        assert_eq!(
            command.get_envs().count(),
            0,
            "the child inherits this process's environment unchanged; a variable set here \
             would be a second, undocumented way to configure the Linux host"
        );
        assert!(
            command.get_current_dir().is_none(),
            "and it starts where this process started"
        );
    }

    /// The three streams are inherited by NOT being configured, so the proof is
    /// that this module configures none of them.
    ///
    /// A source assertion rather than a behavioural one, because the behaviour
    /// it guards — the child holding this process's own stdin, stdout and
    /// stderr — is precisely what a harness cannot observe from inside the
    /// parent. What it can observe is that no call which would take a stream
    /// away is written here, and that is a complete account of the mechanism:
    /// [`std::process::Command`] defaults every stream to `inherit`.
    #[test]
    fn the_proxy_configures_no_stream_of_its_own() {
        let source = include_str!("wsl.rs");
        // Scoped to the two functions that build and start the child, so that
        // an unrelated `output.stdout()` elsewhere in the module -- of which
        // there are several, reading what a *captured* command said -- is not
        // mistaken for the proxy taking a stream away.
        for signature in [
            "    pub fn command(&self) -> std::process::Command {",
            "    fn run(&self, plan: &ProxyPlan) -> Result<i32, CliError> {",
        ] {
            let body = body_of(source, signature);
            // The needles are built rather than written, so this test's own
            // text is not what it finds.
            for setter in ["stdin", "stdout", "stderr", "Stdio"] {
                assert!(
                    !body.contains(setter),
                    "`{setter}` appears in `{signature}`. The proxy must configure no \
                     stream: a piped one deadlocks any proxied command that writes more \
                     than a pipe buffer, because nothing here is reading it, and a null one \
                     silently discards the operator's output. Inheriting all three is what \
                     `Command` does when nothing is said."
                );
            }
        }
    }

    /// The body of a function, from its signature to the closing brace at the
    /// indentation the signature was written at.
    ///
    /// The source is normalised to LF first, because the end of the body is
    /// found by a needle that spells the line break itself. `include_str!`
    /// hands over the bytes that are on disk, and a Windows checkout with
    /// `core.autocrlf=true` -- the default Git for Windows installs, and what
    /// GitHub's windows runner image uses -- has rewritten every `\n` in this
    /// file to `\r\n` by the time it is compiled. Without this the closing
    /// brace is never found on that platform and the caller panics on source
    /// the compiler was perfectly happy with. Normalising here rather than
    /// pinning `*.rs` in `.gitattributes` keeps the fix to the one assertion
    /// that reads its own file, and the needles the callers search for carry
    /// no line break of their own.
    fn body_of(source: &str, signature: &str) -> String {
        let source = source.replace("\r\n", "\n");
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("`{signature}` must exist for this test to mean anything"));
        let indentation: String = signature.chars().take_while(|c| *c == ' ').collect();
        let closing = format!("\n{indentation}}}\n");
        let rest = &source[start..];
        let end = rest
            .find(&closing)
            .unwrap_or_else(|| panic!("`{signature}` must be closed"));
        rest[..end].to_string()
    }

    /// `body_of` reads a CRLF checkout exactly as it reads an LF one.
    ///
    /// The regression this pins is the one that failed only on the Windows
    /// leg: the same source, differing solely in line endings, must yield the
    /// same body -- otherwise the stream assertion above cannot run there at
    /// all, and a proxy that piped a stream would go unnoticed on the one
    /// platform that actually runs `wsl.exe`.
    #[test]
    fn the_source_shape_helper_does_not_depend_on_line_endings() {
        let signature = "    fn sample(&self) -> u8 {";
        let lf = format!("impl Thing {{\n{signature}\n        1\n    }}\n}}\n");
        let crlf = lf.replace('\n', "\r\n");

        let from_lf = body_of(&lf, signature);
        let from_crlf = body_of(&crlf, signature);

        assert_eq!(
            from_lf, from_crlf,
            "a CRLF checkout must produce the same body as an LF one"
        );
        assert!(
            from_lf.contains("        1"),
            "the body must actually reach the statement inside it, not stop at the signature"
        );
    }

    /// A plan that runs one line of shell, for the exit-code proofs.
    fn shell_plan(script: &str) -> ProxyPlan {
        #[cfg(windows)]
        let (program, arguments) = ("cmd", vec!["/C".to_string(), script.to_string()]);
        #[cfg(not(windows))]
        let (program, arguments) = ("/bin/sh", vec!["-c".to_string(), script.to_string()]);
        ProxyPlan {
            program: PathBuf::from(program),
            arguments: arguments.into_iter().map(OsString::from).collect(),
        }
    }

    #[test]
    fn the_proxy_returns_the_childs_own_exit_code() {
        for expected in [0, 1, 7, 42] {
            let code = HostProxyRunner
                .run(&shell_plan(&format!("exit {expected}")))
                .expect("the fixture child must run");
            assert_eq!(
                code, expected,
                "a proxied command's result is the child's, not this process's opinion of it"
            );
        }
    }

    #[test]
    fn a_program_that_cannot_be_started_is_a_failure_and_not_a_silent_success() {
        let plan = ProxyPlan {
            program: PathBuf::from("this-program-is-nowhere-on-this-machine"),
            arguments: Vec::new(),
        };
        let refusal = HostProxyRunner.run(&plan).expect_err("nothing to start");
        assert_eq!(refusal.class(), Failure::WslProvisioning);
    }

    #[cfg(unix)]
    #[test]
    fn a_child_killed_by_a_signal_is_reported_the_way_a_shell_reports_it() {
        let code = HostProxyRunner
            .run(&shell_plan("kill -TERM $$"))
            .expect("the fixture child must run");
        assert_eq!(
            code, 143,
            "128 + SIGTERM, which is what every script reading $? already assumes; reporting \
             0 here would turn a killed job into a successful one"
        );
    }

    #[test]
    fn the_two_windows_only_families_cannot_be_addressed_to_another_host() {
        for command in [
            Command::Wsl(WslCommand::List),
            Command::WslHost(WslHostCommand::Hold),
        ] {
            let refusal =
                refuse_a_command_that_cannot_be_proxied(&command).expect_err("not proxyable");
            assert_eq!(refusal.class(), Failure::InvalidArgument);
            assert!(refusal.remedy().is_some(), "and it names what was meant");
        }
        assert!(
            refuse_a_command_that_cannot_be_proxied(&Command::Tui).is_ok(),
            "everything else is the Linux host's to answer"
        );
    }

    // -----------------------------------------------------------------------
    // The credential handoff
    // -----------------------------------------------------------------------

    #[test]
    fn the_credential_crosses_only_on_the_childs_stdin() {
        let mut fixture = Fixture::fresh();
        fixture.install(None).expect("a clean provisioning");

        let planted = canary();
        let piped = String::from_utf8_lossy(&fixture.runner.piped_input()).into_owned();
        assert!(
            piped.contains(&planted),
            "the document must reach the child on its stdin"
        );

        // And nowhere else: not in an argument vector, not in the log, not on
        // the operator's screen, and not in the provider record — the four
        // places `03-security-and-lifecycle.md` item 3 names that this command
        // could plausibly have written.
        for request in fixture.runner.recorded() {
            assert!(
                !request.command_line().contains(&planted),
                "the credential must never be in an argument vector: {}",
                request.command_line()
            );
        }
        for entry in fixture.journal.entries() {
            assert!(!entry.contains(&planted), "nor in the log: {entry}");
        }
        assert!(
            !fixture.output().contains(&planted),
            "nor in what the operator sees: {}",
            fixture.output()
        );
        let record = std::fs::read_to_string(
            WslProviderRecord::path(&fixture.paths, DISTRIBUTION).expect("a record path"),
        )
        .expect("the record was written");
        assert!(!record.contains(&planted), "nor in the provider record");
        assert!(
            !record.contains("ghu_") && !record.contains("ghr_"),
            "nor anything shaped like one: {record}"
        );
    }

    #[test]
    fn the_sink_delivers_to_auth_receive_for_the_start_mode_it_was_given() {
        let journal = Journal::default();
        let (host, runner) = wrap(fresh_script(), &journal);
        let mut sink = WslSecretSink::new(
            host.invoker(),
            DISTRIBUTION,
            DEFAULT_LINUX_DESTINATION,
            StartAt::Boot,
        );
        assert_eq!(sink.delivered(), 0);

        sink.send(&SecretString::from(canary()))
            .expect("the receiver took it");
        assert_eq!(sink.delivered(), 1);

        let recorded = runner.recorded();
        let receive = recorded
            .iter()
            .find(|request| request.command_line().contains("auth receive"))
            .expect("the receive command ran");
        assert_eq!(
            receive.arguments,
            [
                "--distribution",
                DISTRIBUTION,
                "--user",
                "root",
                "--exec",
                DEFAULT_LINUX_DESTINATION,
                "auth",
                "receive",
                "--start-at",
                "boot",
            ]
            .map(str::to_string),
            "the store `receive` writes is named on the command line; the document is not"
        );
        assert_eq!(String::from_utf8_lossy(&receive.stdin), canary());
    }

    #[test]
    fn a_receiver_that_refuses_is_a_different_failure_from_one_that_never_got_it() {
        let journal = Journal::default();
        let (host, _) = wrap(
            ScriptedRunner::new().always("auth receive", refused("the store is read-only")),
            &journal,
        );
        let mut sink = WslSecretSink::new(
            host.invoker(),
            DISTRIBUTION,
            DEFAULT_LINUX_DESTINATION,
            StartAt::Login,
        );
        let refusal = sink
            .send(&SecretString::from(canary()))
            .expect_err("the receiver said no");
        assert!(
            matches!(refusal, SecretSinkError::Refused { .. }),
            "a store that refused needs a different remedy from a pipe that broke: {refusal}"
        );
        assert!(
            !refusal.to_string().contains("ghu_"),
            "and it carries no part of the document: {refusal}"
        );
        assert_eq!(sink.delivered(), 0);
    }

    // -----------------------------------------------------------------------
    // The install transaction
    // -----------------------------------------------------------------------

    #[test]
    fn the_install_runs_its_stages_in_the_documented_order() {
        let mut fixture = Fixture::fresh();
        let (document, outcome) = fixture.install(Some(8)).expect("a clean provisioning");

        assert!(document.healthy, "{document:#?}");
        assert!(outcome.binary_replaced);
        assert!(outcome.credential_issued);
        assert_eq!(outcome.capacity_set, Some(8));
        assert!(outcome.service_installed);

        // `02-target-architecture.md`'s eight numbered steps, read back as the
        // order they really happened in.
        let downloaded = format!("assets download {}", fixture.assets.asset());
        fixture.journal.in_order(&[
            "--list --verbose",                   // 1. is it there, and is it WSL2
            "--exec id -u",                       //    does it start as root
            "--exec uname -m",                    //    is its architecture published
            "--exec systemctl is-system-running", //    does it run systemd
            "assets SHA256SUMS",                  // 2. the exact-version artifact
            &downloaded,
            "--exec mkdir", // 3. install the binary atomically
            "--exec tar",
            "--exec mv",
            "device flow",         // 4. issue a credential, having found none
            "auth receive",        //    and hand it over on a pipe
            "host set-capacity 8", // 5. capacity, because one was supplied
            "service install --start-at boot", // 6. the Linux service
            "/Create",             // 7. the Windows lifecycle task
            "/Run",
            "--exec docker info", // 8. the read-back
        ]);

        // The preflight really did precede every mutation, rather than merely
        // appearing before it in a list that also holds the read-back's probes.
        let first_mutation = fixture.journal.at("--exec mkdir");
        for probe in [
            "--list --verbose",
            "--exec id -u",
            "--exec uname -m",
            "--exec systemctl is-system-running",
        ] {
            assert!(fixture.journal.at(probe) < first_mutation, "{probe}");
        }
        assert!(
            fixture.journal.at("device flow") > fixture.journal.at("--exec mv"),
            "a credential is issued only once the host is able to hold it"
        );
    }

    /// Nothing that changes the host, and no device flow, happened.
    fn assert_untouched(fixture: &Fixture, what: &str) {
        for mutation in [
            "device flow",
            "auth receive",
            "assets download",
            "--exec mkdir",
            "--exec tar",
            "--exec mv",
            "host set-capacity",
            "service install",
            "/Create",
            "/Delete",
        ] {
            assert!(
                fixture.journal.position(mutation).is_none(),
                "{what}: {mutation} must not have happened. The journal was:\n{:#?}",
                fixture.journal.entries()
            );
        }
        assert!(
            WslProviderRecord::read(&fixture.paths, DISTRIBUTION)
                .expect("a readable record directory")
                .is_none(),
            "{what}: no provider record may be written"
        );
    }

    #[test]
    fn nothing_is_mutated_and_no_credential_is_issued_when_the_preflight_refuses() {
        let refusals: [(&str, ScriptedRunner, Failure); 5] = [
            (
                "a distribution that is not installed",
                ScriptedRunner::new().always("--list --verbose", ok("  Debian   Running   2\n")),
                Failure::NotFound,
            ),
            (
                "WSL1, which has neither systemd nor a Linux kernel",
                ScriptedRunner::new().always("--list --verbose", ok("* Ubuntu   Running   1\n")),
                Failure::UnsupportedHost,
            ),
            (
                "a distribution that does not start as root",
                ScriptedRunner::new()
                    .always("--list --verbose", ok("* Ubuntu   Running   2\n"))
                    .always("--exec id -u", ok("1000\n")),
                Failure::UnsupportedHost,
            ),
            (
                "an architecture the release does not publish",
                ScriptedRunner::new()
                    .always("--list --verbose", ok("* Ubuntu   Running   2\n"))
                    .always("--exec id -u", ok("0\n"))
                    .always("--exec uname -m", ok("armv7l\n")),
                Failure::UnsupportedHost,
            ),
            (
                "a distribution with no systemd",
                ScriptedRunner::new()
                    .always("--list --verbose", ok("* Ubuntu   Running   2\n"))
                    .always("--exec id -u", ok("0\n"))
                    .always("--exec uname -m", ok("x86_64\n"))
                    .always("--exec systemctl is-system-running", refused("not found")),
                Failure::UnsupportedHost,
            ),
        ];

        for (what, script, class) in refusals {
            let mut fixture = Fixture::over(script);
            let refusal = fixture.install(Some(4)).expect_err(what);
            assert_eq!(refusal.class(), class, "{what}: {refusal}");
            assert!(
                refusal.to_string().contains("nothing has been changed"),
                "{what} must say so: {refusal}"
            );
            assert_untouched(&fixture, what);
        }
    }

    #[test]
    fn a_task_somebody_else_made_stops_the_transaction_before_it_changes_anything() {
        let mut fixture = Fixture::over(
            preflight_script()
                .always("/XML ONE", ok(&foreign_task_xml()))
                .always("/FO CSV", ok("\"task\",\"N/A\",\"Ready\"\n")),
        );

        let refusal = fixture.install(None).expect_err("a foreign task");
        assert_eq!(refusal.class(), Failure::Conflict);
        assert!(refusal.to_string().contains(PRODUCT_MARKER), "{refusal}");
        assert!(
            refusal.to_string().contains("nothing has been changed"),
            "asking in the preflight is what turns this into a no-op: {refusal}"
        );
        assert_untouched(&fixture, "a foreign task");
    }

    #[test]
    fn a_healthy_linux_credential_is_adopted_and_never_replaced() {
        let mut fixture = Fixture::over(provisioned_script(ok("27.1.1\n")));
        let (document, outcome) = fixture.install(None).expect("an adoption");

        assert!(!outcome.credential_issued);
        assert!(
            !outcome.binary_replaced,
            "the binary was already this version"
        );
        fixture.journal.never("device flow");
        fixture.journal.never("auth receive");
        fixture.journal.never("--exec mkdir");
        assert!(document.credential.present);
        assert!(
            fixture.output().contains("left untouched"),
            "and it says so: {}",
            fixture.output()
        );
    }

    #[test]
    fn an_active_outdated_service_hands_over_without_a_systemctl_stop() {
        let old = "0.3.2";
        let script = preflight_script()
            .sequence(
                "status --json",
                vec![
                    ok(&linux_status_json_with_service(true, 8, version(), old)),
                    ok(&linux_status_json_with_service(true, 8, version(), old)),
                    ok(&linux_status_json(true, 8, version())),
                    ok(&linux_status_json(true, 8, version())),
                    ok(&linux_status_json(true, 8, version())),
                    ok(&linux_status_json(true, 8, version())),
                ],
            )
            .always("--exec systemctl is-enabled", ok("enabled\n"))
            .always("--exec systemctl is-active", ok("active\n"))
            .sequence(
                "--exec systemctl show --property=MainPID --value",
                vec![ok("123\n"), ok("124\n")],
            )
            .sequence(
                "--exec /proc/123/exe --version",
                vec![ok(&format!("runner-manager {old}\n"))],
            )
            .always(
                "--exec /proc/124/exe --version",
                ok(&format!("runner-manager {}\n", version())),
            )
            .always("--exec docker info", ok("27.1.1\n"))
            .always("/XML ONE", ok(&our_task_xml(DISTRIBUTION)))
            .always("/FO CSV", ok("\"task\",\"N/A\",\"Running\"\n"));
        let mut fixture = Fixture::over(script);

        let (document, outcome) = fixture
            .install(None)
            .expect("the daemon-owned handover completes");

        assert!(document.healthy, "{document:#?}");
        assert!(!outcome.binary_replaced);
        assert!(!outcome.service_installed);
        fixture.journal.never("--exec systemctl stop");
        fixture.journal.never("service install");
        fixture.journal.in_order(&[
            "--exec /proc/123/exe --version",
            "--exec /proc/124/exe --version",
        ]);
        assert!(
            fixture.output().contains("cooperative upgrade handover"),
            "{}",
            fixture.output()
        );
        assert!(
            fixture.output().contains("systemd restarted it"),
            "{}",
            fixture.output()
        );
    }

    #[test]
    fn replacing_an_active_services_source_requests_its_safe_handover() {
        let old = "0.3.2";
        let script = preflight_script()
            .sequence(
                "status --json",
                vec![
                    ok(&linux_status_json(true, 8, old)),
                    ok(&linux_status_json_with_service(true, 8, version(), old)),
                    ok(&linux_status_json(true, 8, version())),
                ],
            )
            .always("--exec systemctl is-enabled", ok("enabled\n"))
            .always("--exec systemctl is-active", ok("active\n"))
            .always(
                "--exec systemctl show --property=MainPID --value",
                ok("123\n"),
            )
            .always(
                "--exec /proc/123/exe --version",
                ok(&format!("runner-manager {}\n", version())),
            )
            .always("--exec docker info", ok("27.1.1\n"))
            .always("--version", ok(&format!("runner-manager {}\n", version())))
            .always("/XML ONE", ok(&our_task_xml(DISTRIBUTION)))
            .always("/FO CSV", ok("\"task\",\"N/A\",\"Running\"\n"));
        let mut fixture = Fixture::over(script);

        let (document, outcome) = fixture
            .install(None)
            .expect("the source change lets the daemon hand itself over");

        assert!(document.healthy, "{document:#?}");
        assert!(outcome.binary_replaced);
        assert!(!outcome.service_installed);
        fixture.journal.never("--exec systemctl stop");
        fixture.journal.never("service install");
        fixture
            .journal
            .in_order(&["--exec mv", "--exec /proc/123/exe --version"]);
    }

    #[test]
    fn a_failed_cooperative_restart_is_reported_without_forcing_the_service() {
        let old = "0.3.2";
        let script = preflight_script()
            .sequence(
                "status --json",
                vec![
                    ok(&linux_status_json_with_service(true, 8, version(), old)),
                    ok(&linux_status_json_with_service(true, 8, version(), old)),
                    ok(&linux_status_json(true, 8, version())),
                ],
            )
            .sequence(
                "--exec systemctl is-active",
                vec![ok("active\n"), ok("failed\n")],
            )
            .always("/XML ONE", ok(&our_task_xml(DISTRIBUTION)));
        let mut fixture = Fixture::over(script);

        let refusal = fixture
            .install(None)
            .expect_err("a unit that cannot restart must not be reported healthy");

        assert_eq!(refusal.class(), Failure::WslProvisioning);
        assert!(refusal.to_string().contains("systemd reported it failed"));
        fixture.journal.never("--exec systemctl stop");
        fixture.journal.never("service install");
        fixture.journal.never("--exec systemctl start");
    }

    #[test]
    fn an_active_disabled_service_is_drained_before_it_is_enabled() {
        let old = "0.3.2";
        let script = preflight_script()
            .sequence(
                "status --json",
                vec![
                    ok(&linux_status_json_with_service(true, 8, version(), old)),
                    ok(&linux_status_json_with_service(true, 8, version(), old)),
                    ok(&linux_status_json(true, 8, version())),
                ],
            )
            .always("--exec systemctl is-enabled", ok("disabled\n"))
            .always("--exec systemctl is-active", ok("active\n"))
            .always(
                "--exec systemctl show --property=MainPID --value",
                ok("123\n"),
            )
            .always(
                "--exec /proc/123/exe --version",
                ok(&format!("runner-manager {}\n", version())),
            )
            .always("--exec systemctl enable", ok(""))
            .always("--exec docker info", ok("27.1.1\n"))
            .always("/XML ONE", ok(&our_task_xml(DISTRIBUTION)))
            .always("/FO CSV", ok("\"task\",\"N/A\",\"Running\"\n"));
        let mut fixture = Fixture::over(script);

        let (document, outcome) = fixture
            .install(None)
            .expect("the disabled unit is safely repaired");

        assert!(document.healthy, "{document:#?}");
        assert!(!outcome.service_installed);
        fixture.journal.never("--exec systemctl stop");
        fixture.journal.never("service install");
        fixture.journal.in_order(&[
            "--exec /proc/123/exe --version",
            "--exec systemctl enable runner-manager.service",
        ]);
    }

    #[test]
    fn a_legacy_active_service_is_left_untouched() {
        let script = preflight_script()
            .always(
                "status --json",
                ok(&linux_status_json_with_service(true, 8, version(), "0.1.7")),
            )
            .always("--exec systemctl is-active", ok("active\n"))
            .always("/XML ONE", ok(&our_task_xml(DISTRIBUTION)));
        let mut fixture = Fixture::over(script);

        let refusal = fixture
            .install(None)
            .expect_err("a legacy daemon cannot prove it will drain safely");

        assert_eq!(refusal.class(), Failure::WslProvisioning);
        assert!(refusal.to_string().contains("predates"), "{refusal}");
        assert!(refusal.to_string().contains("not stopped"), "{refusal}");
        for unsafe_or_mutating in [
            "--exec systemctl stop",
            "--exec mkdir",
            "--exec tar",
            "--exec mv",
            "service install",
            "--exec systemctl start",
        ] {
            fixture.journal.never(unsafe_or_mutating);
        }
    }

    #[test]
    fn only_known_source_handover_releases_are_accepted() {
        for version in ["0.1.8", "0.3.2", "1.0.0"] {
            assert!(
                supports_cooperative_service_handover(Some(version)),
                "{version} contains the source-watch handover"
            );
        }
        for version in [
            None,
            Some(""),
            Some("0.1.7"),
            Some("0.1.8-rc.1"),
            Some("0.1"),
            Some("release-0.3.2"),
        ] {
            assert!(
                !supports_cooperative_service_handover(version),
                "{version:?} must not be guessed safe"
            );
        }
    }

    #[test]
    fn a_status_that_will_not_answer_refuses_rather_than_issuing_a_second_credential() {
        // The binary landed one stage ago, so a refusal here is not "there is
        // no host to ask" -- it is "the host would not say". Reading it as
        // absence would mint a credential over one this cannot see, and
        // GitHub invalidates both halves of a pair when either renews, so the
        // credential the distribution was working with would be destroyed.
        let mut fixture = Fixture::over(base_script().sequence(
            "status --json",
            vec![
                // Stage 3: there is no binary yet, so one is installed.
                refused("/usr/local/bin/runner-manager: not found"),
                // Stage 4: the binary that just landed will not answer.
                refused("cannot open the local database at /var/lib/runner-manager/state.db"),
            ],
        ));

        let refusal = fixture
            .install(None)
            .expect_err("a status that will not answer is not an absent credential");

        assert_eq!(refusal.class(), Failure::WslProvisioning);
        let message = refusal.to_string();
        assert!(
            message.contains("credential"),
            "the failure must name its stage: {message}"
        );
        assert!(
            message.contains("cannot open the local database"),
            "and it must carry the child's own reason rather than invent one: {message}"
        );
        assert!(
            refusal.remedy().is_some(),
            "and it must name a command: {message}"
        );
        fixture.journal.never("device flow");
        fixture.journal.never("auth receive");
        fixture.journal.never("/Create");
        assert!(
            WslProviderRecord::read(&fixture.paths, DISTRIBUTION)
                .expect("a readable directory")
                .is_none(),
            "and nothing may claim the host is managed"
        );
    }

    #[test]
    fn a_declined_sign_in_leaves_what_landed_and_registers_nothing() {
        let mut fixture = Fixture::fresh();
        fixture.issuer = FakeIssuer::issuing(fixture.journal.clone())
            .refusing("the operator declined on GitHub");
        let refusal = fixture.install(None).expect_err("declined");

        assert_eq!(refusal.class(), Failure::AuthenticationDeclined);
        assert!(refusal.to_string().contains("credential"), "{refusal}");
        fixture.journal.at("--exec mv");
        fixture.journal.never("auth receive");
        fixture.journal.never("/Create");
        assert!(
            WslProviderRecord::read(&fixture.paths, DISTRIBUTION)
                .expect("a readable directory")
                .is_none(),
            "a failed device flow leaves no provider record"
        );
    }

    #[test]
    fn an_enabled_unit_is_adopted_rather_than_reinstalled() {
        let mut fixture = Fixture::over(provisioned_script(ok("27.1.1\n")));
        let (_, outcome) = fixture.install(None).expect("an adoption");

        assert!(!outcome.service_installed);
        fixture.journal.never("service install");
        assert!(
            fixture.output().contains("adopted rather than reinstalled"),
            "{}",
            fixture.output()
        );
    }

    #[test]
    fn an_enabled_but_inactive_unit_is_started_when_it_is_adopted() {
        let mut fixture = Fixture::over(provisioned_inactive_script());
        let (document, outcome) = fixture.install(None).expect("an inactive adoption");

        assert!(document.healthy, "{document:#?}");
        assert!(!outcome.service_installed);
        fixture.journal.never("service install");
        fixture
            .journal
            .at("--exec systemctl start runner-manager.service");
        assert!(
            fixture.output().contains("adopted and started"),
            "{}",
            fixture.output()
        );
    }

    #[test]
    fn capacity_is_changed_only_when_it_was_supplied() {
        let mut without = Fixture::fresh();
        let (_, outcome) = without.install(None).expect("a clean provisioning");
        assert_eq!(outcome.capacity_set, None);
        without.journal.never("host set-capacity");
        assert!(
            without.output().contains("unchanged (none was supplied)"),
            "{}",
            without.output()
        );

        let mut with = Fixture::fresh();
        let (_, outcome) = with.install(Some(8)).expect("a clean provisioning");
        assert_eq!(outcome.capacity_set, Some(8));
        with.journal.at("host set-capacity 8");

        // And nothing else about the Linux host's configuration is touched: no
        // policy is created, no runtime root moved, no credential purged.
        for untouched in [
            "--exec /usr/local/bin/runner-manager repo",
            "--exec /usr/local/bin/runner-manager org",
            "host set-runtime-root",
            "host reset-runtime-root",
            "auth logout",
        ] {
            with.journal.never(untouched);
        }
    }

    #[test]
    fn a_rerun_over_a_provisioned_host_changes_nothing_and_still_succeeds() {
        let mut fixture = Fixture::over(provisioned_script(ok("27.1.1\n")));
        let (document, outcome) = fixture.install(None).expect("a convergent rerun");

        assert!(document.healthy);
        assert_eq!(
            outcome,
            InstallOutcome {
                version: version().to_string(),
                binary_replaced: false,
                credential_issued: false,
                capacity_set: None,
                service_installed: false,
            },
            "a convergent transaction over a host that is already right does nothing to it"
        );
        fixture.journal.never("--exec mkdir");
        fixture.journal.never("device flow");
        fixture.journal.never("service install");
        // The task IS re-registered and restarted: `/Create ... /F` is
        // idempotent and `MultipleInstancesPolicy IgnoreNew` makes `/Run`
        // idempotent too, and between them they repair a task an operator
        // disabled or deleted by hand.
        fixture.journal.at("/Create");
        fixture.journal.at("/Run");
    }

    #[test]
    fn every_injected_failure_names_its_stage_and_leaves_the_host_safe_to_rerun() {
        // One case per mutating stage. Each asserts the same two things: the
        // failure says which stage it was, and it says the host is safe to run
        // this against again — the whole of `03-security-and-lifecycle.md`'s
        // rerun column.
        let mut artifact = Fixture::fresh();
        artifact.assets =
            FakeAssets::publishing(artifact.journal.clone()).refusing("the release is unreachable");

        let cases: [(&str, Fixture); 5] = [
            ("release artifact", artifact),
            (
                "Linux binary",
                Fixture::over(fresh_script().always("--exec mv", refused("Read-only file system"))),
            ),
            (
                "capacity",
                Fixture::over(
                    fresh_script().always("host set-capacity", refused("the database is locked")),
                ),
            ),
            (
                "Linux service",
                Fixture::over(
                    fresh_script().always("service install", refused("systemd refused the unit")),
                ),
            ),
            (
                "Windows lifecycle task",
                Fixture::over(fresh_script().always("/Create", refused("Access is denied."))),
            ),
        ];

        for (stage, mut fixture) in cases {
            let refusal = fixture.install(Some(4)).expect_err(stage);
            let message = refusal.to_string();
            assert!(
                message.contains(stage),
                "the failure must name the stage {stage:?}: {message}"
            );
            assert!(
                message.contains("safe to run again once this is fixed"),
                "and it must say a rerun is safe rather than leave it to be guessed: {message}"
            );
            assert!(
                refusal.remedy().is_some(),
                "and it must name a command: {message}"
            );
        }
    }

    #[test]
    fn a_partly_provisioned_host_is_refused_rather_than_reported_as_working() {
        // Everything lands except the credential, so the read-back sees a host
        // that cannot accept a job.
        let mut fixture = Fixture::over(base_script().sequence(
            "status --json",
            vec![
                refused("not found"),
                ok(&linux_status_json(false, 1, version())),
                ok(&linux_status_json(false, 1, version())),
            ],
        ));
        let (document, _) = fixture.install(None).expect("the stages themselves ran");
        assert!(!document.healthy);

        let refusal = refuse_a_partial_host(&document).expect_err("not a working host");
        assert_eq!(refusal.class(), Failure::WslProvisioning);
        assert!(
            refusal
                .to_string()
                .contains("holds no credential of its own"),
            "the refusal names the part that is missing: {refusal}"
        );
        assert!(
            refusal
                .to_string()
                .contains("Everything that did land stands"),
            "and it does not suggest starting over: {refusal}"
        );
        assert!(
            refuse_a_partial_host(&{
                let mut healthy = document.clone();
                healthy.healthy = true;
                healthy
            })
            .is_ok(),
            "and a healthy host is not refused"
        );
    }

    // -----------------------------------------------------------------------
    // Status
    // -----------------------------------------------------------------------

    #[test]
    fn status_reads_the_host_and_reports_every_documented_part() {
        let (_journal, _root, document) = probe_scripted(fresh_script());

        assert_eq!(document.schema_version, WSL_STATUS_SCHEMA_VERSION);
        assert!(document.provider_record.is_none(), "nothing manages it yet");
        assert!(document.wsl.ready);
        assert_eq!(document.wsl.wsl_version, Some(2));
        assert_eq!(document.wsl.machine.as_deref(), Some("x86_64"));
        assert!(document.binary.problem.is_some(), "no binary is installed");
        assert!(!document.credential.present);
        assert_eq!(document.service.unit, UNIT);
        assert!(!document.lifecycle_task.registered);
        assert_eq!(document.diagnostics.len(), 1);
        assert_eq!(document.diagnostics[0].name, "docker");
        assert!(!document.healthy);
        assert!(
            document
                .availability
                .contains("after the owning Windows account logs on"),
            "the per-user constraint is stated rather than left to be discovered"
        );

        // Every part that is missing is named, so an operator gets a list
        // rather than a verdict.
        let parts = document.unhealthy_parts().join("; ");
        for expected in ["Linux binary", "credential", "lifecycle task"] {
            assert!(
                parts.contains(expected),
                "{expected} must be named: {parts}"
            );
        }
    }

    #[test]
    fn status_is_unhealthy_when_the_running_service_copy_is_an_older_version() {
        let script = preflight_script()
            .always(
                "status --json",
                ok(&linux_status_json_with_service(true, 8, version(), "0.3.2")),
            )
            .always("--exec systemctl is-enabled", ok("enabled\n"))
            .always("--exec systemctl is-active", ok("active\n"))
            .always("--exec docker info", ok("27.1.1\n"))
            .always("/XML ONE", ok(&our_task_xml(DISTRIBUTION)))
            .always("/FO CSV", ok("\"task\",\"N/A\",\"Running\"\n"));
        let (_journal, _root, document) = probe_scripted(script);

        assert!(!document.healthy);
        assert_eq!(document.service.binary_version.as_deref(), Some("0.3.2"));
        assert!(!document.service.matches_expected);
        assert!(
            document
                .unhealthy_parts()
                .join("; ")
                .contains("its binary is 0.3.2")
        );
    }

    #[test]
    fn a_record_never_makes_an_unprovisioned_host_look_healthy() {
        let journal = Journal::default();
        // A record that claims everything, over a host that has nothing.
        let (host, _) = wrap(
            preflight_script()
                .always("status --json", refused("not found"))
                .always("--exec systemctl is-active", ok("inactive\n"))
                .always("/XML ONE", refused("no such task")),
            &journal,
        );
        let (_root, paths) = fixture_paths();
        write_record(&paths, "9.9.9");

        let document = probe(
            &host,
            &paths,
            DISTRIBUTION,
            DEFAULT_LINUX_DESTINATION,
            UNIT,
            version(),
            Utc::now(),
        )
        .expect("a readable host");

        assert!(
            !document.healthy,
            "a record is advisory; health is read from the distribution"
        );
        assert!(document.provider_record.is_some());
        let drift = document.drift.join("; ");
        assert!(drift.contains("no task named"), "{drift}");
        assert!(drift.contains("9.9.9"), "{drift}");
    }

    #[test]
    fn an_absent_record_is_not_drift() {
        let (_journal, _root, document) = probe_scripted(fresh_script());
        assert!(
            document.drift.is_empty(),
            "asking about an unmanaged distribution is a legitimate question with a \
             legitimate answer: {:?}",
            document.drift
        );
    }

    #[test]
    fn a_binary_that_refuses_is_reported_in_its_own_words_and_not_called_absent() {
        // A missing program and an installed one that refused are the same
        // exit status to this process. Only the child's diagnostic tells them
        // apart, so it is reported rather than dropped: an operator whose
        // `status --json` cannot read its journal must not be sent to
        // reinstall a binary that is plainly already there.
        let (_journal, _root, document) = probe_scripted(base_script().always(
            "status --json",
            refused("cannot read this host's attempt journal: database disk image is malformed"),
        ));

        let problem = document
            .binary
            .problem
            .as_deref()
            .expect("a binary that will not answer is a problem");
        assert!(
            problem.contains("database disk image is malformed"),
            "the child's own reason must survive: {problem}"
        );
        assert!(
            !document.binary.installed,
            "nothing usable answered, so nothing may be treated as installed"
        );
        assert!(!document.healthy);
    }

    #[test]
    fn a_question_that_was_never_asked_is_not_drift() {
        // WSL1 has neither systemd nor a Linux kernel, so `probe` never asks
        // the distribution about its binary. Reporting the resulting absence
        // as drift would tell the operator their Linux binary is gone, which
        // nothing here has looked for.
        let journal = Journal::default();
        let (host, _) = wrap(
            ScriptedRunner::new()
                .always("--list --verbose", ok("* Ubuntu   Running   1\n"))
                .always("/XML ONE", ok(&our_task_xml(DISTRIBUTION)))
                .always("/FO CSV", ok("\"task\",\"N/A\",\"Running\"\n")),
            &journal,
        );
        let (_root, paths) = fixture_paths();
        write_record(&paths, version());

        let document = probe(
            &host,
            &paths,
            DISTRIBUTION,
            DEFAULT_LINUX_DESTINATION,
            UNIT,
            version(),
            Utc::now(),
        )
        .expect("a readable host");

        assert!(!document.wsl.ready, "WSL1 is not usable");
        assert!(
            !document
                .drift
                .iter()
                .any(|line| line.contains("readable binary")),
            "the binary was never asked about, so its absence is not evidence: {:?}",
            document.drift
        );
        assert!(
            document.drift.is_empty(),
            "and nothing else disagrees either: {:?}",
            document.drift
        );
        assert!(
            !document.healthy,
            "the distribution is still not a usable host, which is what `wsl` says"
        );
    }

    #[test]
    fn docker_is_a_diagnostic_and_never_decides_health() {
        let (_journal, _root, document) = probe_scripted(provisioned_script(refused(
            "Cannot connect to the Docker daemon",
        )));

        assert!(
            document.healthy,
            "a host with no Docker still runs every job that does not use a container"
        );
        let docker = &document.diagnostics[0];
        assert!(!docker.available);
        assert!(
            docker.detail.contains("container jobs would fail"),
            "and the report says exactly what is affected: {}",
            docker.detail
        );
    }

    #[test]
    fn a_distribution_that_is_not_wsl2_is_reported_as_installed_and_not_ready() {
        let (journal, _root, document) = probe_scripted(
            ScriptedRunner::new().always("--list --verbose", ok("  Ubuntu   Running   1\n")),
        );

        assert!(document.wsl.installed, "it is there");
        assert!(!document.wsl.ready, "and it cannot be a runner host");
        assert!(
            document
                .wsl
                .problem
                .as_deref()
                .unwrap_or_default()
                .contains("WSL2 only"),
            "{:?}",
            document.wsl.problem
        );
        // Nothing was asked of a distribution that cannot answer it.
        journal.never("--exec docker");
        journal.never("status --json");
    }

    #[test]
    fn the_json_document_is_a_document_and_carries_its_version() {
        let (_journal, _root, document) = probe_scripted(fresh_script());

        let mut rendered = Vec::new();
        write_json(&mut rendered, &document).expect("it renders");
        let parsed: serde_json::Value =
            serde_json::from_slice(&rendered).expect("and it is JSON a script can read");

        for key in [
            "schema_version",
            "generated_at",
            "distribution",
            "healthy",
            "provider_record",
            "wsl",
            "binary",
            "credential",
            "service",
            "lifecycle_task",
            "capacity",
            "diagnostics",
            "drift",
            "availability",
        ] {
            assert!(parsed.get(key).is_some(), "the document must carry {key}");
        }
        assert_eq!(parsed["schema_version"], serde_json::json!(1));
        assert_eq!(
            parsed["credential"]["present"],
            serde_json::json!(false),
            "the credential appears as a boolean and never as a value"
        );
    }

    #[test]
    fn the_text_report_names_every_part_separately() {
        let (_journal, _root, document) = probe_scripted(fresh_script());

        let mut rendered = Vec::new();
        write_status_text(&document, &mut rendered).expect("it renders");
        let text = String::from_utf8(rendered).expect("utf-8");
        for row in [
            "provider record",
            "linux binary",
            "credential",
            "linux service",
            "lifecycle task",
            "capacity",
            "docker",
        ] {
            assert!(
                text.contains(row),
                "the report must carry a {row} row:\n{text}"
            );
        }
        assert!(text.contains(AVAILABILITY_NOTE), "{text}");
    }

    // -----------------------------------------------------------------------
    // List
    // -----------------------------------------------------------------------

    #[test]
    fn list_names_every_distribution_and_says_which_are_managed() {
        let journal = Journal::default();
        let (host, _) = wrap(
            ScriptedRunner::new().always(
                "--list --verbose",
                ok("  NAME              STATE           VERSION\n\
                    * Ubuntu            Running         2\n  \
                      Debian GNU Linux  Stopped         2\n  \
                      Legacy            Stopped         1\n"),
            ),
            &journal,
        );
        let (_root, paths) = fixture_paths();
        write_record(&paths, version());

        let mut out = Vec::new();
        list_with(&host, &paths, &mut out).expect("a readable machine");
        let text = String::from_utf8(out).expect("utf-8");

        assert!(
            text.contains(&format!(
                "Ubuntu  WSL2, Running, default (managed, runner-manager {})",
                version()
            )),
            "the managed one is named with the version this machine installed:\n{text}"
        );
        assert!(
            text.contains("Debian GNU Linux  WSL2, Stopped (not managed)"),
            "a name with spaces survives, exactly as WSL spells it:\n{text}"
        );
        assert!(
            text.contains("Legacy  WSL1, Stopped (not managed)"),
            "and a WSL1 distribution is listed rather than hidden, because `wsl install` \
             is the command that explains why it cannot be used:\n{text}"
        );
    }

    #[test]
    fn one_unreadable_record_does_not_hide_the_machines_distributions() {
        // `wsl list` is the remedy every other failure in this module points
        // an operator at, and a record is advisory in any case. One file this
        // build cannot parse must not be able to hide every distribution the
        // machine has, which is the one thing this command exists to say.
        let journal = Journal::default();
        let (host, _) = wrap(
            ScriptedRunner::new().always(
                "--list --verbose",
                ok("* Ubuntu   Running   2\n  Debian   Stopped   2\n"),
            ),
            &journal,
        );
        let (_root, paths) = fixture_paths();
        let path = WslProviderRecord::path(&paths, DISTRIBUTION).expect("a record path");
        std::fs::create_dir_all(WslProviderRecord::directory(&paths))
            .expect("the record directory");
        std::fs::write(&path, "this is not a provider record").expect("a fixture record");

        let mut out = Vec::new();
        list_with(&host, &paths, &mut out).expect("one bad file is not a failure of the listing");
        let text = String::from_utf8(out).expect("utf-8");

        assert!(
            text.contains("Ubuntu") && text.contains("record unreadable"),
            "the row says what is wrong with it rather than vanishing:\n{text}"
        );
        assert!(
            text.contains("Debian  WSL2, Stopped (not managed)"),
            "and every other distribution is still listed:\n{text}"
        );
    }

    #[test]
    fn list_says_so_plainly_when_this_machine_has_no_distributions() {
        let journal = Journal::default();
        let (host, _) = wrap(
            ScriptedRunner::new().always("--list --verbose", ok("")),
            &journal,
        );
        let (_root, paths) = fixture_paths();
        let mut out = Vec::new();
        list_with(&host, &paths, &mut out).expect("an empty machine is not a failure");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("no WSL distributions installed"), "{text}");
    }

    // -----------------------------------------------------------------------
    // Detach
    // -----------------------------------------------------------------------

    #[test]
    fn detach_removes_the_product_task_and_the_record_and_nothing_inside_linux() {
        let journal = Journal::default();
        let (host, _) = wrap(
            ScriptedRunner::new()
                .always("/XML ONE", ok(&our_task_xml(DISTRIBUTION)))
                .always("/FO CSV", ok("\"task\",\"N/A\",\"Running\"\n"))
                .always("/End", ok(""))
                .always("/Delete", ok("")),
            &journal,
        );
        let (_root, paths) = fixture_paths();
        write_record(&paths, version());

        let mut out = Vec::new();
        detach_with(&host, &paths, DISTRIBUTION, &mut out).expect("a clean detach");
        let text = String::from_utf8(out).expect("utf-8");

        journal.at("/End");
        journal.at("/Delete");
        assert!(
            WslProviderRecord::read(&paths, DISTRIBUTION)
                .expect("a readable directory")
                .is_none(),
            "the record is removed"
        );

        // The promise, and the fact that it is kept: nothing at all was run
        // inside the distribution, so no Linux data can have been touched.
        journal.never("--distribution");
        journal.never("--exec");
        assert!(text.contains("Nothing inside Ubuntu was changed"), "{text}");
        assert!(
            text.contains("service uninstall") && text.contains("auth logout"),
            "and it names the commands an operator may run separately: {text}"
        );
    }

    #[test]
    fn detach_is_convergent_over_a_host_that_was_never_managed() {
        let journal = Journal::default();
        let (host, _) = wrap(
            ScriptedRunner::new().always("/Query", refused("no such task")),
            &journal,
        );
        let (_root, paths) = fixture_paths();
        let mut out = Vec::new();
        detach_with(&host, &paths, DISTRIBUTION, &mut out).expect("nothing to do is not a failure");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("was not registered"), "{text}");
        assert!(text.contains("was not there"), "{text}");
        journal.never("/Delete");
    }

    #[test]
    fn detach_refuses_a_foreign_task_and_removes_nothing() {
        let journal = Journal::default();
        let (host, _) = wrap(
            ScriptedRunner::new()
                .always("/XML ONE", ok(&foreign_task_xml()))
                .always("/FO CSV", ok("\"task\",\"N/A\",\"Ready\"\n")),
            &journal,
        );
        let (_root, paths) = fixture_paths();
        write_record(&paths, version());

        let mut out = Vec::new();
        let refusal =
            detach_with(&host, &paths, DISTRIBUTION, &mut out).expect_err("somebody else's task");
        assert_eq!(refusal.class(), Failure::Conflict);
        journal.never("/Delete");
        assert!(
            WslProviderRecord::read(&paths, DISTRIBUTION)
                .expect("a readable directory")
                .is_some(),
            "and the record stays, so an operator can still see what this machine believed"
        );
    }

    // -----------------------------------------------------------------------
    // `wsl-host hold`
    // -----------------------------------------------------------------------

    #[derive(Debug, Default)]
    struct FakeSystemd {
        calls: Mutex<Vec<Vec<String>>>,
        report: String,
        start_fails: bool,
    }

    impl FakeSystemd {
        fn running() -> Self {
            Self {
                report: "running".to_string(),
                ..Self::default()
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().expect("no panic").clone()
        }
    }

    impl Systemd for FakeSystemd {
        fn run(&self, arguments: &[&str]) -> io::Result<std::process::Output> {
            self.calls
                .lock()
                .expect("no panic")
                .push(arguments.iter().map(|a| (*a).to_string()).collect());
            let failed = self.start_fails && arguments.first() == Some(&"start");
            Ok(std::process::Output {
                status: exit_status(i32::from(failed)),
                stdout: if arguments.first() == Some(&"is-system-running") {
                    self.report.clone().into_bytes()
                } else {
                    Vec::new()
                },
                stderr: if failed {
                    b"Failed to start runner-manager.service.".to_vec()
                } else {
                    Vec::new()
                },
            })
        }
    }

    /// An [`std::process::ExitStatus`] with a chosen code, on either platform.
    fn exit_status(code: i32) -> std::process::ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            std::process::ExitStatus::from_raw(code << 8)
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt as _;
            std::process::ExitStatus::from_raw(u32::try_from(code).expect("a small code"))
        }
    }

    #[test]
    fn the_hold_verifies_systemd_then_starts_the_unit_and_waits() {
        let systemd = FakeSystemd::running();
        let mut out = Vec::new();
        let mut wait = || -> Result<HoldStop, CliError> { Ok(HoldStop::Signal("SIGTERM")) };

        hold(&systemd, UNIT, &mut out, &mut wait).expect("a holdable distribution");

        assert_eq!(
            systemd.calls(),
            vec![
                vec!["is-system-running".to_string()],
                vec!["start".to_string(), UNIT.to_string()],
            ],
            "verify, then start, and nothing else: systemd remains the daemon's supervisor \
             and the hold is not a second one"
        );
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("holding this distribution open"), "{text}");
        assert!(
            text.contains("SIGTERM received"),
            "and it says why it stopped: {text}"
        );
        assert!(
            text.contains("is left running"),
            "and that it did not take the daemon down with it: {text}"
        );
    }

    #[test]
    fn the_hold_never_builds_a_shell_command() {
        let command = systemctl_command(&["start", UNIT]);
        assert_eq!(command.get_program(), std::ffi::OsStr::new("systemctl"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![std::ffi::OsStr::new("start"), std::ffi::OsStr::new(UNIT)],
            "an argument vector, so a unit name can never be read as shell syntax"
        );
        for shell in ["sh", "bash", "cmd", "cmd.exe", "powershell"] {
            assert_ne!(command.get_program(), std::ffi::OsStr::new(shell));
        }
    }

    #[test]
    fn the_hold_refuses_a_distribution_without_systemd_and_starts_nothing() {
        let systemd = FakeSystemd {
            report: "offline".to_string(),
            ..FakeSystemd::default()
        };
        let mut out = Vec::new();
        let mut wait = || -> Result<HoldStop, CliError> {
            panic!("the hold must not wait when there is nothing to hold")
        };

        let refusal = hold(&systemd, UNIT, &mut out, &mut wait).expect_err("no systemd");
        assert_eq!(refusal.class(), Failure::WslProvisioning);
        assert!(
            refusal.to_string().contains("not running systemd"),
            "{refusal}"
        );
        assert_eq!(
            systemd.calls(),
            vec![vec!["is-system-running".to_string()]],
            "and it did not try to start a unit that cannot exist"
        );
    }

    #[test]
    fn a_unit_that_will_not_start_is_reported_rather_than_held() {
        let systemd = FakeSystemd {
            report: "running".to_string(),
            start_fails: true,
            ..FakeSystemd::default()
        };
        let mut out = Vec::new();
        let mut wait =
            || -> Result<HoldStop, CliError> { panic!("a hold over a dead unit would be a lie") };

        let refusal = hold(&systemd, UNIT, &mut out, &mut wait).expect_err("the unit failed");
        assert!(refusal.to_string().contains("Failed to start"), "{refusal}");
        assert_eq!(refusal.class(), Failure::WslProvisioning);
    }

    #[test]
    fn a_degraded_or_starting_system_is_still_held() {
        // Both exit non-zero from `systemctl is-system-running` and both are
        // usable: the product's own unit is what matters, and refusing during
        // the first seconds of a cold start would make the hold flaky.
        for word in ["degraded", "starting"] {
            let systemd = FakeSystemd {
                report: word.to_string(),
                ..FakeSystemd::default()
            };
            let mut out = Vec::new();
            let mut wait = || -> Result<HoldStop, CliError> { Ok(HoldStop::Signal("SIGHUP")) };
            hold(&systemd, UNIT, &mut out, &mut wait)
                .unwrap_or_else(|error| panic!("`{word}` must be held: {error}"));
            assert_eq!(systemd.calls().len(), 2, "{word}");
        }
    }

    #[test]
    fn the_lifecycle_task_starts_the_hold_at_logon_with_least_privilege() {
        let task = LifecycleTask::new(
            identity_of(DISTRIBUTION),
            TaskPrincipal::named("FIXTURE\\ivan"),
            &WslExecutable::at("C:\\Windows\\System32\\wsl.exe"),
            DEFAULT_LINUX_DESTINATION,
        );
        assert_eq!(
            task.action_arguments(),
            [
                "--distribution",
                DISTRIBUTION,
                "--user",
                "root",
                "--exec",
                DEFAULT_LINUX_DESTINATION,
                "wsl-host",
                "hold",
            ]
            .map(str::to_string),
            "the task's action is exactly the hidden command this module implements"
        );
        let xml = task.xml();
        assert!(xml.contains("<LogonTrigger>"), "{xml}");
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"), "{xml}");
        assert!(
            !xml.contains("cmd.exe") && !xml.contains("powershell"),
            "and no shell is anywhere in it: {xml}"
        );
    }

    #[test]
    fn the_hold_is_refused_off_linux() {
        let outcome = require_linux();
        if cfg!(target_os = "linux") {
            assert!(outcome.is_ok());
        } else {
            let refusal = outcome.expect_err("not Linux");
            assert_eq!(refusal.class(), Failure::UnsupportedHost);
            assert!(refusal.to_string().contains(std::env::consts::OS));
        }
    }

    // -----------------------------------------------------------------------
    // The platform boundary and the taxonomy
    // -----------------------------------------------------------------------

    #[test]
    fn the_wsl_family_is_refused_off_windows_rather_than_missing_from_help() {
        // The command parses on every platform — that is what keeps it in
        // `--help` — and the refusal comes from the adapter, with a sentence.
        assert!(
            Cli::try_parse_from([
                "runner-manager",
                "wsl",
                "status",
                "--distribution",
                "Ubuntu"
            ])
            .is_ok(),
            "the surface is the same on every platform"
        );
        assert!(
            Cli::try_parse_from([
                "runner-manager",
                "wsl",
                "install",
                "--distribution",
                "Ubuntu"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["runner-manager", "wsl", "install"]).is_err(),
            "and `--distribution` is required, because there is no default host to manage"
        );

        let outcome = host_adapter("`runner-manager wsl status`");
        if cfg!(windows) {
            assert!(outcome.is_ok());
        } else {
            let refusal = outcome.expect_err("not Windows");
            assert_eq!(refusal.class(), Failure::UnsupportedHost);
            assert!(
                refusal.to_string().contains("`runner-manager wsl status`"),
                "the refusal names what was attempted: {refusal}"
            );
            assert!(
                refusal.to_string().contains(std::env::consts::OS),
                "{refusal}"
            );
        }
    }

    #[test]
    fn every_stage_has_a_distinct_label_so_a_failure_can_name_one() {
        let mut labels: Vec<&str> = Stage::ALL.iter().map(|stage| stage.label()).collect();
        assert_eq!(labels.len(), 8, "the eight numbered steps of the design");
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            Stage::ALL.len(),
            "two stages must not share a name, or a failure cannot say which one it was"
        );

        for stage in Stage::ALL.iter().copied() {
            let prefix = stage_prefix(stage);
            if stage == Stage::Preflight {
                assert!(prefix.contains("nothing has been changed"), "{prefix}");
            } else {
                assert!(prefix.contains("safe to run"), "{prefix}");
                assert!(prefix.contains(stage.label()), "{prefix}");
            }
        }
    }

    #[test]
    fn every_platform_failure_maps_onto_a_class_a_script_can_branch_on() {
        let cases = [
            (
                WslError::NotInstalled {
                    requested: DISTRIBUTION.to_string(),
                    available: vec!["Debian".to_string()],
                },
                Failure::NotFound,
            ),
            (
                WslError::NotWsl2 {
                    distribution: DISTRIBUTION.to_string(),
                    version: 1,
                },
                Failure::UnsupportedHost,
            ),
            (
                WslError::ForeignTask {
                    name: "x".to_string(),
                    detail: "y".to_string(),
                },
                Failure::Conflict,
            ),
            (
                WslError::DigestMismatch {
                    path: PathBuf::from("a.tar.gz"),
                    expected: "a".to_string(),
                    actual: "b".to_string(),
                },
                Failure::UnusableResponse,
            ),
            (
                WslError::SecretInCommandLine {
                    program: PathBuf::from("wsl.exe"),
                    location: "argument 3".to_string(),
                },
                Failure::SecretStore,
            ),
            (
                WslError::TaskControl {
                    operation: "register",
                    name: "x".to_string(),
                    detail: "y".to_string(),
                },
                Failure::WslProvisioning,
            ),
            (
                WslError::RecordSchema {
                    path: PathBuf::from("a.toml"),
                    found: 2,
                    supported: 1,
                },
                Failure::LocalState,
            ),
        ];
        for (source, class) in cases {
            let failure = wsl_failure(&source);
            assert_eq!(failure.class(), class, "{source}");
            assert!(
                !failure.to_string().is_empty(),
                "and it carries the platform's own sentence"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The acceptance suite
// ---------------------------------------------------------------------------
// `b3-acceptance-docs`'s end-to-end journeys live in their own file rather than
// in the module above, and are a CHILD of this module rather than a sibling so
// that they can drive `install`, `probe`, `list_with` and `detach_with` -- the
// last two of which are private, because nothing outside this module has any
// business calling them.
//
// They build their own fakes rather than sharing the ones in `mod tests`. That
// is deliberate: the tests above measure parts against fixtures written for
// those parts, and an acceptance suite that inherited them would inherit their
// assumptions too.
#[cfg(test)]
#[path = "wsl_acceptance.rs"]
mod acceptance;
