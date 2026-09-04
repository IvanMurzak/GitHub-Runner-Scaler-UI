// owner: f3-cli-daemon-service

//! Noninteractive wrappers around the platform service transaction.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use runner_manager_domain::model::StartMode;
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_platform::service::{
    HostControls, InstallRequest, ServiceError, ServiceIdentity, ServiceOperations,
    WINDOWS_SCM_HOST_ARGUMENT,
};

use super::{CliError, Context, Failure, ServiceCommand, ServiceInstallArgs, write_failed};

/// Routes one service command. Every arm is synchronous and reads no stdin.
pub fn dispatch(
    context: &Context,
    command: &ServiceCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        ServiceCommand::Install(args) => install(context, args, out),
        ServiceCommand::Uninstall => uninstall(context, out),
        ServiceCommand::Status => status(context, out),
    }
}

/// The variable that lets a test drive these commands without meeting the
/// service this machine actually has installed.
///
/// See [`identity`].
pub(super) const SERVICE_TAG_VARIABLE: &str = "RUNNER_MANAGER_SERVICE_NAME_TAG";

/// The one place that decides which registration this process acts on.
///
/// `pub(crate)` so that the TUI's settings screen switches the start mode of
/// the *same* registration these commands report on. Building
/// [`ServiceOperations::on_this_host`] there instead would leave one code path
/// -- the only one that **writes** -- still pointed at the product's name while
/// everything else was pointed at a fixture.
pub(crate) fn operations(context: &Context) -> ServiceOperations {
    ServiceOperations::with_controls(
        context.paths().clone(),
        identity(),
        std::sync::Arc::new(HostControls),
    )
}

/// Which registration these commands operate on.
///
/// # Why this is not always the product's
///
/// `--data-dir` moves the directories but not the service manager, which has
/// exactly one registration per machine under one constant name. So a test
/// pointed at a temporary directory still meets whatever is really installed
/// here, and `service status` correctly reports a registration with no install
/// record behind it -- a true statement about the machine, and a failure for
/// every developer who has the product installed. Four tests failed that way,
/// on `main`, for exactly as long as somebody had run `service install`.
///
/// [`ServiceIdentity::fixture`] already exists for the privileged installer
/// tests, which register real services under names that cannot collide with the
/// product's. This lets the CLI reach it too, so a test gets a machine that is
/// clean *for the name it is asking about* rather than a machine nobody has
/// used.
///
/// # Why it is safe to read in a shipped binary
///
/// A fixture name is always `runner-manager-selftest-<tag>`, so this cannot
/// point at, hide, or replace a real registration whatever it is set to. It can
/// still *create* one: `service install` under a stray variable registers a
/// real service under a fixture name and writes an ordinary install record, and
/// once the variable is gone `service uninstall` no longer finds it. So
/// [`announce_fixture`] is called by every command that touches the identity --
/// not only [`status`] -- which is what keeps a stray variable in a shell
/// profile from reading as "the service vanished" or as a successful install.
fn identity() -> ServiceIdentity {
    match std::env::var(SERVICE_TAG_VARIABLE) {
        Ok(tag) if !tag.trim().is_empty() => ServiceIdentity::fixture(tag.trim()),
        _ => ServiceIdentity::product(),
    }
}

/// Says out loud that this command is pointed at a test registration.
///
/// Announced by `install` and `uninstall` as well as [`status`], because the
/// write paths are the ones with a lasting consequence: an operator who is not
/// told cannot tell `service install` under a stray [`SERVICE_TAG_VARIABLE`]
/// apart from a real install, and is left with a boot-start service that the
/// product's own `service uninstall` will not remove.
fn announce_fixture(
    operations: &ServiceOperations,
    verb: &str,
    subject: &'static str,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    if !operations.identity().is_fixture() {
        return Ok(());
    }
    writeln!(
        out,
        "note: {SERVICE_TAG_VARIABLE} is set, so this {verb} the test registration \
         `{}` and not the installed service.",
        operations.identity().name()
    )
    .map_err(write_failed(subject))
}

fn daemon_arguments(context: &Context, mode: StartMode) -> Vec<OsString> {
    let paths = context.paths();
    let mut arguments: Vec<OsString> = [
        OsString::from("daemon"),
        OsString::from("run"),
        OsString::from("--service-config-dir"),
        paths.config_dir().as_os_str().to_owned(),
        OsString::from("--service-state-dir"),
        paths.state_dir().as_os_str().to_owned(),
        OsString::from("--service-runtime-dir"),
        paths.runtime_dir().as_os_str().to_owned(),
        OsString::from("--service-logs-dir"),
        paths.logs_dir().as_os_str().to_owned(),
    ]
    .into_iter()
    .collect();
    if cfg!(windows) && mode == StartMode::Boot {
        arguments.push(OsString::from(WINDOWS_SCM_HOST_ARGUMENT));
    }
    arguments
}

/// The copy of this executable that the service runs, and how to undo making
/// it.
///
/// # Why undoing it matters
///
/// The copy is swapped **before** the registration is asked for, because the
/// registration has to name the new path. So every way the install can fail
/// after that point is a way to leave the daemon running a binary that no
/// command completed: the operator is told the install failed and the running
/// service has quietly moved to a new version anyway. On macOS that is not
/// cosmetic — a keychain grants a stored item to the binary that wrote it, so a
/// swapped copy is a daemon locked out of its own credential, which is exactly
/// how a real host spent a night crash-looping.
///
/// [`OwnedCopy::restore`] puts the previous copy back, so a failed
/// `service install` leaves the service running what it was running before.
struct OwnedCopy {
    /// Where the service will run it from.
    path: PathBuf,
    /// Where the copy it replaced was moved to, when there was one.
    replaced: Option<PathBuf>,
}

impl OwnedCopy {
    /// Puts back the copy this install moved aside.
    ///
    /// Best effort and deliberately silent: it runs on a path that is already
    /// returning an error, and a failure to undo is not worth replacing the
    /// operator's actual diagnosis with. What it cannot do is make things
    /// worse — the destination is a file this product owns and just wrote.
    fn restore(self) {
        let Some(replaced) = self.replaced else {
            // Nothing was there before, so the tidy state is nothing there now.
            let _ = std::fs::remove_file(&self.path);
            return;
        };
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::rename(&replaced, &self.path);
    }
}

/// Copies the running executable to a path this product owns, and answers where.
///
/// # Why the copy is replaced rather than reused
///
/// `service install` is also how an operator moves to a new version by hand, so
/// a stale copy left in place would silently keep the old daemon. The previous
/// copy is renamed aside first rather than deleted: on Windows the file cannot
/// be removed while a service still runs it, but it *can* be renamed, which is
/// what makes reinstalling over a running service work at all — and it is what
/// gives [`OwnedCopy::restore`] something to put back.
fn install_owned_copy(context: &Context, source: &std::path::Path) -> Result<OwnedCopy, CliError> {
    fn failed(what: &'static str) -> impl Fn(std::io::Error) -> CliError {
        move |source| CliError::new(Failure::LocalState, format!("cannot {what}: {source}"))
    }
    let bin_dir = context.paths().state_dir().join("bin");
    std::fs::create_dir_all(&bin_dir).map_err(failed("create the service binary directory"))?;
    let owned = bin_dir.join(
        source
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("runner-manager")),
    );
    let mut replaced = None;
    if owned.exists() {
        let aside = owned.with_extension("old");
        let _ = std::fs::remove_file(&aside);
        std::fs::rename(&owned, &aside)
            .map_err(failed("move the previous service binary aside"))?;
        replaced = Some(aside);
    }
    std::fs::copy(source, &owned).map_err(failed("copy the binary the service will run"))?;
    Ok(OwnedCopy {
        path: owned,
        replaced,
    })
}

pub fn install(
    context: &Context,
    args: &ServiceInstallArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this service installation");
    let mode: StartMode = args.start_at.into();
    let store = context.store()?;
    let mut host = super::host::local_host_or_create(context, &store)?;
    let previous = host.service_start_mode;
    let operations = operations(context);
    // Said before anything is registered, so that an operator with a stray
    // variable is told which name is about to appear in their service manager
    // rather than discovering it when `service uninstall` cannot find it.
    announce_fixture(&operations, "installs", "this service installation", out)?;
    if let Some((purpose, path)) = context
        .paths()
        .all()
        .into_iter()
        .find(|(_, path)| !path.is_absolute())
    {
        return Err(CliError::with_remedy(
            Failure::InvalidArgument,
            format!(
                "the {purpose} application-data directory {} is relative; a service starts in a different working directory and would open a different database",
                path.display()
            ),
            "runner-manager --data-dir <ABSOLUTE-DIR> service install",
        ));
    }
    // ------------------------------------------------------------------
    // THE SERVICE RUNS A COPY, NOT THE FILE A PACKAGE MANAGER OWNS.
    // ------------------------------------------------------------------
    // Registering `current_exe` directly is the obvious thing and it makes the
    // service impossible to upgrade on Windows: the running service holds that
    // file open, `npm i -g` cannot replace it, and what npm does instead is
    // worse than failing. It rewrites the package metadata, reports success,
    // and leaves the old executable in place -- so `npm ls -g` says the new
    // version is installed, `runner-manager --version` says the old one, and
    // the daemon goes on running code the operator believes they replaced.
    // That was observed on a real host, twice in a row, before this existed.
    //
    // A copy the product owns has neither problem: the package manager's file
    // is never locked, so an upgrade lands, and the daemon can compare itself
    // against it. `installed_from` keeps the origin, which is what item 6's
    // stale-path detection needs and what the upgrade watch reads.
    let source = std::env::current_exe().map_err(|source| {
        CliError::new(
            Failure::LocalState,
            format!("cannot resolve this executable's own path: {source}"),
        )
    })?;
    let owned = install_owned_copy(context, &source)?;
    let request = InstallRequest::new(mode)
        .for_binary(&owned.path)
        .copied_from(&source)
        .with_arguments(daemon_arguments(context, mode));
    // The swap above is undone on every failure below it. See `OwnedCopy`: a
    // refused install that left the new copy in place is what put a running
    // daemon on a binary nobody registered.
    let installed = match operations.install(&request) {
        Ok(installed) => installed,
        Err(source) => {
            owned.restore();
            return Err(service_failure(source));
        }
    };

    if let Err(source) = persist_mode(&store, &mut host, mode)
        && durable_mode(&store).ok().flatten() != Some(mode)
    {
        let rollback = operations.uninstall();
        return Err(rollback_failure("install", source, rollback.err()));
    }

    writeln!(
        out,
        "{}",
        if installed.replaced_existing {
            "Service re-registered, replacing the registration that was there."
        } else {
            "Service installed."
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  start mode                {}",
        installed.record.start_mode
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  binary                    {}",
        installed.record.binary.display()
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  diagnostic log            {}",
        installed.record.log_file.display()
    )
    .map_err(failed)?;
    writeln!(
        out,
        "  application data          captured from this command's account"
    )
    .map_err(failed)?;
    // The directory jobs will actually run in, which is not one of the four
    // application-data directories above and on Windows is not under the
    // operator's profile at all. Said here because `service install` is where
    // it is created, and because the sentence names who may write there --
    // by role, never by SID. See `docs/service-account.md`.
    //
    // Only when this install actually did something to it. On macOS and Linux
    // the runner root is the runtime directory `AppPaths` already permissions,
    // and the summary is the sentence "nothing was created or changed" -- which
    // under a `runner root` label reads as though there were no runner root at
    // all. `status` prints the effective one on every platform.
    if installed.runner_root.path().is_some() {
        writeln!(out, "  runner root               {}", installed.runner_root).map_err(failed)?;
    }
    if cfg!(target_os = "linux") {
        writeln!(
            out,
            "  Linux sandbox             strict: workflows inherit the service sandbox and cannot elevate or write outside the configured application-data directories"
        )
        .map_err(failed)?;
    }
    if previous != mode {
        writeln!(out, "  host setting              {previous} -> {mode}").map_err(failed)?;
    }
    Ok(())
}

pub fn uninstall(context: &Context, out: &mut dyn Write) -> Result<(), CliError> {
    let operations = operations(context);
    announce_fixture(&operations, "removes", "this service removal", out)?;
    let result = operations.uninstall().map_err(service_failure)?;
    writeln!(out, "{result}").map_err(write_failed("this service removal"))
}

pub fn status(context: &Context, out: &mut dyn Write) -> Result<(), CliError> {
    status_with(&operations(context), out)
}

fn status_with(operations: &ServiceOperations, out: &mut dyn Write) -> Result<(), CliError> {
    // Said before the report rather than after it, because a fixture name
    // describes a service the operator has almost certainly never installed,
    // and `installed: no` is the one answer that would look alarming rather
    // than beside the point.
    announce_fixture(operations, "reports", "this service status", out)?;
    let status = operations.status().map_err(service_failure)?;
    writeln!(out, "{status}").map_err(write_failed("this service status"))?;
    if status.last_github_contact().is_none() {
        writeln!(
            out,
            "  GitHub connectivity       offline (no successful contact recorded)"
        )
        .map_err(write_failed("this service status"))?;
    }
    if status.is_healthy() {
        Ok(())
    } else {
        Err(CliError::with_remedy(
            Failure::LocalState,
            "the service status above contains one or more errors",
            "runner-manager service uninstall && runner-manager service install",
        ))
    }
}

fn persist_mode(
    store: &dyn Store,
    host: &mut runner_manager_domain::model::Host,
    mode: StartMode,
) -> Result<(), StoreError> {
    host.service_start_mode = mode;
    store.put_host(host)
}

fn durable_mode(store: &dyn Store) -> Result<Option<StartMode>, StoreError> {
    Ok(store
        .hosts()?
        .into_iter()
        .next()
        .map(|host| host.service_start_mode))
}

fn rollback_failure(
    operation: &'static str,
    source: StoreError,
    rollback: Option<ServiceError>,
) -> CliError {
    match rollback {
        None => local_state(source),
        Some(rollback) => CliError::new(
            Failure::LocalState,
            format!(
                "could not {operation} in the local database: {source}. The service rollback also failed: {rollback}. Run `runner-manager service status` before retrying."
            ),
        ),
    }
}

fn local_state(source: StoreError) -> CliError {
    CliError::with_remedy(
        Failure::LocalState,
        format!("cannot persist this host's service start mode: {source}"),
        "runner-manager service status",
    )
}

fn service_failure(source: ServiceError) -> CliError {
    let class = match source {
        ServiceError::LockHeld { .. } | ServiceError::AlreadyInstalled { .. } => Failure::Conflict,
        ServiceError::NotInstalled { .. } => Failure::NotFound,
        ServiceError::BinaryPath { .. } | ServiceError::BinaryMissing { .. } => {
            Failure::InvalidArgument
        }
        ServiceError::NeedsElevation { .. } => Failure::UnsupportedHost,
        _ => Failure::LocalState,
    };
    // `service status` is the default remedy and is the wrong one for a
    // failure `service status` itself produced: an operator whose install
    // record could not be read was told to run the command that had just told
    // them that. A record this account may not read is a record written by
    // another one, which on a boot-mode host means `sudo service install` --
    // and re-running the install is what repairs its mode.
    let remedy = match &source {
        ServiceError::Record { operation, .. } if *operation == "read" => {
            "runner-manager service install"
        }
        _ => "runner-manager service status",
    };
    CliError::with_remedy(class, source.to_string(), remedy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use std::sync::Arc;

    use crate::cli::{Cli, Command, DaemonCommand};
    use runner_manager_domain::path::LocalAbsolutePath;
    use runner_manager_platform::service::{RecordingControls, ServiceIdentity, ServiceOperations};

    /// The copy is what makes an upgrade possible at all: a package manager
    /// cannot replace a file a running service holds open, and on Windows it
    /// does not even fail loudly -- it rewrites its metadata, reports success,
    /// and leaves the old executable running.
    #[test]
    fn the_service_binary_is_a_copy_this_product_owns_and_reinstalling_replaces_it() {
        let temporary = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(temporary.path()), &mut Vec::new()).unwrap();
        let source = temporary.path().join("package-manager-owned.bin");
        std::fs::write(&source, b"first version").unwrap();

        let owned = install_owned_copy(&context, &source)
            .expect("the copy is made")
            .path;
        assert!(owned.starts_with(context.paths().state_dir()), "{owned:?}");
        assert_ne!(owned, source, "the service must not run the source itself");
        assert_eq!(std::fs::read(&owned).unwrap(), b"first version");

        // A reinstall moves the old copy aside rather than deleting it: on
        // Windows the file cannot be unlinked while a service is running it,
        // but it can be renamed, and that is what lets this run at all.
        std::fs::write(&source, b"second version").unwrap();
        let again = install_owned_copy(&context, &source)
            .expect("the copy is replaced")
            .path;
        assert_eq!(
            again, owned,
            "the registered path must not move between installs"
        );
        assert_eq!(
            std::fs::read(&again).unwrap(),
            b"second version",
            "a stale copy would silently keep running the old daemon"
        );
        assert_eq!(
            std::fs::read(owned.with_extension("old")).unwrap(),
            b"first version",
            "the previous copy is kept aside, not destroyed"
        );
    }

    /// A `service install` that fails leaves the service running what it was
    /// running.
    ///
    /// The copy has to be swapped before the registration can name it, so every
    /// failure after that point used to leave the daemon on a binary no
    /// completed command ever registered. On macOS that is what locks a daemon
    /// out of its own keychain item.
    #[test]
    fn a_failed_install_puts_back_the_binary_the_service_was_running() {
        let temporary = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(temporary.path()), &mut Vec::new()).unwrap();
        let source = temporary.path().join("package-manager-owned.bin");

        std::fs::write(&source, b"the version that is running").unwrap();
        let running = install_owned_copy(&context, &source)
            .expect("the copy is made")
            .path;

        std::fs::write(&source, b"the version that failed to install").unwrap();
        let attempt = install_owned_copy(&context, &source).expect("the copy is replaced");
        assert_eq!(
            std::fs::read(&running).unwrap(),
            b"the version that failed to install",
            "the discriminator: the swap really happened before it was undone"
        );

        attempt.restore();
        assert_eq!(
            std::fs::read(&running).unwrap(),
            b"the version that is running",
            "a refused install must not move a running service to a new binary"
        );
    }

    /// And on a *first* install there is nothing to put back, so the tidy state
    /// is no copy at all rather than one nothing registered.
    #[test]
    fn a_failed_first_install_leaves_no_copy_behind() {
        let temporary = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(temporary.path()), &mut Vec::new()).unwrap();
        let source = temporary.path().join("package-manager-owned.bin");
        std::fs::write(&source, b"a version nothing registered").unwrap();

        let attempt = install_owned_copy(&context, &source).expect("the copy is made");
        let path = attempt.path.clone();
        assert!(path.exists());

        attempt.restore();
        assert!(
            !path.exists(),
            "a copy no registration names is a copy that should not be there: {}",
            path.display()
        );
    }

    #[test]
    fn installed_daemon_arguments_reproduce_all_four_directories_without_data_dir() {
        let temporary = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(temporary.path()), &mut Vec::new()).unwrap();
        let arguments = daemon_arguments(&context, StartMode::Boot);
        let mut argv = vec![OsString::from("runner-manager")];
        argv.extend(arguments);
        let cli = Cli::try_parse_from(argv).expect("service arguments must parse unattended");
        assert!(
            cli.data_dir.is_none(),
            "--data-dir would re-root the secret store"
        );
        let Command::Daemon(DaemonCommand::Run(args)) = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(args.service_paths().as_ref(), Some(context.paths()));
        assert_eq!(
            args.windows_service_host,
            cfg!(windows),
            "only a Windows boot registration enters SCM"
        );

        let mut login_argv = vec![OsString::from("runner-manager")];
        login_argv.extend(daemon_arguments(&context, StartMode::Login));
        let login = Cli::try_parse_from(login_argv).expect("login arguments parse unattended");
        let Command::Daemon(DaemonCommand::Run(login)) = login.command else {
            panic!("wrong login command");
        };
        assert!(
            !login.windows_service_host,
            "Task Scheduler is not the Service Control Manager"
        );
    }

    #[test]
    fn stale_binary_status_prints_the_diagnosis_and_returns_an_error() {
        let temporary = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(temporary.path()), &mut Vec::new()).unwrap();
        let binary = temporary.path().join("movable-runner-manager.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
        let operations = ServiceOperations::with_controls(
            context.paths().clone(),
            ServiceIdentity::fixture("f3-stale-binary"),
            Arc::new(RecordingControls::new()),
        )
        // `install` prepares the runner root the registration would run jobs
        // under, and the platform default is the real `%SystemDrive%\rman`.
        // A unit test must neither create nor re-permission that, so a fixture
        // registration aims it at this test's own temporary tree.
        .with_runner_root(
            LocalAbsolutePath::new(
                temporary
                    .path()
                    .join("runner-root")
                    .to_str()
                    .expect("a unicode temporary path"),
            )
            .expect("a local absolute path"),
        );
        operations
            .install(&InstallRequest::new(StartMode::Boot).for_binary(&binary))
            .unwrap();
        std::fs::remove_file(binary).unwrap();

        let mut out = Vec::new();
        let error = status_with(&operations, &mut out).expect_err("stale is not healthy");
        let rendered = String::from_utf8(out).unwrap();
        assert_eq!(error.class(), Failure::LocalState);
        assert!(rendered.contains("ERROR"));
        assert!(rendered.contains("nothing is at the recorded path"));
        assert!(rendered.contains("NOT healthy"));
    }
}
