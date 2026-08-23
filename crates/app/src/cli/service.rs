// owner: f3-cli-daemon-service

//! Noninteractive wrappers around the platform service transaction.

use std::ffi::OsString;
use std::io::Write;

use runner_manager_domain::model::StartMode;
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_platform::service::{InstallRequest, ServiceError, ServiceOperations};

use super::{
    CliError, Context, Failure, ServiceCommand, ServiceInstallArgs, ServiceSetStartModeArgs,
    write_failed,
};

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
        ServiceCommand::SetStartMode(args) => set_start_mode(context, args, out),
    }
}

fn operations(context: &Context) -> ServiceOperations {
    ServiceOperations::on_this_host(context.paths().clone())
}

fn daemon_arguments(context: &Context) -> Vec<OsString> {
    let paths = context.paths();
    [
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
    .collect()
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
    let request = InstallRequest::new(mode).with_arguments(daemon_arguments(context));
    let installed = operations.install(&request).map_err(service_failure)?;

    if let Err(source) = persist_mode(&store, &mut host, mode)
        && durable_mode(&store).ok().flatten() != Some(mode)
    {
        let rollback = operations.uninstall();
        return Err(rollback_failure("install", source, rollback.err()));
    }

    writeln!(out, "Service installed.").map_err(failed)?;
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
    let result = operations(context).uninstall().map_err(service_failure)?;
    writeln!(out, "{result}").map_err(write_failed("this service removal"))
}

pub fn status(context: &Context, out: &mut dyn Write) -> Result<(), CliError> {
    status_with(&operations(context), out)
}

fn status_with(operations: &ServiceOperations, out: &mut dyn Write) -> Result<(), CliError> {
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

pub fn set_start_mode(
    context: &Context,
    args: &ServiceSetStartModeArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    set_start_mode_with(context, args, out, &operations(context))
}

fn set_start_mode_with(
    context: &Context,
    args: &ServiceSetStartModeArgs,
    out: &mut dyn Write,
    operations: &ServiceOperations,
) -> Result<(), CliError> {
    let to: StartMode = args.start_at.into();
    let change = operations.set_start_mode(to).map_err(service_failure)?;
    let store = context.store()?;
    let mut host = super::host::local_host_or_create(context, &store)?;

    if let Err(source) = persist_mode(&store, &mut host, to)
        && durable_mode(&store).ok().flatten() != Some(to)
    {
        if change.changed {
            let rollback = operations.set_start_mode(change.from);
            return Err(rollback_failure(
                "persist the new service start mode",
                source,
                rollback.err(),
            ));
        }
        return Err(local_state(source));
    }

    writeln!(out, "{change}").map_err(write_failed("this start-mode change"))
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
    CliError::with_remedy(class, source.to_string(), "runner-manager service status")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use std::sync::Arc;

    use crate::cli::{Cli, Command, DaemonCommand};
    use runner_manager_platform::service::{RecordingControls, ServiceIdentity, ServiceOperations};

    #[test]
    fn installed_daemon_arguments_reproduce_all_four_directories_without_data_dir() {
        let temporary = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(temporary.path()), &mut Vec::new()).unwrap();
        let arguments = daemon_arguments(&context);
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
    }

    #[test]
    fn set_start_mode_is_a_scriptable_command_with_no_prompt_input() {
        let cli = Cli::try_parse_from(["runner-manager", "service", "set-start-mode", "login"])
            .expect("the command parses without stdin");
        assert!(matches!(
            cli.command,
            Command::Service(ServiceCommand::SetStartMode(ServiceSetStartModeArgs {
                start_at: super::super::StartAt::Login
            }))
        ));
    }

    #[test]
    fn switching_start_mode_persists_the_same_mode_host_show_reads() {
        let temporary = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(temporary.path()), &mut Vec::new()).unwrap();
        let controls = Arc::new(RecordingControls::new());
        let operations = ServiceOperations::with_controls(
            context.paths().clone(),
            ServiceIdentity::fixture("f3-mode-round-trip"),
            controls,
        );
        operations
            .install(
                &InstallRequest::new(StartMode::Boot).for_binary(std::env::current_exe().unwrap()),
            )
            .unwrap();
        let store = context.store().unwrap();
        super::super::host::local_host_or_create(&context, &store).unwrap();

        set_start_mode_with(
            &context,
            &ServiceSetStartModeArgs {
                start_at: super::super::StartAt::Login,
            },
            &mut Vec::new(),
            &operations,
        )
        .unwrap();

        assert_eq!(
            operations.status().unwrap().start_mode(),
            Some(StartMode::Login),
            "the service manager/record side must switch"
        );
        assert_eq!(
            context.recorded_start_mode(&store).unwrap(),
            StartMode::Login,
            "host show reads this SQLite field; it must be the returned mode"
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
