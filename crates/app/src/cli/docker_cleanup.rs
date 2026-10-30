//! Operator controls for native Linux Docker accounting. Defaults to report.

use std::io::Write;

use runner_manager_agent::docker_cleanup::{Config, DockerCleanup, Mode, write_json};
use runner_manager_domain::store::Store;

use super::{CliError, Context, Failure, HostDockerCleanupCommand};

pub fn dispatch(
    context: &Context,
    command: &HostDockerCleanupCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let store = context.store()?;
    let host = super::host::local_host_or_create(context, &store)?;
    let cleanup = DockerCleanup::new(
        host.id,
        context.paths().config_dir(),
        context.paths().state_dir(),
    );
    let failed = |error: std::io::Error| {
        CliError::new(Failure::LocalState, format!("Docker cleanup: {error}"))
    };
    let config = Config::load(&cleanup.config).map_err(failed)?;
    let value = match command {
        HostDockerCleanupCommand::Show => serde_json::json!({
            "supported": DockerCleanup::supported(), "mode":config.mode,
            "journal_root":cleanup.root,
            "preserves":["dependency caches", "persistent workspaces", "images", "build cache", "named volumes", "unknown resources"]
        }),
        HostDockerCleanupCommand::SetMode(args) => {
            if !DockerCleanup::supported() {
                return Err(CliError::new(
                    Failure::UnsupportedHost,
                    "Docker accounting is available for native Linux runners; use --host wsl:Ubuntu for a managed WSL host",
                ));
            }
            let mode = match args.mode.as_str() {
                "off" => Mode::Off,
                "report" => Mode::Report,
                "apply" => Mode::Apply,
                _ => {
                    return Err(CliError::new(
                        Failure::InvalidArgument,
                        "expected off, report or apply",
                    ));
                }
            };
            write_json(&cleanup.config, &Config { mode }).map_err(failed)?;
            serde_json::json!({"mode":mode,"applies_to":"next runner launch and next cleanup sweep"})
        }
        HostDockerCleanupCommand::Report | HostDockerCleanupCommand::Sweep => {
            if !DockerCleanup::supported() {
                return Err(CliError::new(
                    Failure::UnsupportedHost,
                    "Docker accounting requires native Linux; no Windows resources were changed",
                ));
            }
            serde_json::to_value(
                cleanup
                    .sweep_with_lookup(
                        &|id| store.attempt(id).map_err(std::io::Error::other),
                        matches!(command, HostDockerCleanupCommand::Report),
                    )
                    .map_err(failed)?,
            )
            .map_err(|error| CliError::new(Failure::LocalState, error.to_string()))?
        }
    };
    writeln!(
        out,
        "{}",
        serde_json::to_string_pretty(&value)
            .map_err(|error| CliError::new(Failure::LocalState, error.to_string()))?
    )
    .map_err(failed)
}
