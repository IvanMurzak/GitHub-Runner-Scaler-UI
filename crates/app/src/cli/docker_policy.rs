//! `host docker-policy`: what native Linux jobs may ask of the Docker engine.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use runner_manager_agent::docker_cleanup::policy::{self, Config};
use runner_manager_agent::docker_cleanup::{self, DockerCleanup};

use super::{CliError, Context, Failure, HostDockerPolicyCommand, set_member, write_failed};

/// Runs a `host docker-policy` subcommand.
///
/// # Errors
/// [`Failure::LocalState`] when the settings or the log cannot be read or
/// written, and [`Failure::InvalidArgument`] for a path that is not absolute.
pub fn dispatch(
    context: &Context,
    command: &HostDockerPolicyCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("the Docker policy");
    let config_dir = context.paths().config_dir();
    let config_path = config_dir.join(policy::CONFIG_FILE);
    let log = context
        .paths()
        .state_dir()
        .join(policy::LOG_DIR)
        .join(policy::LOG_FILE);
    let local = |error: std::io::Error| {
        CliError::new(Failure::LocalState, format!("the Docker policy: {error}"))
    };
    let mut config = Config::load(&config_path).map_err(local)?;
    match command {
        HostDockerPolicyCommand::Show => {
            let accounting =
                docker_cleanup::Config::load(&config_dir.join(docker_cleanup::CONFIG_FILE))
                    .map_err(local)?;
            writeln!(out, "Docker policy: {}", config.mode.as_str()).map_err(failed)?;
            writeln!(out, "  settings                  {}", config_path.display())
                .map_err(failed)?;
            writeln!(out, "  violation log             {}", log.display()).map_err(failed)?;
            if config.allow.is_empty() {
                writeln!(
                    out,
                    "  allowed host paths        none beyond each job's own attempt and caches"
                )
                .map_err(failed)?;
            } else {
                for path in &config.allow {
                    writeln!(out, "  allowed host path         {}", path.display())
                        .map_err(failed)?;
                }
            }
            if !DockerCleanup::supported() {
                writeln!(
                    out,
                    "  note                      applies to native Linux runners only; this host has none"
                )
                .map_err(failed)?;
            } else if accounting.mode == docker_cleanup::Mode::Off {
                writeln!(
                    out,
                    "  note                      Docker accounting is off, so jobs reach the engine \
                     without the proxy that checks this policy; turn it back on with \
                     `host docker-cleanup set-mode --mode report`"
                )
                .map_err(failed)?;
            }
        }
        HostDockerPolicyCommand::SetMode(args) => {
            config.mode = args
                .mode
                .parse()
                .map_err(|error: String| CliError::new(Failure::InvalidArgument, error))?;
            config.save(&config_path).map_err(local)?;
            writeln!(
                out,
                "Docker policy is now {}; runners started from now on get it.",
                config.mode.as_str()
            )
            .map_err(failed)?;
        }
        HostDockerPolicyCommand::AllowPath(args) => {
            let path = absolute(&args.path)?;
            if set_member(&mut config.allow, &path, true) {
                config.save(&config_path).map_err(local)?;
            }
            writeln!(
                out,
                "Jobs may bind-mount {} into their containers from the next runner on.",
                path.display()
            )
            .map_err(failed)?;
        }
        HostDockerPolicyCommand::DisallowPath(args) => {
            let path = absolute(&args.path)?;
            if set_member(&mut config.allow, &path, false) {
                config.save(&config_path).map_err(local)?;
            }
            writeln!(
                out,
                "{} is not an allowed host path for jobs' containers.",
                path.display()
            )
            .map_err(failed)?;
        }
        HostDockerPolicyCommand::Report(args) => {
            let records = policy::read_records(&log);
            if records.is_empty() {
                writeln!(out, "No Docker policy violation recorded.").map_err(failed)?;
                return Ok(());
            }
            let mut by_rule: BTreeMap<(&str, &str), (usize, usize)> = BTreeMap::new();
            for record in &records {
                let entry = by_rule
                    .entry((record.repository.as_str(), record.rule.as_str()))
                    .or_default();
                entry.0 += 1;
                if record.refused {
                    entry.1 += 1;
                }
            }
            writeln!(out, "Docker policy violations, by repository and rule:").map_err(failed)?;
            for ((repository, rule), (count, refused)) in &by_rule {
                writeln!(
                    out,
                    "  {repository:<40} {rule:<20} {count} ({refused} refused)"
                )
                .map_err(failed)?;
            }
            writeln!(out, "\nMost recent:").map_err(failed)?;
            for record in records.iter().rev().take(args.last) {
                writeln!(
                    out,
                    "  {}  {}  {}  {}{}",
                    record.at,
                    record.repository,
                    record.rule,
                    record.detail,
                    if record.refused { "  [refused]" } else { "" }
                )
                .map_err(failed)?;
            }
        }
    }
    Ok(())
}

fn absolute(path: &str) -> Result<PathBuf, CliError> {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(CliError::new(
            Failure::InvalidArgument,
            format!("{} is not an absolute path", path.display()),
        ))
    }
}
