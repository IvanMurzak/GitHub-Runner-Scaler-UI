//! `host protect-path`: host directories no runner or job may reach.

use std::io::Write;
use std::path::PathBuf;

use runner_manager_platform::service::{InstallRecord, ProtectedPaths, sudo_command};

use super::{CliError, Context, Failure, HostProtectPathCommand, set_member, write_failed};

/// Runs a `host protect-path` subcommand.
///
/// # Errors
/// [`Failure::UnsupportedHost`] on a platform that cannot enforce protected
/// paths, [`Failure::InvalidArgument`] for a path that cannot be protected,
/// and [`Failure::LocalState`] when the list cannot be read or written.
pub fn dispatch(
    context: &Context,
    command: &HostProtectPathCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("the protected paths");
    let config_dir = context.paths().config_dir();
    let local = |error: std::io::Error| {
        CliError::new(Failure::LocalState, format!("the protected paths: {error}"))
    };
    let mut protected = ProtectedPaths::load(config_dir).map_err(local)?;
    let changed = |out: &mut dyn Write| {
        writeln!(
            out,
            "Saved in {}. The service applies it once registered again: `{}`.",
            config_dir.join(ProtectedPaths::FILE).display(),
            sudo_command("service install --start-at boot")
        )
    };
    match command {
        HostProtectPathCommand::Add(args) => {
            supported()?;
            let path = PathBuf::from(&args.path);
            let own = context
                .paths()
                .all()
                .iter()
                .map(|(_, path)| path.to_path_buf())
                .chain([PathBuf::from(
                    runner_manager_platform::paths::SYSTEM_DATA_ROOT,
                )])
                .collect::<Vec<_>>();
            if let Some(why) = ProtectedPaths::refusal(&path, &own) {
                return Err(CliError::new(Failure::InvalidArgument, why));
            }
            if set_member(&mut protected.paths, &path, true) {
                protected.save(config_dir).map_err(local)?;
            }
            writeln!(out, "No runner or job will reach {}.", path.display()).map_err(failed)?;
            changed(out).map_err(failed)?;
        }
        HostProtectPathCommand::Remove(args) => {
            supported()?;
            let path = PathBuf::from(&args.path);
            if set_member(&mut protected.paths, &path, false) {
                protected.save(config_dir).map_err(local)?;
            }
            writeln!(out, "{} is no longer protected.", path.display()).map_err(failed)?;
            changed(out).map_err(failed)?;
        }
        HostProtectPathCommand::List => {
            if protected.paths.is_empty() {
                writeln!(out, "No protected path.").map_err(failed)?;
            } else {
                writeln!(out, "Protected paths:").map_err(failed)?;
                for path in &protected.paths {
                    writeln!(out, "  {}", path.display()).map_err(failed)?;
                }
            }
            if !ProtectedPaths::supported() {
                writeln!(out, "This platform cannot enforce them.").map_err(failed)?;
                return Ok(());
            }
            let applied = InstallRecord::read(context.paths())
                .ok()
                .flatten()
                .map(|record| record.protected_paths);
            match applied {
                Some(applied) if applied == protected.paths => {
                    writeln!(out, "The registered service enforces exactly these.")
                        .map_err(failed)?;
                }
                Some(_) => {
                    writeln!(
                        out,
                        "The registered service enforces a different list; register it again: `{}`.",
                        sudo_command("service install --start-at boot")
                    )
                    .map_err(failed)?;
                }
                None => {
                    writeln!(out, "No service is registered from this configuration.")
                        .map_err(failed)?;
                }
            }
        }
    }
    Ok(())
}

fn supported() -> Result<(), CliError> {
    if ProtectedPaths::supported() {
        Ok(())
    } else {
        Err(CliError::new(
            Failure::UnsupportedHost,
            "protected paths are enforced by systemd on Linux; this platform has no equivalent \
             the service can set",
        ))
    }
}
