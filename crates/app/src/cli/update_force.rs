// owner: f1-cli-auth-host-status

//! Forced *source-path* reconciliation. The old daemon already owns the only
//! job-safe handover protocol: it watches the source path recorded at install,
//! drains without a deadline, then swaps its private copy. Never stop or
//! re-register that daemon here; both can interrupt a running job.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use runner_manager_domain::model::StartMode;
use runner_manager_platform::service::{InstallRecord, ServiceError};

use super::{
    CliError, Context, Failure, Installation, compare_versions, display_path, install_over,
    parse_version, same_file, sha256_of, write_failed,
};

fn record_failure(error: ServiceError) -> CliError {
    CliError::with_remedy(
        Failure::LocalState,
        format!("cannot read the installed service for --force: {error}"),
        "runner-manager service status",
    )
}

fn recorded_source(context: &Context) -> Result<Option<(InstallRecord, PathBuf)>, CliError> {
    let Some(record) = InstallRecord::read(context.paths()).map_err(record_failure)? else {
        return Ok(None);
    };
    let source = record.source_binary.clone().ok_or_else(|| {
        CliError::with_remedy(
            Failure::UpdateUnsupported,
            "the installed service has no recorded source; its daemon cannot receive a job-safe upgrade trigger",
            "runner-manager service status",
        )
    })?;
    Ok(Some((record, source)))
}

/// Refuse a mismatched or unobserved service before a newer CLI is installed.
pub(super) fn preflight_force(context: &Context) -> Result<(), CliError> {
    let Some((record, source)) = recorded_source(context)? else {
        return Ok(());
    };
    validate_live_service(context, &record)?;
    let metadata = std::fs::symlink_metadata(&source).map_err(|error| {
        CliError::new(
            Failure::UpdateUnsupported,
            format!(
                "cannot inspect service source {}: {error}",
                display_path(&source)
            ),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(CliError::new(
            Failure::UpdateUnsupported,
            format!(
                "service source {} is not a regular file; --force will not replace a symlink or directory",
                display_path(&source)
            ),
        ));
    }
    Ok(())
}

fn validate_live_service(context: &Context, record: &InstallRecord) -> Result<(), CliError> {
    // A forged or stale record must not make `--force` write an unrelated file.
    // The manager's live registration must name exactly this private copy.
    let status = super::super::service::operations(context)
        .status()
        .map_err(record_failure)?;
    let registration = status.registration().ok_or_else(|| {
        CliError::with_remedy(
            Failure::UpdateUnsupported,
            "the service record exists but no matching registration is installed",
            "runner-manager service status",
        )
    })?;
    if !registration.running
        || registration.start_mode != record.start_mode
        || !registration
            .binary()
            .is_some_and(|binary| same_file(&binary, &record.binary))
    {
        return Err(CliError::with_remedy(
            Failure::UpdateUnsupported,
            "the service is stopped or its registration does not match the recorded binary; --force cannot prove a live daemon will drain jobs",
            "runner-manager service status",
        ));
    }
    Ok(())
}

pub(super) fn report_force_check(
    context: &Context,
    installation: &Installation,
    version: &str,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let Some((record, source)) = recorded_source(context)? else {
        return writeln!(out, "No installed service needs a forced handover.")
            .map_err(write_failed("this update"));
    };
    writeln!(
        out,
        "--force would reconcile {version} from {} at the recorded service source {} (retaining a backup if it needs replacing). The running daemon would stop starting runners, wait without a deadline for its jobs, then restart.",
        display_path(&installation.path),
        display_path(&source)
    )
    .map_err(write_failed("this update"))?;
    if cfg!(target_os = "macos") && record.start_mode == StartMode::Login {
        writeln!(out, "warning: a replacement may need a new login-Keychain grant. Do not sign in while the old daemon is still serving jobs.")
            .map_err(write_failed("this update"))?;
        if version == super::running_version() {
            write_auth_command(context, record.start_mode, &record.binary, out)?;
        } else {
            writeln!(out, "The actual update will print the exact auth login command after installing the new binary.")
                .map_err(write_failed("this update"))?;
        }
    }
    Ok(())
}

/// Stage the new binary at the path the *existing* daemon already watches.
/// This is a request for its unbounded drain, not an immediate service stop.
pub(super) fn force_service_handover(
    context: &Context,
    installation: &Installation,
    version: &str,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this update");
    let Some((record, source)) = recorded_source(context)? else {
        writeln!(out, "No installed service needs a forced handover.").map_err(failed)?;
        return Ok(());
    };

    preflight_force(context)?;

    let candidate = std::fs::canonicalize(&installation.path).map_err(|error| {
        CliError::with_remedy(
            Failure::UpdateUnsupported,
            format!(
                "updated binary {} is unavailable: {error}",
                display_path(&installation.path)
            ),
            "run runner-manager update --force from the newly installed binary",
        )
    })?;
    let candidate_version = executable_version(&candidate).ok_or_else(|| {
        CliError::new(
            Failure::UpdateUnsupported,
            "the updated binary does not answer --version",
        )
    })?;
    if candidate_version != version {
        return Err(CliError::with_remedy(
            Failure::UpdateUnsupported,
            format!(
                "{} reports {candidate_version}, not published version {version}",
                display_path(&candidate)
            ),
            "run runner-manager update --force from the newly installed binary",
        ));
    }
    let service_version = executable_version(&record.binary).ok_or_else(|| {
        CliError::new(
            Failure::UpdateUnsupported,
            "the registered daemon binary does not answer --version",
        )
    })?;
    match compare_versions(version, &service_version) {
        std::cmp::Ordering::Less => {
            return Err(CliError::new(
                Failure::UpdateUnsupported,
                format!(
                    "service {service_version} is newer than candidate {version}; --force never downgrades"
                ),
            ));
        }
        std::cmp::Ordering::Equal => {
            if sha256_of(&candidate)? != sha256_of(&record.binary)? {
                return Err(CliError::with_remedy(
                    Failure::UpdateUnsupported,
                    format!(
                        "service and CLI both report {version} but have different bytes; the running daemon only detects a changed version, so --force cannot safely replace this same-version build"
                    ),
                    "publish a new version before requesting a job-safe handover",
                ));
            }
            writeln!(
                out,
                "The service already reports {version}; no handover is needed."
            )
            .map_err(failed)?;
            report_auth_after_handover(context, &record, version, true, out)?;
            return Ok(());
        }
        std::cmp::Ordering::Greater => {}
    }
    if let Some(source_version) = executable_version(&source)
        && compare_versions(&source_version, version) == std::cmp::Ordering::Greater
    {
        return Err(CliError::new(
            Failure::UpdateUnsupported,
            format!(
                "recorded service source is already {source_version}; --force will not replace it with older {version}"
            ),
        ));
    }

    let metadata = std::fs::symlink_metadata(&source).map_err(|error| {
        CliError::new(
            Failure::UpdateUnsupported,
            format!(
                "cannot inspect service source {}: {error}",
                display_path(&source)
            ),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(CliError::new(
            Failure::UpdateUnsupported,
            format!(
                "service source {} is not a regular file; --force will not replace a symlink or directory",
                display_path(&source)
            ),
        ));
    }
    if same_file(&source, &candidate) {
        writeln!(out, "The daemon already watches this updated source; it will drain and restart without --force replacing a file.")
            .map_err(failed)?;
        report_auth_after_handover(context, &record, version, false, out)?;
        return Ok(());
    }
    if sha256_of(&source)? == sha256_of(&candidate)? {
        writeln!(out, "The recorded service source already contains {version}; its daemon will drain and restart without a second replacement.")
            .map_err(failed)?;
        report_auth_after_handover(context, &record, version, false, out)?;
        return Ok(());
    }

    writeln!(out, "warning: replacing the distinct service source {}. No job will be cancelled; the daemon's upgrade drain has no deadline.", display_path(&source))
        .map_err(failed)?;
    if cfg!(target_os = "macos") && record.start_mode == StartMode::Login {
        writeln!(out, "warning: wait until the service reports {version} before reauthorizing. Signing in now could lock the old daemon out while jobs still run.")
            .map_err(failed)?;
    }
    out.flush().map_err(failed)?;
    let backup = back_up_and_stage_source(&candidate, &source)?;
    writeln!(out, "Previous source retained at {}. Handover requested; check progress with: runner-manager service status", display_path(&backup))
        .map_err(failed)?;
    report_auth_after_handover(context, &record, version, false, out)
}

fn report_auth_after_handover(
    context: &Context,
    record: &InstallRecord,
    version: &str,
    handover_complete: bool,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this update");
    if handover_complete && !credential_readable(&record.binary, context) {
        writeln!(out, "warning: the service binary cannot currently read the GitHub credential. The service may report signed out.")
            .map_err(failed)?;
    }
    writeln!(out, "warning: after the service reports {version}, its new binary may need a fresh Keychain grant. If it reports an unreadable or rejected credential, authorize using the service binary below. Do not do this while old jobs are running. Profiles, settings and the database are preserved:")
        .map_err(failed)?;
    write_auth_command(context, record.start_mode, &record.binary, out)?;
    Ok(())
}

fn executable_version(path: &Path) -> Option<String> {
    let output = Command::new(path).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let version = String::from_utf8(output.stdout)
        .ok()?
        .split_whitespace()
        .last()?
        .to_owned();
    parse_version(&version).map(|_| version)
}

fn credential_readable(candidate: &Path, context: &Context) -> bool {
    let mut command = Command::new(candidate);
    if let Some(root) = context.data_root.as_deref() {
        command.arg("--data-dir").arg(root);
    }
    command
        .args(["auth", "status"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn write_auth_command(
    context: &Context,
    mode: StartMode,
    binary: &Path,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let elevation = if mode == StartMode::Boot && cfg!(unix) {
        "sudo "
    } else {
        ""
    };
    let executable = if cfg!(windows) {
        format!("& \"{}\"", display_path(binary).replace('"', "`\""))
    } else {
        format!("'{}'", display_path(binary).replace('\'', "'\\''"))
    };
    let command = match context.data_root.as_deref() {
        Some(root) if cfg!(windows) => format!(
            "{elevation}{executable} --data-dir \"{}\" auth login --start-at {mode}",
            display_path(root),
            mode = mode_name(mode)
        ),
        Some(root) => format!(
            "{elevation}{executable} --data-dir '{}' auth login --start-at {mode}",
            display_path(root).replace('\'', "'\\''"),
            mode = mode_name(mode)
        ),
        None => format!(
            "{elevation}{executable} auth login --start-at {}",
            mode_name(mode)
        ),
    };
    writeln!(out, "  {command}").map_err(write_failed("this update"))
}

fn mode_name(mode: StartMode) -> &'static str {
    match mode {
        StartMode::Login => "login",
        StartMode::Boot => "boot",
    }
}

/// Leave a recoverable byte copy beside the source before the atomic swap.
fn back_up_and_stage_source(candidate: &Path, source: &Path) -> Result<PathBuf, CliError> {
    if !std::fs::symlink_metadata(source).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return Err(CliError::new(
            Failure::UpdateUnsupported,
            "service source changed or is no longer a regular file; refusing to stage it",
        ));
    }
    let parent = source.parent().ok_or_else(|| {
        CliError::new(
            Failure::LocalState,
            "service source has no parent directory",
        )
    })?;
    let mut backup = tempfile::Builder::new()
        .prefix(".runner-manager-before-force-update-")
        .tempfile_in(parent)
        .map_err(|error| {
            CliError::new(
                Failure::LocalState,
                format!("cannot create service-source backup: {error}"),
            )
        })?;
    let mut original = std::fs::File::open(source).map_err(|error| {
        CliError::new(
            Failure::LocalState,
            format!("cannot read service source for backup: {error}"),
        )
    })?;
    std::io::copy(&mut original, backup.as_file_mut()).map_err(|error| {
        CliError::new(
            Failure::LocalState,
            format!("cannot copy service source into backup: {error}"),
        )
    })?;
    backup.as_file_mut().sync_all().map_err(|error| {
        CliError::new(
            Failure::LocalState,
            format!("cannot sync service-source backup: {error}"),
        )
    })?;
    let (_, backup_path) = backup.keep().map_err(|error| {
        CliError::new(
            Failure::LocalState,
            format!("cannot retain service-source backup: {error}"),
        )
    })?;
    install_over(candidate, source)?;
    Ok(backup_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_backup_is_byte_identical_and_replacement_is_atomic() {
        let root = tempfile::tempdir().unwrap();
        let old = root.path().join("source");
        let next = root.path().join("candidate");
        std::fs::write(&old, b"old signed source").unwrap();
        std::fs::write(&next, b"new release source").unwrap();
        let backup = back_up_and_stage_source(&next, &old).unwrap();
        assert_eq!(std::fs::read(backup).unwrap(), b"old signed source");
        assert_eq!(std::fs::read(old).unwrap(), b"new release source");
    }

    #[test]
    fn auth_remedy_names_the_same_executable_and_data_root() {
        let root = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(root.path()), &mut Vec::new()).unwrap();
        let binary = root.path().join("bin").join("runner-manager");
        let mut output = Vec::new();
        write_auth_command(&context, StartMode::Login, &binary, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(&binary.display().to_string()));
        assert!(output.contains(&root.path().display().to_string()));
        assert!(output.contains("auth login"));
        assert!(output.contains("--start-at login"));
        assert!(!output.contains("sudo"));
    }
}
