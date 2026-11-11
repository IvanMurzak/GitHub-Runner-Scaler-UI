//! Commands a person signed in to the coordinator runs on this host.
//!
//! The coordinator relays `runner-manager` arguments; this host decides what
//! it runs. Only the commands [`access`] names are run at all. A read is
//! always answered. A change is made only once this host's operator allowed
//! it here, with `runner-manager coordinator remote-changes allow`: a
//! coordinator, or a person with its sign-in, can then change what this host
//! runs, so it is the operator's decision, made on the machine. Every command
//! is recorded in `state/remote-commands.jsonl`.

use std::io::Write;
use std::path::{Path, PathBuf};

use runner_manager_domain::coordinator_protocol::{
    CommandResult, MAX_COMMAND_OUTPUT_BYTES, RunCommand,
};
use runner_manager_platform::paths::AppPaths;
use serde::{Deserialize, Serialize};

use super::{
    Cli, CliError, Command, Context, CoordinatorRemoteChangesArgs, Failure, HostCommand,
    RepoCommand, RepoProfileCommand, Styling, write_failed,
};

/// The operator's choice, in the configuration directory.
const SETTINGS_FILE: &str = "remote-changes.json";
/// The record of every remote command, in the state directory.
const RECORD_FILE: &str = "remote-commands.jsonl";
/// The size at which the record moves to `remote-commands.jsonl.1`.
const RECORD_ROTATE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    allow_changes: bool,
}

/// Whether this host's operator allowed changes through the coordinator.
#[must_use]
pub fn changes_allowed(paths: &AppPaths) -> bool {
    runner_manager_platform::settings_file::load::<Settings>(
        &paths.config_dir().join(SETTINGS_FILE),
    )
    .is_ok_and(|settings| settings.allow_changes)
}

/// `coordinator remote-changes allow|deny|status`, on this machine only.
///
/// # Errors
/// [`Failure::LocalState`] when the choice cannot be saved.
pub fn remote_changes(
    context: &Context,
    args: &CoordinatorRemoteChangesArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("the remote-changes setting");
    let path = context.paths().config_dir().join(SETTINGS_FILE);
    let allow = match args.choice.as_str() {
        "allow" => true,
        "deny" => false,
        _ => {
            let allowed = changes_allowed(context.paths());
            writeln!(
                out,
                "Changes through the coordinator: {}",
                if allowed {
                    "allowed"
                } else {
                    "not allowed (reads only)"
                }
            )
            .map_err(failed)?;
            return Ok(());
        }
    };
    runner_manager_platform::settings_file::save(
        &path,
        &Settings {
            allow_changes: allow,
        },
    )
    .map_err(|error| CliError::new(Failure::LocalState, format!("{}: {error}", path.display())))?;
    writeln!(
        out,
        "{}",
        if allow {
            "A person signed in to the coordinator may now change this host's repositories, labels, \
             limits and workspaces. Every change is recorded in remote-commands.jsonl here and on \
             the coordinator. `runner-manager coordinator remote-changes deny` takes it back."
        } else {
            "The coordinator may only read this host's settings now."
        }
    )
    .map_err(failed)?;
    writeln!(
        out,
        "The running service tells the coordinator within a minute."
    )
    .map_err(failed)
}

/// What a command does to this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Change,
}

/// What a command parsed from the coordinator does, or `None` for one this
/// host never runs remotely: anything that signs in, installs, updates,
/// touches another host, or is not about repositories and capacity.
#[must_use]
pub fn access(cli: &Cli) -> Option<Access> {
    if cli.data_dir.is_some() || cli.host.distribution().is_some() {
        return None;
    }
    match &cli.command {
        Command::Status(_)
        | Command::Host(HostCommand::Show)
        | Command::Repo(
            RepoCommand::List(_)
            | RepoCommand::Profile(RepoProfileCommand::List(_) | RepoProfileCommand::Show(_)),
        ) => Some(Access::Read),
        Command::Host(HostCommand::SetCapacity(_))
        | Command::Repo(
            RepoCommand::Add(_)
            | RepoCommand::Remove(_)
            | RepoCommand::SetCapacity(_)
            | RepoCommand::SetScale(_)
            | RepoCommand::AddLabel(_)
            | RepoCommand::RemoveLabel(_)
            | RepoCommand::SetWorkspace(_)
            | RepoCommand::Profile(
                RepoProfileCommand::Add(_)
                | RepoProfileCommand::SetCapacity(_)
                | RepoProfileCommand::SetScale(_)
                | RepoProfileCommand::AddLabel(_)
                | RepoProfileCommand::RemoveLabel(_)
                | RepoProfileCommand::SetWorkspace(_)
                | RepoProfileCommand::Remove(_),
            ),
        ) => Some(Access::Change),
        _ => None,
    }
}

/// Runs a command the coordinator relayed, as this host's service, and says
/// how it ended. Never panics on the command's input.
#[must_use]
pub fn execute(context: &Context, command: &RunCommand) -> CommandResult {
    let result = |exit_code: u8, stdout: String, stderr: String| {
        let (stdout, stderr, truncated) = bounded(stdout, stderr);
        CommandResult {
            request_id: command.request_id.clone(),
            exit_code,
            stdout,
            stderr,
            truncated,
        }
    };
    let refused = |class: Failure, message: String| {
        result(class.code(), String::new(), format!("error: {message}\n"))
    };
    let outcome = (|| {
        if !command.well_formed() {
            return refused(Failure::InvalidArgument, "the command is malformed".into());
        }
        let cli = match <Cli as clap::Parser>::try_parse_from(
            std::iter::once("runner-manager".to_owned()).chain(command.argv.iter().cloned()),
        ) {
            Ok(cli) => cli,
            Err(error) => {
                return result(2, String::new(), error.render().to_string());
            }
        };
        let Some(access) = access(&cli) else {
            return refused(
                Failure::InvalidArgument,
                "this host does not run that command for the coordinator; only reading and \
                 changing repositories, labels, limits and workspaces"
                    .into(),
            );
        };
        if access == Access::Change && !changes_allowed(context.paths()) {
            return refused(
                Failure::Conflict,
                "this host does not take changes through the coordinator; its operator can allow \
                 them there with `runner-manager coordinator remote-changes allow`"
                    .into(),
            );
        }
        let mut stdout = Vec::new();
        match super::route(
            &cli.command,
            context,
            &mut stdout,
            None,
            Styling::plain_for_buffer(),
        ) {
            Ok(()) => result(
                0,
                String::from_utf8_lossy(&stdout).into_owned(),
                String::new(),
            ),
            Err(error) => {
                let mut stderr = Vec::new();
                let _ = error.render(&mut stderr);
                result(
                    error.class().code(),
                    String::from_utf8_lossy(&stdout).into_owned(),
                    String::from_utf8_lossy(&stderr).into_owned(),
                )
            }
        }
    })();
    record(context.paths().state_dir(), command, outcome.exit_code);
    tracing::info!(
        exit_code = outcome.exit_code,
        "ran a command the coordinator relayed"
    );
    outcome
}

/// `stdout` and `stderr` cut to [`MAX_COMMAND_OUTPUT_BYTES`] together,
/// stderr first: it says why a command failed.
fn bounded(stdout: String, stderr: String) -> (String, String, bool) {
    let cut = |text: String, limit: usize| -> (String, bool) {
        if text.len() <= limit {
            return (text, false);
        }
        let mut end = limit;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        (text[..end].to_owned(), true)
    };
    let (stderr, cut_err) = cut(stderr, MAX_COMMAND_OUTPUT_BYTES);
    let (stdout, cut_out) = cut(stdout, MAX_COMMAND_OUTPUT_BYTES - stderr.len());
    (stdout, stderr, cut_err || cut_out)
}

/// Appends one line to the host's record of remote commands. The record is
/// evidence, never the gate: a failure to write it changes no outcome.
fn record(state_dir: &Path, command: &RunCommand, exit_code: u8) {
    let path: PathBuf = state_dir.join(RECORD_FILE);
    if std::fs::metadata(&path).is_ok_and(|meta| meta.len() >= RECORD_ROTATE_BYTES) {
        let _ = std::fs::rename(&path, path.with_extension("jsonl.1"));
    }
    let line = serde_json::json!({
        "at": chrono::Utc::now().to_rfc3339(),
        "by": command.by,
        "argv": command.argv,
        "exit_code": exit_code,
    });
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| writeln!(file, "{line}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(argv: &[&str]) -> Cli {
        <Cli as clap::Parser>::try_parse_from(
            std::iter::once("runner-manager").chain(argv.iter().copied()),
        )
        .expect("parses")
    }

    #[test]
    fn only_repository_and_capacity_commands_run_remotely() {
        assert_eq!(
            access(&parsed(&["repo", "list", "--json"])),
            Some(Access::Read)
        );
        assert_eq!(access(&parsed(&["host", "show"])), Some(Access::Read));
        assert_eq!(
            access(&parsed(&[
                "repo",
                "set-capacity",
                "octo/app",
                "--max-capacity",
                "4"
            ])),
            Some(Access::Change)
        );
        assert_eq!(
            access(&parsed(&[
                "repo",
                "add-label",
                "octo/app",
                "--label",
                "gpu"
            ])),
            Some(Access::Change)
        );
        for refused in [
            &["auth", "logout"][..],
            &["service", "uninstall"],
            &["update"],
            &["host", "protect-path", "add", "/srv"],
            &["coordinator", "leave"],
            &["--host", "wsl:Ubuntu", "repo", "list"],
            &["--data-dir", "/tmp/x", "repo", "list"],
        ] {
            assert_eq!(access(&parsed(refused)), None, "{refused:?}");
        }
    }

    #[test]
    fn output_is_cut_to_fit_one_frame_keeping_the_error() {
        let (stdout, stderr, truncated) =
            bounded("o".repeat(MAX_COMMAND_OUTPUT_BYTES), "error: why\n".into());
        assert!(truncated);
        assert_eq!(stderr, "error: why\n");
        assert_eq!(stdout.len() + stderr.len(), MAX_COMMAND_OUTPUT_BYTES);
        assert_eq!(
            bounded("a".into(), String::new()),
            ("a".into(), String::new(), false)
        );
    }
}
