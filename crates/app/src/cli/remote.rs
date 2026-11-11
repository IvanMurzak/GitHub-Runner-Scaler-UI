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

use std::sync::Mutex;

use runner_manager_domain::coordinator_protocol::{
    CommandResult, MAX_COMMAND_OUTPUT_BYTES, RunCommand, UpdateProgress,
};
use runner_manager_platform::lock::{HostLock, LockError, LockKind};
use runner_manager_platform::paths::AppPaths;
use serde::{Deserialize, Serialize};

use super::{
    Cli, CliError, Command, Context, CoordinatorRemoteChangesArgs, Failure, HostCommand,
    RemoteChangesChoice, RepoCommand, RepoProfileCommand, Styling, UpdateArgs, write_failed,
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
    let allow = match args.choice {
        RemoteChangesChoice::Allow => true,
        RemoteChangesChoice::Deny => false,
        RemoteChangesChoice::Status => {
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
             limits and workspaces, and update its runner-manager. Every change is recorded in remote-commands.jsonl here and on \
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
/// host never runs remotely: anything that signs in, installs, updates with a
/// flag,
/// touches another host, or is not about repositories and capacity.
///
/// Every flag of an allowed command comes with it, so the commands here are
/// the ones whose every flag may be set remotely; a test lists those flags,
/// and a new one fails it until someone decides. Creating or removing a
/// profile is not here: it picks an execution backend and an image.
#[must_use]
pub fn access(cli: &Cli) -> Option<Access> {
    if cli.host != super::HostSelector::Local {
        return None;
    }
    match &cli.command {
        Command::Status(_)
        | Command::Host(HostCommand::Show)
        | Command::Repo(
            RepoCommand::List(_)
            | RepoCommand::Profile(RepoProfileCommand::List(_) | RepoProfileCommand::Show(_)),
        ) => Some(Access::Read),
        Command::Update(UpdateArgs {
            check: false,
            force: false,
        })
        | Command::Host(HostCommand::SetCapacity(_))
        | Command::Repo(
            RepoCommand::Add(_)
            | RepoCommand::Remove(_)
            | RepoCommand::SetCapacity(_)
            | RepoCommand::SetScale(_)
            | RepoCommand::AddLabel(_)
            | RepoCommand::RemoveLabel(_)
            | RepoCommand::SetWorkspace(_)
            | RepoCommand::Profile(
                RepoProfileCommand::SetCapacity(_)
                | RepoProfileCommand::SetScale(_)
                | RepoProfileCommand::AddLabel(_)
                | RepoProfileCommand::RemoveLabel(_)
                | RepoProfileCommand::SetWorkspace(_),
            ),
        ) => Some(Access::Change),
        _ => None,
    }
}

/// The last update the coordinator started, while this service runs.
static UPDATE: Mutex<Option<UpdateProgress>> = Mutex::new(None);

fn set_update(state: &str, message: String) {
    *UPDATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(UpdateProgress {
        state: state.to_owned(),
        at: chrono::Utc::now().timestamp(),
        message,
    });
}

/// The last update the coordinator started, for the heartbeat.
#[must_use]
pub fn update_progress() -> Option<UpdateProgress> {
    UPDATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Starts updating this host and answers at once: a package manager can take
/// longer than the coordinator waits for an answer. The heartbeat carries how
/// it went ([`update_progress`]).
fn start_update(context: &Context, request_id: &str) -> CommandResult {
    let lock = match HostLock::try_acquire(context.paths(), LockKind::Update) {
        Ok(lock) => lock,
        Err(LockError::Held { .. }) => {
            return CommandResult::refused(
                request_id,
                Failure::Conflict.code(),
                "an update is already running on this host",
            );
        }
        Err(error) => {
            return CommandResult::refused(
                request_id,
                Failure::LocalState.code(),
                &error.to_string(),
            );
        }
    };
    set_update("running", "Looking for the newest release.".to_owned());
    let context = context.clone();
    std::thread::spawn(move || {
        let _lock = lock;
        let mut report = Vec::new();
        let outcome = super::update::perform(
            &context,
            &UpdateArgs {
                check: false,
                force: false,
            },
            &mut report,
            super::update::Caller::Coordinator,
        );
        super::versions::invalidate();
        match outcome {
            Ok(()) => {
                tracing::info!("the update the coordinator started ended");
                set_update("done", outcome_text(&String::from_utf8_lossy(&report)));
            }
            Err(error) => {
                tracing::warn!(%error, "the update the coordinator started failed");
                set_update("failed", error.to_string());
            }
        }
    });
    CommandResult {
        request_id: request_id.to_owned(),
        exit_code: 0,
        stdout: "Updating runner-manager on this host. The service restarts into the new \
                 version once its running jobs finish; the dashboard shows how it goes.\n"
            .to_owned(),
        stderr: String::new(),
        truncated: false,
        access: None,
    }
}

/// What an update did, from its report: the lines after the header that says
/// what was found, on one line.
fn outcome_text(report: &str) -> String {
    let outcome = report
        .split_once("\n\n")
        .map_or(report, |(_, outcome)| outcome);
    outcome.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Runs a command the coordinator relayed, as this host's service, and says
/// how it ended. Never panics on the command's input.
#[must_use]
pub fn execute(context: &Context, command: &RunCommand) -> CommandResult {
    let refused = |class: Failure, message: &str| {
        CommandResult::refused(&command.request_id, class.code(), message)
    };
    let outcome = (|| {
        if !command.well_formed() {
            return refused(Failure::InvalidArgument, "the command is malformed");
        }
        // Asked of the arguments themselves: `--data-dir` would point the
        // command at another tree, and the service's own environment may set
        // `RUNNER_MANAGER_DATA_DIR`, which clap would read into the same field.
        if names_another_tree(&command.argv) {
            return refused(
                Failure::InvalidArgument,
                "a command from the coordinator runs against this host's own data",
            );
        }
        let cli = match <Cli as clap::Parser>::try_parse_from(
            std::iter::once("runner-manager".to_owned()).chain(command.argv.iter().cloned()),
        ) {
            Ok(cli) => cli,
            Err(error) => {
                let mut result = refused(Failure::InvalidArgument, "");
                let rendered = error.render().to_string();
                // `--help` and `--version` are answers, as on a terminal.
                if matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) {
                    result.exit_code = 0;
                    result.stderr = String::new();
                    result.stdout = rendered;
                } else {
                    result.exit_code = 2;
                    result.stderr = rendered;
                }
                let (stdout, stderr, truncated) = bounded(result.stdout, result.stderr);
                result.stdout = stdout;
                result.stderr = stderr;
                result.truncated = truncated;
                return result;
            }
        };
        let Some(access) = access(&cli) else {
            return refused(
                Failure::InvalidArgument,
                "this host does not run that command for the coordinator; only reading and \
                 changing repositories, labels, limits and workspaces, and `update`",
            );
        };
        let judged = |mut result: CommandResult| {
            result.access = Some(
                match access {
                    Access::Read => "read",
                    Access::Change => "change",
                }
                .to_owned(),
            );
            result
        };
        if access == Access::Change && !changes_allowed(context.paths()) {
            return judged(refused(
                Failure::Conflict,
                "this host does not take changes through the coordinator; its operator can allow \
                 them there with `runner-manager coordinator remote-changes allow`",
            ));
        }
        // Not run as typed, which would update the service's private copy.
        if matches!(cli.command, Command::Update(_)) {
            return judged(start_update(context, &command.request_id));
        }
        let result = |exit_code: u8, stdout: String, stderr: String| {
            let (stdout, stderr, truncated) = bounded(stdout, stderr);
            judged(CommandResult {
                request_id: command.request_id.clone(),
                exit_code,
                stdout,
                stderr,
                truncated,
                access: None,
            })
        };
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
    // Reads are not kept here: opening a host on the dashboard reads it, and
    // that would push the changes out of the record.
    if outcome.access.as_deref() != Some("read") {
        record(context.paths().state_dir(), command, outcome.exit_code);
    }
    tracing::info!(
        exit_code = outcome.exit_code,
        "ran a command the coordinator relayed"
    );
    outcome
}

/// Whether `argv` names a data directory of its own.
fn names_another_tree(argv: &[String]) -> bool {
    argv.iter()
        .any(|argument| argument == "--data-dir" || argument.starts_with("--data-dir="))
}

/// The bytes `character` takes inside a JSON string, as `serde_json`
/// writes it: a quote, a backslash or a control character is escaped.
fn encoded_len(character: char) -> usize {
    match character {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        control if u32::from(control) < 0x20 => 6,
        other => other.len_utf8(),
    }
}

/// The JSON-encoded size of `text`, without its quotes.
fn encoded_size(text: &str) -> usize {
    text.chars().map(encoded_len).sum()
}

/// `stdout` and `stderr` cut to [`MAX_COMMAND_OUTPUT_BYTES`] together, as
/// they are sent (JSON-escaped), stderr first: it says why a command failed.
/// Measured escaped, so that the frame stays under the coordinator's limit
/// whatever the output holds.
fn bounded(stdout: String, stderr: String) -> (String, String, bool) {
    let cut = |text: String, limit: usize| -> (String, bool) {
        let mut size = 0;
        for (index, character) in text.char_indices() {
            size += encoded_len(character);
            if size > limit {
                return (text[..index].to_owned(), true);
            }
        }
        (text, false)
    };
    let (stderr, cut_err) = cut(stderr, MAX_COMMAND_OUTPUT_BYTES);
    let (stdout, cut_out) = cut(stdout, MAX_COMMAND_OUTPUT_BYTES - encoded_size(&stderr));
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
        assert_eq!(access(&parsed(&["update"])), Some(Access::Change));
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
            &["update", "--check"],
            &["update", "--force"],
            &["--host", "wsl:Ubuntu", "update"],
            &["host", "protect-path", "add", "/srv"],
            &["coordinator", "leave"],
            &["--host", "wsl:Ubuntu", "repo", "list"],
            &["--host", "remote:other", "repo", "list"],
            &["repo", "profile", "add", "octo/app", "--name", "gpu"],
        ] {
            assert_eq!(access(&parsed(refused)), None, "{refused:?}");
        }
    }

    #[test]
    fn an_updates_outcome_is_what_follows_its_header() {
        assert_eq!(
            outcome_text(
                "runner-manager update\n  installed  0.4.63\n\n0.4.64 is installed.\nThe service\n  restarts.\n"
            ),
            "0.4.64 is installed. The service restarts."
        );
        assert_eq!(outcome_text("only a line\n"), "only a line");
    }

    #[test]
    fn an_update_needs_changes_allowed_and_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(dir.path()), &mut Vec::new()).unwrap();
        let command = RunCommand {
            request_id: "r1".into(),
            argv: vec!["update".into()],
            by: "someone".into(),
        };
        let refused = execute(&context, &command);
        assert_eq!(refused.exit_code, Failure::Conflict.code());
        assert_eq!(refused.access.as_deref(), Some("change"));
        assert!(
            refused.stderr.contains("remote-changes allow"),
            "{refused:?}"
        );
        assert_eq!(update_progress(), None, "nothing started");
        let record =
            std::fs::read_to_string(context.paths().state_dir().join(RECORD_FILE)).unwrap();
        assert!(record.contains(r#""argv":["update"]"#), "{record}");

        // Allowed, but another update holds the lock: refused, nothing started.
        remote_changes(
            &context,
            &CoordinatorRemoteChangesArgs {
                choice: RemoteChangesChoice::Allow,
            },
            &mut Vec::new(),
        )
        .unwrap();
        let held = HostLock::try_acquire(context.paths(), LockKind::Update).unwrap();
        let busy = execute(&context, &command);
        assert_eq!(busy.exit_code, Failure::Conflict.code());
        assert!(busy.stderr.contains("already running"), "{busy:?}");
        drop(held);
        assert_eq!(update_progress(), None);
    }

    #[test]
    fn output_is_cut_to_fit_one_frame_keeping_the_error() {
        let (stdout, stderr, truncated) =
            bounded("o".repeat(MAX_COMMAND_OUTPUT_BYTES), "error: why\n".into());
        assert!(truncated);
        assert_eq!(stderr, "error: why\n");
        assert_eq!(
            encoded_size(&stdout) + encoded_size(&stderr),
            MAX_COMMAND_OUTPUT_BYTES
        );
        // Escaped output counts as it is sent.
        let (quotes, _, truncated) = bounded("\"".repeat(MAX_COMMAND_OUTPUT_BYTES), String::new());
        assert!(truncated);
        assert_eq!(quotes.len(), MAX_COMMAND_OUTPUT_BYTES / 2);
        assert_eq!(
            bounded("a".into(), String::new()),
            ("a".into(), String::new(), false)
        );
    }

    #[test]
    fn a_command_naming_its_own_data_directory_is_refused() {
        let argv = |items: &[&str]| items.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert!(names_another_tree(&argv(&[
            "--data-dir",
            "/x",
            "repo",
            "list"
        ])));
        assert!(names_another_tree(&argv(&[
            "--data-dir=/x",
            "repo",
            "list"
        ])));
        assert!(!names_another_tree(&argv(&["repo", "list"])));
    }

    /// Every flag of a command the coordinator may run can be set by a person
    /// signed in to it. A flag added to one of these commands fails this test
    /// until someone has decided it may be set remotely.
    #[test]
    fn every_flag_of_a_remote_command_was_decided_on() {
        use clap::CommandFactory as _;
        let approved: &[(&[&str], &[&str])] = &[
            (&["status"], &["json"]),
            (&["host", "show"], &[]),
            (&["host", "set-capacity"], &["capacity"]),
            (&["repo", "list"], &["json"]),
            (
                &["repo", "add"],
                &[
                    "repository",
                    "host_label",
                    "max_capacity",
                    "labels",
                    "enable",
                ],
            ),
            (&["repo", "remove"], &["repository", "profile", "purge"]),
            (
                &["repo", "set-capacity"],
                &["repository", "profile", "max_capacity"],
            ),
            (
                &["repo", "set-scale"],
                &["repository", "profile", "enabled"],
            ),
            (&["repo", "add-label"], &["repository", "profile", "labels"]),
            (
                &["repo", "remove-label"],
                &["repository", "profile", "labels"],
            ),
            (
                &["repo", "set-workspace"],
                &["repository", "profile", "mode", "path"],
            ),
            (&["repo", "profile", "list"], &["repository"]),
            (&["repo", "profile", "show"], &["repository", "profile"]),
            (
                &["repo", "profile", "set-capacity"],
                &["repository", "profile", "max_capacity"],
            ),
            (
                &["repo", "profile", "set-scale"],
                &["repository", "profile", "enabled"],
            ),
            (
                &["repo", "profile", "add-label"],
                &["repository", "profile", "labels"],
            ),
            (
                &["repo", "profile", "remove-label"],
                &["repository", "profile", "labels"],
            ),
            (
                &["repo", "profile", "set-workspace"],
                &["repository", "profile", "mode", "path"],
            ),
        ];
        let root = Cli::command();
        let globals: Vec<String> = root
            .get_arguments()
            .filter(|argument| argument.is_global_set())
            .map(|argument| argument.get_id().to_string())
            .collect();
        let mut undecided = Vec::new();
        for (path, flags) in approved {
            let mut command = &root;
            for name in *path {
                command = command
                    .find_subcommand(name)
                    .unwrap_or_else(|| panic!("no command {path:?}"));
            }
            let mut actual: Vec<String> = command
                .get_arguments()
                .map(|argument| argument.get_id().to_string())
                .filter(|id| id != "help" && !globals.contains(id))
                .collect();
            actual.sort();
            let mut expected: Vec<String> = flags.iter().map(ToString::to_string).collect();
            expected.sort();
            if actual != expected {
                undecided.push(format!("runner-manager {}: {actual:?}", path.join(" ")));
            }
        }
        assert!(
            undecided.is_empty(),
            "flags no one decided on for remote use:\n{}",
            undecided.join("\n")
        );
    }
}
