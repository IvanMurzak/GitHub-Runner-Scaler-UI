//! Restarting this machine, for `host reboot`.
//!
//! The daemon decides *when* (once every running job has finished); this
//! module only knows *how*, on each system and for each account the service
//! may run as, and tries the ways in order until one is accepted. Which
//! commands are tried is a pure function ([`commands`]) so every system's
//! choice is tested on every system, and the daemon takes a [`Rebooter`] so
//! that no test ever restarts the machine running it.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use runner_manager_domain::model::Os;

/// How long one command may take to answer before the next is tried. A
/// restart that was accepted answers at once; `osascript` can wait on a
/// consent dialog nobody will see.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// The seconds Windows waits between accepting the restart and starting it.
const WINDOWS_DELAY_SECS: u32 = 5;

/// One way to ask the system for a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebootCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl RebootCommand {
    fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_owned(),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        }
    }

    /// As a person would type it, for messages.
    #[must_use]
    pub fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// The commands that restart `os`, in the order they are tried, for a
/// service running as an administrator (`root`, LocalSystem) or not.
///
/// - **Windows**: `shutdown.exe /r`, which LocalSystem and an interactive
///   user can both run; `/d p:4:1` records a planned restart for
///   maintenance in the event log, `/c` says who asked.
/// - **Linux**: as root, `systemctl reboot`, then `shutdown -r now`, then
///   `reboot` for a system without systemd. As a user, the same through
///   `sudo -n` (a password is never asked for), after `systemctl reboot`
///   without a password prompt, which polkit allows some sessions.
/// - **macOS**: as root, `shutdown -r now`. As a user (a login LaunchAgent),
///   System Events' restart, which asks the open applications to quit, then
///   `sudo -n shutdown -r now`.
#[must_use]
pub fn commands(os: Os, administrator: bool, reason: &str) -> Vec<RebootCommand> {
    match os {
        Os::Windows => {
            let delay = WINDOWS_DELAY_SECS.to_string();
            vec![RebootCommand {
                program: windows_shutdown_exe(),
                args: ["/r", "/t", &delay, "/d", "p:4:1", "/c", reason]
                    .iter()
                    .map(|arg| (*arg).to_owned())
                    .collect(),
            }]
        }
        Os::Linux if administrator => vec![
            RebootCommand::new("systemctl", &["reboot"]),
            RebootCommand::new("shutdown", &["-r", "now", reason]),
            RebootCommand::new("reboot", &[]),
        ],
        Os::Linux => vec![
            RebootCommand::new("systemctl", &["--no-ask-password", "reboot"]),
            RebootCommand::new("sudo", &["-n", "systemctl", "reboot"]),
            RebootCommand::new("sudo", &["-n", "shutdown", "-r", "now", reason]),
        ],
        Os::MacOs if administrator => {
            vec![RebootCommand::new("/sbin/shutdown", &["-r", "now"])]
        }
        Os::MacOs => vec![
            RebootCommand::new(
                "/usr/bin/osascript",
                &["-e", "tell application \"System Events\" to restart"],
            ),
            RebootCommand::new("/usr/bin/sudo", &["-n", "/sbin/shutdown", "-r", "now"]),
        ],
    }
}

/// `shutdown.exe` by its full path, so a `shutdown` earlier on `PATH` is not
/// the one run.
fn windows_shutdown_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    format!(r"{root}\System32\shutdown.exe")
}

/// Asks the system to restart.
pub trait Rebooter: Send + Sync {
    /// Asks for the restart, and says which command the system accepted.
    ///
    /// # Errors
    /// Why every way was refused, one line per command tried.
    fn reboot(&self, reason: &str) -> Result<String, String>;
}

/// The real thing: runs [`commands`] for this machine until one is accepted.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRebooter;

impl Rebooter for SystemRebooter {
    fn reboot(&self, reason: &str) -> Result<String, String> {
        let os = crate::os::detect_os().ok_or("this system has no known way to restart")?;
        let mut refused = Vec::new();
        for command in commands(os, crate::host_fitness::is_elevated(), reason) {
            match run(&command) {
                Ok(()) => return Ok(command.display()),
                Err(why) => refused.push(format!("`{}`: {why}", command.display())),
            }
        }
        Err(refused.join("; "))
    }
}

/// Runs `command` and waits for it within [`COMMAND_TIMEOUT`]. Its output
/// is kept only to say why it failed.
fn run(command: &RebootCommand) -> Result<(), String> {
    let mut child = Command::new(&command.program)
        .args(&command.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            if status.success() {
                return Ok(());
            }
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
            }
            let stderr = stderr.split_whitespace().collect::<Vec<_>>().join(" ");
            let mut why = format!("exited with {status}");
            if !stderr.is_empty() {
                why.push_str(": ");
                why.push_str(&stderr[..stderr.floor_char_boundary(200)]);
            }
            return Err(why);
        }
        if started.elapsed() >= COMMAND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "gave no answer within {} seconds",
                COMMAND_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn programs(os: Os, administrator: bool) -> Vec<String> {
        commands(os, administrator, "why")
            .into_iter()
            .map(|command| command.display())
            .collect()
    }

    #[test]
    fn windows_restarts_with_shutdown_exe_and_says_why() {
        for administrator in [true, false] {
            let commands = commands(Os::Windows, administrator, "runner-manager: asked");
            let [command] = commands.as_slice() else {
                panic!("one command on Windows");
            };
            assert!(
                command.program.ends_with(r"\System32\shutdown.exe"),
                "{command:?}"
            );
            assert_eq!(
                command.args,
                [
                    "/r",
                    "/t",
                    "5",
                    "/d",
                    "p:4:1",
                    "/c",
                    "runner-manager: asked"
                ]
            );
        }
    }

    #[test]
    fn linux_root_reboots_directly_and_a_user_never_waits_for_a_password() {
        assert_eq!(
            programs(Os::Linux, true),
            ["systemctl reboot", "shutdown -r now why", "reboot"]
        );
        let user = programs(Os::Linux, false);
        assert_eq!(
            user,
            [
                "systemctl --no-ask-password reboot",
                "sudo -n systemctl reboot",
                "sudo -n shutdown -r now why"
            ]
        );
        assert!(
            user.iter()
                .filter(|command| command.starts_with("sudo"))
                .all(|command| command.starts_with("sudo -n ")),
            "sudo must never prompt"
        );
    }

    #[test]
    fn macos_root_shuts_down_and_a_login_agent_asks_system_events_first() {
        assert_eq!(programs(Os::MacOs, true), ["/sbin/shutdown -r now"]);
        assert_eq!(
            programs(Os::MacOs, false),
            [
                "/usr/bin/osascript -e tell application \"System Events\" to restart",
                "/usr/bin/sudo -n /sbin/shutdown -r now"
            ]
        );
    }

    #[test]
    fn a_failed_command_says_how_it_ended() {
        // `false`-like commands only: nothing here may restart anything.
        let missing = RebootCommand::new("runner-manager-no-such-program", &[]);
        assert!(run(&missing).is_err());
        #[cfg(unix)]
        {
            let failing = RebootCommand::new("sh", &["-c", "echo refused >&2; exit 3"]);
            let why = run(&failing).unwrap_err();
            assert!(why.contains("refused"), "{why}");
        }
    }
}
