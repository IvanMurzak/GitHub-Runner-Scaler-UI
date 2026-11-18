//! `host reboot`: restarting this machine once every running job has finished.
//!
//! Only the running service can do it, because only it knows when its runners
//! are done. A request reaches it from this machine's command line (through
//! the state directory, [`service_request::REBOOT`]) or from the coordinator
//! (a remote command, run inside the service). From then on the host says it
//! is draining, so the coordinator places nothing here, and its target loops
//! drain exactly as for an upgrade: no new runner, every running one finishes
//! with no deadline. Then the system is asked to restart
//! ([`runner_manager_platform::reboot`]). A restart the system refuses is
//! reported and the host serves again; it is never left drained.
//!
//! A Windows machine that manages WSL distributions also waits for their
//! runners: restarting Windows stops every guest. It asks each guest to take
//! no new runner (the WSL recovery drain request in the shared directory) and
//! waits until each one's heartbeat says it holds none. A WSL guest itself
//! refuses: the machine to restart is its Windows host.
//!
//! Until the restart has begun, `host reboot --cancel` keeps the machine
//! running: the drain is ended as a service stop ends it (runners still up
//! are adopted, not stopped) and the service takes jobs again.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use runner_manager_domain::coordinator_protocol::{CommandResult, RebootProgress};
use runner_manager_domain::model::StartMode;
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::service_request::{self, AskError, Wait};
use runner_manager_platform::wsl::fence::{
    DrainRequest, GuestHeartbeat, GuestRecoveryConfig, clear_recovery, recovery_root,
};
use runner_manager_platform::wsl::record::WslProviderRecord;

use super::{CliError, Context, Failure, HostRebootArgs, write_failed};

/// What the system's restart log says about who asked.
pub const REASON: &str = "runner-manager: restart requested through `runner-manager host reboot`; \
                          every running job had finished";

/// The service's side of a reboot: whether one is wanted, and how it goes.
pub struct Control {
    /// `true` from a request until the reboot is cancelled or fails.
    wanted: tokio::sync::watch::Sender<bool>,
    progress: Mutex<Option<RebootProgress>>,
    /// Set by the daemon: this process serves the machine, and how.
    serving: Mutex<Option<Serving>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Serving {
    start_mode: StartMode,
    wsl_guest: bool,
}

static CONTROL: LazyLock<Control> = LazyLock::new(Control::new);

/// This process's control: the daemon's, the coordinator's commands' and the
/// heartbeat's.
#[must_use]
pub fn control() -> &'static Control {
    &CONTROL
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn runners_text(runners: u32) -> String {
    if runners == 1 {
        "1 runner".to_owned()
    } else {
        format!("{runners} runners")
    }
}

impl Control {
    #[must_use]
    pub fn new() -> Self {
        Self {
            wanted: tokio::sync::watch::channel(false).0,
            progress: Mutex::new(None),
            serving: Mutex::new(None),
        }
    }

    /// The daemon serves this machine: requests are taken from now on.
    pub fn attach(&self, start_mode: StartMode, wsl_guest: bool) {
        *locked(&self.serving) = Some(Serving {
            start_mode,
            wsl_guest,
        });
    }

    /// Whether this service can restart the machine: it serves it, and it is
    /// not a WSL guest.
    #[must_use]
    pub fn available(&self) -> bool {
        locked(&self.serving).is_some_and(|serving| !serving.wsl_guest)
    }

    /// Whether the service comes back only once its account signs in.
    #[must_use]
    pub fn starts_at_login(&self) -> bool {
        locked(&self.serving).is_some_and(|serving| serving.start_mode == StartMode::Login)
    }

    /// The last reboot asked, for the heartbeat.
    #[must_use]
    pub fn progress(&self) -> Option<RebootProgress> {
        locked(&self.progress).clone()
    }

    fn set(&self, state: &str, message: String, runners: Option<u32>) {
        *locked(&self.progress) = Some(RebootProgress {
            state: state.to_owned(),
            at: chrono::Utc::now().timestamp(),
            message,
            runners,
        });
    }

    fn state(&self) -> Option<String> {
        locked(&self.progress)
            .as_ref()
            .map(|progress| progress.state.clone())
    }

    /// Asks for a reboot, and says what will happen.
    ///
    /// # Errors
    /// Why this service does not reboot the machine.
    pub fn request(&self) -> Result<String, String> {
        let serving = (*locked(&self.serving))
            .ok_or("the runner-manager service is not serving this machine yet; try again")?;
        if serving.wsl_guest {
            return Err(
                "this host runs inside a WSL distribution; restart the Windows machine \
                        that manages it instead (its own `host reboot` waits for this \
                        distribution's runners too)"
                    .to_owned(),
            );
        }
        if self.state().as_deref() == Some("rebooting") {
            return Err("this machine is already restarting".to_owned());
        }
        let already = self.wanted.send_replace(true);
        if !already {
            self.set(
                "pending",
                "Waiting for the running jobs to finish; taking no new one.".to_owned(),
                None,
            );
        }
        let mut answer = if already {
            "A reboot was already asked: this machine restarts once every running job has \
             finished."
                .to_owned()
        } else {
            "This machine takes no new job from now on and restarts once every running job \
             has finished, however long that takes."
                .to_owned()
        };
        answer.push_str(" `runner-manager host reboot --cancel` keeps it running until then.");
        if serving.start_mode == StartMode::Login {
            answer.push_str(
                " The service starts when its account signs in, so after the restart it works \
                 again only once that account is signed in (automatically, or by a person).",
            );
        }
        Ok(answer)
    }

    /// Cancels a pending reboot, and says so.
    ///
    /// # Errors
    /// The restart has already begun.
    pub fn cancel(&self) -> Result<String, String> {
        if self.state().as_deref() == Some("rebooting") {
            return Err("the restart has already begun and can no longer be cancelled".to_owned());
        }
        if !self.wanted.send_replace(false) {
            return Ok("No reboot is pending on this machine.".to_owned());
        }
        self.set(
            "cancelled",
            "Cancelled; the service takes jobs again.".to_owned(),
            None,
        );
        Ok(
            "The reboot is cancelled: the service takes jobs again within a minute; nothing \
            that was running is stopped."
                .to_owned(),
        )
    }

    /// Resolves once a reboot is wanted.
    pub async fn requested(&self) {
        let mut wanted = self.wanted.subscribe();
        let _ = wanted.wait_for(|wanted| *wanted).await;
    }

    /// Resolves once the reboot is no longer wanted (cancelled).
    pub async fn cancelled(&self) {
        let mut wanted = self.wanted.subscribe();
        let _ = wanted.wait_for(|wanted| !*wanted).await;
    }

    /// Still draining: what it waits for.
    pub fn waiting(&self, runners: Option<u32>, guest: Option<String>) {
        let message = match (runners, guest) {
            (_, Some(guest)) => guest,
            (Some(0), None) => "Every job has finished.".to_owned(),
            (Some(runners), None) => format!(
                "Waiting for {} to finish; taking no new job.",
                runners_text(runners)
            ),
            (None, None) => "Waiting for the running jobs to finish; taking no new one.".to_owned(),
        };
        self.set("pending", message, runners);
    }

    /// Every runner is done: the system is about to be asked.
    pub fn rebooting(&self, message: String) {
        self.set("rebooting", message, Some(0));
    }

    /// The restart did not happen: the reboot is no longer wanted, and the
    /// host serves again.
    pub fn failed(&self, why: &str) {
        self.wanted.send_replace(false);
        self.set(
            "failed",
            format!("{why} The service takes jobs again."),
            None,
        );
    }
}

impl Default for Control {
    fn default() -> Self {
        Self::new()
    }
}

/// `host reboot [--cancel]` typed on this machine: asks the running service.
///
/// # Errors
/// [`Failure::LocalState`] when no service took the request, or it refused.
pub fn command(
    context: &Context,
    args: &HostRebootArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("the reboot request");
    let channel = if args.cancel {
        service_request::REBOOT_CANCEL
    } else {
        service_request::REBOOT
    };
    match channel.ask::<String>(context.paths().state_dir(), Wait::REBOOT) {
        Ok(answer) => writeln!(out, "{answer}").map_err(failed),
        Err(error @ (AskError::NotSent(_) | AskError::NotTaken(_) | AskError::NoAnswer(_))) => {
            Err(CliError::with_remedy(
                Failure::LocalState,
                format!("the running service did not answer: {error}"),
                "runner-manager service status   (only the running service can restart this \
                 machine, once its jobs have finished)",
            ))
        }
        Err(AskError::Refused(why)) => Err(CliError::new(Failure::Conflict, why)),
    }
}

/// `host reboot [--cancel]` relayed by the coordinator, inside the service.
#[must_use]
pub fn remote(control: &Control, request_id: &str, args: &HostRebootArgs) -> CommandResult {
    let outcome = if args.cancel {
        control.cancel()
    } else {
        control.request()
    };
    match outcome {
        Ok(answer) => CommandResult {
            request_id: request_id.to_owned(),
            exit_code: 0,
            stdout: format!("{answer}\n"),
            stderr: String::new(),
            truncated: false,
            access: None,
        },
        Err(why) => CommandResult::refused(request_id, Failure::Conflict.code(), &why),
    }
}

/// Answers `host reboot` typed on this machine, for as long as the service
/// runs: through a reboot's drain too, so that `--cancel` is heard.
pub async fn answer_requests(state_dir: PathBuf) {
    use service_request::{POLL, REBOOT, REBOOT_CANCEL};
    loop {
        for (channel, act) in [
            (
                REBOOT,
                Control::request as fn(&Control) -> Result<String, String>,
            ),
            (REBOOT_CANCEL, Control::cancel),
        ] {
            for request in channel.take(&state_dir) {
                let outcome = act(control());
                tracing::info!(
                    cancel = channel == REBOOT_CANCEL,
                    accepted = outcome.is_ok(),
                    "`host reboot` was asked on this machine"
                );
                if let Err(error) = channel.answer(&state_dir, &request, outcome) {
                    tracing::warn!(%error, "could not answer `host reboot`");
                }
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

// ---------------------------------------------------------------------------
// The WSL guests of a Windows machine
// ---------------------------------------------------------------------------

/// Where the generation of the guests' drain is kept while it stands, so a
/// service that comes back after the restart lifts it.
const GUEST_DRAIN_FILE: &str = "reboot-wsl-drain";

/// The managed WSL distributions a reboot of this Windows machine waits for.
pub struct GuestDrain {
    guests: Vec<(String, PathBuf)>,
    generation: u64,
    state_dir: PathBuf,
}

impl GuestDrain {
    /// This machine's managed distributions; none off Windows.
    #[must_use]
    pub fn of(paths: &AppPaths) -> Self {
        let guests = if cfg!(windows) {
            WslProviderRecord::all(paths)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|record| {
                    recovery_root(paths, &record.distribution)
                        .ok()
                        .map(|root| (record.distribution, root))
                })
                .collect()
        } else {
            Vec::new()
        };
        Self::over(guests, paths.state_dir())
    }

    /// Over the given distributions' shared directories.
    #[must_use]
    pub fn over(guests: Vec<(String, PathBuf)>, state_dir: &Path) -> Self {
        Self {
            guests,
            generation: u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(1),
            state_dir: state_dir.to_path_buf(),
        }
    }

    /// Asks every guest to start no runner, or renews the request: one not
    /// renewed for minutes is retired as abandoned by the recovery watchdog.
    pub fn request(&self) {
        if self.guests.is_empty() {
            return;
        }
        let _ = std::fs::create_dir_all(&self.state_dir);
        let _ = std::fs::write(
            self.state_dir.join(GUEST_DRAIN_FILE),
            self.generation.to_string(),
        );
        for (distribution, root) in &self.guests {
            if let Err(error) = DrainRequest::new(self.generation, chrono::Utc::now()).write(root) {
                tracing::warn!(%distribution, %error, "a WSL guest could not be asked to drain for the reboot");
            }
        }
    }

    /// What the reboot still waits for among the guests, or `None` when every
    /// guest has said, since it was asked, that it holds no runner.
    #[must_use]
    pub fn waiting(&self) -> Option<String> {
        self.guests.iter().find_map(|(distribution, root)| {
            let heartbeat = GuestHeartbeat::read(root).ok().flatten();
            match heartbeat {
                Some(heartbeat) if heartbeat.acknowledged_generation == Some(self.generation) => {
                    match heartbeat.local_active_attempts {
                        Some(0) => None,
                        Some(runners) => Some(format!(
                            "Waiting for WSL {distribution}: {} still running.",
                            runners_text(runners)
                        )),
                        None => Some(format!(
                            "Waiting for WSL {distribution}: it cannot read its runners."
                        )),
                    }
                }
                _ => Some(format!(
                    "Waiting for WSL {distribution} to confirm it takes no new job (its service \
                     has not answered yet)."
                )),
            }
        })
    }

    /// The reboot did not happen: the guests take jobs again.
    pub fn release(&self) {
        release(&self.guests, self.generation, &self.state_dir);
    }

    /// Lifts a guests' drain an earlier service left for a reboot: on the
    /// first start after the restart, or after a crash.
    pub fn release_left_over(paths: &AppPaths) {
        let file = paths.state_dir().join(GUEST_DRAIN_FILE);
        let Some(generation) = std::fs::read_to_string(&file)
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
        else {
            let _ = std::fs::remove_file(&file);
            return;
        };
        let guests = Self::of(paths).guests;
        release(&guests, generation, paths.state_dir());
    }
}

fn release(guests: &[(String, PathBuf)], generation: u64, state_dir: &Path) {
    for (distribution, root) in guests {
        if let Err(error) = clear_recovery(root, generation) {
            tracing::warn!(%distribution, %error, "a WSL guest's reboot drain could not be lifted");
        }
    }
    let _ = std::fs::remove_file(state_dir.join(GUEST_DRAIN_FILE));
}

/// Whether this host is a WSL guest a Windows machine manages.
#[must_use]
pub fn is_wsl_guest(paths: &AppPaths) -> bool {
    GuestRecoveryConfig::path(paths).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use runner_manager_platform::wsl::fence::SCHEMA_VERSION;

    fn serving(mode: StartMode) -> Control {
        let control = Control::new();
        control.attach(mode, false);
        control
    }

    #[test]
    fn a_reboot_is_asked_once_and_can_be_cancelled_until_it_begins() {
        let control = serving(StartMode::Boot);
        assert!(control.available());
        assert_eq!(control.progress(), None);
        let answer = control.request().unwrap();
        assert!(answer.contains("takes no new job"), "{answer}");
        assert!(!answer.contains("signs in"), "{answer}");
        assert_eq!(control.progress().unwrap().state, "pending");
        let again = control.request().unwrap();
        assert!(again.contains("already asked"), "{again}");

        control.waiting(Some(2), None);
        let progress = control.progress().unwrap();
        assert_eq!(progress.runners, Some(2));
        assert!(progress.message.contains("2 runners"), "{progress:?}");

        assert!(control.cancel().unwrap().contains("cancelled"));
        assert_eq!(control.progress().unwrap().state, "cancelled");
        assert!(control.cancel().unwrap().contains("No reboot is pending"));

        control.request().unwrap();
        control.rebooting("Restarting.".into());
        assert!(control.cancel().is_err(), "too late once it has begun");
        assert!(control.request().is_err());
        control.failed("The system refused.");
        let failed = control.progress().unwrap();
        assert_eq!(failed.state, "failed");
        assert!(failed.message.contains("takes jobs again"), "{failed:?}");
        assert!(
            control.request().is_ok(),
            "a failed reboot can be asked again"
        );
    }

    #[test]
    fn a_wsl_guest_and_a_service_not_serving_yet_refuse() {
        let idle = Control::new();
        assert!(!idle.available());
        assert!(idle.request().is_err());
        let guest = Control::new();
        guest.attach(StartMode::Boot, true);
        assert!(!guest.available());
        assert!(guest.request().unwrap_err().contains("Windows machine"));
        assert_eq!(guest.progress(), None);
    }

    #[test]
    fn a_login_service_says_it_comes_back_only_once_signed_in() {
        let control = serving(StartMode::Login);
        assert!(control.starts_at_login());
        assert!(control.request().unwrap().contains("signs in"));
    }

    #[tokio::test]
    async fn the_daemon_hears_a_request_and_a_cancel() {
        let control = std::sync::Arc::new(serving(StartMode::Boot));
        let waiting = tokio::spawn({
            let control = std::sync::Arc::clone(&control);
            async move { control.requested().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        control.request().unwrap();
        waiting.await.unwrap();
        let cancelled = tokio::spawn({
            let control = std::sync::Arc::clone(&control);
            async move { control.cancelled().await }
        });
        tokio::task::yield_now().await;
        assert!(!cancelled.is_finished());
        control.cancel().unwrap();
        cancelled.await.unwrap();
    }

    fn heartbeat(root: &Path, generation: Option<u64>, active: Option<u32>) {
        GuestHeartbeat {
            schema_version: SCHEMA_VERSION,
            observed_at: chrono::Utc::now(),
            acknowledged_generation: generation,
            local_active_attempts: active,
            local_busy_attempts: active,
            managed_targets: Vec::new(),
            unmanaged_runner_services: None,
        }
        .write(root)
        .unwrap();
    }

    #[test]
    fn a_guest_counts_as_drained_only_once_it_acknowledged_and_holds_no_runner() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Ubuntu");
        let state = dir.path().join("state");
        let drain = GuestDrain::over(vec![("Ubuntu".into(), root.clone())], &state);
        drain.request();
        assert_eq!(
            DrainRequest::read(&root).unwrap().unwrap().generation,
            drain.generation
        );
        assert!(drain.waiting().unwrap().contains("has not answered"));
        // Idle, but from before the request: not yet a promise.
        heartbeat(&root, None, Some(0));
        assert!(drain.waiting().is_some());
        heartbeat(&root, Some(drain.generation), Some(1));
        assert!(drain.waiting().unwrap().contains("1 runner"));
        heartbeat(&root, Some(drain.generation), Some(0));
        assert_eq!(drain.waiting(), None);

        // A reboot that did not happen lifts the guests' drain.
        drain.release();
        assert_eq!(DrainRequest::read(&root).unwrap(), None);
        assert!(!state.join(GUEST_DRAIN_FILE).exists());
    }

    #[test]
    fn a_guest_drain_left_behind_is_lifted_at_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Ubuntu");
        let state = dir.path().join("state");
        let drain = GuestDrain::over(vec![("Ubuntu".into(), root.clone())], &state);
        drain.request();
        assert!(state.join(GUEST_DRAIN_FILE).exists());
        // What `release_left_over` does with this machine's guests.
        let generation: u64 = std::fs::read_to_string(state.join(GUEST_DRAIN_FILE))
            .unwrap()
            .parse()
            .unwrap();
        release(&[("Ubuntu".into(), root.clone())], generation, &state);
        assert_eq!(DrainRequest::read(&root).unwrap(), None);
        // A request of the recovery watchdog's own generation is not ours.
        DrainRequest::new(generation + 1, chrono::Utc::now())
            .write(&root)
            .unwrap();
        release(&[("Ubuntu".into(), root.clone())], generation, &state);
        assert!(DrainRequest::read(&root).unwrap().is_some());
    }
}
