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
    DrainRequest, FenceClaim, FenceOwnerKind, GuestHeartbeat, GuestRecoveryConfig, clear_recovery,
    recovery_root,
};
use runner_manager_platform::wsl::record::WslProviderRecord;

use super::{CliError, Context, Failure, HostRebootArgs, write_failed};

/// What the system's restart log says about who asked.
pub const REASON: &str = "runner-manager: restart requested through `runner-manager host reboot`; \
                          every running job had finished";

/// The service's side of a reboot: whether one is wanted, and how it goes.
///
/// `wanted` and the progress change together, under `state`'s lock: a cancel
/// can never be answered while the restart begins, and a late progress line
/// never overwrites a cancel.
pub struct Control {
    /// `true` from a request until the reboot is cancelled or fails.
    wanted: tokio::sync::watch::Sender<bool>,
    state: Mutex<State>,
}

struct State {
    progress: Option<RebootProgress>,
    /// Set by the daemon: this process serves the machine, and how; or why
    /// it takes no request now.
    serving: Result<Serving, &'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Serving {
    start_mode: StartMode,
    wsl_guest: bool,
}

const NOT_SERVING: &str = "the runner-manager service is not serving this machine yet; try again";

static CONTROL: LazyLock<Control> = LazyLock::new(Control::new);

/// This process's control: the daemon's, the coordinator's commands' and the
/// heartbeat's.
#[must_use]
pub fn control() -> &'static Control {
    &CONTROL
}

fn runners_text(runners: u32) -> String {
    if runners == 1 {
        "1 runner".to_owned()
    } else {
        format!("{runners} runners")
    }
}

fn progress(state: &str, message: String, runners: Option<u32>) -> Option<RebootProgress> {
    Some(RebootProgress {
        state: state.to_owned(),
        at: chrono::Utc::now().timestamp(),
        message,
        runners,
    })
}

impl State {
    fn is(&self, state: &str) -> bool {
        self.progress
            .as_ref()
            .is_some_and(|progress| progress.state == state)
    }
}

impl Control {
    #[must_use]
    pub fn new() -> Self {
        Self {
            wanted: tokio::sync::watch::channel(false).0,
            state: Mutex::new(State {
                progress: None,
                serving: Err(NOT_SERVING),
            }),
        }
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The daemon serves this machine: requests are taken from now on.
    pub fn attach(&self, start_mode: StartMode, wsl_guest: bool) {
        self.locked().serving = Ok(Serving {
            start_mode,
            wsl_guest,
        });
    }

    /// The daemon is going away (an upgrade, a stop): a request now would be
    /// answered and then forgotten, so it is refused with `why`.
    pub fn unavailable(&self, why: &'static str) {
        self.locked().serving = Err(why);
    }

    /// Whether this service can restart the machine: it serves it, and it is
    /// not a WSL guest.
    #[must_use]
    pub fn available(&self) -> bool {
        self.locked()
            .serving
            .is_ok_and(|serving| !serving.wsl_guest)
    }

    /// Whether the service comes back only once its account signs in.
    #[must_use]
    pub fn starts_at_login(&self) -> bool {
        self.locked()
            .serving
            .is_ok_and(|serving| serving.start_mode == StartMode::Login)
    }

    /// The last reboot asked, for the heartbeat.
    #[must_use]
    pub fn progress(&self) -> Option<RebootProgress> {
        self.locked().progress.clone()
    }

    /// Asks for a reboot, and says what will happen.
    ///
    /// # Errors
    /// Why this service does not reboot the machine.
    pub fn request(&self) -> Result<String, String> {
        let mut state = self.locked();
        let serving = state.serving.map_err(str::to_owned)?;
        if serving.wsl_guest {
            return Err(
                "this host runs inside a WSL distribution; restart the Windows machine that \
                 manages it instead (its own `host reboot` waits for this distribution's runners \
                 too)"
                    .to_owned(),
            );
        }
        if state.is("rebooting") {
            return Err("this machine is already restarting".to_owned());
        }
        let already = self.wanted.send_replace(true);
        if !already {
            state.progress = progress(
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
        let mut state = self.locked();
        if state.is("rebooting") {
            return Err("the restart has already begun and can no longer be cancelled".to_owned());
        }
        let was = self.wanted.send_replace(false);
        if !was && !state.is("pending") {
            return Ok("No reboot is pending on this machine.".to_owned());
        }
        state.progress = progress(
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

    /// Still draining: what it waits for. Nothing once cancelled.
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
        let mut state = self.locked();
        if *self.wanted.borrow() {
            state.progress = progress("pending", message, runners);
        }
    }

    /// Every runner is done: the restart begins, and can no longer be
    /// cancelled. `false` when it was cancelled first.
    #[must_use]
    pub fn begin_restart(&self, message: String) -> bool {
        let mut state = self.locked();
        if !*self.wanted.borrow() {
            return false;
        }
        state.progress = progress("rebooting", message, Some(0));
        true
    }

    /// The restart has begun: what the system said.
    pub fn rebooting(&self, message: String) {
        self.locked().progress = progress("rebooting", message, Some(0));
    }

    /// An accepted restart did not happen and could not be called off: still
    /// wanted, and cancellable again, so a person decides when to serve.
    pub fn stalled(&self, message: String) {
        let mut state = self.locked();
        if *self.wanted.borrow() {
            state.progress = progress("pending", message, Some(0));
        }
    }

    /// Something started running during the grace: back to waiting, still
    /// wanted.
    pub fn back_to_pending(&self) {
        self.locked().progress = progress(
            "pending",
            "A runner started; waiting for it to finish.".to_owned(),
            None,
        );
    }

    /// The restart did not happen: the reboot is no longer wanted, and the
    /// host serves again.
    pub fn failed(&self, why: &str) {
        let mut state = self.locked();
        self.wanted.send_replace(false);
        state.progress = progress(
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
    let administrator = runner_manager_platform::host_fitness::is_elevated();
    loop {
        for (channel, act) in [
            (
                REBOOT,
                Control::request as fn(&Control) -> Result<String, String>,
            ),
            (REBOOT_CANCEL, Control::cancel),
        ] {
            let (taken, refused) =
                channel.take_where(&state_dir, |meta| asked_by_an_equal(meta, administrator));
            let answers = taken
                .into_iter()
                .map(|request| (request, act(control())))
                .chain(refused.into_iter().map(|request| {
                    (
                        request,
                        Err(
                            "this service runs as an administrator: ask with administrator \
                             rights (`sudo runner-manager host reboot`)"
                                .to_owned(),
                        ),
                    )
                }));
            for (request, outcome) in answers {
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

/// Whether a request file was left by an account that may restart the
/// machine as this service would. The state directory belongs to the account
/// that installed the service, and runners may run as that account: a
/// service running as root restarts the machine only for a request root
/// wrote (`sudo`). A user service, which could restart the machine only
/// with its own rights anyway, takes its account's requests. Windows is not
/// asked (its service's state directory is not writable by runners there).
fn asked_by_an_equal(meta: &std::fs::Metadata, administrator: bool) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        !administrator || written_by_root(meta.file_type().is_file(), meta.uid(), meta.nlink())
    }
    #[cfg(not(unix))]
    {
        let _ = (meta, administrator);
        true
    }
}

/// A request root wrote itself: a regular file root owns, under one name. A
/// hard link to some root-owned file elsewhere (which macOS, and Linux
/// without `protected_hardlinks`, let any account make) has two.
#[cfg_attr(not(unix), allow(dead_code))]
const fn written_by_root(regular: bool, uid: u32, links: u64) -> bool {
    regular && uid == 0 && links == 1
}

// ---------------------------------------------------------------------------
// The WSL guests of a Windows machine
// ---------------------------------------------------------------------------

/// Where the generation of the guests' drain is kept while it stands, so a
/// service that comes back after the restart lifts it.
const GUEST_DRAIN_FILE: &str = "reboot-wsl-drain";

/// How many distinct idle heartbeats, after the fence was taken, a guest must
/// send before it counts as drained: one could have been sampled while a
/// launch it had begun was not journaled yet.
const QUIET_HEARTBEATS: u8 = 2;

/// How long a guest may give no sign of this drain (no fence taken, no
/// acknowledging heartbeat) before the reboot fails rather than wait on a
/// guest that may be busy and cannot say so.
pub const GUEST_UNRESPONSIVE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// One managed distribution, and what it said since the drain began.
struct Guest {
    distribution: String,
    root: PathBuf,
    /// When the guest's launch fence was first seen held against launches
    /// (taken by this drain, or held by a WSL recovery): from then on no
    /// launch the guest had begun can slip through.
    fenced_at: Option<chrono::DateTime<chrono::Utc>>,
    last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    quiet: u8,
}

/// Where a reboot stands with the guests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestWait {
    /// Every guest holds no runner, or is not running at all.
    Drained,
    /// Still waiting, and why.
    Waiting(String),
    /// A guest gave no sign of the drain within [`GUEST_UNRESPONSIVE`]: the
    /// reboot fails rather than restart over a guest that may be busy.
    Unresponsive(String),
}

/// Whether a distribution is known to be stopped (it then runs nothing).
type StoppedProbe = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// The managed WSL distributions a reboot of this Windows machine waits for.
///
/// It does what the WSL recovery watchdog does before it touches a
/// distribution: a drain request in the shared directory (renewed, so the
/// watchdog never retires it as abandoned), the launch fence taken as a
/// Windows recovery of its own generation (so no launch the guest had begun
/// slips through), and several idle heartbeats after that. A distribution
/// WSL lists as stopped runs nothing and is not waited for.
pub struct GuestDrain {
    guests: Vec<Guest>,
    generation: u64,
    started: chrono::DateTime<chrono::Utc>,
    state_dir: PathBuf,
    /// The managed distributions could not be listed: the reboot does not
    /// guess that there are none.
    unreadable: Option<String>,
    stopped: StoppedProbe,
}

impl GuestDrain {
    /// This machine's managed distributions; none off Windows.
    #[must_use]
    pub fn of(paths: &AppPaths) -> Self {
        let (roots, unreadable) = if cfg!(windows) {
            match WslProviderRecord::all(paths) {
                Ok(records) => (guest_roots(paths, records), None),
                Err(error) => (Vec::new(), Some(error.to_string())),
            }
        } else {
            (Vec::new(), None)
        };
        let mut drain = Self::over(roots, paths.state_dir());
        drain.unreadable = unreadable;
        drain.stopped = Box::new(known_stopped);
        drain
    }

    /// Over the given distributions' shared directories, none known stopped.
    #[must_use]
    pub fn over(guests: Vec<(String, PathBuf)>, state_dir: &Path) -> Self {
        let started = chrono::Utc::now();
        Self {
            guests: guests
                .into_iter()
                .map(|(distribution, root)| Guest {
                    distribution,
                    root,
                    fenced_at: None,
                    last_heartbeat: None,
                    quiet: 0,
                })
                .collect(),
            generation: u64::try_from(started.timestamp_millis()).unwrap_or(1),
            started,
            state_dir: state_dir.to_path_buf(),
            unreadable: None,
            stopped: Box::new(|_| false),
        }
    }

    /// Why the managed distributions could not be listed, if they could not.
    #[must_use]
    pub fn unreadable(&self) -> Option<&str> {
        self.unreadable.as_deref()
    }

    /// Asks every guest to start no runner, or renews the request, and takes
    /// each guest's launch fence once the guest is not holding it.
    pub fn request(&mut self) {
        if self.guests.is_empty() {
            return;
        }
        let _ = std::fs::create_dir_all(&self.state_dir);
        let _ = std::fs::write(
            self.state_dir.join(GUEST_DRAIN_FILE),
            self.generation.to_string(),
        );
        for guest in &mut self.guests {
            let distribution = &guest.distribution;
            if let Err(error) =
                DrainRequest::new(self.generation, chrono::Utc::now()).write(&guest.root)
            {
                tracing::warn!(%distribution, %error, "a WSL guest could not be asked to drain for the reboot");
            }
            if guest.fenced_at.is_none() {
                match FenceClaim::try_claim(
                    &guest.root,
                    FenceOwnerKind::WindowsRecovery,
                    Some(self.generation),
                ) {
                    Ok(Some(claim)) => {
                        // Lifted by `release` (`clear_recovery` of this
                        // generation), or by the next start after the restart.
                        claim.make_durable();
                        guest.fenced_at = Some(chrono::Utc::now());
                    }
                    // A WSL recovery holds it: the guest starts nothing either
                    // (and a launch it begins after the recovery reads this
                    // drain's request). A guest's own claim is a launch in
                    // flight: taken at a later turn.
                    Ok(None) => {
                        if FenceClaim::owner(&guest.root)
                            .ok()
                            .flatten()
                            .is_some_and(|owner| owner.kind == FenceOwnerKind::WindowsRecovery)
                        {
                            guest.fenced_at = Some(chrono::Utc::now());
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%distribution, %error, "a WSL guest's launch fence could not be taken for the reboot");
                    }
                }
            }
        }
    }

    /// Where the reboot stands with the guests.
    pub fn waiting(&mut self) -> GuestWait {
        self.waiting_at(chrono::Utc::now())
    }

    fn waiting_at(&mut self, now: chrono::DateTime<chrono::Utc>) -> GuestWait {
        let generation = self.generation;
        let patience =
            chrono::Duration::from_std(GUEST_UNRESPONSIVE).unwrap_or(chrono::Duration::MAX);
        let mut waiting = None;
        for guest in &mut self.guests {
            let distribution = &guest.distribution;
            let heartbeat = GuestHeartbeat::read(&guest.root)
                .ok()
                .flatten()
                .filter(|heartbeat| heartbeat.acknowledged_generation == Some(generation));
            if let (Some(heartbeat), Some(fenced_at)) = (&heartbeat, guest.fenced_at)
                && heartbeat.observed_at > fenced_at
                && guest.last_heartbeat != Some(heartbeat.observed_at)
            {
                guest.last_heartbeat = Some(heartbeat.observed_at);
                guest.quiet = if heartbeat.local_active_attempts == Some(0) {
                    guest.quiet.saturating_add(1)
                } else {
                    0
                };
            }
            if guest.quiet >= QUIET_HEARTBEATS || (self.stopped)(distribution) {
                continue;
            }
            // A sign of life since the drain began: the fence, and a heartbeat
            // that read this drain's request, the latest within the patience.
            let answered = heartbeat.as_ref().map_or(self.started, |heartbeat| {
                heartbeat.observed_at.max(self.started)
            });
            if guest.fenced_at.is_none() && now - self.started > patience {
                return GuestWait::Unresponsive(format!(
                    "WSL {distribution} kept its launch fence for {} minutes (a runner start that \
                     never finished?); its runners cannot be vouched for.",
                    GUEST_UNRESPONSIVE.as_secs() / 60
                ));
            }
            if now - answered > patience {
                return GuestWait::Unresponsive(format!(
                    "WSL {distribution} has not answered for {} minutes and is not known to be \
                     stopped; its runners cannot be vouched for.",
                    GUEST_UNRESPONSIVE.as_secs() / 60
                ));
            }
            waiting.get_or_insert_with(|| match (guest.fenced_at, heartbeat.map(|h| h.local_active_attempts)) {
                (None, _) => format!("Waiting for WSL {distribution} to finish starting a runner."),
                (_, Some(Some(runners))) if runners > 0 => format!(
                    "Waiting for WSL {distribution}: {} still running.",
                    runners_text(runners)
                ),
                (_, Some(None)) => format!("Waiting for WSL {distribution}: it cannot read its runners."),
                (_, Some(Some(_))) => format!("Waiting for WSL {distribution} to confirm it is idle."),
                (_, None) => format!(
                    "Waiting for WSL {distribution} to confirm it takes no new job (its service \
                     has not answered yet)."
                ),
            });
        }
        waiting.map_or(GuestWait::Drained, GuestWait::Waiting)
    }

    /// The reboot did not happen: the guests take jobs again.
    pub fn release(&self) {
        let roots: Vec<_> = self
            .guests
            .iter()
            .map(|guest| (guest.distribution.clone(), guest.root.clone()))
            .collect();
        release(&roots, self.generation, &self.state_dir);
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
        let roots = WslProviderRecord::all(paths)
            .map(|records| guest_roots(paths, records))
            .unwrap_or_default();
        release(&roots, generation, paths.state_dir());
    }
}

/// Whether WSL lists `distribution` as stopped. Only the English word is
/// trusted (`--list` localises it), and anything else, an error included
/// (a LocalSystem service cannot list a user's distributions), is "not
/// known": the heartbeat decides then.
fn known_stopped(distribution: &str) -> bool {
    runner_manager_platform::wsl::WslHost::on_this_host("the reboot's WSL drain")
        .ok()
        .and_then(|host| {
            let table = host.invoker().list().ok()?;
            let entry = table.exactly(distribution).ok()?;
            Some(entry.state() == "Stopped")
        })
        .unwrap_or(false)
}

fn guest_roots(paths: &AppPaths, records: Vec<WslProviderRecord>) -> Vec<(String, PathBuf)> {
    records
        .into_iter()
        .filter_map(|record| {
            recovery_root(paths, &record.distribution)
                .ok()
                .map(|root| (record.distribution, root))
        })
        .collect()
}

/// Lifts the drain request and the fence of `generation`; a request or a
/// fence of any other generation (the recovery watchdog's) is left alone.
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
        assert!(control.begin_restart("Restarting.".into()));
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
    fn a_cancel_is_never_overwritten_and_wins_over_a_restart_not_begun() {
        let control = serving(StartMode::Boot);
        control.request().unwrap();
        control.cancel().unwrap();
        // A progress line the drain wrote late changes nothing.
        control.waiting(Some(1), None);
        assert_eq!(control.progress().unwrap().state, "cancelled");
        assert!(
            !control.begin_restart("Restarting.".into()),
            "a cancelled reboot never begins"
        );
        assert_eq!(control.progress().unwrap().state, "cancelled");
        // A pending state left behind is cleared by a cancel.
        control.request().unwrap();
        control.failed("x");
        control.back_to_pending();
        assert!(control.cancel().unwrap().contains("cancelled"));
        assert_eq!(control.progress().unwrap().state, "cancelled");
        // A service going away refuses rather than forgetting.
        control.unavailable("the service is stopping");
        assert!(!control.available());
        assert_eq!(control.request().unwrap_err(), "the service is stopping");
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

    fn heartbeat(
        root: &Path,
        at: chrono::DateTime<chrono::Utc>,
        generation: Option<u64>,
        active: u32,
    ) {
        GuestHeartbeat {
            schema_version: SCHEMA_VERSION,
            observed_at: at,
            acknowledged_generation: generation,
            local_active_attempts: Some(active),
            local_busy_attempts: Some(active),
            managed_targets: Vec::new(),
            unmanaged_runner_services: None,
        }
        .write(root)
        .unwrap();
    }

    #[test]
    fn a_guest_counts_as_drained_only_when_fenced_and_idle_twice_since() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Ubuntu");
        let state = dir.path().join("state");
        // The guest is starting a runner: it holds the launch fence.
        let guest_launch = FenceClaim::try_claim(&root, FenceOwnerKind::GuestLaunch, None)
            .unwrap()
            .unwrap();
        let mut drain = GuestDrain::over(vec![("Ubuntu".into(), root.clone())], &state);
        drain.request();
        let generation = drain.generation;
        assert_eq!(
            DrainRequest::read(&root).unwrap().unwrap().generation,
            generation
        );
        assert!(waiting_text(&mut drain).contains("starting a runner"));
        drop(guest_launch);
        drain.request();
        let owner = FenceClaim::owner(&root).unwrap().unwrap();
        assert_eq!(owner.kind, FenceOwnerKind::WindowsRecovery);
        assert_eq!(owner.generation, Some(generation));

        let after = |secs| chrono::Utc::now() + chrono::Duration::seconds(secs);
        // Idle, but not acknowledging this drain: not yet a promise.
        heartbeat(&root, after(1), None, 0);
        assert!(waiting_text(&mut drain).contains("has not answered"));
        heartbeat(&root, after(2), Some(generation), 1);
        assert!(waiting_text(&mut drain).contains("1 runner"));
        heartbeat(&root, after(3), Some(generation), 0);
        assert!(
            drain.waiting() != GuestWait::Drained,
            "one idle heartbeat is not enough"
        );
        assert!(
            drain.waiting() != GuestWait::Drained,
            "the same heartbeat counts once"
        );
        heartbeat(&root, after(4), Some(generation), 0);
        assert_eq!(drain.waiting(), GuestWait::Drained);

        // A reboot that did not happen lifts the guests' drain and fence.
        drain.release();
        assert_eq!(DrainRequest::read(&root).unwrap(), None);
        assert_eq!(FenceClaim::owner(&root).unwrap(), None);
        assert!(!state.join(GUEST_DRAIN_FILE).exists());
    }

    fn waiting_text(drain: &mut GuestDrain) -> String {
        match drain.waiting() {
            GuestWait::Waiting(text) => text,
            other => panic!("not waiting: {other:?}"),
        }
    }

    #[test]
    fn a_stopped_guest_is_not_waited_for_and_a_silent_one_fails_the_reboot() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let guests = vec![
            ("Stopped".into(), dir.path().join("Stopped")),
            ("Silent".into(), dir.path().join("Silent")),
        ];
        let mut drain = GuestDrain::over(guests, &state);
        drain.stopped = Box::new(|distribution| distribution == "Stopped");
        drain.request();
        // A WSL recovery already holds the silent guest's fence: it starts
        // nothing either, and counts as fenced.
        let root = dir.path().join("Silent");
        clear_recovery(&root, drain.generation).unwrap();
        FenceClaim::try_claim(&root, FenceOwnerKind::WindowsRecovery, Some(7))
            .unwrap()
            .unwrap()
            .make_durable();
        drain.guests[1].fenced_at = None;
        drain.request();
        assert!(drain.guests[1].fenced_at.is_some());
        let text = waiting_text(&mut drain);
        assert!(text.contains("WSL Silent"), "{text}");
        assert!(!text.contains("WSL Stopped"), "{text}");
        let later = drain.started
            + chrono::Duration::from_std(GUEST_UNRESPONSIVE).unwrap()
            + chrono::Duration::seconds(1);
        match drain.waiting_at(later) {
            GuestWait::Unresponsive(why) => assert!(why.contains("WSL Silent"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_guest_busy_for_hours_is_waited_for_while_it_answers() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Ubuntu");
        let mut drain =
            GuestDrain::over(vec![("Ubuntu".into(), root.clone())], &dir.path().join("s"));
        drain.request();
        let hours = drain.started + chrono::Duration::hours(3);
        heartbeat(&root, hours, Some(drain.generation), 1);
        assert!(matches!(drain.waiting_at(hours), GuestWait::Waiting(_)));
        // A guest whose fence stays held by its own launch is not vouched for.
        let stuck = dir.path().join("Stuck");
        let _launch = FenceClaim::try_claim(&stuck, FenceOwnerKind::GuestLaunch, None)
            .unwrap()
            .unwrap();
        let mut drain = GuestDrain::over(vec![("Stuck".into(), stuck)], &dir.path().join("s2"));
        drain.request();
        heartbeat(
            &drain.guests[0].root.clone(),
            hours,
            Some(drain.generation),
            0,
        );
        assert!(matches!(
            drain.waiting_at(hours),
            GuestWait::Unresponsive(_)
        ));
    }

    #[test]
    fn a_guest_drain_lifts_only_its_own_generation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Ubuntu");
        let state = dir.path().join("state");
        let mut drain = GuestDrain::over(vec![("Ubuntu".into(), root.clone())], &state);
        drain.request();
        assert!(state.join(GUEST_DRAIN_FILE).exists());
        let generation: u64 = std::fs::read_to_string(state.join(GUEST_DRAIN_FILE))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(generation, drain.generation);
        // The recovery watchdog's own request is not this drain's.
        DrainRequest::new(generation + 1, chrono::Utc::now())
            .write(&root)
            .unwrap();
        release(&[("Ubuntu".into(), root.clone())], generation, &state);
        assert!(DrainRequest::read(&root).unwrap().is_some());
        assert_eq!(
            FenceClaim::owner(&root).unwrap(),
            None,
            "its fence is lifted"
        );
    }

    #[test]
    fn a_hard_link_to_a_root_file_is_not_a_request_from_root() {
        assert!(written_by_root(true, 0, 1));
        assert!(!written_by_root(true, 0, 2), "a hard link");
        assert!(!written_by_root(false, 0, 1), "not a regular file");
        assert!(!written_by_root(true, 501, 1));
    }

    #[test]
    fn a_root_service_takes_a_reboot_only_from_root() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, "").unwrap();
        let meta = std::fs::symlink_metadata(&file).unwrap();
        assert!(
            asked_by_an_equal(&meta, false),
            "a user service takes its own account's"
        );
        #[cfg(unix)]
        assert_eq!(
            asked_by_an_equal(&meta, true),
            runner_manager_platform::host_fitness::is_elevated(),
            "a root service takes only a file root wrote"
        );
    }
}
