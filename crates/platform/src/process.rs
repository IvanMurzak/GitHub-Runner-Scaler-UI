// owner: d1-platform-core

//! Spawning, observing and terminating a child process; a process identity
//! that survives a restart; and the restrictive handoff that gets a JIT
//! configuration to a runner without it ever appearing in a process listing.
//!
//! # A PID is not an identity
//!
//! The agent records the runner processes it started in a durable journal and
//! reads that journal back after a restart (`03-control-flows.md`, flow 3.2).
//! If the record were a bare PID, then after a reboot — or after enough process
//! churn — the PID in the journal may belong to somebody else's process. Acting
//! on that record means either adopting a stranger as a runner or, worse,
//! terminating it. `e3`'s restart-recovery Definition of Done ("a journal
//! containing a live process adopts it without starting a duplicate") rests
//! entirely on telling those cases apart.
//!
//! So [`ProcessIdentity`] is a PID **plus a start token**: an opaque,
//! platform-defined string that changes when the process at that PID changes.
//! [`ProcessIdentity::recheck`] re-resolves the token and answers
//! [`Adoption::Live`], [`Adoption::Gone`], or [`Adoption::PidRecycled`] — three
//! answers, because collapsing the last two into "not live" is exactly the bug
//! this type exists to prevent.
//!
//! | | Start token | Resolution | Distinct across a reboot |
//! |---|---|---|---|
//! | Windows | `GetProcessTimes` creation `FILETIME` | 100 ns | yes, it is an absolute time |
//! | macOS | `proc_pidinfo(PROC_PIDTBSDINFO)` start `timeval` | 1 µs | yes, it is an absolute time |
//! | Linux | boot id + `/proc/<pid>/stat` field 22 | one clock tick, typically 10 ms | yes, the boot id changes every boot |
//!
//! The Linux token pairs the boot identifier with the raw tick count rather
//! than converting ticks to a wall-clock time. Field 22 counts ticks *since
//! boot*, so on its own it repeats after every reboot; and dividing by
//! `sysconf(_SC_CLK_TCK)` and adding `btime` would produce an absolute time
//! whose precision is bounded by `btime`'s whole seconds — coarser than the
//! ticks it was derived from, and coarser than a PID-recycling discriminator
//! wants. Prefixing the tick count with `/proc/sys/kernel/random/boot_id`
//! keeps the full tick resolution *and* makes the token unrepeatable across a
//! reboot. See [`Adoption`] for what that buys.
//!
//! # The JIT configuration never becomes an argument
//!
//! `07-security.md`'s threat table: *"A process listing reveals a JIT config"*,
//! controlled by *"Do not pass JIT data as a command-line argument; use
//! restrictive file/pipe handoff"*. [`RestrictiveHandoff`] is that file, and
//! [`SpawnSpec::spawn_with_handoff`] refuses to spawn when the payload appears
//! in any argument or environment value, so an obvious mistake fails the launch
//! instead of failing a review. [`SpawnSpec::spawn_runner_with_handoff`] is the
//! one narrow exception: GitHub Runner's supported JIT intake is the secret
//! `ACTIONS_RUNNER_INPUT_JITCONFIG` environment input. The value is injected
//! only while creating the child, is never retained in the public spawn spec,
//! and Runner masks and removes it as its command parser starts.
//!
//! **It is a tripwire, not a proof.** A caller that passes it has not been
//! shown to be safe. The check looks for the payload as a verbatim substring of
//! each argument's and each environment *value's* `to_string_lossy()`, and that
//! is all it looks for. It does not inspect the program path, the working
//! directory, or environment variable *names*; and anything that re-encodes the
//! payload — base64 of the base64, URL-escaping, a different Unicode
//! normalisation — or splits it across two arguments walks straight past it.
//! The control that actually holds is either *"pass the handoff file's path"*
//! to a program that supports one or use the dedicated Runner intake above;
//! `e3` must not read a passing generic check as evidence that a configuration
//! cannot reach a process listing.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// GitHub Runner's supported process-safe JIT configuration input.
///
/// `actions/runner` v2.336.0 reads every `ACTIONS_RUNNER_INPUT_*` variable in
/// `CommandSettings`, registers secret inputs with its masker, and removes the
/// variable from its environment before `Runner.ExecuteCommand` decodes it.
const RUNNER_JIT_CONFIG_ENV: &str = "ACTIONS_RUNNER_INPUT_JITCONFIG";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Something went wrong spawning, observing, or identifying a process.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// The program could not be launched.
    #[error("cannot start {}: {source}", program.display())]
    Spawn {
        /// The program that could not be launched.
        program: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The operating system would not say when a process started.
    #[error("cannot read the start time of process {pid}: {source}")]
    Identity {
        /// The process that could not be identified.
        pid: u32,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// No live process holds this PID, so it has no identity to record.
    #[error("no live process holds PID {pid}")]
    NoSuchProcess {
        /// The PID that resolved to nothing.
        pid: u32,
    },

    /// Waiting on, signalling, or killing a process failed.
    #[error("cannot control process {pid}: {source}")]
    Control {
        /// The process that could not be controlled.
        pid: u32,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The handoff payload was about to be visible in a process listing.
    ///
    /// Returned by [`SpawnSpec::spawn_with_handoff`] rather than logged,
    /// because the whole point is that the launch must not happen.
    #[error(
        "refusing to start {}: the handoff payload appears in {location}, which would put \
         it in this machine's process listing. Pass the handoff file's path instead \
         (`07-security.md`, threat table).",
        program.display()
    )]
    SecretInCommandLine {
        /// The program that would have been launched.
        program: PathBuf,
        /// Where the payload was found — an argument index or an environment
        /// variable name.
        location: String,
    },
}

// ---------------------------------------------------------------------------
// Process identity
// ---------------------------------------------------------------------------

/// A PID paired with a token that changes when the process at that PID does.
///
/// Serializable because its whole reason to exist is being written to the
/// attempt journal and read back after a restart. The token is opaque: its
/// shape is documented at the module level for diagnostics, but nothing should
/// parse it. Comparison — not interpretation — is the operation it supports.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pid: u32,
    start_token: String,
}

/// What a recorded [`ProcessIdentity`] turns out to refer to now.
///
/// # One journal entry can answer differently on different platforms
///
/// For a PID now held by **another account's** process, Linux answers
/// [`Adoption::PidRecycled`] while macOS and Windows answer
/// [`ProcessError::Identity`]: `/proc/<pid>/stat` is world-readable, whereas
/// `proc_pidinfo` and `OpenProcess` refuse an inspection this account is not
/// entitled to. So the same journal entry, read back after the agent's service
/// account has been changed, is a recycled PID on one platform and an error on
/// the other two. `e3` branches on this, and should treat the error as the same
/// *decision* as `PidRecycled` — do not adopt, do not terminate — rather than
/// as a platform bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adoption {
    /// The same process is still running. Adopt it; do not start a replacement.
    Live,

    /// Nothing holds the PID. The process is gone and its attempt is terminal.
    Gone,

    /// Something holds the PID, but it is not the recorded process.
    ///
    /// Distinct from [`Adoption::Gone`] on purpose. The recorded process is
    /// equally gone in both cases, but here there is a stranger at that PID,
    /// and treating this as `Gone` is one refactor away from treating it as
    /// `Live` — which is how an agent terminates somebody else's process.
    PidRecycled {
        /// Whoever holds the PID now.
        current: ProcessIdentity,
    },
}

impl Adoption {
    /// Whether the recorded process is still running.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }
}

/// The outcome of asking a recorded process to stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Termination {
    /// The process was signalled and is no longer running.
    Terminated,
    /// It had already exited; nothing to do.
    AlreadyGone,
    /// The PID belongs to a different process now, so nothing was signalled.
    ///
    /// The refusal is the feature. See [`Adoption::PidRecycled`].
    RefusedPidRecycled {
        /// Whoever holds the PID now.
        current: ProcessIdentity,
    },
}

impl ProcessIdentity {
    /// Reads the identity of a live process.
    ///
    /// # Errors
    ///
    /// [`ProcessError::NoSuchProcess`] when nothing holds the PID, and
    /// [`ProcessError::Identity`] when the operating system refuses to answer —
    /// a process owned by another account, for instance. The two are separate
    /// because "gone" is a normal lifecycle answer and "refused" is a
    /// misconfiguration.
    pub fn resolve(pid: u32) -> Result<Self, ProcessError> {
        Self::read(pid, LivenessFilter::LiveOnly)
    }

    /// Reads the identity of a process this program has just spawned and still
    /// holds the handle to.
    ///
    /// Separate from [`ProcessIdentity::resolve`] because of a race that would
    /// otherwise make short-lived children unlaunchable: a program that exits
    /// before its parent gets round to identifying it is *already* not live by
    /// the time the identity is read, and `resolve` would answer
    /// [`ProcessError::NoSuchProcess`]. Reading an exited child's start time is
    /// safe in a way that reading an arbitrary exited PID's is not — the parent
    /// holds the child handle, so the PID cannot have been reused underneath
    /// it.
    fn of_child(pid: u32) -> Result<Self, ProcessError> {
        Self::read(pid, LivenessFilter::IncludeExited)
    }

    fn read(pid: u32, filter: LivenessFilter) -> Result<Self, ProcessError> {
        match sys::start_token(pid, filter) {
            Ok(Some(start_token)) => Ok(Self { pid, start_token }),
            Ok(None) => Err(ProcessError::NoSuchProcess { pid }),
            Err(source) => Err(ProcessError::Identity { pid, source }),
        }
    }

    /// The identity of the calling process.
    ///
    /// # Errors
    ///
    /// As [`ProcessIdentity::resolve`], though a process can always see itself
    /// in practice.
    pub fn of_current_process() -> Result<Self, ProcessError> {
        Self::resolve(std::process::id())
    }

    /// The PID. Recorded in `RunnerAttempt::process_id` and shown in the UI;
    /// never used on its own to decide whether a process is ours.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// The opaque start token. Exposed for diagnostics only.
    #[must_use]
    pub fn start_token(&self) -> &str {
        &self.start_token
    }

    /// Re-resolves this identity against the machine as it is now.
    ///
    /// # Errors
    ///
    /// [`ProcessError::Identity`] when the operating system refuses to answer.
    /// A PID that resolves to nothing is [`Adoption::Gone`], not an error.
    pub fn recheck(&self) -> Result<Adoption, ProcessError> {
        match sys::start_token(self.pid, LivenessFilter::LiveOnly) {
            Ok(observed) => Ok(self.classify(observed)),
            Err(source) => Err(ProcessError::Identity {
                pid: self.pid,
                source,
            }),
        }
    }

    /// The adoption decision itself, with the operating system already
    /// consulted.
    ///
    /// Split out of [`ProcessIdentity::recheck`] so that all three answers can
    /// be exercised without spawning anything. One of them cannot be reached
    /// through a spawn on demand: two processes carrying an *identical* start
    /// token. On Windows (100 ns) and macOS (1 µs) that is unreachable, and on
    /// Linux it happens only by landing inside the same 10 ms clock tick, which
    /// is a race a test cannot ask for. Comparing tokens here rather than
    /// inline means the discriminator can be shown to behave correctly on that
    /// input from every leg of the CI matrix.
    fn classify(&self, observed: Option<String>) -> Adoption {
        match observed {
            None => Adoption::Gone,
            Some(token) if token == self.start_token => Adoption::Live,
            Some(token) => Adoption::PidRecycled {
                current: Self {
                    pid: self.pid,
                    start_token: token,
                },
            },
        }
    }

    /// Stops the process this identity names, and nothing else.
    ///
    /// Re-checks the identity immediately before signalling. That check is the
    /// difference between "terminate the runner recorded in the journal" and
    /// "terminate whatever now holds PID 4312", and it is why the recycled case
    /// returns [`Termination::RefusedPidRecycled`] rather than proceeding.
    ///
    /// `grace` applies only where the platform has a polite stop to offer: on
    /// Unix the process is sent `SIGTERM`, given `grace` to exit, and then
    /// `SIGKILL`ed. Windows has no console-independent equivalent, so the
    /// process is terminated immediately and `grace` is ignored — stated here
    /// rather than emulated, because a fake grace period that never actually
    /// asks politely is worse than no grace period.
    ///
    /// # Errors
    ///
    /// [`ProcessError::Control`] when signalling fails for a reason other than
    /// the process having already exited.
    pub fn terminate(&self, grace: Duration) -> Result<Termination, ProcessError> {
        match self.recheck()? {
            Adoption::Gone => return Ok(Termination::AlreadyGone),
            Adoption::PidRecycled { current } => {
                return Ok(Termination::RefusedPidRecycled { current });
            }
            Adoption::Live => {}
        }

        let requested = sys::request_stop(self.pid).map_err(|source| ProcessError::Control {
            pid: self.pid,
            source,
        })?;

        if requested {
            let deadline = Instant::now() + grace;
            while Instant::now() < deadline {
                if matches!(
                    self.recheck()?,
                    Adoption::Gone | Adoption::PidRecycled { .. }
                ) {
                    return Ok(Termination::Terminated);
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }

        // Either the platform has no polite stop, or the grace period expired.
        // Re-check once more so a process that exited during the wait is not
        // reported as force-killed, and so a PID recycled during the wait is
        // not force-killed at all.
        match self.recheck()? {
            Adoption::Gone => Ok(Termination::AlreadyGone),
            Adoption::PidRecycled { current } => Ok(Termination::RefusedPidRecycled { current }),
            Adoption::Live => {
                sys::force_stop(self.pid).map_err(|source| ProcessError::Control {
                    pid: self.pid,
                    source,
                })?;
                Ok(Termination::Terminated)
            }
        }
    }
}

impl fmt::Display for ProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pid {} started {}", self.pid, self.start_token)
    }
}

/// How often a wait loop re-checks. Short enough that a terminating runner is
/// noticed promptly, long enough that a grace period is not a spin.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Whether a start-time lookup should answer for a process that has already
/// exited but whose PID is not yet free.
///
/// Both states exist on both families: a Unix child that has exited and not
/// been reaped is a zombie holding its PID, and a Windows process whose handle
/// is still open leaves a process object behind with a non-zero exit time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LivenessFilter {
    /// Answer only for a process that is still running. What recovery and
    /// adoption need: an exited process is not something to adopt.
    LiveOnly,
    /// Answer for an exited process too. Only ever used by the parent of that
    /// process, which holds its handle and therefore knows the PID is not
    /// somebody else's.
    IncludeExited,
}

// ---------------------------------------------------------------------------
// Spawning
// ---------------------------------------------------------------------------

/// What to do with a child's standard output and standard error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMode {
    /// Send both to the null device. The default: a runner writes its own
    /// diagnostics into its workspace, and inheriting its output would splice
    /// unredacted text into this process's stream.
    #[default]
    Discard,
    /// Inherit this process's handles.
    Inherit,
    /// Capture both, readable through [`ChildProcess::take_stdout`].
    Capture,
}

/// A child process about to be launched.
///
/// A builder rather than a bare [`Command`] so that the arguments and the
/// environment can be inspected before the launch — which is what
/// [`SpawnSpec::spawn_with_handoff`] does.
#[derive(Debug, Clone)]
pub struct SpawnSpec {
    program: PathBuf,
    args: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
    working_dir: Option<PathBuf>,
    output: OutputMode,
}

impl SpawnSpec {
    /// Starts a specification for `program`.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
            working_dir: None,
            output: OutputMode::Discard,
        }
    }

    /// Appends one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Appends several arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    /// Sets one environment variable for the child, on top of the inherited
    /// environment.
    #[must_use]
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.envs
            .push((key.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    /// Sets the child's working directory.
    #[must_use]
    pub fn working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Chooses what happens to the child's output.
    #[must_use]
    pub fn output(mut self, output: OutputMode) -> Self {
        self.output = output;
        self
    }

    /// The arguments as configured. Exposed so a security test can assert what
    /// a process listing would show.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.args
    }

    /// Launches the child.
    ///
    /// # Errors
    ///
    /// [`ProcessError::Spawn`] when the program cannot be launched, and
    /// [`ProcessError::Identity`] when it launches but its start time cannot be
    /// read — which would leave an unrecordable process running, so the child
    /// is killed rather than leaked.
    pub fn spawn(&self) -> Result<ChildProcess, ProcessError> {
        self.spawn_with_extra_env(None)
    }

    fn spawn_with_extra_env(
        &self,
        extra_env: Option<(&OsStr, &OsStr)>,
    ) -> Result<ChildProcess, ProcessError> {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        for (key, value) in &self.envs {
            command.env(key, value);
        }
        if let Some((key, value)) = extra_env {
            command.env(key, value);
        }
        if let Some(dir) = &self.working_dir {
            command.current_dir(dir);
        }
        // Never inherited: a runner that reads this process's stdin would block
        // the agent, and nothing in this design feeds a child interactively.
        command.stdin(Stdio::null());
        let (stdout, stderr) = match self.output {
            OutputMode::Discard => (Stdio::null(), Stdio::null()),
            OutputMode::Inherit => (Stdio::inherit(), Stdio::inherit()),
            OutputMode::Capture => (Stdio::piped(), Stdio::piped()),
        };
        command.stdout(stdout).stderr(stderr);

        let child = command.spawn().map_err(|source| ProcessError::Spawn {
            program: self.program.clone(),
            source,
        })?;

        let pid = child.id();
        match ProcessIdentity::of_child(pid) {
            Ok(identity) => Ok(ChildProcess {
                child,
                identity,
                program: self.program.clone(),
            }),
            Err(error) => {
                // An unidentifiable child cannot be journalled, so it cannot be
                // recovered after a restart. Leaving it running would create
                // exactly the orphan the journal exists to prevent.
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
    }

    /// Launches the child after proving the handoff payload is not in the
    /// command line or the environment.
    ///
    /// This is the enforcement point for `07-security.md`'s control on *"A
    /// process listing reveals a JIT config"*. `e3` should reach for this and
    /// not for [`SpawnSpec::spawn`], because a rule that is checked is a rule,
    /// and a rule that is written down is a hope.
    ///
    /// # Errors
    ///
    /// [`ProcessError::SecretInCommandLine`] when the payload appears in an
    /// argument or an environment value, plus everything
    /// [`SpawnSpec::spawn`] returns.
    pub fn spawn_with_handoff(
        &self,
        handoff: &RestrictiveHandoff,
    ) -> Result<ChildProcess, ProcessError> {
        self.reject_exposed_handoff(handoff)?;
        self.spawn()
    }

    /// Launches GitHub Runner using its supported process-safe JIT input.
    ///
    /// The encoded configuration is deliberately absent from [`SpawnSpec`]:
    /// callers cannot render it as an argument or accidentally retain it in a
    /// reusable specification. It is copied from the restrictive handoff into
    /// the child's initial environment at the final `Command::spawn` boundary.
    /// GitHub Runner's `CommandSettings` treats `jitconfig` as a secret and
    /// removes `ACTIONS_RUNNER_INPUT_JITCONFIG` from the process environment
    /// before executing the `run` command.
    ///
    /// The caller still owns deleting `handoff` immediately after this method
    /// returns. A failed launch leaves deletion to [`RestrictiveHandoff`]'s
    /// fail-closed `Drop` implementation.
    ///
    /// # Errors
    ///
    /// [`ProcessError::SecretInCommandLine`] when the payload was also placed
    /// in an argument or explicitly configured environment value, plus every
    /// error returned by [`SpawnSpec::spawn`].
    pub fn spawn_runner_with_handoff(
        &self,
        handoff: &RestrictiveHandoff,
    ) -> Result<ChildProcess, ProcessError> {
        self.reject_exposed_handoff(handoff)?;
        self.spawn_with_extra_env(Some((
            OsStr::new(RUNNER_JIT_CONFIG_ENV),
            OsStr::new(handoff.payload.expose_secret()),
        )))
    }

    fn reject_exposed_handoff(&self, handoff: &RestrictiveHandoff) -> Result<(), ProcessError> {
        let payload = handoff.payload.expose_secret();
        // An empty payload cannot meaningfully be searched for — every string
        // contains it — and it is not a secret worth protecting either.
        if !payload.is_empty() {
            for (index, arg) in self.args.iter().enumerate() {
                if os_str_contains(arg, payload) {
                    return Err(ProcessError::SecretInCommandLine {
                        program: self.program.clone(),
                        location: format!("argument {index}"),
                    });
                }
            }
            for (key, value) in &self.envs {
                if os_str_contains(value, payload) {
                    return Err(ProcessError::SecretInCommandLine {
                        program: self.program.clone(),
                        location: format!("environment variable {}", key.to_string_lossy()),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Whether `haystack` contains `needle`, for an [`OsStr`] that may not be valid
/// Unicode.
///
/// `to_string_lossy` is enough here: the payload is a base64 JIT configuration,
/// so it is ASCII, and lossy conversion replaces only the bytes that could not
/// have matched it anyway.
fn os_str_contains(haystack: &OsStr, needle: &str) -> bool {
    haystack.to_string_lossy().contains(needle)
}

/// A child process this agent started.
///
/// `04-subsystem-contracts.md`: *"local process state is authoritative only for
/// a child process owned by this agent"*. That is this type. For a process
/// recovered from the journal after a restart there is no [`Child`] and no
/// parent relationship, so [`ProcessIdentity`] is the authority instead.
#[derive(Debug)]
pub struct ChildProcess {
    child: Child,
    identity: ProcessIdentity,
    program: PathBuf,
}

impl ChildProcess {
    /// The identity to record in the journal.
    #[must_use]
    pub const fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// The child's PID.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.identity.pid
    }

    /// Whether the child is still running.
    ///
    /// # Errors
    ///
    /// [`ProcessError::Control`] when the wait fails.
    pub fn is_running(&mut self) -> Result<bool, ProcessError> {
        Ok(self.try_exit_status()?.is_none())
    }

    /// The child's exit status if it has already exited, reaping it if so.
    ///
    /// # Errors
    ///
    /// [`ProcessError::Control`] when the wait fails.
    pub fn try_exit_status(&mut self) -> Result<Option<ExitStatus>, ProcessError> {
        self.child
            .try_wait()
            .map_err(|source| ProcessError::Control {
                pid: self.identity.pid,
                source,
            })
    }

    /// Blocks until the child exits.
    ///
    /// # Errors
    ///
    /// [`ProcessError::Control`] when the wait fails.
    pub fn wait(&mut self) -> Result<ExitStatus, ProcessError> {
        self.child.wait().map_err(|source| ProcessError::Control {
            pid: self.identity.pid,
            source,
        })
    }

    /// Waits up to `timeout` for the child to exit; `None` means it is still
    /// running when the timeout expires.
    ///
    /// # Errors
    ///
    /// [`ProcessError::Control`] when the wait fails.
    pub fn wait_for(&mut self, timeout: Duration) -> Result<Option<ExitStatus>, ProcessError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_exit_status()? {
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Asks the child to stop, forcefully if `grace` expires first.
    ///
    /// See [`ProcessIdentity::terminate`] for what `grace` means on each
    /// platform. Unlike that method this one has the parent relationship, so it
    /// reaps the child and returns its exit status.
    ///
    /// # Errors
    ///
    /// [`ProcessError::Control`] when signalling or waiting fails.
    pub fn stop(&mut self, grace: Duration) -> Result<ExitStatus, ProcessError> {
        if let Some(status) = self.try_exit_status()? {
            return Ok(status);
        }

        let pid = self.identity.pid;
        // Safe to signal by PID: this process holds the child handle, so the
        // PID cannot have been recycled behind our back.
        let requested =
            sys::request_stop(pid).map_err(|source| ProcessError::Control { pid, source })?;

        if requested && let Some(status) = self.wait_for(grace)? {
            return Ok(status);
        }

        self.child
            .kill()
            .map_err(|source| ProcessError::Control { pid, source })?;
        self.wait()
    }

    /// Takes the captured standard output, if [`OutputMode::Capture`] was set.
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Takes the captured standard error, if [`OutputMode::Capture`] was set.
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.stderr.take()
    }

    /// The program that was launched.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }
}

// ---------------------------------------------------------------------------
// Restrictive handoff
// ---------------------------------------------------------------------------

/// Something went wrong creating, inspecting, or removing a handoff file.
#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    /// The file could not be created with restrictive permissions.
    #[error("cannot create a restrictive handoff file in {}: {source}", directory.display())]
    Create {
        /// The directory the file was to be created in.
        directory: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The payload could not be written.
    #[error("cannot write the handoff payload to {}: {source}", path.display())]
    Write {
        /// The file that could not be written.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The file's permissions could not be read back.
    #[error("cannot read the permissions of {}: {source}", path.display())]
    Inspect {
        /// The file that could not be inspected.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The file could not be removed.
    ///
    /// Worth an error rather than a shrug: a JIT configuration left on disk is
    /// the exact thing `05-infrastructure.md` says must be deleted immediately.
    #[error("cannot delete the handoff file {}: {source}", path.display())]
    Delete {
        /// The file that could not be removed.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// What a file's permissions amount to, in terms this product cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsSummary {
    /// Platform-native description — a Unix mode, or a Windows DACL in SDDL
    /// form. For diagnostics and for test failure messages.
    pub description: String,
    /// Whether an ordinary local user other than the file's owner could read
    /// it.
    ///
    /// A local administrator or `root` is deliberately outside this question:
    /// `07-security.md` records that such an account is already assumed able to
    /// read the runner's credentials and job workspaces, so pretending a file
    /// mode could exclude it would be theatre.
    pub readable_by_other_local_users: bool,
}

/// Reads back what a file's permissions actually grant.
///
/// # Errors
///
/// [`HandoffError::Inspect`] when the permissions cannot be read.
pub fn permissions_summary(path: &Path) -> Result<PermissionsSummary, HandoffError> {
    sys::describe_permissions(path)
        .map(
            |(description, readable_by_other_local_users)| PermissionsSummary {
                description,
                readable_by_other_local_users,
            },
        )
        .map_err(|source| HandoffError::Inspect {
            path: path.to_path_buf(),
            source,
        })
}

/// A short-lived file holding a secret, readable only by this account, deleted
/// on every path out.
///
/// `05-infrastructure.md` puts the encoded JIT configuration in a *"restrictive
/// temporary file or process-safe handoff"* and requires *"Delete immediately
/// after runner start or failed start"*. Both halves of that sentence are
/// implemented here: [`RestrictiveHandoff::create`] makes the file
/// unreadable by other local users at the moment of creation, and [`Drop`]
/// deletes it whether the launch succeeded, failed, or panicked.
///
/// # Why creation, not creation-then-chmod
///
/// On Windows the file is created through `CreateFileW` with an explicit
/// `SECURITY_ATTRIBUTES`, and on Unix through `open(2)` with mode `0600`. In
/// both cases the restriction is applied *by the call that creates the file*.
/// Creating a file and then tightening it leaves a window — however short — in
/// which the JIT configuration exists on disk under whatever the parent
/// directory happened to grant, and a window is all a local attacker needs.
///
/// # What is not claimed
///
/// The file is deleted, not securely erased. No modern filesystem lets a
/// userspace program guarantee that the bytes are unrecoverable — a journal, a
/// copy-on-write snapshot, or an SSD's wear levelling can each keep a copy that
/// an overwrite never reaches. Claiming otherwise would be worse than saying
/// so plainly, so the control this design relies on is the file's short life
/// and its access control, not erasure.
#[derive(Debug)]
pub struct RestrictiveHandoff {
    path: PathBuf,
    payload: SecretString,
    deleted: bool,
}

impl RestrictiveHandoff {
    /// Writes `payload` to a new uniquely named file in `directory`.
    ///
    /// The name is a UUID rather than a predictable one, so that another local
    /// account cannot pre-create the path and win the race for it; creation is
    /// exclusive, so if it did, this fails rather than writing into the
    /// squatter's file.
    ///
    /// # Errors
    ///
    /// [`HandoffError::Create`] and [`HandoffError::Write`].
    pub fn create(directory: &Path, payload: SecretString) -> Result<Self, HandoffError> {
        use std::io::Write as _;

        let path = directory.join(format!("jit-{}.tmp", uuid::Uuid::new_v4()));

        let mut file =
            sys::create_restrictive_file(&path).map_err(|source| HandoffError::Create {
                directory: directory.to_path_buf(),
                source,
            })?;

        let handoff = Self {
            path,
            payload,
            deleted: false,
        };

        // From here on the file exists, so every failure path must delete it.
        // `handoff` is already constructed, so `?` unwinds through its `Drop`.
        let write = file
            .write_all(handoff.payload.expose_secret().as_bytes())
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all());
        write.map_err(|source| HandoffError::Write {
            path: handoff.path.clone(),
            source,
        })?;
        drop(file);

        Ok(handoff)
    }

    /// The path to hand to the child process.
    ///
    /// This is the only thing that may reach a command line. The payload is not
    /// exposed at all: it is held as a [`SecretString`], which has no `Display`
    /// and a redacting `Debug`, so it cannot be formatted into an argument by
    /// accident.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What the file's permissions actually grant.
    ///
    /// # Errors
    ///
    /// [`HandoffError::Inspect`].
    pub fn permissions(&self) -> Result<PermissionsSummary, HandoffError> {
        permissions_summary(&self.path)
    }

    /// Deletes the file now, reporting failure.
    ///
    /// The success path should call this rather than relying on [`Drop`], for
    /// one reason: `Drop` cannot report an error, and a JIT configuration that
    /// could not be deleted is something an operator must be told about.
    ///
    /// # Errors
    ///
    /// [`HandoffError::Delete`].
    pub fn delete(mut self) -> Result<(), HandoffError> {
        self.delete_in_place()
    }

    fn delete_in_place(&mut self) -> Result<(), HandoffError> {
        if self.deleted {
            return Ok(());
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => {
                self.deleted = true;
                Ok(())
            }
            // Already gone is the desired end state, not a failure.
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                self.deleted = true;
                Ok(())
            }
            Err(source) => Err(HandoffError::Delete {
                path: self.path.clone(),
                source,
            }),
        }
    }
}

impl Drop for RestrictiveHandoff {
    fn drop(&mut self) {
        if let Err(error) = self.delete_in_place() {
            // The path is logged at `error` because an undeleted JIT
            // configuration is an operator-actionable condition, and the path
            // is the only actionable part. It is redacted by the log sink like
            // every other path (`crate::logging`).
            tracing::error!(
                event = "handoff_delete_failed",
                path = %self.path.display(),
                error = %error,
                "a JIT handoff file could not be deleted and is still on disk"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The Linux `/proc/<pid>/stat` parser
// ---------------------------------------------------------------------------

/// The two fields of `/proc/<pid>/stat` this crate reads.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "parsed on Linux; unit tested on every platform")
)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcStat<'a> {
    /// Field 3: a single character, `R`, `S`, `D`, `Z`, `T`, and so on.
    state: &'a str,
    /// Field 22: the process's start time, in clock ticks since boot.
    start_ticks: &'a str,
}

/// Parses the fields after the `comm` field of a `/proc/<pid>/stat` line.
///
/// Lives here, outside the `#[cfg(unix)]` module, for one reason: it is the
/// riskiest few lines in this crate and the only ones whose correctness is
/// pure string handling. Keeping it platform-independent means it is unit
/// tested on the Windows and macOS legs of CI as well as the Linux one, and by
/// a developer on any machine — rather than being exercised for the first time
/// on the leg where a mistake is a wrong process identity.
///
/// The hazard it exists to handle: **field 2 is the executable name, in
/// parentheses, and it may itself contain spaces and parentheses.** A process
/// really can be called `my prog (v2)`, and `procfs(5)` says so. Splitting the
/// whole line on whitespace therefore mis-indexes every later field, and does
/// so only for the one process whose name happens to be adversarial — which is
/// to say, only when someone is being adversarial. The *last* `)` on the line
/// is the reliable anchor, because every field after `comm` is numeric.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "parsed on Linux; unit tested on every platform")
)]
fn parse_proc_stat(stat: &str) -> Option<ProcStat<'_>> {
    // Everything after the last `)` is field 3 onwards, all of it numeric and
    // whitespace separated.
    let after_comm = &stat[stat.rfind(')')? + 1..];
    let mut fields = after_comm.split_whitespace();

    // `next()` yields field 3; the iterator then stands at field 4, so
    // `nth(k)` yields field `4 + k`.
    let state = fields.next()?;
    let start_ticks = fields.nth(22 - 4)?;

    Some(ProcStat { state, start_ticks })
}

/// Whether a failed start-time probe means the process is *gone*, as opposed to
/// unreadable for some other reason.
///
/// `no_such_process` is the platform's `ESRCH`, passed in rather than read from
/// `libc` here for the same reason [`parse_proc_stat`] lives outside the
/// `#[cfg(unix)]` module: this is a security-relevant decision that is
/// otherwise only compiled on two of the three CI legs and testable on neither
/// a Windows developer's machine nor the Windows leg. As a plain function over
/// an `Option<i32>` it is exercised everywhere.
///
/// **Only `ESRCH` is "gone".** Every other answer — `EPERM` for a process this
/// account may not inspect, or a zero `errno` from a call that failed without
/// setting one — is an error. This is the same rule the Windows leg applies to
/// `ERROR_ACCESS_DENIED`, and for the same reason: an unexplained failure is
/// not evidence of absence, and reporting [`Adoption::Gone`] for one is how an
/// agent decides to start a duplicate runner.
///
/// # Compiled where it is used, rather than allowed where it is not
///
/// This carried `#[cfg_attr(not(target_os = "macos"), allow(dead_code, …))]`,
/// and now carries a `cfg` that names macOS plus `test`. The difference is not
/// tidiness. An allowance leaves the lint's premise true and silences the
/// report; the condition it carries is a claim about every platform it does
/// *not* name, and getting that claim wrong is invisible until the one CI leg
/// that disagrees runs. That is precisely how N1 reached the Linux leg. A
/// `cfg` makes the premise false instead: on a platform that does not call
/// this, the item is not there to be dead, and there is nothing left to allow.
///
/// `test` is in the condition because the unit tests below are the reason this
/// function is a plain function over `Option<i32>` at all -- they are what
/// exercise it on the Windows and Linux legs, where the macOS caller does not
/// exist.
#[cfg(any(target_os = "macos", test))]
const fn probe_failure_means_gone(errno: Option<i32>, no_such_process: i32) -> bool {
    matches!(errno, Some(code) if code == no_such_process)
}

// ---------------------------------------------------------------------------
// Platform implementations
// ---------------------------------------------------------------------------
//
// Each `sys` module offers the same five functions, and the shared code above
// is the only caller:
//
//   start_token(pid, filter)    -> Ok(None) when nothing matching holds the PID
//   request_stop(pid)           -> Ok(false) when the platform has no polite stop
//   force_stop(pid)             -> terminate immediately
//   create_restrictive_file(p)  -> a new file only this account can read
//   describe_permissions(p)     -> (native description, readable by others?)

#[cfg(windows)]
mod sys {
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;

    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_SUCCESS, FILETIME, HANDLE,
        HLOCAL, LocalFree,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_NONE,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
    };
    use windows::core::{PCWSTR, PWSTR};

    /// `HRESULT_FROM_WIN32`, which windows-rs does not re-export as a function.
    const fn hresult_from_win32(code: u32) -> i32 {
        if code == 0 {
            0
        } else {
            ((code & 0x0000_ffff) | 0x8007_0000) as i32
        }
    }

    fn to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn filetime_to_u64(time: FILETIME) -> u64 {
        (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
    }

    fn io_error(error: &windows::core::Error) -> io::Error {
        io::Error::from_raw_os_error(error.code().0)
    }

    pub(super) fn start_token(
        pid: u32,
        filter: super::LivenessFilter,
    ) -> io::Result<Option<String>> {
        let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            Ok(handle) => handle,
            Err(error) => {
                // `OpenProcess` answers a PID nobody holds with
                // ERROR_INVALID_PARAMETER, not with a "no such process" code.
                // Access denied stays an error: a process this agent may not
                // query is not the same as one that is gone, and treating it as
                // gone is how an agent decides to start a duplicate.
                let code = error.code().0;
                if code == hresult_from_win32(ERROR_INVALID_PARAMETER.0) {
                    return Ok(None);
                }
                if code == hresult_from_win32(ERROR_ACCESS_DENIED.0) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("PID {pid} belongs to a process this account may not query"),
                    ));
                }
                return Err(io_error(&error));
            }
        };

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let times =
            unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
        unsafe {
            let _ = CloseHandle(handle);
        }
        times.map_err(|error| io_error(&error))?;

        // A non-zero exit time means the process object outlives the process
        // itself because somebody still holds a handle to it — which this
        // process does, for every child it spawned. Without this check a killed
        // child would keep reporting `Live` until it was reaped.
        if filetime_to_u64(exit) != 0 && filter == super::LivenessFilter::LiveOnly {
            return Ok(None);
        }

        Ok(Some(format!("windows:{}", filetime_to_u64(creation))))
    }

    pub(super) fn request_stop(_pid: u32) -> io::Result<bool> {
        // Windows has no signal a non-console process can be asked to handle
        // from outside. `GenerateConsoleCtrlEvent` needs a shared console, and
        // a service-hosted agent has none. Reporting `false` tells the caller
        // to go straight to `force_stop` rather than sit through a grace period
        // during which nothing was ever asked.
        Ok(false)
    }

    pub(super) fn force_stop(pid: u32) -> io::Result<()> {
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }
            .map_err(|error| io_error(&error))?;
        let result = unsafe { TerminateProcess(handle, 1) };
        unsafe {
            let _ = CloseHandle(handle);
        }
        result.map_err(|error| io_error(&error))
    }

    /// The current account's SID in string form, for the DACL below.
    fn current_user_sid() -> io::Result<String> {
        let mut token = HANDLE(std::ptr::null_mut());
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(|error| io_error(&error))?;

        let mut needed = 0u32;
        // The first call is expected to fail with ERROR_INSUFFICIENT_BUFFER; it
        // is how the required size is learned.
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };

        // `TOKEN_USER` contains a pointer, so the buffer must be
        // pointer-aligned; a `Vec<u8>` is aligned to 1 and casting it would be
        // undefined behaviour.
        let words = (needed as usize).div_ceil(size_of::<usize>()).max(1);
        let mut buffer = vec![0usize; words];

        let information = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        };
        if let Err(error) = information {
            unsafe {
                let _ = CloseHandle(token);
            }
            return Err(io_error(&error));
        }

        let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut sid_string = PWSTR::null();
        let converted = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) };
        unsafe {
            let _ = CloseHandle(token);
        }
        converted.map_err(|error| io_error(&error))?;

        let text = unsafe { sid_string.to_string() }
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sid_string.0.cast())));
        }
        text
    }

    pub(super) fn create_restrictive_file(path: &Path) -> io::Result<File> {
        // A protected DACL — the `P` — so that nothing is inherited from the
        // parent directory, granting full access to exactly two trustees: this
        // account, and the local Administrators group.
        //
        // `BA` is not a weakening: `07-security.md` places a local
        // administrator outside this threat model, because such an account can
        // already read the runner's workspace and its credentials. It is kept
        // so that an operator can clean up a handoff file left behind by an
        // agent running under a service account they are not logged in as.
        //
        // There is deliberately no `(A;;FA;;;SY)` ACE. An earlier version
        // carried one "so that a service running as LocalSystem still works",
        // and that justification was simply wrong: if this agent *is*
        // LocalSystem then `current_user_sid()` returns S-1-5-18 and the third
        // ACE already covers it. So the ACE added nothing in the one case it
        // was written for, and in every other case it widened access to a file
        // whose entire purpose is to be narrow.
        let sddl = format!("D:P(A;;FA;;;BA)(A;;FA;;;{})", current_user_sid()?);
        let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

        let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| io_error(&error))?;

        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.0,
            // False: a handle to the JIT configuration must not be inherited by
            // the runner or by anything else this agent spawns.
            bInheritHandle: windows::core::BOOL(0),
        };

        let wide = to_wide(path);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                Some(&raw const attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };

        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }

        let handle = handle.map_err(|error| io_error(&error))?;
        Ok(unsafe { File::from_raw_handle(handle.0) })
    }

    pub(super) fn describe_permissions(path: &Path) -> io::Result<(String, bool)> {
        let wide = to_wide(path);
        let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(status.0).unwrap_or(i32::MAX),
            ));
        }

        let mut sddl = PWSTR::null();
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                None,
            )
        };
        let text = match converted {
            Ok(()) => {
                let text = unsafe { sddl.to_string() }
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(sddl.0.cast())));
                }
                text
            }
            Err(error) => Err(io_error(&error)),
        };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        let text = text?;

        let readable = dacl_grants_broad_access(&text);
        Ok((text, readable))
    }

    /// Whether a DACL in SDDL form lets an ordinary local user other than the
    /// owner read the object.
    ///
    /// Two conditions, and both matter. An unprotected DACL inherits whatever
    /// the parent directory grants, which is not this program's to vouch for.
    /// And an allow ACE naming one of the broad well-known trustees grants
    /// access to every interactive account on the machine.
    fn dacl_grants_broad_access(sddl: &str) -> bool {
        /// The trustees that mean "more or less anybody logged in here", in
        /// both the two-letter SDDL alias form and the raw SID form the
        /// converter may emit instead.
        const BROAD: &[&str] = &[
            "WD",           // Everyone
            "S-1-1-0",      // Everyone
            "AU",           // Authenticated Users
            "S-1-5-11",     // Authenticated Users
            "BU",           // Builtin Users
            "S-1-5-32-545", // Builtin Users
            "IU",           // Interactive
            "S-1-5-4",      // Interactive
            "AN",           // Anonymous
            "S-1-5-7",      // Anonymous
            "WR",           // Write Restricted
            "LU",           // Performance Log Users
        ];

        let Some(dacl) = sddl.split("D:").nth(1) else {
            // No DACL at all means "everyone, full control" in Windows'
            // security model. Never the answer this function should be
            // optimistic about.
            return true;
        };

        let flags: String = dacl.chars().take_while(|c| *c != '(').collect();
        if !flags.contains('P') {
            return true;
        }

        for ace in dacl.split('(').skip(1) {
            let ace = ace.split(')').next().unwrap_or_default();
            let fields: Vec<&str> = ace.split(';').collect();
            // (type;flags;rights;object_guid;inherit_object_guid;trustee)
            let (Some(kind), Some(trustee)) = (fields.first(), fields.get(5)) else {
                continue;
            };
            // Only allow ACEs grant anything; a deny ACE naming Everyone is a
            // tightening, not a leak.
            if !kind.starts_with('A') {
                continue;
            }
            if BROAD
                .iter()
                .any(|broad| trustee.eq_ignore_ascii_case(broad))
            {
                return true;
            }
        }

        false
    }

    #[cfg(test)]
    mod tests {
        use super::dacl_grants_broad_access;

        #[test]
        fn a_protected_owner_only_dacl_is_not_broadly_readable() {
            // The shape `create_restrictive_file` actually writes: protected,
            // Administrators, and this account. No LocalSystem ACE — see the
            // comment there for why one would add nothing.
            assert!(!dacl_grants_broad_access(
                "D:P(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)"
            ));
            // A LocalSystem agent's own SID is S-1-5-18, which is what makes
            // the separate `SY` ACE redundant rather than load-bearing.
            assert!(!dacl_grants_broad_access(
                "D:P(A;;FA;;;BA)(A;;FA;;;S-1-5-18)"
            ));
            // Still tolerated when it arrives from somewhere else: this
            // heuristic inspects files, and not every file it sees was written
            // by this module.
            assert!(!dacl_grants_broad_access(
                "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)"
            ));
        }

        #[test]
        fn an_everyone_ace_is_broadly_readable_in_either_notation() {
            assert!(dacl_grants_broad_access("D:P(A;;FA;;;SY)(A;;FR;;;WD)"));
            assert!(dacl_grants_broad_access("D:P(A;;FA;;;SY)(A;;FR;;;S-1-1-0)"));
            assert!(dacl_grants_broad_access("D:P(A;;FR;;;BU)"));
        }

        #[test]
        fn an_unprotected_dacl_is_broadly_readable_because_it_inherits() {
            assert!(dacl_grants_broad_access("D:AI(A;ID;FA;;;SY)"));
        }

        #[test]
        fn a_deny_ace_for_everyone_is_not_a_grant() {
            assert!(!dacl_grants_broad_access("D:P(D;;FA;;;WD)(A;;FA;;;SY)"));
        }

        #[test]
        fn a_missing_dacl_is_treated_as_wide_open() {
            assert!(dacl_grants_broad_access("O:BAG:BA"));
        }
    }
}

#[cfg(unix)]
mod sys {
    use std::fs::File;
    use std::io;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::Path;

    pub(super) fn request_stop(pid: u32) -> io::Result<bool> {
        // SAFETY: `kill` takes a PID and a signal number and touches no memory
        // this program owns. The PID is checked for liveness by the caller
        // immediately beforehand, and every caller either holds the child
        // handle or has just re-verified the process identity.
        let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        // The process exited between the liveness check and the signal. That is
        // a normal race, not a failure to stop it.
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(true);
        }
        Err(error)
    }

    pub(super) fn force_stop(pid: u32) -> io::Result<()> {
        // SAFETY: as `request_stop`.
        let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        Err(error)
    }

    pub(super) fn create_restrictive_file(path: &Path) -> io::Result<File> {
        // `mode` is applied by `open(2)` itself, so the file never exists with
        // any other permissions. `create_new` makes it exclusive, so a
        // pre-created path belonging to somebody else is an error rather than a
        // file this process writes a JIT configuration into.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }

    pub(super) fn describe_permissions(path: &Path) -> io::Result<(String, bool)> {
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        // Any group or other bit at all, not just the read bit: an executable
        // or writable bit for another account is not something this file should
        // ever carry either.
        Ok((format!("mode {mode:04o}"), mode & 0o077 != 0))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn start_token(
        pid: u32,
        filter: super::LivenessFilter,
    ) -> io::Result<Option<String>> {
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };

        let parsed = super::parse_proc_stat(&stat).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("/proc/{pid}/stat is not in the documented format"),
            )
        })?;

        // `Z` is a process that has exited and is waiting to be reaped. Its PID
        // is still taken, but it is not a process that can be adopted or asked
        // to do anything.
        if parsed.state == "Z" && filter == super::LivenessFilter::LiveOnly {
            return Ok(None);
        }

        Ok(Some(format!("linux:{}:{}", boot_id()?, parsed.start_ticks)))
    }

    /// An identifier that changes on every boot.
    ///
    /// Needed because `starttime` counts from boot, so without it a process
    /// started 500 ticks after this boot and one started 500 ticks after the
    /// previous boot are indistinguishable — which is exactly the confusion a
    /// journal read back after a reboot invites.
    #[cfg(target_os = "linux")]
    fn boot_id() -> io::Result<String> {
        // Every kernel since 2.6.19 offers this, and it is world-readable.
        if let Ok(id) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            let id = id.trim();
            if !id.is_empty() {
                return Ok(id.to_string());
            }
        }

        // A container or a hardened kernel may hide it. `btime` in
        // `/proc/stat` is the boot wall-clock time in whole seconds and serves
        // the same purpose here: it distinguishes boots. It is only ever the
        // fallback because two boots within the same second would collide, and
        // `boot_id` cannot.
        let stat = std::fs::read_to_string("/proc/stat")?;
        stat.lines()
            .find_map(|line| line.strip_prefix("btime "))
            .map(|value| format!("btime-{}", value.trim()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "neither /proc/sys/kernel/random/boot_id nor /proc/stat btime is readable, \
                     so a process identity that survives a reboot cannot be formed",
                )
            })
    }

    #[cfg(target_os = "macos")]
    pub(super) fn start_token(
        pid: u32,
        filter: super::LivenessFilter,
    ) -> io::Result<Option<String>> {
        // `proc_pidinfo(PROC_PIDTBSDINFO)` rather than `sysctl(KERN_PROC)`:
        // libc 0.2 defines `proc_bsdinfo` for Apple targets but not
        // `kinfo_proc`, so the sysctl route would mean declaring the struct
        // layout by hand — a layout this crate would then own and have to keep
        // correct across macOS releases. `proc_pidinfo` gives the same
        // microsecond start time through a declared type.
        //
        // SAFETY: `info` is a correctly sized, zero-initialised `proc_bsdinfo`
        // and the size passed matches it, so the kernel writes only within it.
        // `proc_pidinfo` reads no memory this program owns other than that
        // buffer.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = i32::try_from(size_of::<libc::proc_bsdinfo>()).unwrap_or(i32::MAX);
        let written = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                std::ptr::from_mut(&mut info).cast(),
                size,
            )
        };

        if written <= 0 {
            let error = io::Error::last_os_error();
            // See `super::probe_failure_means_gone`, which is where this rule
            // lives so that it can be tested on a leg that has no `libc`.
            // Only ESRCH is "gone"; EPERM and a zero `errno` are errors.
            return if super::probe_failure_means_gone(error.raw_os_error(), libc::ESRCH) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if written != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("proc_pidinfo returned {written} bytes for PID {pid}, expected {size}"),
            ));
        }

        // A zombie still holds its PID but is not a process anything can adopt.
        if info.pbi_status == libc::SZOMB && filter == super::LivenessFilter::LiveOnly {
            return Ok(None);
        }

        Ok(Some(format!(
            "macos:{}.{:06}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A program that exits immediately, on every supported platform.
    fn quick_exit() -> SpawnSpec {
        if cfg!(windows) {
            SpawnSpec::new("cmd").args(["/C", "exit", "0"])
        } else {
            SpawnSpec::new("true")
        }
    }

    /// A program that stays alive until it is stopped.
    ///
    /// Deliberately a single process on both families rather than a shell
    /// wrapping one. Terminating a shell does not terminate the child it
    /// spawned, so a `cmd /C …` or `sh -c …` wrapper would leave a stray
    /// process behind after every test that stops it — and would make
    /// `Adoption::Gone` assertions read as passes for the wrong reason.
    ///
    /// `ping -n 600 127.0.0.1` sends one loopback echo a second for ten
    /// minutes: it needs no console, writes to the null device this spec
    /// already sets, and burns no CPU while waiting.
    fn long_running() -> SpawnSpec {
        if cfg!(windows) {
            SpawnSpec::new("ping").args(["-n", "600", "127.0.0.1"])
        } else {
            SpawnSpec::new("sleep").args(["600"])
        }
    }

    /// The coarsest start-token resolution any supported platform has.
    ///
    /// Linux's token carries `/proc/<pid>/stat` field 22, which counts
    /// `USER_HZ` ticks. `USER_HZ` is 100 on every supported distribution, so
    /// one tick is **10 ms** and two processes started inside the same tick get
    /// byte-identical start tokens. Windows resolves creation time to 100 ns
    /// and macOS to 1 µs, so neither can collide this way.
    const COARSEST_START_TOKEN_TICK: Duration = Duration::from_millis(10);

    /// Puts a start-token boundary between two spawns.
    ///
    /// Every "recycled PID" fixture below works by pairing one process's PID
    /// with another process's start token. That only *is* a recycled record if
    /// the two tokens differ. Spawning back to back is well inside one Linux
    /// tick — a `posix_spawn` and two small `/proc` reads — so without this the
    /// synthesised record would be the survivor's genuine identity, `recheck`
    /// would correctly answer `Live`, and the fixture would fail while the
    /// primitive it is testing was working exactly as designed.
    ///
    /// This is a defect in the fixture and not in the discriminator: recycling
    /// a PID for real takes far longer than 10 ms, and `boot_id` changes across
    /// a reboot, so no production record can collide this way.
    fn separate_start_tokens() {
        // Comfortably more than one tick, so a slow or virtualised Linux CI
        // runner does not land on the boundary itself.
        std::thread::sleep(COARSEST_START_TOKEN_TICK * 5 / 2);
    }

    /// Fails with a message naming its own cause if two spawns still collided.
    ///
    /// Without this the collision surfaces as `assert!(!…is_live())` or as a
    /// dead survivor, both of which read as "the start token has stopped
    /// discriminating" — the opposite of what actually happened.
    fn assert_distinguishable(first: &ProcessIdentity, second: &ProcessIdentity) {
        assert_ne!(
            first.start_token(),
            second.start_token(),
            "the two children share a start token, so the record synthesised below would be \
             the second child's real identity rather than a recycled one. This is the fixture \
             colliding inside one start-token tick, not the discriminator failing; lengthen \
             `separate_start_tokens` for this platform."
        );
    }

    // -----------------------------------------------------------------------
    // The Linux `/proc/<pid>/stat` parser
    //
    // Deliberately not `#[cfg(target_os = "linux")]`. This is the only Linux
    // path in the crate whose correctness is decidable without a Linux kernel,
    // and running it on all three legs means a Windows or macOS developer
    // breaking it finds out immediately rather than in the Linux leg of CI.
    // -----------------------------------------------------------------------

    /// A real `/proc/<pid>/stat` line, from a 6.x kernel, truncated after the
    /// fields this crate reads. Fields 1 and 2 are the PID and `comm`; field 3
    /// is the state; field 22 is `starttime`.
    const REAL_STAT: &str = "1234 (bash) S 1200 1234 1234 34816 1234 4194304 3300 5100 0 0 6 5 8 4 20 0 1 0 987654 12345678 900 18446744073709551615";

    #[test]
    fn the_proc_stat_parser_reads_the_state_and_the_start_time() {
        let parsed = parse_proc_stat(REAL_STAT).expect("a well-formed line parses");
        assert_eq!(parsed.state, "S");
        assert_eq!(
            parsed.start_ticks, "987654",
            "field 22 is `starttime`; an off-by-one here silently produces a process identity \
             that is stable but wrong, which is worse than one that fails"
        );
    }

    #[test]
    fn the_proc_stat_parser_survives_a_command_name_containing_spaces_and_parentheses() {
        // `procfs(5)` permits this, and a whitespace split of the whole line
        // mis-indexes every field after it. The failure would show up only for
        // a process whose name was chosen to cause it — that is, only when
        // somebody meant to.
        let hostile = REAL_STAT.replace("(bash)", "(my prog (v2) :) )");
        let parsed = parse_proc_stat(&hostile).expect("a hostile comm still parses");
        assert_eq!(parsed.state, "S");
        assert_eq!(parsed.start_ticks, "987654");
    }

    #[test]
    fn a_naive_whitespace_split_gets_the_hostile_case_wrong() {
        // Shows the previous test is not decorative: the obvious
        // implementation, run on the same input, returns a different field.
        let hostile = REAL_STAT.replace("(bash)", "(my prog (v2) :) )");
        let naive: Vec<&str> = hostile.split_whitespace().collect();
        // Field 22 counting from the start of the line, as the naive reading
        // would.
        let naive_start = naive.get(21).copied();

        assert_ne!(
            naive_start,
            Some(parse_proc_stat(&hostile).expect("parses").start_ticks),
            "if these agree, the hostile fixture no longer exercises the hazard and the test \
             above proves nothing"
        );
    }

    #[test]
    fn the_proc_stat_parser_reports_a_zombie() {
        let zombie = REAL_STAT.replacen(") S ", ") Z ", 1);
        let parsed = parse_proc_stat(&zombie).expect("parses");
        assert_eq!(
            parsed.state, "Z",
            "a zombie holds its PID but is not adoptable; the caller depends on seeing this"
        );
    }

    #[test]
    fn the_proc_stat_parser_rejects_a_truncated_line() {
        assert_eq!(parse_proc_stat(""), None);
        assert_eq!(parse_proc_stat("1234 (bash)"), None);
        assert_eq!(parse_proc_stat("1234 (bash) S 1200"), None);
        assert_eq!(
            parse_proc_stat("no parenthesis here at all"),
            None,
            "a line with no comm field must be rejected, not indexed into"
        );
    }

    #[test]
    fn the_current_process_has_a_stable_identity() {
        let first = ProcessIdentity::of_current_process().expect("this process can see itself");
        let second = ProcessIdentity::of_current_process().expect("twice");

        assert_eq!(
            first, second,
            "an identity that changes between two reads of the same live process would make \
             every journal record unmatchable"
        );
        assert_eq!(first.pid(), std::process::id());
        assert!(
            !first.start_token().is_empty(),
            "an empty start token would make the identity a bare PID again"
        );
        assert_eq!(first.recheck().expect("resolvable"), Adoption::Live);
    }

    #[test]
    fn the_start_token_varies_between_processes() {
        // Guards against the degenerate implementation that satisfies every
        // other test in this module: a token that is the same constant for
        // everything. Such a token would make a recycled PID indistinguishable
        // from the original process.
        let mut child = long_running().spawn().expect("the child starts");
        let mine = ProcessIdentity::of_current_process().expect("this process can see itself");

        assert_ne!(
            child.identity().start_token(),
            mine.start_token(),
            "two different processes must not share a start token"
        );

        child.stop(Duration::from_secs(5)).expect("the child stops");
    }

    #[test]
    fn a_spawned_child_is_observable_and_terminable() {
        let mut child = long_running().spawn().expect("the child starts");

        assert!(child.is_running().expect("observable"), "just spawned");
        assert_eq!(child.identity().pid(), child.pid());
        assert_eq!(
            child.identity().recheck().expect("resolvable"),
            Adoption::Live,
            "a running child must re-resolve to itself"
        );
        assert_eq!(
            child.wait_for(Duration::from_millis(50)).expect("waitable"),
            None,
            "a long-running child must not be reported as exited"
        );

        child
            .stop(Duration::from_secs(10))
            .expect("the child stops");

        assert!(!child.is_running().expect("observable"), "after stop");
        assert_eq!(
            child.identity().recheck().expect("resolvable"),
            Adoption::Gone,
            "a stopped child's identity must not still resolve as live"
        );
    }

    #[test]
    fn a_child_that_exits_on_its_own_is_reported_as_exited() {
        let mut child = quick_exit().spawn().expect("the child starts");

        let status = child
            .wait_for(Duration::from_secs(30))
            .expect("waitable")
            .expect("a program that exits immediately must be seen to exit");
        assert!(status.success(), "{status:?}");
        assert!(!child.is_running().expect("observable"));
    }

    /// The Definition of Done clause this whole module exists for: *"its
    /// recorded identity is re-resolvable after a simulated restart and does
    /// **not** match a recycled PID belonging to a different process"*.
    ///
    /// The restart is simulated by round-tripping the identity through JSON —
    /// the journal's representation — and dropping every in-memory handle, so
    /// the re-resolution has nothing but the serialised record to work from.
    /// The recycling is simulated by pairing a *live* process's PID with a
    /// *different* process's start token, which is precisely the state a real
    /// PID reuse produces.
    #[test]
    fn a_recorded_identity_survives_a_restart_and_rejects_a_recycled_pid() {
        let mut victim = long_running().spawn().expect("the first child starts");
        let recorded = victim.identity().clone();

        // The journal round trip.
        let journalled = serde_json::to_string(&recorded).expect("serialisable");
        let recovered: ProcessIdentity = serde_json::from_str(&journalled).expect("readable back");
        assert_eq!(recovered, recorded);
        assert_eq!(
            recovered.recheck().expect("resolvable"),
            Adoption::Live,
            "a journalled identity whose process is still running must be adoptable; e3's \
             restart recovery depends on exactly this"
        );

        // A second, unrelated process. Its PID is the one the record will be
        // made to point at.
        separate_start_tokens();
        let mut survivor = long_running().spawn().expect("the second child starts");
        let survivor_identity = survivor.identity().clone();
        assert_ne!(survivor_identity.pid(), recorded.pid());
        assert_distinguishable(&recorded, &survivor_identity);

        victim
            .stop(Duration::from_secs(10))
            .expect("the first child stops");

        // The record as it would look after PID reuse: the journalled start
        // token, now pointing at a PID a different process holds.
        let recycled = ProcessIdentity {
            pid: survivor_identity.pid(),
            start_token: recorded.start_token().to_string(),
        };

        match recycled.recheck().expect("resolvable") {
            Adoption::PidRecycled { current } => {
                assert_eq!(
                    current, survivor_identity,
                    "the recycled answer must name whoever actually holds the PID"
                );
            }
            other => panic!(
                "a recycled PID must not be adopted, and must be distinguishable from a PID \
                 nobody holds; got {other:?}"
            ),
        }

        survivor
            .stop(Duration::from_secs(10))
            .expect("the second child stops");
    }

    /// Only `ESRCH` means the process is gone.
    ///
    /// Runs on every leg, including the one with no `libc`, because the rule is
    /// a function over an `Option<i32>` rather than a `match` buried in a
    /// `#[cfg(target_os = "macos")]` body. `ESRCH` is 3 on both Unix platforms,
    /// but it is passed in rather than assumed, so this stays true of a
    /// platform where it is not.
    #[test]
    fn only_no_such_process_means_gone() {
        const ESRCH: i32 = 3;
        const EPERM: i32 = 1;

        assert!(probe_failure_means_gone(Some(ESRCH), ESRCH));

        // The finding this guards. A zero `errno` was once folded in with
        // `ESRCH`, which contradicted the Windows policy on
        // `ERROR_ACCESS_DENIED`: an unexplained failure is not evidence that
        // the process is gone, and answering `Gone` for one is how an agent
        // decides to start a second runner for an attempt that already has one.
        assert!(
            !probe_failure_means_gone(Some(0), ESRCH),
            "a zero errno is an unexplained failure, not an absent process"
        );

        // A process owned by another account. Reporting this as `Gone` would
        // silently un-adopt every runner after a service-account change.
        assert!(!probe_failure_means_gone(Some(EPERM), ESRCH));

        // No errno at all is not evidence of anything either.
        assert!(!probe_failure_means_gone(None, ESRCH));
    }

    /// The attribute this scan walks, and the lint it looks for inside it.
    ///
    /// Assembled rather than written out, so that this file contains no
    /// literal spelling of the attribute outside the attributes themselves.
    /// A text scan reads its own machinery as readily as it reads code: the
    /// first version of this test found the attribute quoted in its own
    /// documentation and failed, which was a fair demonstration that it
    /// detects the shape and a reminder that the needle must not be in the
    /// haystack.
    const CFG_ATTR: &str = concat!("#[cfg_", "attr(");

    /// The lint's own name, which has to appear verbatim in any allowance.
    const DEAD_CODE: &str = concat!("dead_", "code");

    /// The condition of every `dead_code` allowance in `source` that names a
    /// platform rather than the complement of one.
    ///
    /// Split out from the test below so that it can also be run against a
    /// fixture. A scan that finds nothing in this file is worth exactly what
    /// its ability to find something is worth, and the only way to establish
    /// that is to hand it something it must object to -- the same device
    /// `logging.rs` uses to prove its secret-injection scan is capable of
    /// failing.
    fn positive_dead_code_conditions(source: &str) -> Vec<String> {
        // Comment lines go first, for the reason `CFG_ATTR` documents.
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        let mut offenders = Vec::new();

        for block in code.split(CFG_ATTR).skip(1) {
            // Walk to the `)` closing the attribute, and remember the first
            // comma at depth zero: that is what separates the condition from
            // the attributes it applies.
            let mut depth = 0usize;
            let mut body_end = None;
            let mut split_at = None;
            for (index, character) in block.char_indices() {
                match character {
                    '(' => depth += 1,
                    ')' => {
                        if depth == 0 {
                            body_end = Some(index);
                            break;
                        }
                        depth -= 1;
                    }
                    ',' if depth == 0 && split_at.is_none() => split_at = Some(index),
                    _ => {}
                }
            }

            let (Some(body_end), Some(split_at)) = (body_end, split_at) else {
                continue;
            };
            if !block[split_at..body_end].contains(DEAD_CODE) {
                continue;
            }

            let condition = block[..split_at].trim();
            if !condition.starts_with("not(") {
                offenders.push(condition.to_string());
            }
        }

        offenders
    }

    /// Every `dead_code` allowance in this file must name a *complement*.
    ///
    /// A lint on the lint, and it exists because the alternative did not work.
    /// `probe_failure_means_gone` carried a `dead_code` allowance conditioned
    /// on `windows` while its only non-test caller was macOS-only. On Linux the
    /// allowance was inactive *and* the caller absent, so the lint fired on
    /// the lib target and `cargo clippy --all-targets -- -D warnings` failed --
    /// on the one CI leg no Windows developer runs, and invisibly to every
    /// local gate.
    ///
    /// A `dead_code` allowance is a claim about everywhere the caller is *not*,
    /// so its condition is naturally a complement: `not(target_os = "…")`. A
    /// bare positive names a single platform and says nothing whatsoever about
    /// the rest, which is precisely how the wrong one went unnoticed. Requiring
    /// the complement form does not prove the condition names the *right*
    /// platform, but it does refuse the shape that hid the bug.
    ///
    /// # No lower bound, and why the vacuity check is a fixture instead
    ///
    /// This used to end with `checked >= 3`: a lower bound on the number of
    /// allowances found. A lower bound cannot tell "the parser stopped
    /// matching" from "somebody removed an allowance properly", so it punished
    /// the correct remediation. Replacing one of these with a plain
    /// `cfg(any(…, test))` -- no allowance at all, which is strictly stronger,
    /// because it makes the lint's premise false rather than silencing the
    /// report -- left `cargo clippy --all-targets -- -D warnings` clean and
    /// this test failing. A tripwire that fires on the better fix teaches
    /// people to make the worse one.
    ///
    /// Counting parsed attributes against occurrences in the text does not fix
    /// it either, and that was tried: both counts come from the same needle, so
    /// breaking the needle takes both to zero and the check passes. Measured,
    /// not reasoned -- the probe that was meant to fail did not.
    ///
    /// So the vacuity check is
    /// [`the_allowance_scan_catches_a_positive_condition`], which runs the same
    /// walk over a fixture that must be objected to. It cannot go vacuous,
    /// because its input does not depend on what this file happens to contain,
    /// and it costs nothing when an allowance is properly removed.
    ///
    /// # Scope
    ///
    /// Scoped to this file because it is the only one in the crate that carries
    /// a `dead_code` allowance. It is *not* the only one with
    /// target-conditional compilation, which is what this used to claim and
    /// which was untrue: `paths.rs` and `logging.rs` both carry `#[cfg(unix)]`,
    /// and `lock.rs` carries a Windows arm and a Unix arm. Those are a
    /// different shape and not the one guarded here -- a `cfg` that selects an
    /// implementation is load-bearing, while an `allow(dead_code)` conditioned
    /// on one platform is an unexamined claim about all the others. If an
    /// allowance ever appears in another file this scan will not see it, and
    /// widening it is then the fix.
    #[test]
    fn every_dead_code_allowance_names_a_complement() {
        let offenders = positive_dead_code_conditions(include_str!("process.rs"));
        assert!(
            offenders.is_empty(),
            "a dead_code allowance must name the complement of its caller's \
             cfg rather than one platform, or it says nothing about the legs \
             it does not name: {offenders:?}"
        );
    }

    /// Proves the scan above is capable of finding something.
    ///
    /// Without this, "no offending allowance in the file" and "the walk no
    /// longer recognises an attribute" are the same passing test. The fixtures
    /// are assembled with `concat!` for the reason [`CFG_ATTR`] documents: a
    /// literal here would be found by the file scan itself and reported as a
    /// defect in the file.
    #[test]
    fn the_allowance_scan_catches_a_positive_condition() {
        let offending = concat!(
            "#[cfg_",
            "attr(windows, allow(dead_",
            "code, reason = \"a reason\"))]\nfn f() {}"
        );
        assert_eq!(
            positive_dead_code_conditions(offending),
            vec!["windows".to_string()],
            "the walk no longer recognises an allowance, so the scan over this \
             file is checking nothing"
        );

        // The shape this file actually uses is not objected to.
        let complement = concat!(
            "#[cfg_",
            "attr(not(target_os = \"linux\"), allow(dead_",
            "code, reason = \"a reason\"))]\nfn f() {}"
        );
        assert!(positive_dead_code_conditions(complement).is_empty());

        // Nor is a `cfg_attr` that allows something other than this lint, at
        // any condition: the rule is about claims made on this lint's behalf.
        let unrelated = concat!(
            "#[cfg_",
            "attr(windows, allow(clippy::needless_return))]\nfn f() {}"
        );
        assert!(positive_dead_code_conditions(unrelated).is_empty());

        // A comment is not code. The rule this enforces is quoted in prose
        // above, and reading prose as code is how the first version of this
        // scan failed.
        let commented = concat!(
            "// #[cfg_",
            "attr(windows, allow(dead_",
            "code))]\nfn f() {}"
        );
        assert!(positive_dead_code_conditions(commented).is_empty());
    }

    /// The three-way answer, on synthesised tokens, on every platform.
    ///
    /// The spawn-based tests above cannot cover the case where two identities
    /// carry the *same* start token: on Windows and macOS the resolution makes
    /// it unreachable, and on Linux it is a 10 ms race rather than something a
    /// test can request. That case is exactly what the tick boundary in
    /// `separate_start_tokens` is there to avoid, so it is worth pinning down
    /// what the discriminator does with it — and pinning it down on the Windows
    /// leg, which cannot exhibit the collision any other way.
    #[test]
    fn identical_start_tokens_are_the_same_process_and_differing_ones_are_not() {
        let recorded = ProcessIdentity {
            pid: 4312,
            start_token: "platform:token-a".to_string(),
        };

        // The collision. This is the answer that makes a colliding fixture fail
        // for the wrong reason: `Live` is *correct* here, because on the
        // evidence available the two are the same process.
        assert_eq!(
            recorded.classify(Some("platform:token-a".to_string())),
            Adoption::Live,
            "an identical token is the same process; a fixture that spawns twice inside one \
             tick is therefore asserting against a correct answer"
        );

        // A different token at the same PID is the recycled case, and it must
        // carry whoever holds the PID now.
        assert_eq!(
            recorded.classify(Some("platform:token-b".to_string())),
            Adoption::PidRecycled {
                current: ProcessIdentity {
                    pid: 4312,
                    start_token: "platform:token-b".to_string(),
                },
            }
        );

        assert_eq!(recorded.classify(None), Adoption::Gone);
        assert!(
            recorded
                .classify(Some("platform:token-a".to_string()))
                .is_live()
        );
        assert!(
            !recorded
                .classify(Some("platform:token-b".to_string()))
                .is_live()
        );
        assert!(!recorded.classify(None).is_live());
    }

    /// The Linux token shape is the one that can collide, so assert the
    /// collision is a tick-granularity property rather than a boot-id one.
    ///
    /// Runs everywhere: these are strings, not `/proc` reads.
    #[test]
    fn two_linux_tokens_collide_only_within_one_tick_of_one_boot() {
        let boot = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
        let at = |ticks: u64| ProcessIdentity {
            pid: 4312,
            start_token: format!("linux:{boot}:{ticks}"),
        };

        // Same boot, same tick: indistinguishable. This is the H1 collision,
        // reproduced without a Linux kernel.
        assert_eq!(
            at(884_213).classify(Some(at(884_213).start_token)),
            Adoption::Live
        );

        // One tick apart — 10 ms — is enough to tell them apart, which is why
        // `separate_start_tokens` sleeps for longer than one tick.
        assert!(
            !at(884_213)
                .classify(Some(at(884_214).start_token))
                .is_live()
        );

        // The same tick count across a reboot is a different token, which is
        // the whole reason the boot id is in there.
        let other_boot = ProcessIdentity {
            pid: 4312,
            start_token: "linux:6ba7b810-9dad-11d1-80b4-00c04fd430c8:884213".to_string(),
        };
        assert!(!at(884_213).classify(Some(other_boot.start_token)).is_live());
    }

    /// Shows the previous test is not vacuous.
    ///
    /// A bare-PID identity — the implementation the task specification calls
    /// insufficient — is built here and run through the same comparison. It
    /// reports the recycled record as a match, which is the failure the start
    /// token exists to prevent. If this test ever stops finding a difference,
    /// the start token has stopped discriminating and the test above has become
    /// decoration.
    #[test]
    fn a_bare_pid_would_have_accepted_the_recycled_record() {
        let mut victim = long_running().spawn().expect("the first child starts");
        let recorded = victim.identity().clone();
        separate_start_tokens();
        let mut survivor = long_running().spawn().expect("the second child starts");
        let survivor_identity = survivor.identity().clone();
        assert_distinguishable(&recorded, &survivor_identity);

        victim
            .stop(Duration::from_secs(10))
            .expect("the first child stops");

        let recycled = ProcessIdentity {
            pid: survivor_identity.pid(),
            start_token: recorded.start_token().to_string(),
        };

        // What a PID-only comparison would conclude.
        let bare_pid_says_live = recycled.pid() == survivor_identity.pid();
        assert!(
            bare_pid_says_live,
            "the recycled record must genuinely point at a live process, or the test above is \
             not testing recycling at all"
        );

        // What this module concludes.
        assert!(
            !recycled.recheck().expect("resolvable").is_live(),
            "the start token must reject what a bare PID accepts"
        );

        survivor
            .stop(Duration::from_secs(10))
            .expect("the second child stops");
    }

    #[test]
    fn terminating_a_recycled_record_refuses_rather_than_killing_a_stranger() {
        let mut victim = long_running().spawn().expect("the first child starts");
        let recorded = victim.identity().clone();
        separate_start_tokens();
        let mut survivor = long_running().spawn().expect("the second child starts");
        let survivor_identity = survivor.identity().clone();
        // Without this guard a token collision would make the test SIGTERM and
        // then SIGKILL the very process it exists to prove is protected, and
        // then fail on `survivor.is_running()` — a failure that names the wrong
        // cause and has already destroyed its own evidence.
        assert_distinguishable(&recorded, &survivor_identity);

        victim
            .stop(Duration::from_secs(10))
            .expect("the first child stops");

        let recycled = ProcessIdentity {
            pid: survivor_identity.pid(),
            start_token: recorded.start_token().to_string(),
        };

        let outcome = recycled
            .terminate(Duration::from_secs(1))
            .expect("terminable");
        assert_eq!(
            outcome,
            Termination::RefusedPidRecycled {
                current: survivor_identity,
            },
            "terminating a recycled record must refuse; killing a stranger's process is the \
             worst outcome this primitive can produce"
        );

        assert!(
            survivor.is_running().expect("observable"),
            "the innocent process must still be running"
        );
        survivor.stop(Duration::from_secs(10)).expect("cleanup");
    }

    #[test]
    fn terminating_by_identity_stops_a_process_this_agent_did_not_spawn_as_a_child() {
        // The post-restart shape: an identity from the journal, no `Child`.
        let mut child = long_running().spawn().expect("the child starts");
        let identity = child.identity().clone();

        assert_eq!(
            identity
                .terminate(Duration::from_secs(10))
                .expect("terminable"),
            Termination::Terminated
        );

        // Reap it so the PID is released; on Unix an unreaped child stays a
        // zombie and keeps its PID.
        let status = child.wait_for(Duration::from_secs(30)).expect("waitable");
        assert!(status.is_some(), "the process must actually have stopped");

        assert_eq!(
            identity
                .terminate(Duration::from_secs(1))
                .expect("terminable"),
            Termination::AlreadyGone,
            "terminating an already-dead identity must be a no-op, not an error: recovery runs \
             this on every journal entry"
        );
    }

    #[test]
    fn resolving_a_pid_nobody_holds_is_a_distinct_error() {
        // PID 0 is the idle/kernel process on Windows and the scheduler on
        // Linux; neither is a process this account can adopt, and on macOS
        // `proc_pidinfo` reports nothing for it. Using a child's PID after it
        // has been reaped is the honest test, so do that instead.
        let mut child = quick_exit().spawn().expect("the child starts");
        let pid = child.pid();
        child.wait().expect("the child exits");

        match ProcessIdentity::resolve(pid) {
            Err(ProcessError::NoSuchProcess { pid: reported }) => assert_eq!(reported, pid),
            // A PID freed moments ago can legitimately be reused by an
            // unrelated process on a busy machine. That is not this test's
            // failure; it is the very thing the module handles.
            Ok(other) => assert_eq!(other.pid(), pid),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    // -----------------------------------------------------------------------
    // Restrictive handoff
    // -----------------------------------------------------------------------

    /// Stands in for an encoded JIT configuration: long, base64-shaped, and
    /// the thing `07-security.md` says must never reach a process listing.
    fn jit_payload() -> SecretString {
        SecretString::from(
            "eyJhZ2VudCI6ICJydW5uZXItbWFuYWdlciIsICJqaXQiOiAidGhpcy1pcy1ub3QtYS1yZWFsLWNvbmZp\
             Zy1idXQtaXQtaXMtdGhlLXJpZ2h0LXNoYXBlLWFuZC1sZW5ndGgifQ=="
                .to_string(),
        )
    }

    #[test]
    fn a_handoff_file_is_unreadable_by_other_local_users() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let payload = jit_payload();
        let handoff =
            RestrictiveHandoff::create(directory.path(), payload).expect("the file is created");

        let contents = std::fs::read_to_string(handoff.path()).expect("this account can read it");
        assert_eq!(contents, jit_payload().expose_secret());

        let permissions = handoff.permissions().expect("inspectable");
        assert!(
            !permissions.readable_by_other_local_users,
            "the JIT handoff is readable by other local accounts: {}",
            permissions.description
        );
    }

    #[test]
    fn the_permissions_check_catches_a_world_readable_file() {
        // Without this, `a_handoff_file_is_unreadable_by_other_local_users`
        // could be passing because the check always says "no". Create a file
        // the ordinary way — inheriting whatever the directory grants, with no
        // restriction applied — and require the check to tell it apart from the
        // restrictive one.
        let directory = tempfile::tempdir().expect("a temporary directory");

        let restrictive = directory.path().join("restrictive");
        drop(super::sys::create_restrictive_file(&restrictive).expect("created"));
        let restrictive_summary = permissions_summary(&restrictive).expect("inspectable");
        assert!(!restrictive_summary.readable_by_other_local_users);

        let open = directory.path().join("open");
        std::fs::write(&open, b"not a secret").expect("created");
        make_world_readable(&open);
        let open_summary = permissions_summary(&open).expect("inspectable");

        assert!(
            open_summary.readable_by_other_local_users,
            "a deliberately permissive file was reported as restricted, so the assertion in \
             `a_handoff_file_is_unreadable_by_other_local_users` proves nothing. \
             restrictive={} permissive={}",
            restrictive_summary.description, open_summary.description
        );
    }

    #[cfg(unix)]
    fn make_world_readable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
            .expect("the mode can be widened");
    }

    #[cfg(windows)]
    fn make_world_readable(path: &Path) {
        // `icacls` is part of Windows itself and is the shortest way to put a
        // real Everyone ACE on a real file. Test-only: nothing in the product
        // ever widens a DACL.
        //
        // Best effort, and the caller's assertion does not depend on it. A file
        // created the ordinary way already inherits the parent directory's
        // DACL, which is unprotected — and an unprotected DACL is by itself
        // something `dacl_grants_broad_access` must report, because this
        // program cannot vouch for what a directory it did not create grants.
        let _ = std::process::Command::new("icacls")
            .arg(path)
            .args(["/grant", "*S-1-1-0:(R)"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    #[test]
    fn a_handoff_file_is_deleted_on_the_success_path() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let handoff = RestrictiveHandoff::create(directory.path(), jit_payload()).expect("created");
        let path = handoff.path().to_path_buf();
        assert!(path.exists());

        handoff.delete().expect("deletable");
        assert!(!path.exists(), "the handoff outlived its explicit deletion");
    }

    #[test]
    fn a_handoff_file_is_deleted_on_the_failure_path() {
        let directory = tempfile::tempdir().expect("a temporary directory");

        // A launch that fails after the handoff exists. `?` unwinds through
        // `RestrictiveHandoff`'s `Drop`, which is the only thing standing
        // between a failed start and a JIT configuration left on disk.
        fn launch_and_fail(directory: &Path) -> Result<PathBuf, ProcessError> {
            let handoff = RestrictiveHandoff::create(directory, jit_payload())
                .expect("the handoff is created");
            let path = handoff.path().to_path_buf();
            SpawnSpec::new("a-program-that-does-not-exist-anywhere")
                .arg(handoff.path())
                .spawn_with_handoff(&handoff)?;
            Ok(path)
        }

        let before = std::fs::read_dir(directory.path())
            .expect("readable")
            .count();
        assert_eq!(before, 0, "the temporary directory should start empty");

        let error = launch_and_fail(directory.path()).expect_err("the program does not exist");
        assert!(matches!(error, ProcessError::Spawn { .. }), "{error}");

        let remaining: Vec<PathBuf> = std::fs::read_dir(directory.path())
            .expect("readable")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        assert!(
            remaining.is_empty(),
            "a failed start left the JIT handoff on disk: {remaining:?}"
        );
    }

    #[test]
    fn a_handoff_file_is_deleted_when_a_panic_unwinds_past_it() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let root = directory.path().to_path_buf();

        let panicked = std::panic::catch_unwind(move || {
            let _handoff = RestrictiveHandoff::create(&root, jit_payload()).expect("created");
            panic!("something went wrong after the handoff was written");
        });
        assert!(panicked.is_err());

        let remaining: Vec<PathBuf> = std::fs::read_dir(directory.path())
            .expect("readable")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        assert!(
            remaining.is_empty(),
            "a panic left the JIT handoff on disk: {remaining:?}"
        );
    }

    #[test]
    fn spawning_refuses_to_put_the_payload_in_an_argument() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let handoff = RestrictiveHandoff::create(directory.path(), jit_payload()).expect("created");

        // The mistake `07-security.md`'s threat table names: the configuration
        // itself on the command line, where every local account's process
        // listing shows it.
        let spec = long_running()
            .arg("--jit-config")
            .arg(jit_payload().expose_secret());

        let error = spec
            .spawn_with_handoff(&handoff)
            .expect_err("the payload must never reach a command line");
        match error {
            ProcessError::SecretInCommandLine { location, .. } => {
                assert!(location.starts_with("argument"), "{location}");
            }
            other => panic!("expected a refusal, got {other}"),
        }
    }

    #[test]
    fn spawning_refuses_to_put_the_payload_in_the_environment() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let handoff = RestrictiveHandoff::create(directory.path(), jit_payload()).expect("created");

        let spec = long_running().env("ACTIONS_RUNNER_JITCONFIG", jit_payload().expose_secret());

        let error = spec
            .spawn_with_handoff(&handoff)
            .expect_err("the payload must not be inherited through the environment either");
        match error {
            ProcessError::SecretInCommandLine { location, .. } => {
                assert!(location.contains("ACTIONS_RUNNER_JITCONFIG"), "{location}");
            }
            other => panic!("expected a refusal, got {other}"),
        }
    }

    #[test]
    fn runner_handoff_injects_the_supported_secret_input_without_an_argument() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let payload = jit_payload();
        let payload_length = payload.expose_secret().len();
        let handoff = RestrictiveHandoff::create(directory.path(), payload).expect("created");
        let spec = runner_jit_input_probe(payload_length);

        let rendered: Vec<String> = spec
            .arguments()
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert!(
            rendered
                .iter()
                .all(|argument| !argument.contains(jit_payload().expose_secret())),
            "the JIT payload reached the command line: {rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .all(|argument| argument != "--jit-config-file"),
            "the obsolete listener option returned: {rendered:?}"
        );

        let mut child = spec
            .spawn_runner_with_handoff(&handoff)
            .expect("the probe starts");
        handoff
            .delete()
            .expect("the handoff is deleted immediately");
        let status = child.wait().expect("the probe exits");
        assert!(
            status.success(),
            "the child did not receive the complete {RUNNER_JIT_CONFIG_ENV} input: {status}"
        );
    }

    #[cfg(windows)]
    fn runner_jit_input_probe(expected_length: usize) -> SpawnSpec {
        SpawnSpec::new("powershell.exe").args([
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            format!(
                "$value = [Environment]::GetEnvironmentVariable('{RUNNER_JIT_CONFIG_ENV}'); \
                 if ($null -eq $value -or $value.Length -ne {expected_length}) {{ exit 41 }}"
            ),
        ])
    }

    #[cfg(unix)]
    fn runner_jit_input_probe(expected_length: usize) -> SpawnSpec {
        SpawnSpec::new("/bin/sh").args([
            "-c".to_owned(),
            format!("test \"${{#{RUNNER_JIT_CONFIG_ENV}}}\" -eq \"{expected_length}\""),
        ])
    }

    #[test]
    fn spawning_allows_the_handoff_path_itself() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let handoff = RestrictiveHandoff::create(directory.path(), jit_payload()).expect("created");

        let spec = long_running().arg("--jit-config-file").arg(handoff.path());
        let mut child = spec
            .spawn_with_handoff(&handoff)
            .expect("passing the path is the supported handoff");

        // What a process listing would show: the path, and nothing that
        // contains the payload.
        let rendered: Vec<String> = spec
            .arguments()
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let payload = jit_payload();
        assert!(
            rendered
                .iter()
                .all(|arg| !arg.contains(payload.expose_secret())),
            "the payload reached the argument vector: {rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|arg| arg == &handoff.path().display().to_string()),
            "the handoff path should be there: {rendered:?}"
        );

        child.stop(Duration::from_secs(10)).expect("cleanup");
    }

    #[test]
    fn the_handoff_path_is_unique_per_handoff() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let first = RestrictiveHandoff::create(directory.path(), jit_payload()).expect("created");
        let second = RestrictiveHandoff::create(directory.path(), jit_payload()).expect("created");

        assert_ne!(
            first.path(),
            second.path(),
            "two concurrent attempts must not share a handoff file"
        );
    }

    #[test]
    fn the_payload_has_no_debug_or_display_that_reveals_it() {
        // The structural half of the control: even a careless
        // `format!("{:?}", …)` in a later task cannot print the configuration.
        let payload = jit_payload();
        let rendered = format!("{payload:?}");
        assert!(
            !rendered.contains(payload.expose_secret()),
            "SecretString's Debug leaked the payload: {rendered}"
        );

        let directory = tempfile::tempdir().expect("a temporary directory");
        let handoff = RestrictiveHandoff::create(directory.path(), jit_payload()).expect("created");
        let rendered = format!("{handoff:?}");
        assert!(
            !rendered.contains(jit_payload().expose_secret()),
            "RestrictiveHandoff's Debug leaked the payload: {rendered}"
        );
    }
}
