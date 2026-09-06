// owner: a1-wsl-platform-adapter

//! Running a program with a **literal argument vector**, bounded output, a
//! deadline, a cancellation flag, and an optional anonymous stdin pipe.
//!
//! # Why this exists instead of `std::process::Command`
//!
//! Everything the WSL adapter does is "run `wsl.exe` with these exact
//! arguments and read what it says". Three properties of that sentence are
//! load-bearing, and none of them is `Command`'s default:
//!
//! 1. **There is no shell.** Not a `cmd /c`, not a `bash -c`, not a string that
//!    something downstream re-splits. [`CommandRequest`] holds a program and a
//!    `Vec<OsString>`, and that is the only shape it can hold — a distribution
//!    named `Ubuntu & rm -rf /` is one argument, everywhere, by construction.
//! 2. **Output is bounded.** `Command::output` reads until EOF. A hung child
//!    writing to stderr in a loop would then be an unbounded allocation in a
//!    service that is supposed to stay up. [`OutputLimits`] caps what is kept
//!    while still draining the pipe, because a child that is not drained
//!    blocks instead of finishing.
//! 3. **The credential goes in through stdin and comes out nowhere.**
//!    [`ChildInput::Piped`] holds its bytes in a [`secrecy::SecretBox`], its
//!    `Debug` prints a length, and [`CommandRequest::refuse_payload_in_argv`]
//!    refuses to launch at all if the payload is a verbatim substring of the
//!    program path or of any argument. `03-security-and-lifecycle.md` item 3
//!    says the document "is absent from argv, environment, provider records,
//!    logs, errors, status JSON, temporary files and scheduled-task XML"; this
//!    module is where the argv and environment halves of that are enforced
//!    rather than reviewed.
//!
//! # The environment half is enforced by absence
//!
//! [`CommandRequest`] has **no** method that sets an environment variable, and
//! [`HostCommandRunner`] makes no `env` call. That is deliberate and is the
//! whole control: there is no API through which a caller could put a secret in
//! the child's environment, so there is no code path to audit for one. The
//! child inherits this process's environment unchanged, which is the same
//! environment `wsl.exe` would have inherited from an operator's shell.
//!
//! # The seam
//!
//! [`CommandRunner`] is the injection point. Production uses
//! [`HostCommandRunner`], which really spawns. Tests use [`ScriptedRunner`],
//! which answers from a table and records every request — including the stdin
//! bytes, so that a test can assert a canary reached the child's stdin *and
//! nothing else*. Both are usable on every CI leg, which is what lets the
//! Windows-shaped logic in this module be tested on Linux and macOS too.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretBox, SecretString};

use super::WslError;

/// How long a probe-shaped command is given before it is killed.
///
/// Chosen against the slowest thing this adapter routinely asks for: the first
/// `wsl.exe` invocation after a boot starts the whole distribution, and a cold
/// start on a spinning disk is seconds, not milliseconds.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// How much of stdout is kept.
///
/// Everything this adapter reads from a child is a table, a version string, or
/// a task document; a megabyte is three orders of magnitude more than any of
/// them and still small enough to be irrelevant to a service's footprint.
pub const DEFAULT_STDOUT_LIMIT: usize = 1024 * 1024;

/// How much of stderr is kept. Smaller, because its only use is a diagnostic
/// sentence in an error.
pub const DEFAULT_STDERR_LIMIT: usize = 64 * 1024;

/// The largest payload [`CommandRequest::refuse_payload_in_argv`] scans for.
///
/// Above this there is nothing to check: Windows caps a command line at 32 767
/// characters, so a payload larger than that cannot be in one. The bound
/// matters because the artifact installer pipes a whole release archive
/// through the same [`ChildInput`], and scanning fifteen megabytes against
/// every argument on every install would be pure cost for a question whose
/// answer is already known.
const ARGV_SCAN_LIMIT: usize = 32 * 1024;

/// How often the wait loop looks at a running child.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

/// A flag a caller can raise to stop a running child early.
///
/// Deliberately not a channel or a future: the one caller is a synchronous
/// provisioning transaction that wants to abandon a `wsl.exe` invocation when
/// the operator hits Ctrl-C, and a shared boolean is the whole of that
/// requirement. Cloning shares the flag.
#[derive(Debug, Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    /// A flag that has not been raised.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Raises it. Every request holding a clone is killed at the next poll.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether it has been raised.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// The child's stdin
// ---------------------------------------------------------------------------

/// Bytes destined for a child's stdin, which never appear anywhere else.
///
/// The inner value is a [`SecretBox`] and the `Debug` implementation prints a
/// length. That is unconditional rather than opt-in: the two things this
/// adapter pipes are a GitHub credential document and a release archive, and
/// treating both as sensitive costs nothing while removing the possibility
/// that a future caller pipes a secret through the "not a secret" variant.
pub struct PipedInput {
    bytes: SecretBox<Vec<u8>>,
    length: usize,
}

impl PipedInput {
    /// Takes ownership of bytes to be written to the child.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let length = bytes.len();
        Self {
            bytes: SecretBox::new(Box::new(bytes)),
            length,
        }
    }

    /// The UTF-8 encoding of a secret string, which is how a stored credential
    /// document crosses the Windows/Linux boundary.
    #[must_use]
    pub fn from_secret_text(text: &SecretString) -> Self {
        Self::from_bytes(text.expose_secret().as_bytes().to_vec())
    }

    /// How many bytes will be written. Safe to print; the bytes are not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.length
    }

    /// Whether there is nothing to write.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// The bytes themselves.
    ///
    /// Crate-visible on purpose. Two callers need them — the runner that
    /// writes the pipe and [`ScriptedRunner`], which records them so a test can
    /// assert the payload arrived *here* and nowhere else — and neither is
    /// outside this crate. A caller in another crate that wants to make the
    /// same assertion goes through [`ScriptedRunner::piped_input`], which is
    /// one documented door rather than a general accessor.
    pub(crate) fn expose_bytes(&self) -> &[u8] {
        self.bytes.expose_secret()
    }
}

impl fmt::Debug for PipedInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PipedInput(<redacted; {} bytes>)", self.length)
    }
}

/// What the child sees on stdin.
#[derive(Debug, Default)]
pub enum ChildInput {
    /// An immediately closed pipe. A child that reads gets EOF.
    #[default]
    Empty,
    /// An anonymous pipe carrying these bytes, then closed.
    Piped(PipedInput),
}

impl ChildInput {
    /// The payload, when there is one.
    #[must_use]
    pub fn piped(&self) -> Option<&PipedInput> {
        match self {
            Self::Empty => None,
            Self::Piped(input) => Some(input),
        }
    }
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// How much of each stream is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputLimits {
    /// Bytes of stdout kept; the rest is drained and dropped.
    pub stdout: usize,
    /// Bytes of stderr kept.
    pub stderr: usize,
}

impl Default for OutputLimits {
    fn default() -> Self {
        Self {
            stdout: DEFAULT_STDOUT_LIMIT,
            stderr: DEFAULT_STDERR_LIMIT,
        }
    }
}

/// One program, one literal argument vector, and the bounds it runs under.
///
/// There is no `env`, no `current_dir`, and no shell. See the module
/// documentation for why each absence is a control rather than an omission.
#[derive(Default)]
pub struct CommandRequest {
    program: PathBuf,
    arguments: Vec<OsString>,
    input: ChildInput,
    limits: OutputLimits,
    timeout: Duration,
    cancellation: Option<Cancellation>,
}

impl CommandRequest {
    /// A request to run `program` with no arguments.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            input: ChildInput::Empty,
            limits: OutputLimits::default(),
            timeout: DEFAULT_TIMEOUT,
            cancellation: None,
        }
    }

    /// Appends one argument, verbatim.
    #[must_use]
    pub fn arg(mut self, argument: impl Into<OsString>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    /// Appends several arguments, verbatim and in order.
    #[must_use]
    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    /// Gives the child something on stdin.
    #[must_use]
    pub fn with_input(mut self, input: ChildInput) -> Self {
        self.input = input;
        self
    }

    /// Replaces the default deadline.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replaces the default capture bounds.
    #[must_use]
    pub fn with_limits(mut self, limits: OutputLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Lets a caller kill this child before its deadline.
    #[must_use]
    pub fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// The program that will be launched.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The argument vector, in order.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// The argument vector as lossy strings, for assertions and diagnostics.
    #[must_use]
    pub fn argument_strings(&self) -> Vec<String> {
        self.arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    /// What the child will see on stdin.
    #[must_use]
    pub fn input(&self) -> &ChildInput {
        &self.input
    }

    /// The capture bounds.
    #[must_use]
    pub fn limits(&self) -> OutputLimits {
        self.limits
    }

    /// The deadline.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The cancellation flag, when one was attached.
    #[must_use]
    pub fn cancellation(&self) -> Option<&Cancellation> {
        self.cancellation.as_ref()
    }

    /// Refuses the launch when the stdin payload is also in the command line.
    ///
    /// The same tripwire as [`crate::process::SpawnSpec::spawn_with_handoff`],
    /// and with the same honest limits: it looks for the payload as a verbatim
    /// byte substring of the program path and of each argument, and that is
    /// all. A payload that is re-encoded, split across two arguments, or
    /// normalised differently walks straight past it. It is here because an
    /// *obvious* mistake should fail the launch rather than fail a review — not
    /// because passing it is evidence of anything.
    ///
    /// Payloads larger than a Windows command line cannot be in one, so they
    /// are not scanned.
    ///
    /// # Errors
    ///
    /// [`WslError::SecretInCommandLine`] naming where the payload was found.
    pub fn refuse_payload_in_argv(&self) -> Result<(), WslError> {
        let Some(payload) = self.input.piped() else {
            return Ok(());
        };
        if payload.is_empty() || payload.len() > ARGV_SCAN_LIMIT {
            return Ok(());
        }
        let needle = payload.expose_bytes();
        let found_in = |value: &OsStr| {
            let text = value.to_string_lossy();
            contains_subslice(text.as_bytes(), needle)
        };
        if found_in(self.program.as_os_str()) {
            return Err(WslError::SecretInCommandLine {
                program: self.program.clone(),
                location: "the program path".to_string(),
            });
        }
        for (index, argument) in self.arguments.iter().enumerate() {
            if found_in(argument) {
                return Err(WslError::SecretInCommandLine {
                    program: self.program.clone(),
                    location: format!("argument {index}"),
                });
            }
        }
        Ok(())
    }
}

/// `Debug` that cannot print the payload: [`PipedInput`]'s own `Debug` prints
/// a length, and every other field is a program name, an argument, or a bound.
impl fmt::Debug for CommandRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandRequest")
            .field("program", &self.program)
            .field("arguments", &self.arguments)
            .field("input", &self.input)
            .field("limits", &self.limits)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Whether `haystack` contains `needle`.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// The result
// ---------------------------------------------------------------------------

/// How a child stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// It ran to the end by itself.
    Exited,
    /// Its deadline passed and it was killed.
    TimedOut,
    /// Its cancellation flag was raised and it was killed.
    Cancelled,
}

/// What a child said and how it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    completion: Completion,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

impl CommandOutput {
    /// A completed run, for a test double or for the real runner.
    #[must_use]
    pub fn exited(exit_code: i32, stdout: impl Into<Vec<u8>>, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            completion: Completion::Exited,
            exit_code: Some(exit_code),
            stdout: stdout.into(),
            stderr: stderr.into(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    /// A run that hit its deadline.
    #[must_use]
    pub fn timed_out() -> Self {
        Self {
            completion: Completion::TimedOut,
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    /// Marks the captured streams as having been cut short.
    #[must_use]
    pub fn with_truncation(mut self, stdout: bool, stderr: bool) -> Self {
        self.stdout_truncated = stdout;
        self.stderr_truncated = stderr;
        self
    }

    /// How it stopped.
    #[must_use]
    pub fn completion(&self) -> Completion {
        self.completion
    }

    /// The exit code, when the process exited with one.
    ///
    /// `None` covers both a killed child and a Unix child that died of a
    /// signal, which have no code to report.
    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Whether it exited by itself with status zero.
    #[must_use]
    pub fn success(&self) -> bool {
        self.completion == Completion::Exited && self.exit_code == Some(0)
    }

    /// The captured stdout bytes.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// The captured stderr bytes.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Whether stdout was longer than the limit.
    #[must_use]
    pub fn stdout_truncated(&self) -> bool {
        self.stdout_truncated
    }

    /// Whether stderr was longer than the limit.
    #[must_use]
    pub fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }

    /// stdout decoded for a human, trimmed.
    ///
    /// Goes through [`super::discovery::decode_console_output`] rather than
    /// `from_utf8_lossy`, because the Windows console programs this adapter
    /// runs answer in UTF-16 as often as in UTF-8.
    #[must_use]
    pub fn stdout_text(&self) -> String {
        super::discovery::decode_console_output(&self.stdout)
            .into_text()
            .trim()
            .to_string()
    }

    /// stderr decoded for a human, trimmed.
    #[must_use]
    pub fn stderr_text(&self) -> String {
        super::discovery::decode_console_output(&self.stderr)
            .into_text()
            .trim()
            .to_string()
    }

    /// The sentence an error carries: whichever stream said something.
    #[must_use]
    pub fn diagnostic(&self) -> String {
        let stderr = self.stderr_text();
        if !stderr.is_empty() {
            return stderr;
        }
        let stdout = self.stdout_text();
        if !stdout.is_empty() {
            return stdout;
        }
        match self.completion {
            Completion::Exited => match self.exit_code {
                Some(code) => format!("it exited with status {code} and said nothing"),
                None => "it was terminated and said nothing".to_string(),
            },
            Completion::TimedOut => "it did not finish before its deadline".to_string(),
            Completion::Cancelled => "it was cancelled".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

/// Runs a [`CommandRequest`].
///
/// The whole reason the WSL adapter is testable on a Linux CI leg: production
/// injects [`HostCommandRunner`], every test injects [`ScriptedRunner`], and
/// nothing above this trait knows the difference.
pub trait CommandRunner: fmt::Debug + Send + Sync {
    /// Runs it, or says why it could not be started.
    ///
    /// A non-zero exit is **not** an error here — it is a [`CommandOutput`]
    /// with a code. Only a failure to launch, a refused payload, or an
    /// operating-system failure while waiting is an `Err`.
    ///
    /// # Errors
    ///
    /// [`WslError::Spawn`], [`WslError::SecretInCommandLine`], or
    /// [`WslError::ChildControl`].
    fn run(&self, request: &CommandRequest) -> Result<CommandOutput, WslError>;
}

// ---------------------------------------------------------------------------
// The real runner
// ---------------------------------------------------------------------------

/// Really spawns the program.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostCommandRunner;

impl CommandRunner for HostCommandRunner {
    fn run(&self, request: &CommandRequest) -> Result<CommandOutput, WslError> {
        request.refuse_payload_in_argv()?;

        // No `.env()`, no `.env_clear()`, no `.current_dir()`. See the module
        // documentation: the absence is the control.
        let mut command = Command::new(request.program());
        command
            .args(request.arguments())
            .stdin(match request.input() {
                ChildInput::Empty => Stdio::null(),
                ChildInput::Piped(_) => Stdio::piped(),
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().map_err(|source| WslError::Spawn {
            program: request.program().to_path_buf(),
            source,
        })?;

        let stdin = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .expect("stdout was piped when the child was configured");
        let stderr = child
            .stderr
            .take()
            .expect("stderr was piped when the child was configured");
        let limits = request.limits();

        // Scoped threads rather than spawned ones so that the payload is
        // *borrowed* by the writer: moving it would mean a second copy of a
        // credential on the heap for the lifetime of the call.
        let (waited, out, err) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || write_input(stdin, request.input()));
            let out = scope.spawn(move || read_bounded(stdout, limits.stdout));
            let err = scope.spawn(move || read_bounded(stderr, limits.stderr));
            let waited = wait_for(&mut child, request.timeout(), request.cancellation());
            // A write that failed because the child stopped reading is the
            // ordinary shape of a refused handoff, and the child's own exit
            // status is the better diagnostic. It is dropped rather than
            // reported for that reason.
            drop(writer.join());
            (
                waited,
                out.join().unwrap_or_else(|_| (Vec::new(), false)),
                err.join().unwrap_or_else(|_| (Vec::new(), false)),
            )
        });

        let (completion, exit_code) = waited.map_err(|source| WslError::ChildControl {
            program: request.program().to_path_buf(),
            source,
        })?;

        Ok(CommandOutput {
            completion,
            exit_code,
            stdout: out.0,
            stderr: err.0,
            stdout_truncated: out.1,
            stderr_truncated: err.1,
        })
    }
}

/// Writes the payload and closes the pipe, so a child blocked on EOF proceeds.
fn write_input(stdin: Option<std::process::ChildStdin>, input: &ChildInput) -> std::io::Result<()> {
    let Some(mut pipe) = stdin else {
        return Ok(());
    };
    if let Some(payload) = input.piped() {
        pipe.write_all(payload.expose_bytes())?;
        pipe.flush()?;
    }
    drop(pipe);
    Ok(())
}

/// Reads to EOF, keeping at most `limit` bytes.
///
/// It keeps reading after the limit rather than stopping: a child whose pipe
/// is full blocks in `write`, so a reader that gives up early converts a
/// chatty child into a hung one.
fn read_bounded(mut source: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut kept: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let room = limit.saturating_sub(kept.len());
                if room > 0 {
                    kept.extend_from_slice(&buffer[..read.min(room)]);
                }
                if read > room {
                    truncated = true;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (kept, truncated)
}

/// Waits for the child, killing it on its deadline or on cancellation.
fn wait_for(
    child: &mut Child,
    timeout: Duration,
    cancellation: Option<&Cancellation>,
) -> std::io::Result<(Completion, Option<i32>)> {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((Completion::Exited, status.code()));
        }
        if cancellation.is_some_and(Cancellation::is_cancelled) {
            child.kill()?;
            let status = child.wait()?;
            return Ok((Completion::Cancelled, status.code()));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            child.kill()?;
            let status = child.wait()?;
            return Ok((Completion::TimedOut, status.code()));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

// ---------------------------------------------------------------------------
// The test double
// ---------------------------------------------------------------------------

/// One request as [`ScriptedRunner`] saw it.
///
/// The stdin bytes are held verbatim. That is the point: a security test
/// injects a canary, runs the adapter, and asserts the canary is in
/// [`RecordedRequest::stdin`] and in no argument, no rendered document, and no
/// file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    /// The program that would have been launched.
    pub program: PathBuf,
    /// The literal argument vector.
    pub arguments: Vec<String>,
    /// What would have been written to the child's stdin.
    pub stdin: Vec<u8>,
    /// The deadline it would have run under.
    pub timeout: Duration,
}

impl RecordedRequest {
    /// The program and arguments joined by a single space, for a match rule.
    #[must_use]
    pub fn command_line(&self) -> String {
        let mut line = self.program.to_string_lossy().into_owned();
        for argument in &self.arguments {
            line.push(' ');
            line.push_str(argument);
        }
        line
    }
}

/// A [`CommandRunner`] that answers from a table and records what it was asked.
///
/// Match rules are checked in the order they were added, against the
/// space-joined command line, as a substring. The first rule that matches
/// answers; an unmatched request gets [`ScriptedRunner::default_response`],
/// which starts as a successful, silent exit.
#[derive(Debug, Default)]
pub struct ScriptedRunner {
    rules: Mutex<Vec<Rule>>,
    recorded: Mutex<Vec<RecordedRequest>>,
    default_response: Mutex<Option<CommandOutput>>,
}

#[derive(Debug)]
struct Rule {
    contains: String,
    responses: Vec<CommandOutput>,
    used: usize,
}

impl ScriptedRunner {
    /// A runner whose every answer is a silent success.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers any request whose command line contains `contains` with
    /// `response`, for every match.
    #[must_use]
    pub fn always(self, contains: &str, response: CommandOutput) -> Self {
        self.push_rule(contains, vec![response]);
        self
    }

    /// Answers successive matches of `contains` with successive responses, and
    /// repeats the last one once the list is exhausted.
    #[must_use]
    pub fn sequence(self, contains: &str, responses: Vec<CommandOutput>) -> Self {
        self.push_rule(contains, responses);
        self
    }

    /// Replaces the answer given to a request no rule matched.
    #[must_use]
    pub fn otherwise(self, response: CommandOutput) -> Self {
        *self
            .default_response
            .lock()
            .expect("the scripted runner's response is not shared across a panic") = Some(response);
        self
    }

    fn push_rule(&self, contains: &str, responses: Vec<CommandOutput>) {
        self.rules
            .lock()
            .expect("the scripted runner's rules are not shared across a panic")
            .push(Rule {
                contains: contains.to_string(),
                responses,
                used: 0,
            });
    }

    /// Every request, in the order it was made.
    #[must_use]
    pub fn recorded(&self) -> Vec<RecordedRequest> {
        self.recorded
            .lock()
            .expect("the scripted runner's log is not shared across a panic")
            .clone()
    }

    /// How many requests were made.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.recorded
            .lock()
            .expect("the scripted runner's log is not shared across a panic")
            .len()
    }

    /// The command lines, joined, for a coarse assertion.
    #[must_use]
    pub fn command_lines(&self) -> Vec<String> {
        self.recorded()
            .iter()
            .map(RecordedRequest::command_line)
            .collect()
    }

    /// Everything that was written to a child's stdin, concatenated.
    ///
    /// The documented door for a security test in another crate: it is the one
    /// place a piped payload can be read back, so an assertion that a canary is
    /// *here and nowhere else* has exactly one thing to look at.
    #[must_use]
    pub fn piped_input(&self) -> Vec<u8> {
        let mut all = Vec::new();
        for request in self.recorded() {
            all.extend_from_slice(&request.stdin);
        }
        all
    }
}

impl CommandRunner for ScriptedRunner {
    fn run(&self, request: &CommandRequest) -> Result<CommandOutput, WslError> {
        request.refuse_payload_in_argv()?;
        let recorded = RecordedRequest {
            program: request.program().to_path_buf(),
            arguments: request.argument_strings(),
            stdin: request
                .input()
                .piped()
                .map(|input| input.expose_bytes().to_vec())
                .unwrap_or_default(),
            timeout: request.timeout(),
        };
        let line = recorded.command_line();
        self.recorded
            .lock()
            .expect("the scripted runner's log is not shared across a panic")
            .push(recorded);

        let mut rules = self
            .rules
            .lock()
            .expect("the scripted runner's rules are not shared across a panic");
        for rule in rules.iter_mut() {
            if line.contains(&rule.contains) {
                let index = rule.used.min(rule.responses.len().saturating_sub(1));
                rule.used += 1;
                if let Some(response) = rule.responses.get(index) {
                    return Ok(response.clone());
                }
            }
        }
        drop(rules);

        Ok(self
            .default_response
            .lock()
            .expect("the scripted runner's response is not shared across a panic")
            .clone()
            .unwrap_or_else(|| CommandOutput::exited(0, Vec::new(), Vec::new())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canary() -> SecretString {
        SecretString::from(format!("{}{}", "ghu_", "a1WslFixtureNotARealCredential00"))
    }

    #[test]
    fn a_piped_payload_never_appears_in_debug_output() {
        let secret = canary();
        let request = CommandRequest::new("wsl.exe")
            .arg("--distribution")
            .arg("Ubuntu")
            .with_input(ChildInput::Piped(PipedInput::from_secret_text(&secret)));

        let printed = format!("{request:?}");
        assert!(
            !printed.contains(secret.expose_secret()),
            "the payload reached Debug output: {printed}"
        );
        assert!(
            printed.contains("<redacted; 36 bytes>"),
            "the redacted form should still say how much there was: {printed}"
        );
    }

    #[test]
    fn a_payload_that_is_also_an_argument_refuses_to_launch() {
        let secret = canary();
        let request = CommandRequest::new("wsl.exe")
            .arg("--exec")
            .arg(format!("--token={}", secret.expose_secret()))
            .with_input(ChildInput::Piped(PipedInput::from_secret_text(&secret)));

        let error = request
            .refuse_payload_in_argv()
            .expect_err("the payload is in argument 1");
        assert!(
            matches!(&error, WslError::SecretInCommandLine { location, .. } if location == "argument 1"),
            "unexpected error: {error:?}"
        );
        // And the refusal itself must not quote the payload.
        assert!(!error.to_string().contains(secret.expose_secret()));
    }

    #[test]
    fn a_payload_that_is_only_on_stdin_is_allowed() {
        let secret = canary();
        let request = CommandRequest::new("wsl.exe")
            .arg("--distribution")
            .arg("Ubuntu")
            .with_input(ChildInput::Piped(PipedInput::from_secret_text(&secret)));
        request
            .refuse_payload_in_argv()
            .expect("stdin is the supported channel");
    }

    #[test]
    fn a_payload_too_large_for_a_command_line_is_not_scanned() {
        // A release archive goes through the same pipe; scanning it would cost
        // megabytes of comparison to answer a question Windows already answers.
        let request = CommandRequest::new("wsl.exe")
            .arg("--exec")
            .with_input(ChildInput::Piped(PipedInput::from_bytes(vec![
                b'x';
                ARGV_SCAN_LIMIT
                    + 1
            ])));
        request.refuse_payload_in_argv().expect("not scanned");
    }

    #[test]
    fn arguments_are_kept_verbatim_and_never_joined() {
        let request = CommandRequest::new("wsl.exe")
            .arg("--distribution")
            .arg("Ubuntu & shutdown /s")
            .arg("--exec");
        assert_eq!(
            request.argument_strings(),
            vec![
                "--distribution".to_string(),
                "Ubuntu & shutdown /s".to_string(),
                "--exec".to_string(),
            ]
        );
    }

    #[test]
    fn a_scripted_runner_answers_in_rule_order_and_records_stdin() {
        let secret = canary();
        let runner = ScriptedRunner::new()
            .always(
                "--version",
                CommandOutput::exited(0, "runner-manager 0.4.0", ""),
            )
            .otherwise(CommandOutput::exited(1, "", "no rule"));

        let versioned = runner
            .run(&CommandRequest::new("wsl.exe").arg("--version"))
            .expect("scripted");
        assert_eq!(versioned.stdout_text(), "runner-manager 0.4.0");

        let other = runner
            .run(
                &CommandRequest::new("wsl.exe")
                    .arg("--exec")
                    .with_input(ChildInput::Piped(PipedInput::from_secret_text(&secret))),
            )
            .expect("scripted");
        assert_eq!(other.exit_code(), Some(1));

        assert_eq!(runner.call_count(), 2);
        assert_eq!(runner.piped_input(), secret.expose_secret().as_bytes());
        assert!(
            runner
                .command_lines()
                .iter()
                .all(|line| !line.contains(secret.expose_secret())),
            "the canary must not be in any recorded command line"
        );
    }

    #[test]
    fn a_sequence_rule_advances_and_then_repeats_its_last_answer() {
        let runner = ScriptedRunner::new().sequence(
            "probe",
            vec![
                CommandOutput::exited(1, "", "not yet"),
                CommandOutput::exited(0, "ready", ""),
            ],
        );
        let first = runner.run(&CommandRequest::new("probe")).expect("scripted");
        let second = runner.run(&CommandRequest::new("probe")).expect("scripted");
        let third = runner.run(&CommandRequest::new("probe")).expect("scripted");
        assert_eq!(first.exit_code(), Some(1));
        assert_eq!(second.stdout_text(), "ready");
        assert_eq!(third.stdout_text(), "ready");
    }

    #[test]
    fn output_is_bounded_but_the_stream_is_still_drained() {
        let (kept, truncated) = read_bounded(&b"0123456789"[..], 4);
        assert_eq!(kept, b"0123");
        assert!(truncated);

        let (kept, truncated) = read_bounded(&b"012"[..], 4);
        assert_eq!(kept, b"012");
        assert!(!truncated);
    }

    #[test]
    fn a_diagnostic_prefers_stderr_and_never_invents_one() {
        let output = CommandOutput::exited(2, "some stdout", "the real reason");
        assert_eq!(output.diagnostic(), "the real reason");

        let output = CommandOutput::exited(2, "some stdout", "");
        assert_eq!(output.diagnostic(), "some stdout");

        let output = CommandOutput::exited(2, "", "");
        assert_eq!(
            output.diagnostic(),
            "it exited with status 2 and said nothing"
        );

        assert_eq!(
            CommandOutput::timed_out().diagnostic(),
            "it did not finish before its deadline"
        );
    }

    #[test]
    fn cancellation_is_shared_by_every_clone() {
        let cancellation = Cancellation::new();
        let clone = cancellation.clone();
        assert!(!clone.is_cancelled());
        cancellation.cancel();
        assert!(clone.is_cancelled());
    }

    // -- The real runner, exercised against a program every CI leg has -------
    //
    // `HostCommandRunner` is the one thing here that cannot be proven with a
    // double, so it is proven against this very test binary: `std::env::args`
    // gives a program that certainly exists on all three platforms, and the
    // harness's own `--list` flag makes it exit quickly with output.

    fn this_test_binary() -> PathBuf {
        std::env::current_exe().expect("a test binary knows its own path")
    }

    #[test]
    fn the_host_runner_captures_output_and_an_exit_code() {
        let output = HostCommandRunner
            .run(
                &CommandRequest::new(this_test_binary())
                    .arg("--list")
                    .with_timeout(Duration::from_secs(60)),
            )
            .expect("this binary can run itself");
        assert_eq!(output.completion(), Completion::Exited);
        assert_eq!(output.exit_code(), Some(0));
        assert!(
            output.stdout_text().contains("test"),
            "`--list` should name at least one test: {}",
            output.stdout_text()
        );
    }

    #[test]
    fn the_host_runner_reports_a_program_that_is_not_there() {
        let error = HostCommandRunner
            .run(&CommandRequest::new(
                "runner-manager-a1-no-such-program-exists",
            ))
            .expect_err("there is no such program");
        assert!(matches!(error, WslError::Spawn { .. }), "{error:?}");
    }

    #[test]
    fn the_host_runner_bounds_what_it_keeps() {
        let output = HostCommandRunner
            .run(
                &CommandRequest::new(this_test_binary())
                    .arg("--list")
                    .with_limits(OutputLimits {
                        stdout: 8,
                        stderr: 8,
                    })
                    .with_timeout(Duration::from_secs(60)),
            )
            .expect("this binary can run itself");
        assert!(output.stdout().len() <= 8);
        assert!(output.stdout_truncated());
    }

    #[test]
    fn the_host_runner_kills_a_child_that_outlives_its_deadline() {
        // `--test-threads` with no value makes libtest wait on stdin? No: it
        // errors out. The reliable "runs forever" program on all three
        // platforms is this binary running the sleeping test below, which is
        // `#[ignore]`d in an ordinary run and selected by name here.
        let output = HostCommandRunner
            .run(
                &CommandRequest::new(this_test_binary())
                    .arg("--exact")
                    .arg("wsl::exec::tests::a_child_that_never_finishes")
                    .arg("--ignored")
                    .arg("--nocapture")
                    .with_timeout(Duration::from_millis(300)),
            )
            .expect("this binary can run itself");
        assert_eq!(output.completion(), Completion::TimedOut);
    }

    #[test]
    fn the_host_runner_kills_a_cancelled_child() {
        let cancellation = Cancellation::new();
        let flag = cancellation.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            flag.cancel();
        });
        let output = HostCommandRunner
            .run(
                &CommandRequest::new(this_test_binary())
                    .arg("--exact")
                    .arg("wsl::exec::tests::a_child_that_never_finishes")
                    .arg("--ignored")
                    .arg("--nocapture")
                    .with_timeout(Duration::from_secs(60))
                    .with_cancellation(cancellation),
            )
            .expect("this binary can run itself");
        assert_eq!(output.completion(), Completion::Cancelled);
    }

    #[test]
    fn the_host_runner_writes_stdin_and_the_child_reads_it() {
        // The child is this binary again, selected onto the echoing test below.
        let payload = b"a1-wsl-stdin-round-trip\n".to_vec();
        let output = HostCommandRunner
            .run(
                &CommandRequest::new(this_test_binary())
                    .arg("--exact")
                    .arg("wsl::exec::tests::a_child_that_echoes_its_stdin")
                    .arg("--ignored")
                    .arg("--nocapture")
                    .with_input(ChildInput::Piped(PipedInput::from_bytes(payload)))
                    .with_timeout(Duration::from_secs(60)),
            )
            .expect("this binary can run itself");
        assert!(
            output.stdout_text().contains("a1-wsl-stdin-round-trip"),
            "the child did not see the payload: {}",
            output.stdout_text()
        );
    }

    /// Not a test: the child program the deadline and cancellation tests need.
    ///
    /// Bounded at thirty seconds rather than left to sleep forever. Nothing
    /// selects it except the two tests above, both of which kill it in well
    /// under a second — but a stray `cargo test -- --ignored` should cost half
    /// a minute rather than hang a developer's terminal.
    #[test]
    #[ignore = "a helper child process, selected by name by the tests above"]
    fn a_child_that_never_finishes() {
        std::thread::sleep(Duration::from_secs(30));
    }

    /// Not a test: the child program the stdin test needs.
    #[test]
    #[ignore = "a helper child process, selected by name by the test above"]
    fn a_child_that_echoes_its_stdin() {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
            .expect("the parent writes and closes the pipe");
        println!("{text}");
    }
}
