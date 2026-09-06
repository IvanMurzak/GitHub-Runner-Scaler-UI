// owner: a1-wsl-platform-adapter

//! The one Windows login task that keeps a managed WSL distribution alive,
//! and the four operations on it: render, register, query, remove.
//!
//! # What the task promises, and what it does not
//!
//! WSL distributions are registered **per user**, so nothing that runs before
//! a user logs on can start one. The 2026-09-06 review closed exactly this
//! defect: an earlier design promised boot availability that Windows cannot
//! deliver. So this is a `LogonTrigger` task for one named principal, and
//! `02-target-architecture.md` states the consequence in the product's own
//! words — *"unattended Linux availability after that user's logon, not before
//! any interactive logon after a Windows reboot"*.
//!
//! # There is no shell text in the action, at any layer
//!
//! The other half of that review closed a design that composed `systemctl` and
//! a keep-alive through a shell string. The action here is
//!
//! ```text
//! <Command>C:\Windows\System32\wsl.exe</Command>
//! <Arguments>--distribution Ubuntu --user root --exec /usr/local/bin/runner-manager wsl-host hold</Arguments>
//! ```
//!
//! Task Scheduler has no `Arguments` *vector* — the element is a single string
//! that Windows splits with `CommandLineToArgvW` — so
//! [`LifecycleTask::action_arguments`] builds the vector and
//! [`LifecycleTask::rendered_arguments`] quotes each element with the same
//! function the service installer uses. A distribution called `My Ubuntu` is
//! therefore `"My Ubuntu"` in the document and one argument again on the way
//! out. What is *not* there is a `cmd /c`, a `&&`, a `;`, or anything else a
//! shell would interpret, and `no_shell_text_reaches_the_task_document` is the
//! test that keeps it that way.
//!
//! `wsl-host hold` is a hidden Linux-only command that starts the existing
//! systemd unit by argument-vector process execution and then stays alive.
//! Naming it here is this crate's whole contribution to the lifecycle: the
//! Linux side of it belongs to the CLI.
//!
//! # A task this did not create is never touched
//!
//! The name is derived from the distribution, so two workstations agree on it
//! and a re-run updates the task rather than accumulating copies. That same
//! determinism means the name could collide with something an operator made by
//! hand — and on the target workstation there *is* a hand-created task doing
//! this job today (`01-current-architecture.md`). So every mutating operation
//! reads the task back first and refuses unless its description carries
//! [`PRODUCT_MARKER`]. `wsl detach` removing somebody else's keep-alive task
//! would be precisely the destructive behaviour the review renamed the command
//! to avoid.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::WslError;
use super::discovery::{decode_console_output, validate_distribution_name};
use super::exec::{CommandRequest, CommandRunner};
use super::probe::{LINUX_USER, WslExecutable, locate_in_system32};
use crate::service::{TaskPrincipal, quote_argument, xml_escape, xml_unescape};

/// The prefix every product-owned lifecycle task name starts with.
pub const LIFECYCLE_TASK_PREFIX: &str = "runner-manager-wsl";

/// The string that says a task is this product's.
///
/// It is in the task's `Description`, which Task Scheduler round-trips
/// verbatim through `/Query /XML`, so ownership survives an export and import
/// and does not depend on parsing the action.
pub const PRODUCT_MARKER: &str = "runner-manager-wsl-lifecycle/v1";

/// The hidden Linux command the task runs.
///
/// `02-target-architecture.md`: it "verifies systemd, starts the existing unit
/// by argument-vector process execution, and then remains alive with
/// signal-aware shutdown so WSL does not retire the distribution".
pub const HOLD_ARGUMENTS: [&str; 2] = ["wsl-host", "hold"];

/// How many characters of the escaped distribution name go into a task name.
///
/// The remainder is covered by the digest suffix, so truncation cannot make
/// two distributions share a task.
const ESCAPED_NAME_BUDGET: usize = 48;

/// How many hex characters of the name's SHA-256 are appended.
const DIGEST_SUFFIX_LENGTH: usize = 8;

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// The stable, per-distribution name of the product's lifecycle task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleTaskIdentity {
    distribution: String,
    name: String,
}

impl LifecycleTaskIdentity {
    /// Derives the task identity for a distribution.
    ///
    /// # The name is escaped *and* hashed, and both halves are load-bearing
    ///
    /// Task Scheduler refuses `\ / : * ? " < > |` in a name, and a
    /// distribution may legitimately contain several of them —
    /// `Debian GNU/Linux 12` does. Escaping alone would map
    /// `Debian GNU/Linux` and `Debian GNU:Linux` onto one task, which is two
    /// distributions quietly sharing one keep-alive. The digest suffix is what
    /// makes the mapping injective; the escaped prefix is what makes the name
    /// readable in `taskschd.msc`.
    ///
    /// # Errors
    ///
    /// [`WslError::InvalidName`] for a name that cannot be used at all.
    pub fn for_distribution(distribution: &str) -> Result<Self, WslError> {
        validate_distribution_name(distribution)?;
        let escaped: String = distribution
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                    character
                } else {
                    '_'
                }
            })
            .take(ESCAPED_NAME_BUDGET)
            .collect();
        let digest = hex::encode(Sha256::digest(distribution.as_bytes()));
        let suffix = &digest[..DIGEST_SUFFIX_LENGTH];
        Ok(Self {
            distribution: distribution.to_string(),
            name: format!("{LIFECYCLE_TASK_PREFIX}-{escaped}-{suffix}"),
        })
    }

    /// The distribution this task keeps alive.
    #[must_use]
    pub fn distribution(&self) -> &str {
        &self.distribution
    }

    /// The Task Scheduler name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The description the document carries, which also carries the marker.
    #[must_use]
    pub fn description(&self) -> String {
        format!(
            "Keeps the WSL distribution \"{}\" running so its runner-manager service can \
             accept jobs after this account logs on. Created and owned by runner-manager \
             ({PRODUCT_MARKER}); remove it with `runner-manager wsl detach --distribution \
             {}`.",
            self.distribution, self.distribution
        )
    }
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// Everything needed to render the task.
#[derive(Debug, Clone)]
pub struct LifecycleTask {
    identity: LifecycleTaskIdentity,
    principal: TaskPrincipal,
    wsl_executable: PathBuf,
    linux_binary: String,
}

impl LifecycleTask {
    /// Builds the task for one distribution and one Windows account.
    #[must_use]
    pub fn new(
        identity: LifecycleTaskIdentity,
        principal: TaskPrincipal,
        wsl_executable: &WslExecutable,
        linux_binary: impl Into<String>,
    ) -> Self {
        Self {
            identity,
            principal,
            wsl_executable: wsl_executable.path().to_path_buf(),
            linux_binary: linux_binary.into(),
        }
    }

    /// Which task this is.
    #[must_use]
    pub fn identity(&self) -> &LifecycleTaskIdentity {
        &self.identity
    }

    /// The account it runs as.
    #[must_use]
    pub fn principal(&self) -> &TaskPrincipal {
        &self.principal
    }

    /// The program the task starts.
    #[must_use]
    pub fn command(&self) -> &Path {
        &self.wsl_executable
    }

    /// The action's argument **vector**.
    ///
    /// The same shape [`super::probe::LinuxCommand`] builds for every other
    /// invocation, which is deliberate: the task starts the distribution the
    /// same way the provisioning transaction does, so there is one thing to
    /// get right rather than two.
    #[must_use]
    pub fn action_arguments(&self) -> Vec<String> {
        let mut argv = vec![
            "--distribution".to_string(),
            self.identity.distribution.clone(),
            "--user".to_string(),
            LINUX_USER.to_string(),
            "--exec".to_string(),
            self.linux_binary.clone(),
        ];
        argv.extend(
            HOLD_ARGUMENTS
                .iter()
                .map(|argument| (*argument).to_string()),
        );
        argv
    }

    /// The vector, quoted into the single string Task Scheduler stores.
    #[must_use]
    pub fn rendered_arguments(&self) -> String {
        self.action_arguments()
            .iter()
            .map(|argument| quote_argument(argument))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The Task Scheduler document.
    #[must_use]
    pub fn xml(&self) -> String {
        let user = xml_escape(self.principal.user_id());
        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n");
        out.push_str(
            "<Task version=\"1.4\" \
             xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n",
        );
        out.push_str("  <RegistrationInfo>\n");
        out.push_str(&format!(
            "    <Description>{}</Description>\n",
            xml_escape(&self.identity.description())
        ));
        out.push_str(&format!(
            "    <URI>\\{}</URI>\n",
            xml_escape(self.identity.name())
        ));
        out.push_str("  </RegistrationInfo>\n");

        out.push_str("  <Triggers>\n    <LogonTrigger>\n");
        out.push_str("      <Enabled>true</Enabled>\n");
        out.push_str(&format!("      <UserId>{user}</UserId>\n"));
        out.push_str("    </LogonTrigger>\n  </Triggers>\n");

        // `LeastPrivilege` is the whole of Windows' answer to "this task does
        // not need administrator": `wsl.exe` needs no elevation to start a
        // distribution the logged-on user owns, and the systemd unit inside it
        // is root's business, not Windows'.
        out.push_str("  <Principals>\n    <Principal id=\"Author\">\n");
        out.push_str(&format!("      <UserId>{user}</UserId>\n"));
        out.push_str("      <LogonType>InteractiveToken</LogonType>\n");
        out.push_str("      <RunLevel>LeastPrivilege</RunLevel>\n");
        out.push_str("    </Principal>\n  </Principals>\n");

        out.push_str("  <Settings>\n");
        // One hold process per distribution. A second would keep the same
        // distribution alive twice and tell an operator nothing new.
        out.push_str("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n");
        out.push_str("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n");
        out.push_str("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n");
        out.push_str("    <AllowHardTerminate>true</AllowHardTerminate>\n");
        out.push_str("    <StartWhenAvailable>true</StartWhenAvailable>\n");
        out.push_str("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n");
        out.push_str("    <IdleSettings>\n");
        out.push_str("      <StopOnIdleEnd>false</StopOnIdleEnd>\n");
        out.push_str("      <RestartOnIdle>false</RestartOnIdle>\n");
        out.push_str("    </IdleSettings>\n");
        out.push_str("    <AllowStartOnDemand>true</AllowStartOnDemand>\n");
        out.push_str("    <Enabled>true</Enabled>\n");
        out.push_str("    <Hidden>false</Hidden>\n");
        out.push_str("    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n");
        out.push_str("    <WakeToRun>false</WakeToRun>\n");
        // The hold has no natural end, so a limit here would be a scheduled
        // kill of the thing that keeps the distribution up.
        out.push_str("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n");
        out.push_str("    <Priority>7</Priority>\n");
        out.push_str("    <RestartOnFailure>\n");
        out.push_str("      <Interval>PT1M</Interval>\n");
        out.push_str("      <Count>5</Count>\n");
        out.push_str("    </RestartOnFailure>\n");
        out.push_str("  </Settings>\n");

        out.push_str("  <Actions Context=\"Author\">\n    <Exec>\n");
        out.push_str(&format!(
            "      <Command>{}</Command>\n",
            xml_escape(&self.wsl_executable.to_string_lossy())
        ));
        out.push_str(&format!(
            "      <Arguments>{}</Arguments>\n",
            xml_escape(&self.rendered_arguments())
        ));
        out.push_str("    </Exec>\n  </Actions>\n");
        out.push_str("</Task>\n");
        out
    }
}

// ---------------------------------------------------------------------------
// Reading a task back
// ---------------------------------------------------------------------------

/// What Task Scheduler says about a task that is registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredTask {
    name: String,
    command: String,
    arguments: String,
    account: Option<String>,
    description: String,
    enabled: bool,
    running: bool,
}

impl RegisteredTask {
    /// Reads the fields this module cares about out of a `/Query /XML`
    /// document.
    #[must_use]
    pub fn from_document(name: &str, document: &str, running: bool) -> Self {
        Self {
            name: name.to_string(),
            command: element(document, "Command").unwrap_or_default(),
            arguments: element(document, "Arguments").unwrap_or_default(),
            account: element(document, "UserId"),
            description: element(document, "Description").unwrap_or_default(),
            enabled: element(document, "Enabled").as_deref() != Some("false"),
            running,
        }
    }

    /// The Task Scheduler name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The program it starts.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// The single argument string it stores.
    #[must_use]
    pub fn arguments(&self) -> &str {
        &self.arguments
    }

    /// The account, when the document names one.
    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// Its description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Whether it is enabled.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether Task Scheduler reports it as running.
    ///
    /// **Read from localised output**, exactly as
    /// [`crate::service`]'s Windows backend reads it, and for the same reason:
    /// `schtasks /Query /FO CSV` prints its `Status` column in the machine's
    /// display language and there is no locale-independent equivalent short of
    /// COM. On a non-English Windows this is `false` for a task that is in fact
    /// running. Nothing in the provisioning transaction branches on it — the
    /// authority for "is the Linux host healthy" is the Linux service's own
    /// status — so it is a display value and only that.
    #[must_use]
    pub fn running(&self) -> bool {
        self.running
    }

    /// Whether this product created it.
    ///
    /// The gate on every mutation. See the module documentation: the name is
    /// derived, so it can collide with a hand-made task, and the marker is
    /// what tells the two apart.
    #[must_use]
    pub fn is_product_owned(&self) -> bool {
        self.description.contains(PRODUCT_MARKER)
    }
}

/// The text of the first `<name>…</name>` element, unescaped.
///
/// A deliberately small reader rather than an XML parser: the four values this
/// needs are single-line elements Task Scheduler writes itself, and a
/// dependency on a full parser to read them would be a much larger surface for
/// a much smaller job. Anything it cannot find is `None`, which every caller
/// treats as "the task does not say".
fn element(document: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = document.find(&open)? + open.len();
    let end = document[start..].find(&close)? + start;
    Some(xml_unescape(document[start..end].trim()))
}

// ---------------------------------------------------------------------------
// The control
// ---------------------------------------------------------------------------

/// Registering, reading and removing the product's lifecycle task.
///
/// Everything goes through a [`CommandRunner`], so the whole of this — the
/// argument vectors, the idempotent replacement, the foreign-task refusal and
/// the non-destructive removal — is testable on a CI leg that has no Task
/// Scheduler at all.
#[derive(Debug)]
pub struct LifecycleTaskControl<'runner> {
    runner: &'runner dyn CommandRunner,
    schtasks: PathBuf,
}

/// What [`LifecycleTaskControl::detach`] did, and what it deliberately did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detached {
    /// Whether there was a task to remove.
    pub removed: bool,
    /// The task's name, whether or not it was there.
    pub name: String,
}

impl<'runner> LifecycleTaskControl<'runner> {
    /// Uses the host's `schtasks.exe`.
    #[must_use]
    pub fn new(runner: &'runner dyn CommandRunner) -> Self {
        Self {
            runner,
            schtasks: locate_in_system32("schtasks.exe"),
        }
    }

    /// Uses a named `schtasks.exe`, for a test.
    #[must_use]
    pub fn with_executable(
        runner: &'runner dyn CommandRunner,
        schtasks: impl Into<PathBuf>,
    ) -> Self {
        Self {
            runner,
            schtasks: schtasks.into(),
        }
    }

    /// What Task Scheduler holds under this name, if anything.
    ///
    /// # Errors
    ///
    /// [`WslError::Spawn`] when `schtasks.exe` cannot be started at all.
    pub fn query(
        &self,
        identity: &LifecycleTaskIdentity,
    ) -> Result<Option<RegisteredTask>, WslError> {
        let output = self.schtasks(&["/Query", "/TN", identity.name(), "/XML", "ONE"])?;
        if !output.success() {
            // `schtasks` reports "no such task" and "Task Scheduler is broken"
            // with the same non-zero exit and no distinct code. Reading it as
            // absence is the safe choice: a caller either registers, which
            // then fails loudly, or reports "not installed", which is what an
            // operator with no task sees.
            return Ok(None);
        }
        let document = decode_console_output(output.stdout()).into_text();
        Ok(Some(RegisteredTask::from_document(
            identity.name(),
            &document,
            self.is_running(identity),
        )))
    }

    /// Registers the task, replacing a previous registration of the same task.
    ///
    /// Idempotent: running it twice leaves one task whose definition is the
    /// current one. `schtasks /Create … /F` is what makes the replacement
    /// atomic from Task Scheduler's point of view — there is no window in
    /// which the task is absent.
    ///
    /// # Errors
    ///
    /// [`WslError::ForeignTask`] when a task of this name exists and is not
    /// this product's; [`WslError::TaskControl`] when `schtasks` refused;
    /// [`WslError::Record`] when the document could not be written to a
    /// temporary file for `schtasks /XML` to read.
    pub fn register(&self, task: &LifecycleTask) -> Result<(), WslError> {
        let identity = task.identity();
        if let Some(existing) = self.query(identity)?
            && !existing.is_product_owned()
        {
            return Err(WslError::ForeignTask {
                name: identity.name().to_string(),
                detail: format!(
                    "a task of this name already exists, its description does not identify it \
                     as this product's ({PRODUCT_MARKER}), and it starts `{}`. Rename or \
                     remove it yourself if it is the hand-created keep-alive this feature \
                     replaces.",
                    existing.command()
                ),
            });
        }

        let directory = tempfile::tempdir().map_err(|error| WslError::Record {
            operation: "write",
            path: PathBuf::from("<the scheduled-task document>"),
            detail: error.to_string(),
        })?;
        let document = directory.path().join("task.xml");
        write_utf16(&document, &task.xml()).map_err(|error| WslError::Record {
            operation: "write",
            path: document.clone(),
            detail: error.to_string(),
        })?;

        let output = self.schtasks(&[
            "/Create",
            "/TN",
            identity.name(),
            "/XML",
            &document.to_string_lossy(),
            "/F",
        ])?;
        if !output.success() {
            return Err(self.task_error("register", identity.name(), &output.diagnostic()));
        }
        Ok(())
    }

    /// Removes the product's task, and nothing else.
    ///
    /// This is the whole of `wsl detach`'s Windows half. It does not
    /// unregister the WSL distribution, stop or uninstall the Linux service,
    /// remove a credential, or delete any Linux data — it cannot, because the
    /// only program it runs is `schtasks.exe`.
    ///
    /// # Errors
    ///
    /// [`WslError::ForeignTask`] when the task is not this product's, and
    /// [`WslError::TaskControl`] when `schtasks` refused to delete it.
    pub fn detach(&self, identity: &LifecycleTaskIdentity) -> Result<Detached, WslError> {
        let Some(existing) = self.query(identity)? else {
            return Ok(Detached {
                removed: false,
                name: identity.name().to_string(),
            });
        };
        if !existing.is_product_owned() {
            return Err(WslError::ForeignTask {
                name: identity.name().to_string(),
                detail: format!(
                    "a task of this name exists but its description does not identify it as \
                     this product's ({PRODUCT_MARKER}), so `detach` will not remove it."
                ),
            });
        }
        let output = self.schtasks(&["/Delete", "/TN", identity.name(), "/F"])?;
        if !output.success() {
            return Err(self.task_error("remove", identity.name(), &output.diagnostic()));
        }
        Ok(Detached {
            removed: true,
            name: identity.name().to_string(),
        })
    }

    /// Starts the task now, rather than at the next logon.
    ///
    /// # Errors
    ///
    /// [`WslError::NoSuchTask`] when nothing is registered,
    /// [`WslError::ForeignTask`] when the registration is not this product's,
    /// and [`WslError::TaskControl`] when `schtasks` refused.
    pub fn start(&self, identity: &LifecycleTaskIdentity) -> Result<(), WslError> {
        self.require_ours("start", identity)?;
        let output = self.schtasks(&["/Run", "/TN", identity.name()])?;
        if !output.success() {
            return Err(self.task_error("start", identity.name(), &output.diagnostic()));
        }
        Ok(())
    }

    /// Ends a running instance. Returns whether one was running.
    ///
    /// # Errors
    ///
    /// As [`LifecycleTaskControl::start`].
    pub fn stop(&self, identity: &LifecycleTaskIdentity) -> Result<bool, WslError> {
        let existing = self.require_ours("stop", identity)?;
        if !existing.running() {
            return Ok(false);
        }
        let output = self.schtasks(&["/End", "/TN", identity.name()])?;
        if !output.success() {
            return Err(self.task_error("stop", identity.name(), &output.diagnostic()));
        }
        Ok(true)
    }

    fn require_ours(
        &self,
        operation: &'static str,
        identity: &LifecycleTaskIdentity,
    ) -> Result<RegisteredTask, WslError> {
        let Some(existing) = self.query(identity)? else {
            return Err(WslError::NoSuchTask {
                name: identity.name().to_string(),
            });
        };
        if !existing.is_product_owned() {
            return Err(WslError::ForeignTask {
                name: identity.name().to_string(),
                detail: format!(
                    "a task of this name exists but is not this product's ({PRODUCT_MARKER}), \
                     so it will not be used to {operation} anything."
                ),
            });
        }
        Ok(existing)
    }

    fn schtasks(&self, arguments: &[&str]) -> Result<super::exec::CommandOutput, WslError> {
        let request =
            CommandRequest::new(&self.schtasks).args(arguments.iter().map(OsString::from));
        self.runner.run(&request)
    }

    /// Whether Task Scheduler reports the task as running. See
    /// [`RegisteredTask::running`] for why this is best-effort.
    fn is_running(&self, identity: &LifecycleTaskIdentity) -> bool {
        let Ok(output) = self.schtasks(&["/Query", "/TN", identity.name(), "/FO", "CSV", "/NH"])
        else {
            return false;
        };
        if !output.success() {
            return false;
        }
        decode_console_output(output.stdout())
            .into_text()
            .lines()
            .filter_map(|line| line.rsplit(',').next())
            .any(|status| {
                status
                    .trim()
                    .trim_matches('"')
                    .eq_ignore_ascii_case("running")
            })
    }

    fn task_error(&self, operation: &'static str, name: &str, detail: &str) -> WslError {
        if detail.to_ascii_lowercase().contains("access is denied") {
            return WslError::NeedsElevation {
                operation,
                name: name.to_string(),
                detail: detail.to_string(),
            };
        }
        WslError::TaskControl {
            operation,
            name: name.to_string(),
            detail: detail.to_string(),
        }
    }
}

/// Writes a task document as UTF-16LE with a byte-order mark.
///
/// `schtasks /XML` reads its input as UTF-16 and the `<?xml … encoding
/// ="UTF-16"?>` declaration this module writes says so; handing it UTF-8 is
/// the one mistake that makes a perfectly good document unreadable.
fn write_utf16(path: &Path, text: &str) -> std::io::Result<()> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wsl::exec::{CommandOutput, ScriptedRunner};

    fn identity(distribution: &str) -> LifecycleTaskIdentity {
        LifecycleTaskIdentity::for_distribution(distribution).expect("a usable name")
    }

    fn task(distribution: &str) -> LifecycleTask {
        LifecycleTask::new(
            identity(distribution),
            TaskPrincipal::named("IVANPC\\IvanD"),
            &WslExecutable::at("C:\\Windows\\System32\\wsl.exe"),
            "/usr/local/bin/runner-manager",
        )
    }

    fn registered_document(distribution: &str) -> CommandOutput {
        CommandOutput::exited(0, task(distribution).xml(), "")
    }

    // -- Identity ------------------------------------------------------------

    #[test]
    fn the_task_name_is_stable_for_a_distribution() {
        assert_eq!(identity("Ubuntu").name(), identity("Ubuntu").name());
        assert!(
            identity("Ubuntu")
                .name()
                .starts_with("runner-manager-wsl-Ubuntu-")
        );
    }

    #[test]
    fn a_name_task_scheduler_could_not_hold_is_escaped_into_one_that_it_can() {
        let name = identity("Debian GNU/Linux 12").name().to_string();
        for forbidden in ['\\', '/', ':', '*', '?', '"', '<', '>', '|'] {
            assert!(
                !name.contains(forbidden),
                "{name} still contains {forbidden:?}"
            );
        }
        assert!(name.contains("Debian_GNU_Linux_12"), "{name}");
    }

    #[test]
    fn two_distributions_that_escape_alike_still_get_different_tasks() {
        // The reason the digest suffix exists. Without it these two would be
        // one task, and the second `wsl install` would silently retarget the
        // first distribution's keep-alive.
        let first = identity("Debian GNU/Linux");
        let second = identity("Debian GNU:Linux");
        assert_ne!(first.name(), second.name());
        assert!(first.name().contains("Debian_GNU_Linux"));
        assert!(second.name().contains("Debian_GNU_Linux"));
    }

    #[test]
    fn a_very_long_name_is_bounded_and_still_unique() {
        let long = "u".repeat(200);
        let other = format!("{long}x");
        let first = identity(&long);
        let second = identity(&other);
        assert_ne!(first.name(), second.name());
        assert!(
            first.name().len()
                <= LIFECYCLE_TASK_PREFIX.len() + 1 + ESCAPED_NAME_BUDGET + 1 + DIGEST_SUFFIX_LENGTH,
            "{}",
            first.name()
        );
    }

    #[test]
    fn a_distribution_name_that_is_not_usable_never_becomes_a_task_name() {
        assert!(LifecycleTaskIdentity::for_distribution("--shutdown").is_err());
        assert!(LifecycleTaskIdentity::for_distribution("").is_err());
    }

    // -- The document --------------------------------------------------------

    #[test]
    fn the_action_is_the_documented_argument_vector() {
        assert_eq!(
            task("Ubuntu").action_arguments(),
            vec![
                "--distribution",
                "Ubuntu",
                "--user",
                "root",
                "--exec",
                "/usr/local/bin/runner-manager",
                "wsl-host",
                "hold",
            ]
        );
    }

    #[test]
    fn a_name_with_spaces_is_quoted_so_windows_splits_it_back_into_one_argument() {
        let rendered = task("My Ubuntu").rendered_arguments();
        assert!(
            rendered.contains("--distribution \"My Ubuntu\" --user root"),
            "{rendered}"
        );
    }

    #[test]
    fn no_shell_text_reaches_the_task_document() {
        // The P1 the 2026-09-06 review closed: an action that composed
        // `systemctl` and a keep-alive through shell text.
        let document = task("Ubuntu & echo pwned").xml();
        let arguments = element(&document, "Arguments").expect("the document has an action");
        for shell in ["cmd", "powershell", "/c", "&&", "||", ";", "$(", "`"] {
            assert!(
                !arguments.contains(shell),
                "the rendered arguments contain shell text {shell:?}: {arguments}"
            );
        }
        assert_eq!(
            element(&document, "Command").as_deref(),
            Some("C:\\Windows\\System32\\wsl.exe")
        );
        // The `&` in the distribution name survived as data, escaped in the
        // document and quoted in the argument string.
        assert!(document.contains("&amp;"), "{document}");
        assert!(arguments.contains("\"Ubuntu & echo pwned\""), "{arguments}");
    }

    #[test]
    fn the_document_is_a_least_privilege_logon_task_for_the_named_principal() {
        let document = task("Ubuntu").xml();
        assert!(document.contains("<LogonTrigger>"), "{document}");
        assert!(
            document.contains("<RunLevel>LeastPrivilege</RunLevel>"),
            "{document}"
        );
        assert!(
            document.contains("<UserId>IVANPC\\IvanD</UserId>"),
            "{document}"
        );
        // No end to the hold, so no scheduled kill of it.
        assert!(document.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
    }

    #[test]
    fn the_document_carries_the_ownership_marker_and_names_the_distribution() {
        let document = task("Ubuntu").xml();
        let description = element(&document, "Description").expect("a description");
        assert!(description.contains(PRODUCT_MARKER), "{description}");
        assert!(description.contains("Ubuntu"), "{description}");
        assert!(description.contains("wsl detach"), "{description}");
    }

    #[test]
    fn a_rendered_document_reads_back_as_this_products_task() {
        let document = task("Ubuntu").xml();
        let read = RegisteredTask::from_document("whatever", &document, false);
        assert!(read.is_product_owned());
        assert_eq!(read.account(), Some("IVANPC\\IvanD"));
        assert!(read.enabled());
        assert!(
            read.arguments().contains("wsl-host hold"),
            "{}",
            read.arguments()
        );
    }

    #[test]
    fn a_task_this_product_did_not_write_is_not_product_owned() {
        let hand_made = concat!(
            "<Task><RegistrationInfo><Description>GitHub Actions Linux Runner - Ubuntu WSL",
            "</Description></RegistrationInfo><Actions><Exec><Command>wsl.exe</Command>",
            "<Arguments>-d Ubuntu -u root /bin/sleep infinity</Arguments></Exec></Actions></Task>",
        );
        let read = RegisteredTask::from_document("whatever", hand_made, false);
        assert!(!read.is_product_owned());
    }

    // -- The control ---------------------------------------------------------

    fn control(runner: &ScriptedRunner) -> LifecycleTaskControl<'_> {
        LifecycleTaskControl::with_executable(runner, "schtasks.exe")
    }

    #[test]
    fn registering_writes_a_utf16_document_and_replaces_in_place() {
        let runner = ScriptedRunner::new().always("/Query", CommandOutput::exited(1, "", ""));
        let task = task("Ubuntu");
        control(&runner).register(&task).expect("registered");

        let create = runner
            .recorded()
            .into_iter()
            .find(|request| request.arguments.first().map(String::as_str) == Some("/Create"))
            .expect("a /Create call");
        assert_eq!(create.arguments[1], "/TN");
        assert_eq!(create.arguments[2], task.identity().name());
        assert_eq!(create.arguments[3], "/XML");
        assert_eq!(
            create.arguments[5], "/F",
            "without /F a second `wsl install` fails instead of updating the task"
        );
    }

    #[test]
    fn registering_over_this_products_own_task_is_allowed_and_idempotent() {
        let runner = ScriptedRunner::new()
            .always("/Query", registered_document("Ubuntu"))
            .always("/Create", CommandOutput::exited(0, "SUCCESS", ""));
        control(&runner)
            .register(&task("Ubuntu"))
            .expect("replaced");
        control(&runner)
            .register(&task("Ubuntu"))
            .expect("replaced again");
    }

    #[test]
    fn registering_over_a_foreign_task_refuses_and_changes_nothing() {
        let hand_made = CommandOutput::exited(
            0,
            concat!(
                "<Task><RegistrationInfo><Description>GitHub Actions Linux Runner - Ubuntu WSL",
                "</Description></RegistrationInfo><Actions><Exec><Command>wsl.exe</Command>",
                "</Exec></Actions></Task>",
            ),
            "",
        );
        let runner = ScriptedRunner::new().always("/Query", hand_made);
        let error = control(&runner)
            .register(&task("Ubuntu"))
            .expect_err("not ours");
        assert!(matches!(error, WslError::ForeignTask { .. }), "{error:?}");
        assert!(
            runner
                .command_lines()
                .iter()
                .all(|line| !line.contains("/Create")),
            "nothing may be written: {:?}",
            runner.command_lines()
        );
    }

    #[test]
    fn detach_removes_only_the_product_task_and_runs_nothing_else() {
        let runner = ScriptedRunner::new()
            .always("/Query", registered_document("Ubuntu"))
            .always("/Delete", CommandOutput::exited(0, "SUCCESS", ""));
        let detached = control(&runner)
            .detach(&identity("Ubuntu"))
            .expect("detached");
        assert!(detached.removed);

        for request in runner.recorded() {
            assert_eq!(
                request.program.to_string_lossy(),
                "schtasks.exe",
                "detach must not run anything but Task Scheduler: {request:?}"
            );
        }
        let lines = runner.command_lines();
        assert!(
            lines.iter().all(|line| !line.contains("wsl.exe")),
            "detach must not reach into the distribution: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .all(|line| !line.contains("--unregister") && !line.contains("systemctl")),
            "detach must not unregister WSL or touch the Linux service: {lines:?}"
        );
    }

    #[test]
    fn detach_without_a_task_is_not_an_error() {
        let runner = ScriptedRunner::new().always("/Query", CommandOutput::exited(1, "", ""));
        let detached = control(&runner)
            .detach(&identity("Ubuntu"))
            .expect("nothing to remove");
        assert!(!detached.removed);
        assert!(
            runner
                .command_lines()
                .iter()
                .all(|line| !line.contains("/Delete"))
        );
    }

    #[test]
    fn detach_refuses_a_foreign_task_rather_than_deleting_it() {
        let runner = ScriptedRunner::new().always(
            "/Query",
            CommandOutput::exited(
                0,
                "<Task><RegistrationInfo><Description>Somebody else's task</Description>\
                 </RegistrationInfo></Task>",
                "",
            ),
        );
        let error = control(&runner)
            .detach(&identity("Ubuntu"))
            .expect_err("not ours");
        assert!(matches!(error, WslError::ForeignTask { .. }), "{error:?}");
        assert!(
            runner
                .command_lines()
                .iter()
                .all(|line| !line.contains("/Delete")),
            "a task this product does not own must not be deleted"
        );
    }

    #[test]
    fn access_denied_is_reported_as_needing_elevation_rather_than_as_a_generic_failure() {
        let runner = ScriptedRunner::new()
            .always("/Query", CommandOutput::exited(1, "", ""))
            .always(
                "/Create",
                CommandOutput::exited(1, "", "ERROR: Access is denied.\n"),
            );
        let error = control(&runner)
            .register(&task("Ubuntu"))
            .expect_err("denied");
        assert!(
            matches!(error, WslError::NeedsElevation { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn starting_a_task_that_is_not_registered_says_so() {
        let runner = ScriptedRunner::new().always("/Query", CommandOutput::exited(1, "", ""));
        let error = control(&runner)
            .start(&identity("Ubuntu"))
            .expect_err("not registered");
        assert!(matches!(error, WslError::NoSuchTask { .. }), "{error:?}");
    }

    #[test]
    fn a_query_reads_a_utf16_document_as_schtasks_really_writes_it() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in task("Ubuntu").xml().encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let runner = ScriptedRunner::new()
            .always("/XML ONE", CommandOutput::exited(0, bytes, ""))
            .always(
                "/FO CSV",
                CommandOutput::exited(0, "\"task\",\"N/A\",\"Ready\"\n", ""),
            );
        let found = control(&runner)
            .query(&identity("Ubuntu"))
            .expect("queried")
            .expect("registered");
        assert!(found.is_product_owned());
        assert!(!found.running());
        assert!(found.arguments().contains("wsl-host hold"));
    }

    #[test]
    fn a_running_task_is_reported_from_the_csv_status_column() {
        let runner = ScriptedRunner::new()
            .always("/XML ONE", registered_document("Ubuntu"))
            .always(
                "/FO CSV",
                CommandOutput::exited(0, "\"\\task\",\"N/A\",\"Running\"\n", ""),
            );
        let found = control(&runner)
            .query(&identity("Ubuntu"))
            .expect("queried")
            .expect("registered");
        assert!(found.running());
    }

    // -- The document round-trips through a file -----------------------------

    #[test]
    fn the_document_is_written_as_utf16_little_endian_with_a_byte_order_mark() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("task.xml");
        write_utf16(&path, &task("Ubuntu").xml()).expect("written");
        let bytes = std::fs::read(&path).expect("readable");
        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        let decoded = decode_console_output(&bytes);
        assert_eq!(decoded.text(), task("Ubuntu").xml());
    }

    #[test]
    fn no_credential_shaped_value_can_reach_the_document() {
        // `03-security-and-lifecycle.md` item 3 lists scheduled-task XML among
        // the places the credential document must be absent from. The control
        // is structural -- `LifecycleTask` has no field that could hold one --
        // and this is the test that says so about the rendered result.
        let document = task("Ubuntu").xml().to_ascii_lowercase();
        for shape in [
            "ghu_",
            "ghs_",
            "gho_",
            "github_pat_",
            "access_token",
            "refresh_token",
            "jitconfig",
            "secret",
            "password",
            "credential",
        ] {
            assert!(
                !document.contains(shape),
                "the task document mentions {shape:?}: {document}"
            );
        }
        // `token` on its own is deliberately *not* in that list: Task
        // Scheduler's own `<LogonType>InteractiveToken</LogonType>` contains
        // it, so a substring test for it would fail on a document that is
        // exactly right. The shapes above are credential-shaped; that one is a
        // Windows API word.
        assert!(document.contains("interactivetoken"));
    }
}
