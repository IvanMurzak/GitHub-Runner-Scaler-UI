//! Hyper-V-isolated Windows container execution.
//!
//! Docker is used as the Windows container control plane, but no Docker socket,
//! host directory, device, or credential is exposed to the container.  The
//! verified runner package is copied into a fresh writable layer and the JIT
//! value crosses the boundary once over the attached container stdin.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Write as _;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;

use runner_manager_domain::attempt::{FailureReason, RunnerAttempt};
use runner_manager_domain::execution::{
    AttemptExecution, Backend, ExecutionPolicy, ImageReference, ResourceLimits,
};
use runner_manager_domain::model::{AttemptId, HostId};
use runner_manager_domain::policy::ScalePolicy;

use super::{
    EnvironmentIdentity, EnvironmentState, ExecutionProvider, OneTimeJitHandoff,
    PreparedEnvironment, ProcessStartFailure, ProviderCapability, ProviderDestroy,
    ProviderDiagnostic, ProviderStop, ResolvedEnvironment, TERMINATE_INTENT_FILE,
    write_durable_file,
};

const LABEL_HOST: &str = "runner-manager.host";
const LABEL_ATTEMPT: &str = "runner-manager.attempt";
const LABEL_GENERATION: &str = "runner-manager.generation";
const LABEL_IMAGE: &str = "runner-manager.image";
const LABEL_PROVIDER: &str = "runner-manager.provider";
const PROVIDER_VALUE: &str = "windows-hyper-v-container";
const MAX_CAPTURE: usize = 64 * 1024;
const PREFLIGHT_INPUT: &str = "runner-manager-preflight-v1";
const BOOTSTRAP: &str = "$ErrorActionPreference='Stop'; $payload=[Console]::In.ReadToEnd(); if ([String]::IsNullOrWhiteSpace($payload)) { exit 70 }; if ($payload -eq 'runner-manager-preflight-v1') { & C:\\runner\\bin\\Runner.Listener.exe --version *> $null; if ($LASTEXITCODE -ne 0) { exit 72 }; exit 0 }; $psi=[System.Diagnostics.ProcessStartInfo]::new(); $psi.FileName='C:\\runner\\bin\\Runner.Listener.exe'; $psi.Arguments='run'; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; $psi.EnvironmentVariables['ACTIONS_RUNNER_INPUT_JITCONFIG']=$payload; $listener=[System.Diagnostics.Process]::new(); $listener.StartInfo=$psi; try { $started=$listener.Start() } finally { $psi.EnvironmentVariables.Remove('ACTIONS_RUNNER_INPUT_JITCONFIG'); $payload=$null }; if (-not $started) { exit 71 }; $listener.WaitForExit(); exit $listener.ExitCode";

/// Host-only preflight detail. It is a closed vocabulary and never carries
/// provider output, so CLI/TUI surfaces cannot accidentally expose it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsHyperVHostState {
    Ready,
    UnsupportedHost,
    HyperVUnavailable,
    ContainersUnavailable,
    RuntimeNotInstalled,
    RuntimePermissionDenied,
    RuntimeInLinuxMode,
    RuntimeDegraded,
}

impl WindowsHyperVHostState {
    #[must_use]
    pub const fn capability(self) -> ProviderCapability {
        match self {
            Self::Ready => ProviderCapability::Ready,
            Self::UnsupportedHost | Self::RuntimeInLinuxMode => ProviderCapability::Unsupported,
            Self::HyperVUnavailable | Self::ContainersUnavailable | Self::RuntimeNotInstalled => {
                ProviderCapability::NotInstalled
            }
            Self::RuntimePermissionDenied => ProviderCapability::PermissionDenied,
            Self::RuntimeDegraded => ProviderCapability::Degraded,
        }
    }

    #[must_use]
    pub const fn remedy(self) -> Option<&'static str> {
        match self {
            Self::Ready => None,
            Self::UnsupportedHost => {
                Some("use Windows Pro, Enterprise, Education, or Server with Hyper-V support")
            }
            Self::HyperVUnavailable => Some("enable Hyper-V and restart Windows"),
            Self::ContainersUnavailable => {
                Some("enable the Windows Containers feature and restart Windows")
            }
            Self::RuntimeNotInstalled => {
                Some("install a Windows container runtime with Docker-compatible CLI")
            }
            Self::RuntimePermissionDenied => {
                Some("grant the runner-manager service account access to the container runtime")
            }
            Self::RuntimeInLinuxMode => Some("switch the container runtime to Windows containers"),
            Self::RuntimeDegraded => Some("repair or start the Windows container runtime"),
        }
    }
}

#[derive(Debug)]
pub struct WindowsHyperVContainers {
    host_id: HostId,
    children: Mutex<BTreeMap<AttemptId, Child>>,
    diagnostics: Mutex<BTreeMap<AttemptId, Vec<ProviderDiagnostic>>>,
}

impl WindowsHyperVContainers {
    #[must_use]
    pub fn new(host_id: HostId) -> Self {
        Self {
            host_id,
            children: Mutex::new(BTreeMap::new()),
            diagnostics: Mutex::new(BTreeMap::new()),
        }
    }

    #[must_use]
    pub fn host_state() -> WindowsHyperVHostState {
        #[cfg(test)]
        {
            WindowsHyperVHostState::UnsupportedHost
        }
        #[cfg(not(test))]
        {
            host_state_with(&SystemCommands)
        }
    }

    fn note(&self, attempt: AttemptId, diagnostic: ProviderDiagnostic) {
        let mut all = self
            .diagnostics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entries = all.entry(attempt).or_default();
        if entries.len() < 32 && !entries.contains(&diagnostic) {
            entries.push(diagnostic);
        }
    }

    fn docker(args: &[OsString]) -> Result<CommandResult, CommandFailure> {
        SystemCommands.run("docker", args)
    }

    fn inspect_record(name: &str) -> Result<Option<ResourceRecord>, CommandFailure> {
        let format = format!(
            "{{{{.Name}}}}|{{{{.State.Status}}}}|{{{{.State.ExitCode}}}}|{{{{index .Config.Labels \"{LABEL_HOST}\"}}}}|\
             {{{{index .Config.Labels \"{LABEL_ATTEMPT}\"}}}}|\
             {{{{index .Config.Labels \"{LABEL_GENERATION}\"}}}}|\
             {{{{index .Config.Labels \"{LABEL_IMAGE}\"}}}}|\
             {{{{index .Config.Labels \"{LABEL_PROVIDER}\"}}}}"
        );
        let result = Self::docker(&os_args(["inspect", "--format", &format, name]))?;
        if !result.success {
            return if result.is_missing_resource() {
                Ok(None)
            } else {
                Err(result.failure())
            };
        }
        Ok(ResourceRecord::parse(result.stdout.trim()))
    }

    fn identity_for(
        &self,
        attempt: &RunnerAttempt,
        environment_id: String,
    ) -> Option<EnvironmentIdentity> {
        let AttemptExecution::Isolated {
            provider_kind,
            resolved_image,
            generation,
            ..
        } = attempt.execution()
        else {
            return None;
        };
        Some(EnvironmentIdentity::Isolated {
            host: self.host_id,
            attempt: attempt.id,
            provider_kind: *provider_kind,
            environment_id,
            resolved_image: resolved_image.clone(),
            generation: generation.clone(),
        })
    }

    fn expected_record(&self, attempt: &RunnerAttempt) -> Option<ResourceRecord> {
        let AttemptExecution::Isolated {
            provider_kind: Backend::WindowsHyperVContainer,
            resolved_image,
            generation,
            ..
        } = attempt.execution()
        else {
            return None;
        };
        Some(ResourceRecord {
            name: container_name(self.host_id, attempt.id, generation),
            state: String::new(),
            exit_code: None,
            host: self.host_id,
            attempt: attempt.id,
            generation: generation.clone(),
            image: resolved_image.clone(),
        })
    }

    fn intent_path(attempt: &RunnerAttempt) -> std::path::PathBuf {
        attempt.runtime_path().join(TERMINATE_INTENT_FILE)
    }
}

impl ExecutionProvider for WindowsHyperVContainers {
    fn probe(&self, policy: &ScalePolicy) -> ProviderCapability {
        let ExecutionPolicy::Isolated { backend, image, .. } = policy.execution_policy() else {
            return ProviderCapability::Unsupported;
        };
        if !matches!(backend, Backend::Auto | Backend::WindowsHyperVContainer) {
            return ProviderCapability::Unsupported;
        }
        let host = Self::host_state().capability();
        if host != ProviderCapability::Ready {
            return host;
        }
        match inspect_image(image) {
            Ok(true) => ProviderCapability::Ready,
            Ok(false) => ProviderCapability::ImageUnavailableOrIncompatible,
            Err(CommandFailure::PermissionDenied) => ProviderCapability::PermissionDenied,
            Err(_) => ProviderCapability::ImageUnavailableOrIncompatible,
        }
    }

    fn resolve(&self, policy: &ScalePolicy) -> Result<Option<ResolvedEnvironment>, FailureReason> {
        let ExecutionPolicy::Isolated { backend, image, .. } = policy.execution_policy() else {
            return Err(failure("Windows Hyper-V provider received a native policy"));
        };
        if !matches!(backend, Backend::Auto | Backend::WindowsHyperVContainer) {
            return Err(failure("Windows Hyper-V provider was not selected"));
        }
        if self.probe(policy) != ProviderCapability::Ready {
            return Err(failure("Windows Hyper-V provider preflight failed"));
        }
        Ok(Some(ResolvedEnvironment {
            provider_kind: Backend::WindowsHyperVContainer,
            image: image.clone(),
        }))
    }

    fn prepare(
        &self,
        attempt: &RunnerAttempt,
        policy: &ScalePolicy,
    ) -> Result<PreparedEnvironment, FailureReason> {
        let Some(expected) = self.expected_record(attempt) else {
            self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
            return Err(failure("Windows Hyper-V allocation is invalid"));
        };
        let ExecutionPolicy::Isolated { resources, .. } = policy.execution_policy() else {
            return Err(failure("Windows Hyper-V policy is invalid"));
        };

        let exists = match Self::inspect_record(&expected.name) {
            Ok(Some(found))
                if found.same_owner(&expected)
                    && matches!(found.state.as_str(), "created" | "exited") =>
            {
                true
            }
            Ok(Some(found)) if found.same_owner(&expected) => {
                self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
                return Err(failure(
                    "Windows Hyper-V container state is incompatible with preparation",
                ));
            }
            Ok(Some(_)) => {
                self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
                return Err(failure("Windows Hyper-V container ownership mismatch"));
            }
            Ok(None) => false,
            Err(_) => {
                self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
                return Err(failure("Windows Hyper-V container inspection failed"));
            }
        };

        if !exists {
            let create = Self::docker(&create_args(&expected, *resources))
                .map_err(|_| failure("Windows Hyper-V container creation failed"))?;
            if !create.success {
                self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
                return Err(failure("Windows Hyper-V container creation failed"));
            }
        }

        let source = format!(
            "{}{}.",
            attempt.runtime_path().display(),
            std::path::MAIN_SEPARATOR
        );
        let destination = format!("{}:C:\\runner", expected.name);
        let copied = Self::docker(&os_args(["cp", &source, &destination]));
        if !matches!(copied, Ok(result) if result.success) {
            let _ = Self::docker(&os_args(["rm", "--force", expected.name.as_str()]));
            self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
            return Err(failure(
                "runner package copy into Windows Hyper-V container failed",
            ));
        }

        // Exercise the exact Hyper-V container, bootstrap, and copied runner
        // before GitHub issues a JIT registration. An OS/architecture match is
        // insufficient: an image can still lack PowerShell or the libraries
        // Runner.Listener needs. The fixed marker is non-secret and the same
        // stopped container is restarted later with the one-time JIT input.
        let mut preflight = Command::new("docker")
            .args([
                OsStr::new("start"),
                OsStr::new("--attach"),
                OsStr::new("--interactive"),
                OsStr::new(expected.name.as_str()),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let preflight_ok = match &mut preflight {
            Ok(child) => {
                child
                    .stdin
                    .take()
                    .ok_or_else(|| std::io::Error::other("docker stdin unavailable"))
                    .and_then(|mut stdin| {
                        stdin.write_all(PREFLIGHT_INPUT.as_bytes())?;
                        stdin.flush()
                    })
                    .is_ok()
                    && child.wait().is_ok_and(|status| status.success())
            }
            Err(_) => false,
        };
        let preflight_record = Self::inspect_record(&expected.name).ok().flatten();
        if !preflight_ok
            || !preflight_record.is_some_and(|record| {
                record.same_owner(&expected)
                    && record.state == "exited"
                    && record.exit_code == Some(0)
            })
        {
            if let Ok(child) = &mut preflight {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = Self::docker(&os_args(["rm", "--force", expected.name.as_str()]));
            self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
            return Err(failure(
                "Windows Hyper-V image bootstrap compatibility check failed",
            ));
        }

        let identity = self
            .identity_for(attempt, expected.name)
            .ok_or_else(|| failure("Windows Hyper-V identity is invalid"))?;
        Ok(PreparedEnvironment::isolated(attempt.id, identity))
    }

    fn start(
        &self,
        prepared: PreparedEnvironment,
        attempt: &RunnerAttempt,
        handoff: OneTimeJitHandoff<'_>,
    ) -> Result<EnvironmentIdentity, ProcessStartFailure> {
        let Some(expected) = self.expected_record(attempt) else {
            return Err(ProcessStartFailure::before_spawn(failure(
                "Windows Hyper-V allocation is invalid",
            )));
        };
        if prepared.identity() != self.identity_for(attempt, expected.name.clone()).as_ref() {
            self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
            return Err(ProcessStartFailure::before_spawn(failure(
                "Windows Hyper-V prepared identity mismatch",
            )));
        }
        if !self.owns(attempt).unwrap_or(false) {
            self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
            return Err(ProcessStartFailure::before_spawn(failure(
                "Windows Hyper-V container ownership mismatch",
            )));
        }
        // The script is constant container metadata. The JIT value is never an
        // argument, Docker environment setting, label, file, or layer; it is
        // read from stdin and placed only in Runner.Listener's initial
        // environment. Runner.Listener is the primary workload, so its exit
        // makes the container observably exit.
        let mut child = Command::new("docker")
            .args([
                OsStr::new("start"),
                OsStr::new("--attach"),
                OsStr::new("--interactive"),
                OsStr::new(expected.name.as_str()),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| {
                ProcessStartFailure::before_spawn(failure("Windows runner bootstrap failed"))
            })?;
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("docker stdin unavailable"))
            .and_then(|mut stdin| {
                stdin.write_all(handoff.consume().expose().as_bytes())?;
                stdin.flush()
            });
        if write_result.is_err() {
            let _ = child.kill();
            let _ = Self::docker(&os_args(["stop", "--time", "0", expected.name.as_str()]));
            self.note(attempt.id, ProviderDiagnostic::StartFailed);
            return Err(ProcessStartFailure::after_spawn_stopped());
        }
        self.children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(attempt.id, child);
        self.identity_for(attempt, expected.name)
            .ok_or_else(ProcessStartFailure::after_spawn_stopped)
    }

    fn inspect(&self, attempt: &RunnerAttempt) -> Result<EnvironmentState, FailureReason> {
        let Some(expected) = self.expected_record(attempt) else {
            return Err(failure("Windows Hyper-V allocation is invalid"));
        };
        let Some(found) = Self::inspect_record(&expected.name)
            .map_err(|_| failure("Windows Hyper-V container inspection failed"))?
        else {
            return Ok(EnvironmentState::Missing);
        };
        if !found.same_owner(&expected) {
            self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
            return Err(failure("Windows Hyper-V container ownership mismatch"));
        }
        Ok(match found.state.as_str() {
            "created" | "restarting" => EnvironmentState::Starting,
            "running" | "paused" => EnvironmentState::Running,
            "exited" | "dead" | "removing" => EnvironmentState::Exited,
            _ => EnvironmentState::Exited,
        })
    }

    fn stop(&self, attempt: &RunnerAttempt) -> Result<ProviderStop, FailureReason> {
        let Some(expected) = self.expected_record(attempt) else {
            return Err(failure("Windows Hyper-V allocation is invalid"));
        };
        if !self.owns(attempt)? {
            return if Self::inspect_record(&expected.name)
                .ok()
                .flatten()
                .is_none()
            {
                Ok(ProviderStop::Stopped)
            } else {
                self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
                Err(failure("Windows Hyper-V container ownership mismatch"))
            };
        }
        if let Some(mut child) = self
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&attempt.id)
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        if matches!(Self::inspect_record(&expected.name), Ok(Some(record)) if matches!(record.state.as_str(), "exited" | "dead"))
        {
            return Ok(ProviderStop::Stopped);
        }
        let stopped = Self::docker(&os_args(["stop", "--time", "10", expected.name.as_str()]))
            .map_err(|_| failure("Windows Hyper-V container stop failed"))?;
        Ok(if stopped.success || stopped.is_missing_resource() {
            ProviderStop::Stopped
        } else {
            ProviderStop::StillRunning
        })
    }

    fn destroy(&self, attempt: &RunnerAttempt) -> Result<ProviderDestroy, FailureReason> {
        let Some(expected) = self.expected_record(attempt) else {
            return Err(failure("Windows Hyper-V allocation is invalid"));
        };
        if !self.owns(attempt)? {
            return if Self::inspect_record(&expected.name)
                .ok()
                .flatten()
                .is_none()
            {
                Ok(ProviderDestroy::Destroyed)
            } else {
                self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
                Err(failure("Windows Hyper-V container ownership mismatch"))
            };
        }
        let removed = Self::docker(&os_args(["rm", "--force", expected.name.as_str()]))
            .map_err(|_| failure("Windows Hyper-V container destroy failed"))?;
        if (removed.success || removed.is_missing_resource())
            && Self::inspect_record(&expected.name)
                .ok()
                .flatten()
                .is_none()
        {
            return Ok(ProviderDestroy::Destroyed);
        }
        self.note(attempt.id, ProviderDiagnostic::CleanupDeferred);
        Ok(ProviderDestroy::Deferred(
            "container runtime retained resource",
        ))
    }

    fn recover(&self, attempt: &RunnerAttempt) -> Result<EnvironmentState, FailureReason> {
        self.inspect(attempt)
    }

    fn enumerate_owned(&self, host_id: HostId) -> Vec<EnvironmentIdentity> {
        let filter = format!("label={LABEL_HOST}={host_id}");
        let Ok(list) = Self::docker(&os_args([
            "ps",
            "--all",
            "--filter",
            &filter,
            "--format",
            "{{.Names}}",
        ])) else {
            return Vec::new();
        };
        if !list.success {
            return Vec::new();
        }
        list.stdout
            .lines()
            .take(1024)
            .filter_map(|name| Self::inspect_record(name).ok().flatten())
            .filter(|record| record.host == host_id)
            .map(|record| EnvironmentIdentity::Isolated {
                host: record.host,
                attempt: record.attempt,
                provider_kind: Backend::WindowsHyperVContainer,
                environment_id: record.name,
                resolved_image: record.image,
                generation: record.generation,
            })
            .collect()
    }

    fn diagnostics(&self, attempt: &RunnerAttempt) -> Vec<ProviderDiagnostic> {
        self.diagnostics
            .lock()
            .ok()
            .and_then(|all| all.get(&attempt.id).cloned())
            .unwrap_or_default()
    }

    fn owns(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
        let Some(expected) = self.expected_record(attempt) else {
            return Ok(false);
        };
        Self::inspect_record(&expected.name)
            .map(|found| found.is_some_and(|record| record.same_owner(&expected)))
            .map_err(|_| failure("Windows Hyper-V ownership inspection failed"))
    }

    fn spawn(
        &self,
        _attempt: &RunnerAttempt,
        _config: &runner_manager_github::jit::EncodedJitConfig,
    ) -> Result<u32, ProcessStartFailure> {
        Err(ProcessStartFailure::before_spawn(failure(
            "Windows Hyper-V provider cannot launch native processes",
        )))
    }

    fn is_alive(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
        self.inspect(attempt).map(|state| {
            matches!(
                state,
                EnvironmentState::Starting | EnvironmentState::Running
            )
        })
    }

    fn recovered_pid(&self, _attempt: &RunnerAttempt) -> Result<Option<u32>, FailureReason> {
        Ok(None)
    }

    fn completed_successfully(&self, attempt: &RunnerAttempt) -> bool {
        let Some(expected) = self.expected_record(attempt) else {
            return false;
        };
        matches!(Self::inspect_record(&expected.name), Ok(Some(record)) if record.same_owner(&expected) && record.state == "exited" && record.exit_code == Some(0))
    }

    fn record_terminate_intent(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason> {
        write_durable_file(&Self::intent_path(attempt), b"registration-timeout\n")
            .map_err(|_| failure("terminate intent could not be journalled"))
    }

    fn has_terminate_intent(&self, attempt: &RunnerAttempt) -> bool {
        Self::intent_path(attempt).is_file()
    }

    fn terminate(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason> {
        self.stop(attempt).map(|_| ())
    }
}

#[derive(Debug, Clone)]
struct ResourceRecord {
    name: String,
    state: String,
    exit_code: Option<i64>,
    host: HostId,
    attempt: AttemptId,
    generation: String,
    image: ImageReference,
}

impl ResourceRecord {
    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.trim_start_matches('/').split('|');
        let name = fields.next()?.to_owned();
        let state = fields.next()?.to_owned();
        let exit_code = fields.next()?.parse().ok();
        let host = HostId::from_uuid(uuid::Uuid::parse_str(fields.next()?).ok()?);
        let attempt = AttemptId::from_uuid(uuid::Uuid::parse_str(fields.next()?).ok()?);
        let generation = fields.next()?.to_owned();
        let image = ImageReference::new(fields.next()?).ok()?;
        (fields.next()? == PROVIDER_VALUE && fields.next().is_none()).then_some(Self {
            name,
            state,
            exit_code,
            host,
            attempt,
            generation,
            image,
        })
    }

    fn same_owner(&self, other: &Self) -> bool {
        self.name == other.name
            && self.host == other.host
            && self.attempt == other.attempt
            && self.generation == other.generation
            && self.image == other.image
    }
}

#[derive(Debug)]
struct CommandResult {
    success: bool,
    stdout: String,
    stderr: String,
}

impl CommandResult {
    fn from_output(output: Output) -> Self {
        Self {
            success: output.status.success(),
            stdout: bounded_text(output.stdout),
            stderr: bounded_text(output.stderr),
        }
    }

    fn permission_denied(&self) -> bool {
        let text = self.stderr.to_ascii_lowercase();
        text.contains("access is denied") || text.contains("permission denied")
    }

    fn is_missing_resource(&self) -> bool {
        let text = self.stderr.to_ascii_lowercase();
        text.contains("no such container") || text.contains("no such object")
    }

    fn failure(&self) -> CommandFailure {
        if self.permission_denied() {
            CommandFailure::PermissionDenied
        } else {
            CommandFailure::Failed
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandFailure {
    NotFound,
    PermissionDenied,
    Failed,
}

trait CommandRunner {
    fn run(&self, program: &str, args: &[OsString]) -> Result<CommandResult, CommandFailure>;
}

#[derive(Debug)]
struct SystemCommands;

impl CommandRunner for SystemCommands {
    fn run(&self, program: &str, args: &[OsString]) -> Result<CommandResult, CommandFailure> {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map(CommandResult::from_output)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    CommandFailure::NotFound
                } else if error.kind() == std::io::ErrorKind::PermissionDenied {
                    CommandFailure::PermissionDenied
                } else {
                    CommandFailure::Failed
                }
            })
    }
}

fn host_state_with(commands: &dyn CommandRunner) -> WindowsHyperVHostState {
    if !cfg!(windows) {
        return WindowsHyperVHostState::UnsupportedHost;
    }
    const PROBE: &str = "$edition=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction Stop).EditionID; $f=Get-CimInstance Win32_OptionalFeature -ErrorAction Stop; $hv=@($f | Where-Object { $_.Name -in @('Microsoft-Hyper-V','Microsoft-Hyper-V-All') -and $_.InstallState -eq 1 }).Count; $ct=@($f | Where-Object { $_.Name -eq 'Containers' -and $_.InstallState -eq 1 }).Count; Write-Output \"edition=$edition\"; Write-Output \"hyperv=$hv\"; Write-Output \"containers=$ct\"";
    let system = match commands.run(
        "powershell.exe",
        &os_args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            PROBE,
        ]),
    ) {
        Ok(result) if result.success => result,
        Ok(result) if result.permission_denied() => {
            return WindowsHyperVHostState::RuntimePermissionDenied;
        }
        _ => return WindowsHyperVHostState::RuntimeDegraded,
    };
    let edition = value(&system.stdout, "edition").unwrap_or_default();
    if !supported_edition(edition) {
        return WindowsHyperVHostState::UnsupportedHost;
    }
    let Some(hyper_v_features) =
        value(&system.stdout, "hyperv").and_then(|count| count.parse::<u32>().ok())
    else {
        return WindowsHyperVHostState::RuntimeDegraded;
    };
    if hyper_v_features == 0 {
        return WindowsHyperVHostState::HyperVUnavailable;
    }
    let Some(container_features) =
        value(&system.stdout, "containers").and_then(|count| count.parse::<u32>().ok())
    else {
        return WindowsHyperVHostState::RuntimeDegraded;
    };
    if container_features == 0 {
        return WindowsHyperVHostState::ContainersUnavailable;
    }
    let runtime = match commands.run(
        "docker",
        &os_args(["version", "--format", "{{.Server.Os}}"]),
    ) {
        Err(CommandFailure::NotFound) => return WindowsHyperVHostState::RuntimeNotInstalled,
        Err(CommandFailure::PermissionDenied) => {
            return WindowsHyperVHostState::RuntimePermissionDenied;
        }
        Err(CommandFailure::Failed) => return WindowsHyperVHostState::RuntimeDegraded,
        Ok(result) if result.permission_denied() => {
            return WindowsHyperVHostState::RuntimePermissionDenied;
        }
        Ok(result) if !result.success => return WindowsHyperVHostState::RuntimeDegraded,
        Ok(result) => result,
    };
    if runtime.stdout.trim() != "windows" {
        return WindowsHyperVHostState::RuntimeInLinuxMode;
    }
    WindowsHyperVHostState::Ready
}

fn inspect_image(image: &ImageReference) -> Result<bool, CommandFailure> {
    let result = WindowsHyperVContainers::docker(&os_args([
        "image",
        "inspect",
        "--format",
        "{{.Os}}|{{.Architecture}}",
        image.as_str(),
    ]))?;
    if !result.success {
        return if result.permission_denied() {
            Err(CommandFailure::PermissionDenied)
        } else {
            Ok(false)
        };
    }
    Ok(compatible_image_metadata(&result.stdout))
}

fn compatible_image_metadata(metadata: &str) -> bool {
    let mut fields = metadata.trim().split('|');
    fields.next() == Some("windows") && fields.next() == Some("amd64") && fields.next().is_none()
}

fn create_args(record: &ResourceRecord, resources: ResourceLimits) -> Vec<OsString> {
    let cpu = format!("{:.3}", f64::from(resources.cpu_millis) / 1000.0);
    let memory = format!("{}m", resources.memory_mib);
    let disk = format!("{}m", resources.disk_mib);
    let host = record.host.to_string();
    let attempt = record.attempt.to_string();
    os_args([
        "create",
        "--name",
        record.name.as_str(),
        "--isolation=hyperv",
        "--interactive",
        "--network=nat",
        "--cpus",
        &cpu,
        "--memory",
        &memory,
        "--storage-opt",
        &format!("size={disk}"),
        "--label",
        &format!("{LABEL_HOST}={host}"),
        "--label",
        &format!("{LABEL_ATTEMPT}={attempt}"),
        "--label",
        &format!("{LABEL_GENERATION}={}", record.generation),
        "--label",
        &format!("{LABEL_IMAGE}={}", record.image.as_str()),
        "--label",
        &format!("{LABEL_PROVIDER}={PROVIDER_VALUE}"),
        "--entrypoint",
        "powershell.exe",
        record.image.as_str(),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        BOOTSTRAP,
    ])
}

fn container_name(host: HostId, attempt: AttemptId, generation: &str) -> String {
    let compact = generation
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .take(12)
        .collect::<String>();
    format!("runner-manager-{host}-{attempt}-{compact}")
}

fn supported_edition(edition: &str) -> bool {
    let edition = edition.to_ascii_lowercase();
    edition.contains("professional")
        || edition.contains("enterprise")
        || edition.contains("education")
        || edition.contains("server")
        || edition.contains("iotenterprise")
}

fn value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(key)?.strip_prefix('='))
}

fn os_args<const N: usize>(args: [&str; N]) -> Vec<OsString> {
    args.into_iter().map(OsString::from).collect()
}

fn bounded_text(mut bytes: Vec<u8>) -> String {
    bytes.truncate(MAX_CAPTURE);
    String::from_utf8_lossy(&bytes).into_owned()
}

fn failure(message: &'static str) -> FailureReason {
    FailureReason::Other(message.into())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[cfg(windows)]
    #[derive(Debug)]
    struct FakeCommands(Mutex<VecDeque<Result<CommandResult, CommandFailure>>>);

    #[cfg(windows)]
    impl CommandRunner for FakeCommands {
        fn run(&self, _program: &str, _args: &[OsString]) -> Result<CommandResult, CommandFailure> {
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted command")
        }
    }

    #[cfg(windows)]
    fn output(stdout: &str) -> Result<CommandResult, CommandFailure> {
        Ok(CommandResult {
            success: true,
            stdout: stdout.into(),
            stderr: String::new(),
        })
    }

    #[cfg(windows)]
    fn host_probe(
        system: Result<CommandResult, CommandFailure>,
        runtime: Option<Result<CommandResult, CommandFailure>>,
    ) -> WindowsHyperVHostState {
        let mut commands = VecDeque::from([system]);
        if let Some(runtime) = runtime {
            commands.push_back(runtime);
        }
        host_state_with(&FakeCommands(Mutex::new(commands)))
    }

    #[test]
    fn editions_are_fail_closed() {
        for supported in [
            "Professional",
            "EnterpriseS",
            "Education",
            "ServerStandard",
            "IoTEnterprise",
        ] {
            assert!(supported_edition(supported), "{supported}");
        }
        for refused in ["", "Core", "Home", "Cloud", "mystery"] {
            assert!(!supported_edition(refused), "{refused}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn host_probe_distinguishes_every_fail_closed_prerequisite() {
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=1\n"),
                Some(output("windows\n"))
            ),
            WindowsHyperVHostState::Ready
        );
        assert_eq!(
            host_probe(output("edition=Core\nhyperv=1\ncontainers=1\n"), None),
            WindowsHyperVHostState::UnsupportedHost
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=0\ncontainers=1\n"),
                None
            ),
            WindowsHyperVHostState::HyperVUnavailable
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=0\n"),
                None
            ),
            WindowsHyperVHostState::ContainersUnavailable
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=1\n"),
                Some(Err(CommandFailure::NotFound))
            ),
            WindowsHyperVHostState::RuntimeNotInstalled
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=1\n"),
                Some(output("linux\n"))
            ),
            WindowsHyperVHostState::RuntimeInLinuxMode
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=1\n"),
                Some(Err(CommandFailure::PermissionDenied))
            ),
            WindowsHyperVHostState::RuntimePermissionDenied
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=1\n"),
                Some(Err(CommandFailure::Failed))
            ),
            WindowsHyperVHostState::RuntimeDegraded
        );
        for malformed in [
            "edition=Professional\ncontainers=1\n",
            "edition=Professional\nhyperv=not-a-count\ncontainers=1\n",
            "edition=Professional\nhyperv=1\n",
            "edition=Professional\nhyperv=1\ncontainers=not-a-count\n",
        ] {
            assert_eq!(
                host_probe(output(malformed), None),
                WindowsHyperVHostState::RuntimeDegraded,
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn image_metadata_requires_the_windows_amd64_pair_exactly() {
        assert!(compatible_image_metadata("windows|amd64\n"));
        for rejected in [
            "linux|amd64",
            "windows|arm64",
            "windows|amd64|extra",
            "windows",
            "",
        ] {
            assert!(!compatible_image_metadata(rejected), "{rejected}");
        }
    }

    #[test]
    fn resource_record_requires_every_ownership_label() {
        let host = HostId::from_u128(1);
        let attempt = AttemptId::from_u128(2);
        let image = format!("registry.example/runner@sha256:{}", "a".repeat(64));
        let line = format!("name|running|0|{host}|{attempt}|generation|{image}|{PROVIDER_VALUE}");
        let record = ResourceRecord::parse(&line).expect("complete record");
        assert_eq!(record.host, host);
        assert_eq!(record.attempt, attempt);
        assert!(ResourceRecord::parse(&line.replace(PROVIDER_VALUE, "process")).is_none());
        assert!(ResourceRecord::parse("name|running").is_none());
    }

    #[test]
    fn bootstrap_never_embeds_the_jit_value_in_docker_metadata() {
        assert!(BOOTSTRAP.contains("[Console]::In.ReadToEnd()"));
        assert!(BOOTSTRAP.contains("ACTIONS_RUNNER_INPUT_JITCONFIG"));
        assert!(BOOTSTRAP.contains("ProcessStartInfo"));
        assert!(BOOTSTRAP.contains(PREFLIGHT_INPUT));
        assert!(!BOOTSTRAP.contains("$env:ACTIONS_RUNNER_INPUT_JITCONFIG"));
        assert!(!BOOTSTRAP.contains("fixture-jit-value"));
    }

    #[test]
    fn create_forces_hyper_v_limits_and_has_no_host_escape_surface() {
        let record = ResourceRecord {
            name: "runner-manager-fixture".into(),
            state: String::new(),
            exit_code: None,
            host: HostId::from_u128(1),
            attempt: AttemptId::from_u128(2),
            generation: "fixture-generation".into(),
            image: ImageReference::new(format!(
                "registry.example/runner@sha256:{}",
                "a".repeat(64)
            ))
            .unwrap(),
        };
        let args = create_args(
            &record,
            ResourceLimits {
                cpu_millis: 2500,
                memory_mib: 3072,
                disk_mib: 8192,
            },
        )
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
        assert!(args.iter().any(|arg| arg == "--isolation=hyperv"));
        assert!(args.windows(2).any(|pair| pair == ["--cpus", "2.500"]));
        assert!(args.windows(2).any(|pair| pair == ["--memory", "3072m"]));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--storage-opt", "size=8192m"])
        );
        for forbidden in ["--volume", "--mount", "--device", "--privileged"] {
            assert!(!args.iter().any(|arg| arg == forbidden), "{args:?}");
        }
        assert!(!args.iter().any(|arg| arg.contains("docker.sock")));
    }
}
