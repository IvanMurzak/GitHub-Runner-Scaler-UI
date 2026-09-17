//! Rootless Podman-compatible provider for dependency-isolated Linux runners.
//! The runtime is installed by the operator; this adapter never starts a native
//! runner for an isolated policy and never grants a host filesystem mount.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use runner_manager_domain::attempt::{FailureReason, IsolationProviderFailure, RunnerAttempt};
use runner_manager_domain::execution::{
    AttemptExecution, Backend, ExecutionPolicy, ImageReference,
};
use runner_manager_domain::model::{AttemptId, HostId};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_github::jit::EncodedJitConfig;

use crate::lifecycle::{
    EnvironmentIdentity, EnvironmentState, ExecutionProvider, NativeProcesses, OneTimeJitHandoff,
    PreparedEnvironment, ProcessStartFailure, ProviderCapability, ProviderDestroy, ProviderStop,
    ResolvedEnvironment,
};

const HOST_LABEL: &str = "io.runner-manager.host";
const ATTEMPT_LABEL: &str = "io.runner-manager.attempt";
const GENERATION_LABEL: &str = "io.runner-manager.generation";
const IMAGE_LABEL: &str = "io.runner-manager.image";
const BOOTSTRAP: &str = "IFS= read -r jit || exit 43; export ACTIONS_RUNNER_INPUT_JITCONFIG=\"$jit\"; unset jit; cd /runner || exit 44; exec ./bin/Runner.Listener run";
const OCI_RUNTIME_ENV: &str = "RUNNER_MANAGER_OCI_RUNTIME";
const BOUNDED_STORAGE_SCHEMA: u64 = 1;
const BOUNDED_STORAGE_MODE: &str = "exclusive-filesystem-pool";
const QUOTA_PROBE_MIB: u64 = 1024;

#[derive(Debug)]
pub struct OciProcesses {
    host: HostId,
    native: NativeProcesses,
    runtime: String,
    runtime_configuration_valid: bool,
    attached: Mutex<BTreeMap<AttemptId, Child>>,
}

impl OciProcesses {
    #[must_use]
    pub fn new(host: HostId) -> Self {
        let (runtime, runtime_configuration_valid) = match std::env::var(OCI_RUNTIME_ENV) {
            Ok(runtime) if operator_runtime_is_trusted(Path::new(&runtime)) => (runtime, true),
            Ok(_) => ("/runner-manager-invalid-oci-runtime".into(), false),
            Err(std::env::VarError::NotPresent) => ("podman".into(), true),
            Err(std::env::VarError::NotUnicode(_)) => {
                ("/runner-manager-invalid-oci-runtime".into(), false)
            }
        };
        Self {
            host,
            native: NativeProcesses::new(),
            runtime,
            runtime_configuration_valid,
            attached: Mutex::new(BTreeMap::new()),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.runtime);
        command.stdin(Stdio::null()).stderr(Stdio::null());
        command
    }

    fn output(&self, args: &[&str]) -> Result<String, FailureReason> {
        let output = self
            .command()
            .args(args)
            .output()
            .map_err(|_| provider_failure())?;
        if !output.status.success() || output.stdout.len() > 64 * 1024 {
            return Err(provider_failure());
        }
        String::from_utf8(output.stdout).map_err(|_| provider_failure())
    }

    fn status(&self, args: &[&str]) -> Result<(), FailureReason> {
        let status = self
            .command()
            .args(args)
            .stdout(Stdio::null())
            .status()
            .map_err(|_| provider_failure())?;
        if status.success() {
            Ok(())
        } else {
            Err(provider_failure())
        }
    }

    fn rootless_ready(&self) -> ProviderCapability {
        self.rootless_ready_for(QUOTA_PROBE_MIB)
    }

    fn rootless_ready_for(&self, requested_mib: u64) -> ProviderCapability {
        if !cfg!(target_os = "linux") {
            return ProviderCapability::Unsupported;
        }
        if !self.runtime_configuration_valid {
            return ProviderCapability::PermissionDenied;
        }
        let info = match self.command().args(["info", "--format=json"]).output() {
            Ok(output) if output.status.success() && output.stdout.len() <= 64 * 1024 => {
                match String::from_utf8(output.stdout) {
                    Ok(info) => info,
                    Err(_) => return ProviderCapability::Degraded,
                }
            }
            Ok(_) => return ProviderCapability::PermissionDenied,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ProviderCapability::NotInstalled;
            }
            Err(_) => return ProviderCapability::Degraded,
        };
        let Ok(info) = serde_json::from_str::<serde_json::Value>(&info) else {
            return ProviderCapability::Degraded;
        };
        if info
            .pointer("/host/security/rootless")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        {
            return ProviderCapability::PermissionDenied;
        }
        let mappings = ["/host/idMappings/uidmap", "/host/idMappings/gidmap"];
        if mappings.iter().any(|path| {
            info.pointer(path)
                .and_then(serde_json::Value::as_array)
                .is_none_or(|ranges| {
                    !ranges.iter().any(|range| {
                        range
                            .get("size")
                            .and_then(serde_json::Value::as_u64)
                            .is_some_and(|size| size >= 65536)
                    })
                })
        }) {
            return ProviderCapability::PermissionDenied;
        }
        if info
            .pointer("/host/cgroupVersion")
            .and_then(serde_json::Value::as_str)
            != Some("v2")
        {
            return ProviderCapability::Degraded;
        }
        let Some(controllers) = info
            .pointer("/host/cgroupControllers")
            .and_then(serde_json::Value::as_array)
        else {
            return ProviderCapability::Degraded;
        };
        if ["cpu", "memory", "pids"].iter().any(|needed| {
            !controllers
                .iter()
                .any(|controller| controller.as_str() == Some(needed))
        }) {
            return ProviderCapability::Degraded;
        }
        let Some(graph_root) = info
            .pointer("/store/graphRoot")
            .and_then(serde_json::Value::as_str)
        else {
            return ProviderCapability::Degraded;
        };
        let Some(run_root) = info
            .pointer("/store/runRoot")
            .and_then(serde_json::Value::as_str)
        else {
            return ProviderCapability::Degraded;
        };
        if !graph_root.starts_with('/')
            || !run_root.starts_with('/')
            || graph_root.starts_with("/mnt/")
            || run_root.starts_with("/mnt/")
        {
            return ProviderCapability::PermissionDenied;
        }
        let backing_filesystem = info
            .pointer("/store/graphStatus/Backing Filesystem")
            .and_then(serde_json::Value::as_str);
        let storage_size = format!("size={requested_mib}m");
        let quota_probe =
            match self.output(&["--storage-opt", &storage_size, "info", "--format=json"]) {
                Ok(output) => output,
                Err(_) => return ProviderCapability::DiskQuotaUnavailable,
            };
        // Native Podman writable-layer quotas require XFS project quotas. XFS
        // alone is insufficient: rootless quota setup can still fail with
        // EPERM, which the command above catches before allocation or JIT.
        if backing_filesystem == Some("xfs") {
            return ProviderCapability::Ready;
        }
        // Managed WSL can instead use an operator-provisioned runtime helper.
        // The helper routes every `size=...` create into an exclusive finite
        // filesystem and attests that contract in the quota-probe response.
        // Plain Podman on extfs has no attestation and remains fail-closed.
        let Ok(quota_info) = serde_json::from_str::<serde_json::Value>(&quota_probe) else {
            return ProviderCapability::DiskQuotaUnavailable;
        };
        if bounded_storage_attested(&quota_info, graph_root, run_root, requested_mib) {
            ProviderCapability::Ready
        } else {
            ProviderCapability::DiskQuotaUnavailable
        }
    }

    fn capability_or(&self, fallback: FailureReason) -> FailureReason {
        let capability = self.rootless_ready();
        if capability == ProviderCapability::Ready {
            fallback
        } else {
            capability.refusal()
        }
    }

    fn image_ready(&self, image: &ImageReference) -> Result<(), FailureReason> {
        let Some((_, expected)) = image.as_str().rsplit_once("@sha256:") else {
            return Err(image_failure());
        };
        self.status(&["pull", "--quiet", image.as_str()])
            .map_err(|_| self.capability_or(image_failure()))?;
        let digests = self
            .output(&[
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                image.as_str(),
            ])
            .map_err(|_| self.capability_or(image_failure()))?;
        let values: Vec<String> =
            serde_json::from_str(digests.trim()).map_err(|_| image_failure())?;
        if !values
            .iter()
            .any(|value| value.ends_with(&format!("@sha256:{expected}")))
        {
            return Err(image_failure());
        }
        Ok(())
    }

    fn isolated_identity(
        &self,
        attempt: &RunnerAttempt,
        id: String,
    ) -> Result<EnvironmentIdentity, FailureReason> {
        let AttemptExecution::Isolated {
            provider_kind: Backend::Oci,
            resolved_image,
            generation,
            ..
        } = attempt.execution()
        else {
            return Err(ownership_failure());
        };
        Ok(EnvironmentIdentity::Isolated {
            host: self.host,
            attempt: attempt.id,
            provider_kind: Backend::Oci,
            environment_id: id,
            resolved_image: resolved_image.clone(),
            generation: generation.clone(),
        })
    }

    fn environment_id<'a>(&self, attempt: &'a RunnerAttempt) -> Result<&'a str, FailureReason> {
        let AttemptExecution::Isolated {
            provider_kind: Backend::Oci,
            environment_id: Some(id),
            ..
        } = attempt.execution()
        else {
            return Err(ownership_failure());
        };
        Ok(id)
    }

    fn labels(&self, id: &str) -> Result<BTreeMap<String, String>, FailureReason> {
        let labels = self.output(&[
            "container",
            "inspect",
            "--format",
            "{{json .Config.Labels}}",
            id,
        ])?;
        serde_json::from_str(labels.trim()).map_err(|_| ownership_failure())
    }

    fn exists(&self, id: &str) -> Result<bool, FailureReason> {
        let status = self
            .command()
            .args(["container", "exists", id])
            .stdout(Stdio::null())
            .status()
            .map_err(|_| provider_failure())?;
        match status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(provider_failure()),
        }
    }

    fn check_ownership(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
        let id = self.environment_id(attempt)?;
        let labels = self.labels(id)?;
        let AttemptExecution::Isolated { resolved_image, .. } = attempt.execution() else {
            return Err(ownership_failure());
        };
        Ok(self.matches_attempt_labels(&labels, attempt)
            && labels
                .get(IMAGE_LABEL)
                .is_some_and(|value| value == resolved_image.as_str()))
    }

    fn matches_attempt_labels(
        &self,
        labels: &BTreeMap<String, String>,
        attempt: &RunnerAttempt,
    ) -> bool {
        let AttemptExecution::Isolated { generation, .. } = attempt.execution() else {
            return false;
        };
        labels.get(HOST_LABEL) == Some(&self.host.to_string())
            && labels.get(ATTEMPT_LABEL) == Some(&attempt.id.to_string())
            && labels.get(GENERATION_LABEL) == Some(generation)
    }

    fn state(&self, attempt: &RunnerAttempt) -> Result<EnvironmentState, FailureReason> {
        if !self.exists(self.environment_id(attempt)?)? {
            return Ok(EnvironmentState::Missing);
        }
        if !self.check_ownership(attempt)? {
            return Err(ownership_failure());
        }
        let status = self.output(&[
            "container",
            "inspect",
            "--format",
            "{{.State.Status}}",
            self.environment_id(attempt)?,
        ])?;
        match status.trim() {
            "running" => Ok(EnvironmentState::Running),
            "created" | "configured" => Ok(EnvironmentState::Starting),
            "exited" | "stopped" => Ok(EnvironmentState::Exited),
            _ => Err(provider_failure()),
        }
    }

    fn reap_attached(&self, attempt: AttemptId) {
        let child = self
            .attached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&attempt);
        if let Some(mut child) = child {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

#[cfg(unix)]
fn operator_runtime_is_trusted(path: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !path.is_absolute() {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    if canonical == Path::new("/mnt") || canonical.starts_with("/mnt/") {
        return false;
    }
    let Ok(metadata) = canonical.metadata() else {
        return false;
    };
    let mode = metadata.permissions().mode();
    metadata.is_file() && metadata.uid() == 0 && mode & 0o111 != 0 && mode & 0o022 == 0
}

#[cfg(not(unix))]
fn operator_runtime_is_trusted(_path: &Path) -> bool {
    false
}

fn bounded_storage_attested(
    info: &serde_json::Value,
    graph_root: &str,
    run_root: &str,
    requested_mib: u64,
) -> bool {
    info.pointer("/host/security/rootless")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        && info
            .pointer("/store/graphRoot")
            .and_then(serde_json::Value::as_str)
            == Some(graph_root)
        && info
            .pointer("/store/runRoot")
            .and_then(serde_json::Value::as_str)
            == Some(run_root)
        && info
            .pointer("/runnerManagerStorage/schema")
            .and_then(serde_json::Value::as_u64)
            == Some(BOUNDED_STORAGE_SCHEMA)
        && info
            .pointer("/runnerManagerStorage/mode")
            .and_then(serde_json::Value::as_str)
            == Some(BOUNDED_STORAGE_MODE)
        && info
            .pointer("/runnerManagerStorage/requestedMiB")
            .and_then(serde_json::Value::as_u64)
            == Some(requested_mib)
        && info
            .pointer("/runnerManagerStorage/hardCap")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
}

fn provider_failure() -> FailureReason {
    FailureReason::IsolationProvider(IsolationProviderFailure::RuntimeOperationFailed)
}
fn image_failure() -> FailureReason {
    FailureReason::IsolationProvider(IsolationProviderFailure::ImageUnavailableOrIncompatible)
}
fn ownership_failure() -> FailureReason {
    FailureReason::IsolationProvider(IsolationProviderFailure::OwnershipMismatch)
}

impl ExecutionProvider for OciProcesses {
    fn probe(&self, policy: &ScalePolicy) -> ProviderCapability {
        if policy.execution_policy().is_native() {
            return ProviderCapability::Ready;
        }
        let ExecutionPolicy::Isolated {
            backend,
            image,
            resources,
        } = policy.execution_policy()
        else {
            return ProviderCapability::Unsupported;
        };
        if !matches!(backend, Backend::Auto | Backend::Oci) {
            return ProviderCapability::Unsupported;
        }
        let capability = self.rootless_ready_for(u64::from(resources.disk_mib));
        if capability != ProviderCapability::Ready {
            return capability;
        }
        if self.image_ready(image).is_err() {
            let capability = self.rootless_ready_for(u64::from(resources.disk_mib));
            if capability == ProviderCapability::Ready {
                ProviderCapability::ImageUnavailableOrIncompatible
            } else {
                capability
            }
        } else {
            ProviderCapability::Ready
        }
    }

    fn resolve(&self, policy: &ScalePolicy) -> Result<Option<ResolvedEnvironment>, FailureReason> {
        let ExecutionPolicy::Isolated {
            backend,
            image,
            resources,
        } = policy.execution_policy()
        else {
            return Ok(None);
        };
        if !matches!(backend, Backend::Auto | Backend::Oci) {
            return Err(ProviderCapability::Unsupported.refusal());
        }
        let capability = self.rootless_ready_for(u64::from(resources.disk_mib));
        if capability != ProviderCapability::Ready {
            return Err(capability.refusal());
        }
        self.image_ready(image)?;
        Ok(Some(ResolvedEnvironment {
            provider_kind: Backend::Oci,
            image: image.clone(),
        }))
    }

    fn prepare(
        &self,
        attempt: &RunnerAttempt,
        policy: &ScalePolicy,
    ) -> Result<PreparedEnvironment, FailureReason> {
        let ExecutionPolicy::Isolated { resources, .. } = policy.execution_policy() else {
            return ExecutionProvider::prepare(&self.native, attempt, policy);
        };
        let AttemptExecution::Isolated {
            provider_kind: Backend::Oci,
            resolved_image,
            generation,
            ..
        } = attempt.execution()
        else {
            return Err(ownership_failure());
        };
        // Managed WSL must keep runner bytes in the distribution's Linux FS.
        if attempt
            .runtime_path()
            .to_str()
            .is_none_or(|path| !path.starts_with('/') || path.starts_with("/mnt/"))
        {
            return Err(FailureReason::IsolationProvider(
                IsolationProviderFailure::UnsafeRuntimePath,
            ));
        }
        let capability = self.rootless_ready_for(u64::from(resources.disk_mib));
        if capability != ProviderCapability::Ready {
            return Err(capability.refusal());
        }
        let name = format!(
            "rm-{}-{}",
            attempt.id,
            &generation[..generation.len().min(8)]
        );
        let cpu = format!("{:.3}", f64::from(resources.cpu_millis) / 1000.0);
        let memory = format!("{}m", resources.memory_mib);
        let disk = format!("size={}m", resources.disk_mib);
        let host_label = format!("{HOST_LABEL}={}", self.host);
        let attempt_label = format!("{ATTEMPT_LABEL}={}", attempt.id);
        let generation_label = format!("{GENERATION_LABEL}={generation}");
        let image_label = format!("{IMAGE_LABEL}={}", resolved_image.as_str());
        let id = self
            .output(&[
                "create",
                "--interactive",
                "--name",
                &name,
                "--pull=never",
                "--entrypoint=sh",
                "--log-driver=none",
                "--image-volume=ignore",
                "--http-proxy=false",
                "--userns=keep-id",
                "--user=0",
                "--cap-drop=all",
                "--cap-add=CHOWN",
                "--cap-add=SETUID",
                "--cap-add=SETGID",
                "--cap-add=DAC_OVERRIDE",
                "--cap-add=FOWNER",
                "--security-opt=no-new-privileges",
                "--network=slirp4netns",
                "--pids-limit=128",
                "--cpus",
                &cpu,
                "--memory",
                &memory,
                "--storage-opt",
                &disk,
                "--label",
                &host_label,
                "--label",
                &attempt_label,
                "--label",
                &generation_label,
                "--label",
                &image_label,
                resolved_image.as_str(),
                "-c",
                BOOTSTRAP,
            ])
            .map_err(|reason| self.capability_or(reason))?
            .trim()
            .to_owned();
        if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(self.capability_or(provider_failure()));
        }
        let identity = self.isolated_identity(attempt, id.clone())?;
        // The package copy is host-to-guest only; no host path is mounted.
        let source = format!("{}/.", attempt.runtime_path().display());
        let destination = format!("{id}:/runner");
        if self.status(&["cp", &source, &destination]).is_err() {
            // Roll back before returning without a journalled environment ID.
            // An unavailable runtime leaves a labelled orphan for enumeration.
            if self
                .labels(&id)
                .is_ok_and(|labels| self.matches_attempt_labels(&labels, attempt))
            {
                let _ = self.status(&["rm", "--force", &id]);
            }
            return Err(self.capability_or(provider_failure()));
        }
        Ok(PreparedEnvironment::isolated(attempt.id, identity))
    }

    fn start(
        &self,
        prepared: PreparedEnvironment,
        attempt: &RunnerAttempt,
        handoff: OneTimeJitHandoff<'_>,
    ) -> Result<EnvironmentIdentity, ProcessStartFailure> {
        if attempt.execution().is_native() {
            return ExecutionProvider::start(&self.native, prepared, attempt, handoff);
        }
        let Some(identity @ EnvironmentIdentity::Isolated { .. }) = prepared.identity().cloned()
        else {
            return Err(ProcessStartFailure::before_spawn(ownership_failure()));
        };
        let EnvironmentIdentity::Isolated { environment_id, .. } = &identity else {
            unreachable!()
        };
        if self.environment_id(attempt).ok() != Some(environment_id.as_str())
            || self.check_ownership(attempt) != Ok(true)
        {
            return Err(ProcessStartFailure::before_spawn(ownership_failure()));
        }
        let config = handoff.consume();
        let payload = config.expose();
        if payload.is_empty()
            || payload.len() > 64 * 1024
            || payload
                .bytes()
                .any(|byte| byte == b'\n' || byte == b'\r' || byte == 0)
        {
            return Err(ProcessStartFailure::before_spawn(
                FailureReason::IsolationProvider(IsolationProviderFailure::JitHandoffRejected),
            ));
        }
        let mut command = self.command();
        let mut child = command
            .args([
                "start",
                "--attach",
                "--interactive",
                "--sig-proxy=false",
                environment_id,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ProcessStartFailure::before_spawn(provider_failure()))?;
        let write = child.stdin.take().is_some_and(|mut stdin| {
            stdin.write_all(payload.as_bytes()).is_ok() && stdin.write_all(b"\n").is_ok()
        });
        if !write {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProcessStartFailure::before_spawn(provider_failure()));
        }
        self.attached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(attempt.id, child);
        Ok(identity)
    }

    fn inspect(&self, attempt: &RunnerAttempt) -> Result<EnvironmentState, FailureReason> {
        if attempt.execution().is_native() {
            return ExecutionProvider::inspect(&self.native, attempt);
        }
        self.state(attempt)
    }

    fn recover(&self, attempt: &RunnerAttempt) -> Result<EnvironmentState, FailureReason> {
        let AttemptExecution::Isolated {
            environment_id: None,
            generation,
            ..
        } = attempt.execution()
        else {
            return self.inspect(attempt);
        };
        let filters = [
            format!("label={HOST_LABEL}={}", self.host),
            format!("label={ATTEMPT_LABEL}={}", attempt.id),
            format!("label={GENERATION_LABEL}={generation}"),
        ];
        let ids = self.output(&[
            "ps",
            "--all",
            "--no-trunc",
            "--filter",
            &filters[0],
            "--filter",
            &filters[1],
            "--filter",
            &filters[2],
            "--format",
            "{{.ID}}",
        ])?;
        if ids.trim().is_empty() {
            Ok(EnvironmentState::Missing)
        } else {
            Ok(EnvironmentState::Starting)
        }
    }

    fn stop(&self, attempt: &RunnerAttempt) -> Result<ProviderStop, FailureReason> {
        if attempt.execution().is_native() {
            return ExecutionProvider::stop(&self.native, attempt);
        }
        if !self.exists(self.environment_id(attempt)?)? {
            return Ok(ProviderStop::Stopped);
        }
        if self.state(attempt)? == EnvironmentState::Exited {
            return Ok(ProviderStop::Stopped);
        }
        if !self.check_ownership(attempt)? {
            return Err(ownership_failure());
        }
        self.status(&["stop", "--time=10", self.environment_id(attempt)?])
            .map_err(|reason| self.capability_or(reason))?;
        Ok(ProviderStop::Stopped)
    }

    fn destroy(&self, attempt: &RunnerAttempt) -> Result<ProviderDestroy, FailureReason> {
        if attempt.execution().is_native() {
            return ExecutionProvider::destroy(&self.native, attempt);
        }
        if !self.exists(self.environment_id(attempt)?)? {
            self.reap_attached(attempt.id);
            return Ok(ProviderDestroy::Destroyed);
        }
        if !self.check_ownership(attempt)? {
            return Err(ownership_failure());
        }
        self.status(&["rm", "--force", self.environment_id(attempt)?])
            .map_err(|reason| self.capability_or(reason))?;
        self.reap_attached(attempt.id);
        Ok(ProviderDestroy::Destroyed)
    }

    fn owns(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
        if attempt.execution().is_native() {
            Ok(true)
        } else {
            if !self.exists(self.environment_id(attempt)?)? {
                return Ok(false);
            }
            self.check_ownership(attempt)
        }
    }

    fn enumerate_owned(&self, host: HostId) -> Vec<EnvironmentIdentity> {
        // Recovery discovery must still work when a capability has degraded
        // since creation. A failed readiness probe is not evidence of absence.
        if host != self.host {
            return Vec::new();
        }
        let filter = format!("label={HOST_LABEL}={host}");
        let Ok(ids) = self.output(&[
            "ps",
            "--all",
            "--no-trunc",
            "--filter",
            &filter,
            "--format",
            "{{.ID}}",
        ]) else {
            return Vec::new();
        };
        ids.lines()
            .filter_map(|id| {
                if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return None;
                }
                let labels = self.labels(id).ok()?;
                if labels.get(HOST_LABEL)? != &host.to_string() {
                    return None;
                }
                let attempt =
                    AttemptId::from_uuid(uuid::Uuid::parse_str(labels.get(ATTEMPT_LABEL)?).ok()?);
                let generation = labels.get(GENERATION_LABEL)?.clone();
                let resolved_image = ImageReference::new(labels.get(IMAGE_LABEL)?.clone()).ok()?;
                Some(EnvironmentIdentity::Isolated {
                    host,
                    attempt,
                    provider_kind: Backend::Oci,
                    environment_id: id.to_owned(),
                    resolved_image,
                    generation,
                })
            })
            .collect()
    }

    fn spawn(
        &self,
        attempt: &RunnerAttempt,
        config: &EncodedJitConfig,
    ) -> Result<u32, ProcessStartFailure> {
        if !attempt.execution().is_native() {
            return Err(ProcessStartFailure::before_spawn(ownership_failure()));
        }
        self.native.spawn(attempt, config)
    }
    fn is_alive(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
        if !attempt.execution().is_native() {
            return Err(ownership_failure());
        }
        self.native.is_alive(attempt)
    }
    fn recovered_pid(&self, attempt: &RunnerAttempt) -> Result<Option<u32>, FailureReason> {
        if !attempt.execution().is_native() {
            return Err(ownership_failure());
        }
        self.native.recovered_pid(attempt)
    }
    fn completed_successfully(&self, attempt: &RunnerAttempt) -> bool {
        if attempt.execution().is_native() {
            return self.native.completed_successfully(attempt);
        }
        self.attached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&attempt.id)
            .and_then(|child| child.try_wait().ok().flatten())
            .is_some_and(|status| status.success())
    }
    fn record_terminate_intent(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason> {
        if !attempt.execution().is_native() {
            return Err(ownership_failure());
        }
        self.native.record_terminate_intent(attempt)
    }
    fn has_terminate_intent(&self, attempt: &RunnerAttempt) -> bool {
        attempt.execution().is_native() && self.native.has_terminate_intent(attempt)
    }
    fn terminate(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason> {
        if !attempt.execution().is_native() {
            return Err(ownership_failure());
        }
        self.native.terminate(attempt)
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use runner_manager_domain::model::Clock;
    use runner_manager_testkit::{clock::FakeClock, fixtures};

    #[test]
    fn isolated_attempt_cannot_use_native_compatibility_methods() {
        let root = tempfile::tempdir().unwrap();
        let policy = fixtures::policy().build();
        let mut attempt = RunnerAttempt::allocate(
            AttemptId::new_random(),
            policy.id,
            root.path(),
            FakeClock::default().now(),
        );
        attempt
            .allocate_execution(AttemptExecution::Isolated {
                provider_kind: Backend::Oci,
                environment_id: None,
                resolved_image: ImageReference::new(format!(
                    "registry.example/runner@sha256:{}",
                    "a".repeat(64)
                ))
                .unwrap(),
                generation: "generation-1".into(),
            })
            .unwrap();
        let provider = OciProcesses::new(HostId::from_u128(1));
        let config = EncodedJitConfig::new("test-jit");
        let failure = provider.spawn(&attempt, &config).unwrap_err();
        assert_eq!(failure.reason, ownership_failure());
        assert!(failure.live_pid.is_none());
        assert_eq!(provider.is_alive(&attempt), Err(ownership_failure()));
        assert_eq!(provider.recovered_pid(&attempt), Err(ownership_failure()));
        assert_eq!(
            provider.record_terminate_intent(&attempt),
            Err(ownership_failure())
        );
        assert!(!provider.has_terminate_intent(&attempt));
        assert_eq!(provider.terminate(&attempt), Err(ownership_failure()));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use runner_manager_domain::attempt::{AttemptOutcome, AttemptState};
    use runner_manager_domain::execution::ResourceLimits;
    use runner_manager_domain::model::Clock;
    use runner_manager_domain::store::{SqliteStore, Store};
    use runner_manager_testkit::{clock::FakeClock, fixtures};
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    fn fixture(info: &str) -> (tempfile::TempDir, OciProcesses) {
        fixture_with_quota(info, true)
    }

    fn fixture_with_quota(info: &str, quota_ok: bool) -> (tempfile::TempDir, OciProcesses) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("podman");
        let quota_gate = if quota_ok {
            ""
        } else {
            "if [ \"$1\" = \"--storage-opt\" ]; then exit 1; fi\n"
        };
        let script = format!(
            "#!/bin/sh\n{quota_gate}printf '%s' '{}'\n",
            info.replace('\'', "'\\''")
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = OciProcesses::new(HostId::from_u128(1));
        provider.runtime = path.to_string_lossy().into_owned();
        (root, provider)
    }

    fn info(rootless: bool, graph_root: &str, subuids: u64) -> String {
        serde_json::json!({
            "host": {
                "security": {"rootless": rootless},
                "cgroupVersion": "v2",
                "cgroupControllers": ["cpu", "memory", "pids"],
                "idMappings": {
                    "uidmap": [{"size": 1}, {"size": subuids}],
                    "gidmap": [{"size": 1}, {"size": subuids}]
                }
            },
            "store": {
                "graphRoot": graph_root,
                "runRoot": "/run/user/1000/containers",
                "graphStatus": {"Backing Filesystem": "xfs"}
            }
        })
        .to_string()
    }

    #[test]
    fn rootless_probe_refuses_rootful_and_drvfs_storage() {
        let (_root, provider) = fixture(&info(false, "/home/ivan/.local/share/containers", 65536));
        assert_eq!(
            provider.rootless_ready(),
            ProviderCapability::PermissionDenied
        );
        let (_root, provider) = fixture(&info(true, "/mnt/c/containers", 65536));
        assert_eq!(
            provider.rootless_ready(),
            ProviderCapability::PermissionDenied
        );
        let (_root, provider) = fixture(&info(true, "/home/ivan/.local/share/containers", 1));
        assert_eq!(
            provider.rootless_ready(),
            ProviderCapability::PermissionDenied
        );
        let (_root, provider) = fixture(&info(true, "/home/ivan/.local/share/containers", 65536));
        assert_eq!(provider.rootless_ready(), ProviderCapability::Ready);
        let no_pids = info(true, "/home/ivan/.local/share/containers", 65536)
            .replace("\"pids\"", "\"missing\"");
        let (_root, provider) = fixture(&no_pids);
        assert_eq!(provider.rootless_ready(), ProviderCapability::Degraded);
        let extfs = info(true, "/home/ivan/.local/share/containers", 65536).replace(
            "\"Backing Filesystem\":\"xfs\"",
            "\"Backing Filesystem\":\"extfs\"",
        );
        let (_root, provider) = fixture(&extfs);
        assert_eq!(
            provider.rootless_ready(),
            ProviderCapability::DiskQuotaUnavailable
        );
        let mut bounded: serde_json::Value = serde_json::from_str(&extfs).unwrap();
        bounded["runnerManagerStorage"] = serde_json::json!({
            "schema": BOUNDED_STORAGE_SCHEMA,
            "mode": BOUNDED_STORAGE_MODE,
            "requestedMiB": QUOTA_PROBE_MIB,
            "hardCap": true
        });
        let (_root, provider) = fixture(&bounded.to_string());
        assert_eq!(provider.rootless_ready(), ProviderCapability::Ready);
        assert_eq!(
            provider.rootless_ready_for(2048),
            ProviderCapability::DiskQuotaUnavailable,
            "the helper must attest the exact requested size"
        );
        bounded["runnerManagerStorage"]["hardCap"] = serde_json::json!(false);
        let (_root, provider) = fixture(&bounded.to_string());
        assert_eq!(
            provider.rootless_ready(),
            ProviderCapability::DiskQuotaUnavailable
        );
        let (_root, provider) = fixture_with_quota(
            &info(true, "/home/ivan/.local/share/containers", 65536),
            false,
        );
        assert_eq!(
            provider.rootless_ready(),
            ProviderCapability::DiskQuotaUnavailable
        );
    }

    #[test]
    fn missing_operator_runtime_is_not_treated_as_ready() {
        let mut provider = OciProcesses::new(HostId::from_u128(1));
        provider.runtime = "/a/path/that/cannot/be/podman".into();
        assert_eq!(provider.rootless_ready(), ProviderCapability::NotInstalled);
    }

    #[test]
    fn recovery_discovers_owned_container_when_capability_degrades() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("podman");
        let host = HostId::from_u128(1);
        let attempt = AttemptId::new_random();
        let generation = "generation-1";
        let image = format!("registry.example/runner@sha256:{}", "a".repeat(64));
        let id = "b".repeat(64);
        let degraded_info = info(true, "/home/ivan/.local/share/containers", 65536)
            .replace("\"pids\"", "\"missing\"");
        let labels = BTreeMap::from([
            (HOST_LABEL, host.to_string()),
            (ATTEMPT_LABEL, attempt.to_string()),
            (GENERATION_LABEL, generation.to_owned()),
            (IMAGE_LABEL, image),
        ]);
        let labels = serde_json::to_string(&labels).unwrap();
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n  info) printf '%s' '{degraded_info}' ;;\n  ps) printf '%s\\n' '{id}' ;;\n  container) printf '%s' '{labels}' ;;\n  *) exit 1 ;;\nesac\n"
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = OciProcesses::new(host);
        provider.runtime = path.to_string_lossy().into_owned();
        assert_eq!(provider.rootless_ready(), ProviderCapability::Degraded);
        let owned = provider.enumerate_owned(host);
        assert_eq!(owned.len(), 1);
        assert!(matches!(
            &owned[0],
            EnvironmentIdentity::Isolated {
                host: found_host,
                attempt: found_attempt,
                environment_id,
                generation: found_generation,
                ..
            } if *found_host == host && *found_attempt == attempt
                && environment_id == &id && found_generation == generation
        ));
    }

    #[test]
    fn native_start_still_delegates_to_the_existing_process_supervisor() {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("runtime");
        let bin = runtime.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let listener = bin.join("Runner.Listener");
        std::fs::write(&listener, "#!/bin/sh\nsleep 10\n").unwrap();
        std::fs::set_permissions(&listener, std::fs::Permissions::from_mode(0o700)).unwrap();
        let policy = fixtures::policy()
            .repository("octo/repo")
            .autoscale("home", 1)
            .active()
            .build();
        let attempt = RunnerAttempt::allocate(
            AttemptId::new_random(),
            policy.id,
            &runtime,
            FakeClock::default().now(),
        );
        let provider = OciProcesses::new(HostId::from_u128(1));
        let prepared = provider.prepare(&attempt, &policy).unwrap();
        let config = EncodedJitConfig::new("native-test-jit");
        let identity = provider
            .start(prepared, &attempt, OneTimeJitHandoff::new(&config))
            .unwrap();
        assert!(matches!(identity, EnvironmentIdentity::NativeProcess(_)));
        provider.stop(&attempt).unwrap();
    }

    const LIVE_IMAGE_ENV: &str = "RUNNER_MANAGER_OCI_ACCEPTANCE_IMAGE";
    const LIVE_HOST: u128 = 0x00ac_ce7a_ce00_0000_0000_0000_0000_0001;
    const LIVE_PACKAGE: &str = "runner-manager-oci-conflict";

    fn live_runtime() -> String {
        std::env::var(OCI_RUNTIME_ENV).unwrap_or_else(|_| "podman".into())
    }

    fn podman(args: &[&str]) -> std::process::Output {
        Command::new(live_runtime())
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("podman {args:?} did not execute: {error}"))
    }

    fn podman_ok(args: &[&str]) -> String {
        let output = podman(args);
        assert!(
            output.status.success(),
            "podman {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("podman emitted UTF-8")
    }

    fn write_listener(runtime: &Path) {
        let bin = runtime.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let listener = bin.join("Runner.Listener");
        // The real runner consumes the same environment variable. This fixture
        // proves the provider's stdin-to-bootstrap handoff, then removes it
        // before the long-lived child exists so the sentinel is not retained
        // in the process environment or writable layer.
        std::fs::write(
            &listener,
            "#!/bin/sh\n\
             test -n \"${ACTIONS_RUNNER_INPUT_JITCONFIG:-}\" || exit 70\n\
             unset ACTIONS_RUNNER_INPUT_JITCONFIG\n\
             : > /tmp/runner-manager-jit-received\n\
             exec sleep 600\n",
        )
        .unwrap();
        std::fs::set_permissions(&listener, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn build_conflicting_package(runtime: &Path, version: &str) -> PathBuf {
        let root = runtime.join(format!("package-{version}"));
        let debian = root.join("DEBIAN");
        let bin = root.join("usr/local/bin");
        std::fs::create_dir_all(&debian).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(
            debian.join("control"),
            format!(
                "Package: {LIVE_PACKAGE}\nVersion: {version}\nArchitecture: all\n\
                 Maintainer: Runner Manager acceptance <nobody@example.invalid>\n\
                 Description: isolated package database acceptance fixture\n"
            ),
        )
        .unwrap();
        let tool = bin.join("runner-manager-conflict");
        std::fs::write(&tool, format!("#!/bin/sh\nprintf '%s\\n' '{version}'\n")).unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        let package = runtime.join("conflict.deb");
        let output = Command::new("dpkg-deb")
            .args(["--build", "--root-owner-group"])
            .arg(&root)
            .arg(&package)
            .output()
            .expect("dpkg-deb must be installed by the native acceptance job");
        assert!(
            output.status.success(),
            "dpkg-deb failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        package
    }

    fn isolated_policy(image: ImageReference) -> ScalePolicy {
        let mut policy = fixtures::policy()
            .repository("octo/oci-native-acceptance")
            .autoscale("isolated", 3)
            .active()
            .build();
        policy
            .set_execution_policy(ExecutionPolicy::Isolated {
                backend: Backend::Oci,
                image,
                resources: ResourceLimits {
                    cpu_millis: 1000,
                    memory_mib: 512,
                    disk_mib: 1024,
                },
            })
            .unwrap();
        policy
    }

    fn prepare_live_attempt(
        provider: &OciProcesses,
        policy: &ScalePolicy,
        image: &ImageReference,
        version: Option<&str>,
        generation: &str,
        production_quota_path: bool,
    ) -> (
        tempfile::TempDir,
        RunnerAttempt,
        PreparedEnvironment,
        String,
    ) {
        let runtime = tempfile::tempdir().unwrap();
        write_listener(runtime.path());
        if let Some(version) = version {
            build_conflicting_package(runtime.path(), version);
        }
        let mut attempt = RunnerAttempt::allocate(
            AttemptId::new_random(),
            policy.id,
            runtime.path(),
            FakeClock::default().now(),
        );
        attempt
            .allocate_execution(AttemptExecution::Isolated {
                provider_kind: Backend::Oci,
                environment_id: None,
                resolved_image: image.clone(),
                generation: generation.into(),
            })
            .unwrap();
        if production_quota_path {
            let prepared = provider.prepare(&attempt, policy).unwrap();
            let EnvironmentIdentity::Isolated { environment_id, .. } =
                prepared.identity().cloned().expect("isolated identity")
            else {
                panic!("OCI prepare returned a native identity")
            };
            return (runtime, attempt, prepared, environment_id);
        }
        let ExecutionPolicy::Isolated { resources, .. } = policy.execution_policy() else {
            panic!("structural acceptance needs an isolated policy")
        };
        let name = format!("rm-{}-{}", attempt.id, generation);
        let cpu = format!("{:.3}", f64::from(resources.cpu_millis) / 1000.0);
        let memory = format!("{}m", resources.memory_mib);
        let host_label = format!("{HOST_LABEL}={}", provider.host);
        let attempt_label = format!("{ATTEMPT_LABEL}={}", attempt.id);
        let generation_label = format!("{GENERATION_LABEL}={generation}");
        let image_label = format!("{IMAGE_LABEL}={}", image.as_str());
        // Rootless Podman cannot initialize XFS project quotas because project
        // IDs are not namespaced and an unprivileged user cannot create the
        // backing block-device node. The acceptance first proves the production
        // provider refuses that missing hard cap. This second, explicitly
        // structural fixture omits only --storage-opt so the remaining real
        // container boundary can still be measured on the hard-bounded loop FS.
        let environment_id = provider
            .output(&[
                "create",
                "--interactive",
                "--name",
                &name,
                "--pull=never",
                "--entrypoint=sh",
                "--log-driver=none",
                "--image-volume=ignore",
                "--http-proxy=false",
                "--userns=keep-id",
                "--user=0",
                "--cap-drop=all",
                "--cap-add=CHOWN",
                "--cap-add=SETUID",
                "--cap-add=SETGID",
                "--cap-add=DAC_OVERRIDE",
                "--cap-add=FOWNER",
                "--security-opt=no-new-privileges",
                "--network=slirp4netns",
                "--pids-limit=128",
                "--cpus",
                &cpu,
                "--memory",
                &memory,
                "--label",
                &host_label,
                "--label",
                &attempt_label,
                "--label",
                &generation_label,
                "--label",
                &image_label,
                image.as_str(),
                "-c",
                BOOTSTRAP,
            ])
            .unwrap()
            .trim()
            .to_owned();
        assert!(!environment_id.is_empty());
        let source = format!("{}/.", attempt.runtime_path().display());
        let destination = format!("{environment_id}:/runner");
        provider.status(&["cp", &source, &destination]).unwrap();
        let identity = provider
            .isolated_identity(&attempt, environment_id.clone())
            .unwrap();
        let prepared = PreparedEnvironment::isolated(attempt.id, identity);
        (runtime, attempt, prepared, environment_id)
    }

    fn start_live_attempt(
        provider: &OciProcesses,
        attempt: &mut RunnerAttempt,
        prepared: PreparedEnvironment,
        environment_id: &str,
        sentinel: &str,
    ) {
        attempt
            .prepared_environment(environment_id.to_owned())
            .unwrap();
        let config = EncodedJitConfig::new(sentinel);
        provider
            .start(prepared, attempt, OneTimeJitHandoff::new(&config))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let received = podman(&[
                "exec",
                environment_id,
                "test",
                "-f",
                "/tmp/runner-manager-jit-received",
            ]);
            if received.status.success() {
                break;
            }
            assert!(Instant::now() < deadline, "listener did not consume JIT");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn inspect_controls(environment_id: &str, image: &ImageReference, sentinel: &str) {
        let raw = podman_ok(&["container", "inspect", environment_id]);
        assert!(
            !raw.contains(sentinel),
            "JIT sentinel reached inspect metadata"
        );
        assert!(!raw.contains("/run/podman/podman.sock"));
        assert!(!raw.contains("/var/run/docker.sock"));
        let inspect: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let item = &inspect[0];
        assert_eq!(
            item.pointer("/Mounts")
                .and_then(|v| v.as_array())
                .map(Vec::len),
            Some(0)
        );
        assert!(
            item.pointer("/HostConfig/Devices")
                .is_none_or(|value| value.is_null() || value.as_array().is_some_and(Vec::is_empty)),
            "host devices were attached: {}",
            item["HostConfig"]["Devices"]
        );
        assert!(
            item.pointer("/HostConfig/Binds")
                .is_none_or(|value| value.is_null() || value.as_array().is_some_and(Vec::is_empty)),
            "host bind mounts were attached: {}",
            item["HostConfig"]["Binds"]
        );
        assert_eq!(item["HostConfig"]["PidsLimit"].as_i64(), Some(128));
        assert_eq!(
            item["HostConfig"]["Memory"].as_u64(),
            Some(512 * 1024 * 1024)
        );
        assert_eq!(
            item["Config"]["Labels"][IMAGE_LABEL].as_str(),
            Some(image.as_str())
        );
        let command = item["Config"]["CreateCommand"]
            .as_array()
            .expect("Podman records create command");
        for forbidden in ["--device", "--mount", "--volume", "-v", "--privileged"] {
            assert!(
                !command.iter().any(|part| part.as_str() == Some(forbidden)),
                "forbidden create option {forbidden} was present"
            );
        }
        let socket_check = podman(&[
            "exec",
            environment_id,
            "sh",
            "-c",
            "test ! -S /run/podman/podman.sock && test ! -S /var/run/docker.sock",
        ]);
        assert!(
            socket_check.status.success(),
            "a host runtime socket is visible"
        );
        let logs = podman(&["logs", environment_id]);
        assert!(!String::from_utf8_lossy(&logs.stdout).contains(sentinel));
        assert!(!String::from_utf8_lossy(&logs.stderr).contains(sentinel));
        let history = podman_ok(&["history", "--no-trunc", image.as_str()]);
        assert!(
            !history.contains(sentinel),
            "JIT sentinel reached image history"
        );
    }

    fn assert_export_excludes(environment_id: &str, sentinel: &str) {
        let mut child = Command::new(live_runtime())
            .args(["export", environment_id])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("podman export starts");
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "podman export failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel.as_bytes()),
            "JIT sentinel reached the container root filesystem"
        );
    }

    fn wait_for_container_file(environment_id: &str, path: &str, deadline: Instant) -> bool {
        loop {
            if podman(&["exec", environment_id, "test", "-f", path])
                .status
                .success()
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn assert_live_jit_absent(environment_id: &str, image: &ImageReference, jit: &str) {
        let inspect = podman_ok(&["container", "inspect", environment_id]);
        assert!(
            !inspect.contains(jit),
            "JIT reached container inspect metadata"
        );

        let top = podman(&["top", environment_id, "pid,args"]);
        assert!(top.status.success(), "container process listing failed");
        assert!(
            !top.stdout
                .windows(jit.len())
                .any(|window| window == jit.as_bytes()),
            "JIT reached the container process listing"
        );

        let logs = podman(&["logs", environment_id]);
        assert!(
            !logs
                .stdout
                .windows(jit.len())
                .any(|window| window == jit.as_bytes())
        );
        assert!(
            !logs
                .stderr
                .windows(jit.len())
                .any(|window| window == jit.as_bytes())
        );
        let history = podman_ok(&["history", "--no-trunc", image.as_str()]);
        assert!(!history.contains(jit), "JIT reached image history");
    }

    fn stop_and_destroy(provider: &OciProcesses, attempt: &RunnerAttempt) {
        assert_eq!(provider.stop(attempt).unwrap(), ProviderStop::Stopped);
        assert_eq!(
            provider.destroy(attempt).unwrap(),
            ProviderDestroy::Destroyed
        );
        assert_eq!(
            provider.inspect(attempt).unwrap(),
            EnvironmentState::Missing
        );
    }

    fn run_live_rootless_acceptance(production_quota_path: bool) {
        let image = ImageReference::new(
            std::env::var(LIVE_IMAGE_ENV)
                .unwrap_or_else(|_| panic!("{LIVE_IMAGE_ENV} must name a pinned image digest")),
        )
        .unwrap();
        let provider = OciProcesses::new(HostId::from_u128(LIVE_HOST));
        let policy = isolated_policy(image.clone());

        if production_quota_path {
            assert_eq!(provider.probe(&policy), ProviderCapability::Ready);
            let resolution = provider.resolve(&policy).unwrap().unwrap();
            assert_eq!(resolution.provider_kind, Backend::Oci);
            assert_eq!(resolution.image, image);
        } else {
            assert_eq!(
                provider.probe(&policy),
                ProviderCapability::DiskQuotaUnavailable
            );
            assert_eq!(
                provider.resolve(&policy),
                Err(ProviderCapability::DiskQuotaUnavailable.refusal()),
                "the production provider must fail before image allocation or JIT"
            );
            provider.image_ready(&image).unwrap();
        }
        assert!(
            !Command::new("dpkg-query")
                .args(["-W", LIVE_PACKAGE])
                .status()
                .unwrap()
                .success(),
            "acceptance package unexpectedly exists on the host"
        );

        let (_runtime_one, mut one, prepared_one, id_one) = prepare_live_attempt(
            &provider,
            &policy,
            &image,
            Some("1.0"),
            "native-one",
            production_quota_path,
        );
        let sentinel_one = "rm-jit-sentinel-native-one-8eeb09c26b8a";
        start_live_attempt(&provider, &mut one, prepared_one, &id_one, sentinel_one);
        inspect_controls(&id_one, &image, sentinel_one);
        podman_ok(&["exec", &id_one, "dpkg", "-i", "/runner/conflict.deb"]);
        assert_eq!(
            podman_ok(&[
                "exec",
                &id_one,
                "dpkg-query",
                "-W",
                "-f=${Version}",
                LIVE_PACKAGE,
            ])
            .trim(),
            "1.0"
        );
        assert_eq!(
            podman_ok(&["exec", &id_one, "/usr/local/bin/runner-manager-conflict"]).trim(),
            "1.0"
        );

        let (_runtime_two, mut two, prepared_two, id_two) = prepare_live_attempt(
            &provider,
            &policy,
            &image,
            Some("2.0"),
            "native-two",
            production_quota_path,
        );
        let sentinel_two = "rm-jit-sentinel-native-two-62b2db40633b";
        start_live_attempt(&provider, &mut two, prepared_two, &id_two, sentinel_two);
        inspect_controls(&id_two, &image, sentinel_two);
        podman_ok(&["exec", &id_two, "dpkg", "-i", "/runner/conflict.deb"]);
        assert_eq!(
            podman_ok(&[
                "exec",
                &id_two,
                "dpkg-query",
                "-W",
                "-f=${Version}",
                LIVE_PACKAGE,
            ])
            .trim(),
            "2.0"
        );
        assert_eq!(
            podman_ok(&["exec", &id_one, "/usr/local/bin/runner-manager-conflict"]).trim(),
            "1.0",
            "the second package install mutated its sibling"
        );
        assert_export_excludes(&id_one, sentinel_one);
        assert_export_excludes(&id_two, sentinel_two);

        // Prove the loopback store's hard upper bound with real writes. A
        // fallocate-only probe may fail because an overlay does not implement
        // allocation, which says nothing about the backing filesystem's cap.
        // `dd` writes zeroes through fuse-overlayfs until ext4/XFS returns
        // ENOSPC; `df` records that the same filesystem reached zero available
        // bytes. Remove the partial file before Podman needs to journal the
        // process exit or destroy the container.
        let oversize_mib = if production_quota_path {
            "1100"
        } else {
            "7168"
        };
        let exhaustion = podman(&[
            "exec",
            &id_one,
            "sh",
            "-c",
            "set +e; printf 'RM_FS_BEFORE '; df -B1 --output=size,used,avail / | tail -n 1; dd if=/dev/zero of=/backing-store-cap bs=1M count=\"$1\" conv=fsync status=none; status=$?; printf 'RM_FS_FULL '; df -B1 --output=size,used,avail / | tail -n 1; rm -f /backing-store-cap; sync; exit \"$status\"",
            "sh",
            oversize_mib,
        ]);
        assert!(
            !exhaustion.status.success(),
            "the backing-store hard cap allowed an oversized allocation"
        );
        let exhaustion_stdout = String::from_utf8(exhaustion.stdout).unwrap();
        let exhaustion_stderr = String::from_utf8(exhaustion.stderr).unwrap();
        assert!(
            exhaustion_stderr.contains("No space left on device"),
            "the write failed without ENOSPC: {exhaustion_stderr}"
        );
        let df_line = |marker: &str| {
            exhaustion_stdout
                .lines()
                .find_map(|line| line.strip_prefix(marker))
                .map(|line| {
                    line.split_whitespace()
                        .map(|value| value.parse().expect("df emitted integer byte counts"))
                        .collect::<Vec<u64>>()
                })
                .unwrap_or_else(|| {
                    panic!("the write did not emit {marker:?} df evidence: {exhaustion_stdout}")
                })
        };
        let before = df_line("RM_FS_BEFORE ");
        let full = df_line("RM_FS_FULL ");
        assert_eq!(
            before.len(),
            3,
            "unexpected initial df evidence: {before:?}"
        );
        assert_eq!(full.len(), 3, "unexpected full df evidence: {full:?}");
        assert!(
            full[1] >= before[1] + 512 * 1024 * 1024,
            "the ENOSPC probe did not perform substantial writes: before={before:?} full={full:?}"
        );
        assert!(
            full[2] <= 1024 * 1024,
            "ENOSPC left more than 1 MiB available: {full:?}"
        );
        stop_and_destroy(&provider, &one);
        stop_and_destroy(&provider, &two);

        let (_runtime_fresh, mut fresh, prepared_fresh, id_fresh) = prepare_live_attempt(
            &provider,
            &policy,
            &image,
            None,
            "native-fresh",
            production_quota_path,
        );
        start_live_attempt(
            &provider,
            &mut fresh,
            prepared_fresh,
            &id_fresh,
            "rm-jit-sentinel-native-fresh-c1b9f470d09e",
        );
        assert!(
            !podman(&["exec", &id_fresh, "dpkg-query", "-W", LIVE_PACKAGE])
                .status
                .success(),
            "a fresh sibling inherited the earlier package database"
        );
        assert!(
            !podman(&[
                "exec",
                &id_fresh,
                "test",
                "-e",
                "/usr/local/bin/runner-manager-conflict",
            ])
            .status
            .success(),
            "a fresh sibling inherited an earlier writable-layer file"
        );
        stop_and_destroy(&provider, &fresh);

        // Simulate the crash gap after create and before the environment ID is
        // journalled. Recovery discovers and quarantines exactly the labelled
        // orphan; after the durable identity is restored, normal destroy owns
        // and removes it.
        let (_runtime_orphan, mut orphan, prepared_orphan, orphan_id) = prepare_live_attempt(
            &provider,
            &policy,
            &image,
            None,
            "native-orphan",
            production_quota_path,
        );
        assert_eq!(
            provider.recover(&orphan).unwrap(),
            EnvironmentState::Starting
        );
        let owned = provider.enumerate_owned(HostId::from_u128(LIVE_HOST));
        assert_eq!(owned.len(), 1, "recovery did not isolate one owned orphan");
        assert!(matches!(
            &owned[0],
            EnvironmentIdentity::Isolated { environment_id, .. } if environment_id == &orphan_id
        ));
        orphan.prepared_environment(orphan_id).unwrap();
        assert_eq!(
            provider.destroy(&orphan).unwrap(),
            ProviderDestroy::Destroyed
        );
        assert!(
            provider
                .enumerate_owned(HostId::from_u128(LIVE_HOST))
                .is_empty()
        );
        drop(prepared_orphan);

        assert!(
            !Command::new("dpkg-query")
                .args(["-W", LIVE_PACKAGE])
                .status()
                .unwrap()
                .success(),
            "container package installation mutated the host package database"
        );
    }

    const RESTART_FIXTURE_ENV: &str = "RUNNER_MANAGER_OCI_RESTART_FIXTURE";

    fn restart_fixture_root() -> PathBuf {
        let root = PathBuf::from(std::env::var(RESTART_FIXTURE_ENV).unwrap_or_else(|_| {
            panic!("{RESTART_FIXTURE_ENV} must name the durable fixture root")
        }));
        assert!(root.is_absolute() && !root.starts_with("/mnt"));
        root
    }

    fn restart_attempt(
        root: &Path,
        policy: &ScalePolicy,
        image: &ImageReference,
        suffix: &str,
        id: u128,
        generation: &str,
    ) -> RunnerAttempt {
        let runtime = root.join("runtimes").join(suffix);
        std::fs::create_dir_all(&runtime).unwrap();
        write_listener(&runtime);
        let mut attempt = RunnerAttempt::allocate(
            AttemptId::from_u128(id),
            policy.id,
            runtime,
            FakeClock::default().now(),
        );
        attempt
            .allocate_execution(AttemptExecution::Isolated {
                provider_kind: Backend::Oci,
                environment_id: None,
                resolved_image: image.clone(),
                generation: generation.into(),
            })
            .unwrap();
        attempt
    }

    fn prepare_restart_resource(
        provider: &OciProcesses,
        policy: &ScalePolicy,
        attempt: &mut RunnerAttempt,
    ) -> (PreparedEnvironment, String) {
        attempt.begin_prepare(FakeClock::default().now()).unwrap();
        let prepared = provider.prepare(attempt, policy).unwrap();
        let EnvironmentIdentity::Isolated { environment_id, .. } =
            prepared.identity().cloned().expect("isolated identity")
        else {
            panic!("OCI prepare returned a native identity")
        };
        (prepared, environment_id)
    }

    #[test]
    #[ignore = "seeds real managed-WSL resources for the terminate/restart acceptance"]
    fn live_rootless_managed_wsl_restart_seed() {
        let root = restart_fixture_root();
        std::fs::create_dir_all(&root).unwrap();
        let journal = SqliteStore::open(root.join("attempts.sqlite3")).unwrap();
        let image = ImageReference::new(
            std::env::var(LIVE_IMAGE_ENV)
                .unwrap_or_else(|_| panic!("{LIVE_IMAGE_ENV} must name a pinned image digest")),
        )
        .unwrap();
        let provider = OciProcesses::new(HostId::from_u128(LIVE_HOST));
        let policy = isolated_policy(image.clone());
        let nonce = std::env::var("RUNNER_MANAGER_OCI_RESTART_NONCE").expect(
            "RUNNER_MANAGER_OCI_RESTART_NONCE must contain the non-secret acceptance nonce",
        );
        assert!(nonce.starts_with("rm-reboot-nonce-") && nonce.len() == 48);
        assert_eq!(provider.probe(&policy), ProviderCapability::Ready);

        let clock = FakeClock::default();
        let mut prepared = restart_attempt(
            &root,
            &policy,
            &image,
            "prepared",
            0xd101,
            "restart-prepared",
        );
        let (_prepared_handle, prepared_id) =
            prepare_restart_resource(&provider, &policy, &mut prepared);
        prepared.prepared_environment(prepared_id).unwrap();
        prepared.mark_prepared(clock.now()).unwrap();
        journal.record_attempt(&prepared).unwrap();

        let mut running =
            restart_attempt(&root, &policy, &image, "running", 0xd102, "restart-running");
        let (running_handle, running_id) =
            prepare_restart_resource(&provider, &policy, &mut running);
        running.prepared_environment(running_id.clone()).unwrap();
        running.mark_prepared(clock.now()).unwrap();
        running.jit_received(clock.now()).unwrap();
        provider
            .start(
                running_handle,
                &running,
                OneTimeJitHandoff::new(&EncodedJitConfig::new(&nonce)),
            )
            .unwrap();
        running.started_isolated(clock.now()).unwrap();
        assert!(wait_for_container_file(
            &running_id,
            "/tmp/runner-manager-jit-received",
            Instant::now() + Duration::from_secs(60),
        ));
        journal.record_attempt(&running).unwrap();
        inspect_controls(&running_id, &image, &nonce);
        assert_export_excludes(&running_id, &nonce);

        let mut deferred = restart_attempt(
            &root,
            &policy,
            &image,
            "cleanup-deferred",
            0xd103,
            "restart-deferred",
        );
        let (_deferred_handle, deferred_id) =
            prepare_restart_resource(&provider, &policy, &mut deferred);
        deferred.prepared_environment(deferred_id).unwrap();
        deferred.mark_prepared(clock.now()).unwrap();
        deferred.jit_received(clock.now()).unwrap();
        deferred.started_isolated(clock.now()).unwrap();
        deferred
            .conclude(AttemptOutcome::Orphaned, clock.now())
            .unwrap();
        deferred.begin_destroy(clock.now()).unwrap();
        deferred.defer_cleanup(clock.now()).unwrap();
        journal.record_attempt(&deferred).unwrap();

        let mut orphaned = restart_attempt(
            &root,
            &policy,
            &image,
            "orphaned",
            0xd104,
            "restart-orphaned",
        );
        let (_orphaned_handle, orphaned_id) =
            prepare_restart_resource(&provider, &policy, &mut orphaned);
        orphaned.prepared_environment(orphaned_id).unwrap();
        orphaned.mark_prepared(clock.now()).unwrap();
        orphaned
            .conclude(AttemptOutcome::Orphaned, clock.now())
            .unwrap();
        journal.record_attempt(&orphaned).unwrap();

        // Crash gap: the provider resource exists, but its ID was never put in
        // the journal. Recovery may adopt only the resource carrying this exact
        // attempt and generation label.
        let mut orphan = restart_attempt(
            &root,
            &policy,
            &image,
            "crash-gap-orphan",
            0xd105,
            "restart-orphan",
        );
        let (_orphan_handle, _orphan_id) =
            prepare_restart_resource(&provider, &policy, &mut orphan);
        journal.record_attempt(&orphan).unwrap();

        let attempts = journal.uncleaned_ephemeral_attempts().unwrap();
        assert_eq!(attempts.len(), 5);
        assert!(attempts.iter().all(RunnerAttempt::counts_against_capacity));
        assert_eq!(
            provider.enumerate_owned(HostId::from_u128(LIVE_HOST)).len(),
            5
        );
        assert!(
            !std::fs::read(root.join("attempts.sqlite3"))
                .unwrap()
                .windows(nonce.len())
                .any(|window| window == nonce.as_bytes()),
            "the non-secret JIT stand-in reached the durable attempt journal"
        );
        std::fs::write(root.join("registration-count"), "0\n").unwrap();
        std::fs::write(
            root.join("seed-complete"),
            "prepared starting cleanup_deferred orphaned crash_gap\n",
        )
        .unwrap();
        std::fs::write(
            root.join("security-scan-complete"),
            "inspect logs history export journal: nonce absent; github registrations=0\n",
        )
        .unwrap();
    }

    #[test]
    #[ignore = "recovers real managed-WSL resources after the distribution restarts"]
    fn live_rootless_managed_wsl_restart_recover() {
        let root = restart_fixture_root();
        assert!(root.join("seed-complete").is_file());
        let journal = SqliteStore::open(root.join("attempts.sqlite3")).unwrap();
        let provider = OciProcesses::new(HostId::from_u128(LIVE_HOST));
        let nonce = std::env::var("RUNNER_MANAGER_OCI_RESTART_NONCE")
            .expect("RUNNER_MANAGER_OCI_RESTART_NONCE must survive in the Windows manifest");
        let mut attempts = journal.uncleaned_ephemeral_attempts().unwrap();
        assert_eq!(attempts.len(), 5, "the durable journal lost an attempt");
        assert!(attempts.iter().all(RunnerAttempt::counts_against_capacity));
        let image = match attempts[0].execution() {
            AttemptExecution::Isolated { resolved_image, .. } => resolved_image.clone(),
            _ => unreachable!(),
        };
        let owned = provider.enumerate_owned(HostId::from_u128(LIVE_HOST));
        assert_eq!(owned.len(), 5, "the remounted provider lost a resource");

        for identity in &owned {
            let EnvironmentIdentity::Isolated { environment_id, .. } = identity else {
                unreachable!()
            };
            let inspect = podman_ok(&["container", "inspect", environment_id]);
            assert!(
                !inspect.contains(&nonce),
                "nonce reached durable inspect metadata"
            );
            let logs = podman(&["logs", environment_id]);
            assert!(
                !logs
                    .stdout
                    .windows(nonce.len())
                    .any(|window| window == nonce.as_bytes())
            );
            assert!(
                !logs
                    .stderr
                    .windows(nonce.len())
                    .any(|window| window == nonce.as_bytes())
            );
            assert_export_excludes(environment_id, &nonce);
        }
        let history = podman_ok(&["history", "--no-trunc", image.as_str()]);
        assert!(
            !history.contains(&nonce),
            "nonce reached durable image history"
        );
        assert!(
            !std::fs::read(root.join("attempts.sqlite3"))
                .unwrap()
                .windows(nonce.len())
                .any(|window| window == nonce.as_bytes()),
            "nonce reached the durable attempt journal"
        );

        let clock = FakeClock::default();
        for attempt in &mut attempts {
            if attempt.state() == AttemptState::Preparing {
                let AttemptExecution::Isolated {
                    resolved_image,
                    generation,
                    ..
                } = attempt.execution()
                else {
                    unreachable!()
                };
                let mut wrong_generation = RunnerAttempt::allocate(
                    attempt.id,
                    attempt.policy_id,
                    attempt.runtime_path(),
                    clock.now(),
                );
                wrong_generation
                    .allocate_execution(AttemptExecution::Isolated {
                        provider_kind: Backend::Oci,
                        environment_id: None,
                        resolved_image: resolved_image.clone(),
                        generation: format!("{generation}-wrong"),
                    })
                    .unwrap();
                assert_eq!(
                    provider.recover(&wrong_generation).unwrap(),
                    EnvironmentState::Missing,
                    "a different generation adopted the crash-gap resource"
                );
                assert_eq!(
                    provider.recover(attempt).unwrap(),
                    EnvironmentState::Starting
                );
                let identity = owned
                    .iter()
                    .find(|identity| {
                        matches!(identity, EnvironmentIdentity::Isolated {
                            attempt: found_attempt,
                            generation: found_generation,
                            ..
                        } if found_attempt == &attempt.id && found_generation == generation)
                    })
                    .cloned()
                    .expect("the exact crash-gap identity is enumerable");
                let EnvironmentIdentity::Isolated { environment_id, .. } = identity else {
                    unreachable!()
                };
                attempt.prepared_environment(environment_id).unwrap();
                attempt.mark_prepared(clock.now()).unwrap();
            }

            let state_after_restart = provider.inspect(attempt).unwrap();
            assert_eq!(
                state_after_restart,
                EnvironmentState::Starting,
                "the remounted provider did not retain the resource for recovery"
            );
            match attempt.state() {
                AttemptState::Prepared => {
                    attempt
                        .conclude(AttemptOutcome::Orphaned, clock.now())
                        .unwrap();
                    attempt.begin_destroy(clock.now()).unwrap();
                }
                AttemptState::Starting => {
                    attempt
                        .conclude(AttemptOutcome::Orphaned, clock.now())
                        .unwrap();
                    attempt.begin_destroy(clock.now()).unwrap();
                }
                AttemptState::Orphaned | AttemptState::CleanupDeferred => {
                    attempt.begin_destroy(clock.now()).unwrap()
                }
                state => panic!("unexpected restart state {state}"),
            }
            assert_eq!(
                provider.destroy(attempt).unwrap(),
                ProviderDestroy::Destroyed
            );
            attempt.clean_isolated(clock.now()).unwrap();
            journal.record_attempt(attempt).unwrap();
        }

        assert!(journal.uncleaned_ephemeral_attempts().unwrap().is_empty());
        assert!(
            provider
                .enumerate_owned(HostId::from_u128(LIVE_HOST))
                .is_empty()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("registration-count")).unwrap(),
            "0\n",
            "restart recovery attempted a second JIT registration"
        );
        std::fs::write(
            root.join("recovery-complete"),
            "adopted destroyed capacity=0 registrations=0\n",
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires the CI-provisioned native rootless Podman/XFS project-quota fixture"]
    fn live_rootless_native_acceptance() {
        run_live_rootless_acceptance(false);
    }

    #[test]
    #[ignore = "requires a root-owned bounded-storage helper fixture"]
    fn live_rootless_bounded_storage_acceptance() {
        run_live_rootless_acceptance(true);
    }

    #[test]
    #[ignore = "requires a queued same-repository Actions job and a real JIT config on stdin"]
    fn live_rootless_github_jit_acceptance() {
        let image = ImageReference::new(
            std::env::var(LIVE_IMAGE_ENV)
                .unwrap_or_else(|_| panic!("{LIVE_IMAGE_ENV} must name a pinned image digest")),
        )
        .unwrap();
        let runner_root = PathBuf::from(
            std::env::var("RUNNER_MANAGER_OCI_JIT_RUNNER_DIR")
                .expect("RUNNER_MANAGER_OCI_JIT_RUNNER_DIR must name the extracted runner package"),
        );
        assert!(runner_root.is_absolute());
        assert!(!runner_root.starts_with("/mnt"));
        assert!(runner_root.join("bin/Runner.Listener").is_file());

        let mut jit = String::new();
        std::io::stdin()
            .read_to_string(&mut jit)
            .expect("JIT stdin could not be read");
        while matches!(jit.as_bytes().last(), Some(b'\n' | b'\r')) {
            jit.pop();
        }
        assert!(!jit.is_empty(), "JIT stdin was empty");
        assert!(
            jit.len() <= 64 * 1024,
            "JIT stdin exceeded the provider limit"
        );
        assert!(
            !jit.bytes()
                .any(|byte| byte == b'\n' || byte == b'\r' || byte == 0),
            "JIT stdin contained a forbidden delimiter"
        );

        let provider = OciProcesses::new(HostId::from_u128(LIVE_HOST));
        let policy = isolated_policy(image.clone());
        assert_eq!(provider.probe(&policy), ProviderCapability::Ready);
        let resolution = provider.resolve(&policy).unwrap().unwrap();
        assert_eq!(resolution.provider_kind, Backend::Oci);
        assert_eq!(resolution.image, image);

        let mut attempt = RunnerAttempt::allocate(
            AttemptId::new_random(),
            policy.id,
            &runner_root,
            FakeClock::default().now(),
        );
        attempt
            .allocate_execution(AttemptExecution::Isolated {
                provider_kind: Backend::Oci,
                environment_id: None,
                resolved_image: image.clone(),
                generation: "github-jit".into(),
            })
            .unwrap();
        let prepared = provider.prepare(&attempt, &policy).unwrap();
        let EnvironmentIdentity::Isolated { environment_id, .. } =
            prepared.identity().cloned().expect("isolated identity")
        else {
            panic!("OCI prepare returned a native identity")
        };
        attempt
            .prepared_environment(environment_id.clone())
            .unwrap();
        let config = EncodedJitConfig::new(std::mem::take(&mut jit));
        provider
            .start(prepared, &attempt, OneTimeJitHandoff::new(&config))
            .unwrap();

        let started = wait_for_container_file(
            &environment_id,
            "/tmp/runner-manager-actions-job-started",
            Instant::now() + Duration::from_secs(300),
        );
        assert!(
            started,
            "the queued Actions job was not claimed within five minutes"
        );
        assert_live_jit_absent(&environment_id, &image, config.expose());
        assert!(
            podman(&[
                "exec",
                &environment_id,
                "touch",
                "/tmp/runner-manager-provider-inspected",
            ])
            .status
            .success(),
            "could not release the Actions job after provider-side inspection"
        );

        let completed = wait_for_container_file(
            &environment_id,
            "/tmp/runner-manager-actions-job-complete",
            Instant::now() + Duration::from_secs(600),
        );
        assert!(
            completed,
            "the Actions marker step did not complete within ten minutes"
        );
        let exit_deadline = Instant::now() + Duration::from_secs(120);
        while provider.inspect(&attempt).unwrap() != EnvironmentState::Exited {
            assert!(
                Instant::now() < exit_deadline,
                "the one-time runner did not exit after its job"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        assert_export_excludes(&environment_id, config.expose());
        assert_eq!(
            provider.destroy(&attempt).unwrap(),
            ProviderDestroy::Destroyed
        );
        assert_eq!(
            provider.inspect(&attempt).unwrap(),
            EnvironmentState::Missing
        );
        eprintln!("live GitHub JIT job completed through the OCI provider; evidence is redacted");
    }

    #[test]
    #[ignore = "requires a real rootless Podman fixture with unavailable writable-layer quota"]
    fn live_rootless_quota_refusal_is_typed_before_jit() {
        let provider = OciProcesses::new(HostId::from_u128(1));
        assert_eq!(
            provider.rootless_ready(),
            ProviderCapability::DiskQuotaUnavailable
        );
    }
}
