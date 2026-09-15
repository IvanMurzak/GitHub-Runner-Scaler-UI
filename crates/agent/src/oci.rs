//! Rootless Podman-compatible provider for dependency-isolated Linux runners.
//! The runtime is installed by the operator; this adapter never starts a native
//! runner for an isolated policy and never grants a host filesystem mount.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use runner_manager_domain::attempt::{FailureReason, RunnerAttempt};
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

#[derive(Debug)]
pub struct OciProcesses {
    host: HostId,
    native: NativeProcesses,
    runtime: String,
    attached: Mutex<BTreeMap<AttemptId, Child>>,
}

impl OciProcesses {
    #[must_use]
    pub fn new(host: HostId) -> Self {
        Self {
            host,
            native: NativeProcesses::new(),
            runtime: "podman".into(),
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
        if !cfg!(target_os = "linux") {
            return ProviderCapability::Unsupported;
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
        // Podman's writable-layer size quota requires XFS project quotas.
        // extfs (the default WSL distro filesystem) must be refused before JIT.
        if info
            .pointer("/store/graphStatus/Backing Filesystem")
            .and_then(serde_json::Value::as_str)
            != Some("xfs")
        {
            return ProviderCapability::DiskQuotaUnavailable;
        }
        // XFS alone is insufficient: rootless quota setup can fail with EPERM.
        // Probe the storage driver before allocation or GitHub JIT, without
        // creating a container or recording any job content.
        if self
            .status(&["--storage-opt", "size=1024m", "info", "--format=json"])
            .is_err()
        {
            return ProviderCapability::DiskQuotaUnavailable;
        }
        ProviderCapability::Ready
    }

    fn image_ready(&self, image: &ImageReference) -> Result<(), FailureReason> {
        let Some((_, expected)) = image.as_str().rsplit_once("@sha256:") else {
            return Err(image_failure());
        };
        self.status(&["pull", "--quiet", image.as_str()])
            .map_err(|_| image_failure())?;
        let digests = self
            .output(&[
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                image.as_str(),
            ])
            .map_err(|_| image_failure())?;
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
        let AttemptExecution::Isolated {
            generation,
            resolved_image,
            ..
        } = attempt.execution()
        else {
            return Err(ownership_failure());
        };
        Ok(labels
            .get(HOST_LABEL)
            .is_some_and(|value| value == &self.host.to_string())
            && labels
                .get(ATTEMPT_LABEL)
                .is_some_and(|value| value == &attempt.id.to_string())
            && labels
                .get(GENERATION_LABEL)
                .is_some_and(|value| value == generation)
            && labels
                .get(IMAGE_LABEL)
                .is_some_and(|value| value == resolved_image.as_str()))
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

fn provider_failure() -> FailureReason {
    FailureReason::Other("rootless OCI runtime operation failed".into())
}
fn image_failure() -> FailureReason {
    FailureReason::Other("pinned OCI image unavailable or mismatched".into())
}
fn ownership_failure() -> FailureReason {
    FailureReason::Other("OCI environment ownership mismatch".into())
}

impl ExecutionProvider for OciProcesses {
    fn probe(&self, policy: &ScalePolicy) -> ProviderCapability {
        if policy.execution_policy().is_native() {
            return ProviderCapability::Ready;
        }
        let ExecutionPolicy::Isolated { backend, image, .. } = policy.execution_policy() else {
            return ProviderCapability::Unsupported;
        };
        if !matches!(backend, Backend::Auto | Backend::Oci) {
            return ProviderCapability::Unsupported;
        }
        let capability = self.rootless_ready();
        if capability != ProviderCapability::Ready {
            return capability;
        }
        if self.image_ready(image).is_err() {
            ProviderCapability::ImageUnavailableOrIncompatible
        } else {
            ProviderCapability::Ready
        }
    }

    fn resolve(&self, policy: &ScalePolicy) -> Result<Option<ResolvedEnvironment>, FailureReason> {
        let ExecutionPolicy::Isolated { backend, image, .. } = policy.execution_policy() else {
            return Ok(None);
        };
        if !matches!(backend, Backend::Auto | Backend::Oci)
            || self.rootless_ready() != ProviderCapability::Ready
        {
            return Err(provider_failure());
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
            return Err(FailureReason::Other(
                "OCI runner runtime must be on the Linux filesystem".into(),
            ));
        }
        if self.rootless_ready() != ProviderCapability::Ready {
            return Err(provider_failure());
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
            ])?
            .trim()
            .to_owned();
        if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(provider_failure());
        }
        let identity = self.isolated_identity(attempt, id.clone())?;
        // The package copy is host-to-guest only; no host path is mounted.
        let source = format!("{}/.", attempt.runtime_path().display());
        let destination = format!("{id}:/runner");
        if self.status(&["cp", &source, &destination]).is_err() {
            // Roll back before returning without a journalled environment ID.
            // An unavailable runtime leaves a labelled orphan for enumeration.
            if self.labels(&id).is_ok_and(|labels| {
                labels
                    .get(HOST_LABEL)
                    .is_some_and(|value| value == &self.host.to_string())
                    && labels
                        .get(ATTEMPT_LABEL)
                        .is_some_and(|value| value == &attempt.id.to_string())
                    && labels
                        .get(GENERATION_LABEL)
                        .is_some_and(|value| value == generation)
            }) {
                let _ = self.status(&["rm", "--force", &id]);
            }
            return Err(provider_failure());
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
            return Err(ProcessStartFailure::before_spawn(FailureReason::Other(
                "OCI JIT handoff is not a single bounded line".into(),
            )));
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
        self.status(&["stop", "--time=10", self.environment_id(attempt)?])?;
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
        self.status(&["rm", "--force", self.environment_id(attempt)?])?;
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
        if host != self.host
            || !matches!(
                self.rootless_ready(),
                ProviderCapability::Ready | ProviderCapability::DiskQuotaUnavailable
            )
        {
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
        self.native.spawn(attempt, config)
    }
    fn is_alive(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
        self.native.is_alive(attempt)
    }
    fn recovered_pid(&self, attempt: &RunnerAttempt) -> Result<Option<u32>, FailureReason> {
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
        self.native.record_terminate_intent(attempt)
    }
    fn has_terminate_intent(&self, attempt: &RunnerAttempt) -> bool {
        self.native.has_terminate_intent(attempt)
    }
    fn terminate(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason> {
        self.native.terminate(attempt)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use runner_manager_domain::model::Clock;
    use runner_manager_testkit::{clock::FakeClock, fixtures};
    use std::os::unix::fs::PermissionsExt;

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
        let extfs = info(true, "/home/ivan/.local/share/containers", 65536).replace(
            "\"Backing Filesystem\":\"xfs\"",
            "\"Backing Filesystem\":\"extfs\"",
        );
        let (_root, provider) = fixture(&extfs);
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
