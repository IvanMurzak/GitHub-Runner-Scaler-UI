//! Disposable native macOS virtual-machine execution.
//!
//! Runner Manager deliberately does not build or install macOS images. An
//! operator supplies a helper backed by Virtualization.framework and a pinned
//! template. The helper protocol keeps every hypervisor-specific operation on
//! the platform side while this adapter retains lifecycle, ownership, and
//! one-time JIT guarantees.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use runner_manager_domain::attempt::{FailureReason, RunnerAttempt};
use runner_manager_domain::execution::{
    AttemptExecution, Backend, ExecutionPolicy, ImageReference, ResourceLimits,
};
use runner_manager_domain::model::{AttemptId, HostId};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_github::jit::EncodedJitConfig;
use secrecy::zeroize::Zeroize as _;
use serde::Deserialize;

use super::{
    EnvironmentIdentity, EnvironmentState, ExecutionProvider, NativeProcesses, OneTimeJitHandoff,
    PreparedEnvironment, ProcessStartFailure, ProviderCapability, ProviderDestroy,
    ProviderDiagnostic, ProviderStop, ResolvedEnvironment, TERMINATE_INTENT_FILE,
    write_durable_file,
};

const PROTOCOL_VERSION: u16 = 1;
const DEFAULT_HELPER: &str = "runner-manager-macos-vm";
const MAX_RESPONSE: usize = 64 * 1024;
const MAX_HELPER_STDERR: usize = 4 * 1024;
const MAX_DIAGNOSTICS: usize = 32;
const HELPER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const PROCESS_LIMIT: u32 = 512;

/// A closed, non-secret summary of macOS VM readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacOsVmHostState {
    Ready,
    UnsupportedHost,
    UnsupportedArchitecture,
    HelperNotInstalled,
    HelperPermissionDenied,
    HelperStorePermissionDenied,
    HelperTimedOut,
    HelperIoFailed,
    HelperExitedUnexpectedly,
    HelperIncompatible,
    EntitlementMissing,
    PrivateChannelUnavailable,
    ResourceLimitsUnavailable,
    RuntimeDegraded,
}

impl MacOsVmHostState {
    #[must_use]
    pub const fn capability(self) -> ProviderCapability {
        match self {
            Self::Ready => ProviderCapability::Ready,
            Self::UnsupportedHost | Self::UnsupportedArchitecture | Self::HelperIncompatible => {
                ProviderCapability::Unsupported
            }
            Self::HelperNotInstalled => ProviderCapability::NotInstalled,
            Self::HelperPermissionDenied
            | Self::HelperStorePermissionDenied
            | Self::EntitlementMissing => ProviderCapability::PermissionDenied,
            Self::PrivateChannelUnavailable
            | Self::ResourceLimitsUnavailable
            | Self::HelperTimedOut
            | Self::HelperIoFailed
            | Self::HelperExitedUnexpectedly
            | Self::RuntimeDegraded => ProviderCapability::Degraded,
        }
    }

    #[must_use]
    pub const fn remedy(self) -> Option<&'static str> {
        match self {
            Self::Ready => None,
            Self::UnsupportedHost => Some("use a supported macOS host"),
            Self::UnsupportedArchitecture => {
                Some("install a helper and template for this Mac architecture")
            }
            Self::HelperNotInstalled => Some(
                "install a Virtualization.framework-compatible helper named runner-manager-macos-vm",
            ),
            Self::HelperPermissionDenied => {
                Some("allow the runner-manager service account to execute the macOS VM helper")
            }
            Self::HelperStorePermissionDenied => Some(
                "move the macOS VM helper store to a volume the background service can access, or grant the signed helper access to that volume",
            ),
            Self::HelperTimedOut => {
                Some("repair the macOS VM helper operation that exceeded the five-minute timeout")
            }
            Self::HelperIoFailed => {
                Some("repair the macOS VM helper process I/O channel and retry the operation")
            }
            Self::HelperExitedUnexpectedly => Some(
                "inspect the signed macOS VM helper installation and retry the failed operation",
            ),
            Self::HelperIncompatible => Some("install a helper that implements protocol version 1"),
            Self::EntitlementMissing => Some(
                "install and sign the helper with the required Virtualization.framework entitlement",
            ),
            Self::PrivateChannelUnavailable => {
                Some("configure the helper's private virtio/vsock guest control channel")
            }
            Self::ResourceLimitsUnavailable => {
                Some("configure the helper to enforce CPU, memory, and writable-disk limits")
            }
            Self::RuntimeDegraded => {
                Some("repair the configured macOS VM helper and template store")
            }
        }
    }
}

#[derive(Debug)]
pub struct MacOsVmProcesses {
    host: HostId,
    native: NativeProcesses,
    helper: Arc<dyn HelperCommand>,
    host_supported: bool,
    architecture: &'static str,
    diagnostics: Mutex<BTreeMap<AttemptId, Vec<ProviderDiagnostic>>>,
}

impl MacOsVmProcesses {
    #[must_use]
    pub fn new(host: HostId) -> Self {
        Self {
            host,
            native: NativeProcesses::new(),
            helper: Arc::new(SystemHelper::configured()),
            host_supported: cfg!(target_os = "macos"),
            architecture: host_architecture(),
            diagnostics: Mutex::new(BTreeMap::new()),
        }
    }

    #[must_use]
    pub fn host_state() -> MacOsVmHostState {
        let provider = Self::new(HostId::from_u128(0));
        provider.probe_host()
    }

    /// An operator action scoped to the exact policy that failed readiness.
    /// Host-wide status cannot diagnose a missing template because it has no
    /// policy image, so image failures name the durable reference directly.
    #[must_use]
    pub fn policy_remedy(policy: &ScalePolicy, capability: ProviderCapability) -> String {
        let (image, macos_vm) = match policy.execution_policy() {
            ExecutionPolicy::Isolated { backend, image, .. } => (
                Some(image.as_str()),
                matches!(backend, Backend::Auto | Backend::VirtualMachine),
            ),
            ExecutionPolicy::Native => (None, false),
        };
        if !macos_vm {
            return "runner-manager host isolation status".into();
        }
        match capability {
            ProviderCapability::ImageUnavailableOrIncompatible => format!(
                "install the exact pinned macOS VM template {} in the configured helper, verify its SHA-256 identity, then retry enabling this profile",
                image.unwrap_or("from this profile")
            ),
            ProviderCapability::NotInstalled => {
                "install and configure runner-manager-macos-vm for the daemon service account"
                    .into()
            }
            ProviderCapability::PermissionDenied => {
                "allow the daemon service account to execute the signed helper and read this profile's pinned template".into()
            }
            ProviderCapability::Unsupported => {
                "use a supported macOS architecture and a protocol-version-1 helper".into()
            }
            ProviderCapability::Degraded => {
                "repair the configured helper, its guest control channel, template store, resource enforcement, or timed-out operation".into()
            }
            ProviderCapability::DiskQuotaUnavailable => {
                "repair the configured isolation provider's bounded storage enforcement".into()
            }
            ProviderCapability::Ready => "no remediation required".into(),
        }
    }

    fn probe_host(&self) -> MacOsVmHostState {
        if !self.host_supported {
            return MacOsVmHostState::UnsupportedHost;
        }
        if !matches!(self.architecture, "arm64" | "x86_64") {
            return MacOsVmHostState::UnsupportedArchitecture;
        }
        let response = match self.helper.run(&strings(["probe", "--json"]), None) {
            Ok(response) => response,
            Err(HelperFailure::NotInstalled) => return MacOsVmHostState::HelperNotInstalled,
            Err(HelperFailure::PermissionDenied) => {
                return MacOsVmHostState::HelperPermissionDenied;
            }
            Err(HelperFailure::StorePermissionDenied) => {
                return MacOsVmHostState::HelperStorePermissionDenied;
            }
            Err(HelperFailure::TimedOut) => return MacOsVmHostState::HelperTimedOut,
            Err(HelperFailure::IoFailed) => return MacOsVmHostState::HelperIoFailed,
            Err(HelperFailure::UnexpectedExit) => {
                return MacOsVmHostState::HelperExitedUnexpectedly;
            }
            Err(
                HelperFailure::Missing | HelperFailure::Rejected | HelperFailure::TemplateMismatch,
            ) => {
                return MacOsVmHostState::HelperIncompatible;
            }
        };
        let Ok(probe) = serde_json::from_slice::<ProbeResponse>(&response) else {
            return MacOsVmHostState::HelperIncompatible;
        };
        if probe.protocol_version != PROTOCOL_VERSION {
            return MacOsVmHostState::HelperIncompatible;
        }
        if probe.architecture != self.architecture {
            return MacOsVmHostState::UnsupportedArchitecture;
        }
        if !probe.virtualization_framework {
            return MacOsVmHostState::RuntimeDegraded;
        }
        if !probe.macos_guest_entitlement {
            return MacOsVmHostState::EntitlementMissing;
        }
        if !probe.private_jit_channel {
            return MacOsVmHostState::PrivateChannelUnavailable;
        }
        if !probe.fresh_writable_disks || !probe.resource_limits || !probe.process_limits {
            return MacOsVmHostState::ResourceLimitsUnavailable;
        }
        MacOsVmHostState::Ready
    }

    fn note(&self, attempt: AttemptId, diagnostic: ProviderDiagnostic) {
        let mut all = self
            .diagnostics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entries = all.entry(attempt).or_default();
        if entries.len() < MAX_DIAGNOSTICS && !entries.contains(&diagnostic) {
            entries.push(diagnostic);
        }
    }

    fn inspect_image_metadata(
        &self,
        image: &ImageReference,
    ) -> Result<ImageResponse, HelperFailure> {
        if !image.as_str().starts_with("vm-version:") {
            return Err(HelperFailure::Rejected);
        }
        let output = self.helper.run(
            &[
                "image".into(),
                "inspect".into(),
                "--image".into(),
                image.as_str().into(),
                "--json".into(),
            ],
            None,
        )?;
        let image_response: ImageResponse =
            serde_json::from_slice(&output).map_err(|_| HelperFailure::Rejected)?;
        if image.vm_template_digest() != Some(image_response.template_digest.as_str()) {
            return Err(HelperFailure::TemplateMismatch);
        }
        if image_response.protocol_version != PROTOCOL_VERSION
            || image_response.image != image.as_str()
            || image_response.guest_os != "macos"
            || image_response.architecture != self.architecture
            || !image_response.immutable
            || !image_response.bootstrap_ready
        {
            return Err(HelperFailure::Rejected);
        }
        Ok(image_response)
    }

    fn inspect_image(&self, image: &ImageReference) -> Result<ImageResponse, FailureReason> {
        self.inspect_image_metadata(image)
            .map_err(image_helper_failure)
    }

    fn expected<'a>(
        &self,
        attempt: &'a RunnerAttempt,
    ) -> Result<ExpectedResource<'a>, FailureReason> {
        let AttemptExecution::Isolated {
            provider_kind: Backend::VirtualMachine,
            resolved_image,
            generation,
            ..
        } = attempt.execution()
        else {
            return Err(failure("macOS VM allocation is invalid"));
        };
        Ok(ExpectedResource {
            environment_id: environment_name(attempt.id, generation),
            attempt: attempt.id,
            generation,
            image: resolved_image,
        })
    }

    fn inspect_named(
        &self,
        environment_id: &str,
        attempt: Option<AttemptId>,
    ) -> Result<Option<ResourceRecord>, FailureReason> {
        let output = self.helper.run(
            &[
                "inspect".into(),
                "--environment".into(),
                environment_id.into(),
                "--json".into(),
            ],
            None,
        );
        match output {
            Ok(output) => serde_json::from_slice(&output)
                .map(Some)
                .map_err(|_| failure("macOS VM helper returned invalid environment metadata")),
            Err(HelperFailure::Missing) => Ok(None),
            Err(error) => {
                if error == HelperFailure::TimedOut
                    && let Some(attempt) = attempt
                {
                    self.note(attempt, ProviderDiagnostic::HelperTimedOut);
                }
                Err(operation_helper_failure(error))
            }
        }
    }

    fn record_for(&self, attempt: &RunnerAttempt) -> Result<Option<ResourceRecord>, FailureReason> {
        let expected = self.expected(attempt)?;
        self.inspect_named(&expected.environment_id, Some(attempt.id))
    }

    fn list_records(
        &self,
        host: HostId,
        attempt: Option<AttemptId>,
    ) -> Result<Vec<ResourceRecord>, FailureReason> {
        let output = self
            .helper
            .run(
                &[
                    "list".into(),
                    "--host".into(),
                    host.to_string(),
                    "--json".into(),
                ],
                None,
            )
            .map_err(|error| {
                if error == HelperFailure::TimedOut
                    && let Some(attempt) = attempt
                {
                    self.note(attempt, ProviderDiagnostic::HelperTimedOut);
                }
                operation_helper_failure(error)
            })?;
        serde_json::from_slice(&output)
            .map_err(|_| failure("macOS VM helper returned invalid owned-resource metadata"))
    }

    fn identity_for(
        &self,
        attempt: &RunnerAttempt,
        environment_id: String,
    ) -> Result<EnvironmentIdentity, FailureReason> {
        let AttemptExecution::Isolated {
            provider_kind: Backend::VirtualMachine,
            resolved_image,
            generation,
            ..
        } = attempt.execution()
        else {
            return Err(failure("macOS VM allocation is invalid"));
        };
        Ok(EnvironmentIdentity::Isolated {
            host: self.host,
            attempt: attempt.id,
            provider_kind: Backend::VirtualMachine,
            environment_id,
            resolved_image: resolved_image.clone(),
            generation: generation.clone(),
        })
    }

    fn run_resource_command(
        &self,
        verb: &str,
        attempt: &RunnerAttempt,
    ) -> Result<(), FailureReason> {
        let expected = self.expected(attempt)?;
        self.helper
            .run(
                &[
                    verb.into(),
                    "--environment".into(),
                    expected.environment_id,
                    "--host".into(),
                    self.host.to_string(),
                    "--attempt".into(),
                    attempt.id.to_string(),
                    "--generation".into(),
                    expected.generation.to_owned(),
                ],
                None,
            )
            .map(|_| ())
            .map_err(|error| {
                if error == HelperFailure::TimedOut {
                    self.note(attempt.id, ProviderDiagnostic::HelperTimedOut);
                }
                operation_helper_failure(error)
            })
    }

    fn intent_path(attempt: &RunnerAttempt) -> std::path::PathBuf {
        attempt.runtime_path().join(TERMINATE_INTENT_FILE)
    }
}

impl ExecutionProvider for MacOsVmProcesses {
    fn probe(&self, policy: &ScalePolicy) -> ProviderCapability {
        if policy.execution_policy().is_native() {
            return ProviderCapability::Ready;
        }
        let ExecutionPolicy::Isolated { backend, image, .. } = policy.execution_policy() else {
            return ProviderCapability::Unsupported;
        };
        if !matches!(backend, Backend::Auto | Backend::VirtualMachine) {
            return ProviderCapability::Unsupported;
        }
        let capability = self.probe_host().capability();
        if capability != ProviderCapability::Ready {
            return capability;
        }
        match self.inspect_image_metadata(image) {
            Ok(_) => ProviderCapability::Ready,
            Err(HelperFailure::NotInstalled) => ProviderCapability::NotInstalled,
            Err(HelperFailure::PermissionDenied | HelperFailure::StorePermissionDenied) => {
                ProviderCapability::PermissionDenied
            }
            Err(
                HelperFailure::Missing | HelperFailure::Rejected | HelperFailure::TemplateMismatch,
            ) => ProviderCapability::ImageUnavailableOrIncompatible,
            Err(
                HelperFailure::TimedOut | HelperFailure::IoFailed | HelperFailure::UnexpectedExit,
            ) => ProviderCapability::Degraded,
        }
    }

    fn resolve(&self, policy: &ScalePolicy) -> Result<Option<ResolvedEnvironment>, FailureReason> {
        if policy.execution_policy().is_native() {
            return Ok(None);
        }
        let ExecutionPolicy::Isolated { backend, image, .. } = policy.execution_policy() else {
            unreachable!();
        };
        if !matches!(backend, Backend::Auto | Backend::VirtualMachine) {
            return Err(failure("macOS VM provider was not selected"));
        }
        let host = self.probe_host();
        if host != MacOsVmHostState::Ready {
            return Err(failure(
                host.remedy()
                    .unwrap_or("macOS VM provider preflight failed"),
            ));
        }
        self.inspect_image(image)?;
        Ok(Some(ResolvedEnvironment {
            provider_kind: Backend::VirtualMachine,
            image: image.clone(),
        }))
    }

    fn prepare(
        &self,
        attempt: &RunnerAttempt,
        policy: &ScalePolicy,
    ) -> Result<PreparedEnvironment, FailureReason> {
        if attempt.execution().is_native() {
            return self.native.prepare(attempt, policy);
        }
        let expected = self.expected(attempt)?;
        let ExecutionPolicy::Isolated { resources, .. } = policy.execution_policy() else {
            return Err(failure("macOS VM policy is invalid"));
        };
        let host_state = self.probe_host();
        if host_state != MacOsVmHostState::Ready {
            self.note(
                attempt.id,
                if host_state == MacOsVmHostState::HelperTimedOut {
                    ProviderDiagnostic::HelperTimedOut
                } else {
                    ProviderDiagnostic::CapabilityUnavailable
                },
            );
            return Err(failure("macOS VM provider preflight failed"));
        }
        self.inspect_image_metadata(expected.image)
            .map_err(|error| {
                self.note(
                    attempt.id,
                    if error == HelperFailure::TemplateMismatch {
                        ProviderDiagnostic::TemplateIdentityMismatch
                    } else if error == HelperFailure::TimedOut {
                        ProviderDiagnostic::HelperTimedOut
                    } else {
                        ProviderDiagnostic::ImageRejected
                    },
                );
                image_helper_failure(error)
            })?;

        match self.inspect_named(&expected.environment_id, Some(attempt.id))? {
            Some(record)
                if record.same_owner(self.host, &expected)
                    && record.limits_match(*resources)
                    && record.is_prepared() => {}
            Some(record)
                if record.same_owner(self.host, &expected) && !record.limits_match(*resources) =>
            {
                self.note(attempt.id, ProviderDiagnostic::ResourceLimitMismatch);
                return Err(failure(
                    "macOS VM applied resource limits do not match the requested policy",
                ));
            }
            Some(record) if record.same_owner(self.host, &expected) => {
                self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
                return Err(failure("macOS VM state is incompatible with preparation"));
            }
            Some(_) => {
                self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
                return Err(failure("macOS VM ownership mismatch"));
            }
            None => {
                let args = prepare_args(self.host, attempt, &expected, *resources);
                self.helper.run(&args, None).map_err(|error| {
                    self.note(
                        attempt.id,
                        if error == HelperFailure::TimedOut {
                            ProviderDiagnostic::HelperTimedOut
                        } else {
                            ProviderDiagnostic::PrepareFailed
                        },
                    );
                    operation_helper_failure(error)
                })?;
            }
        }

        let record = self
            .inspect_named(&expected.environment_id, Some(attempt.id))?
            .ok_or_else(|| failure("macOS VM helper did not create the environment"))?;
        if !record.same_owner(self.host, &expected) {
            self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
            return Err(failure(
                "macOS VM prepared resource failed ownership or isolation checks",
            ));
        }
        if !record.limits_match(*resources) {
            self.note(attempt.id, ProviderDiagnostic::ResourceLimitMismatch);
            return Err(failure(
                "macOS VM applied resource limits do not match the requested policy",
            ));
        }
        if !record.is_prepared() {
            self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
            return Err(failure("macOS VM state is incompatible with preparation"));
        }
        if self
            .list_records(self.host, Some(attempt.id))?
            .iter()
            .any(|other| {
                other.environment_id != record.environment_id
                    && other.writable_disk_id == record.writable_disk_id
            })
        {
            self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
            return Err(failure(
                "macOS VM helper reused a writable disk across attempts",
            ));
        }
        let identity = self.identity_for(attempt, expected.environment_id)?;
        Ok(PreparedEnvironment::isolated(attempt.id, identity))
    }

    fn start(
        &self,
        prepared: PreparedEnvironment,
        attempt: &RunnerAttempt,
        handoff: OneTimeJitHandoff<'_>,
    ) -> Result<EnvironmentIdentity, ProcessStartFailure> {
        if attempt.execution().is_native() {
            return self.native.start(prepared, attempt, handoff);
        }
        let expected = self
            .expected(attempt)
            .map_err(ProcessStartFailure::before_spawn)?;
        let identity = self
            .identity_for(attempt, expected.environment_id.clone())
            .map_err(ProcessStartFailure::before_spawn)?;
        let owns = self
            .owns(attempt)
            .map_err(ProcessStartFailure::before_spawn)?;
        if prepared.identity() != Some(&identity) || !owns {
            self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
            return Err(ProcessStartFailure::before_spawn(failure(
                "macOS VM prepared identity mismatch",
            )));
        }
        let payload = handoff.consume().expose().as_bytes();
        let result = self.helper.run(
            &[
                "start".into(),
                "--environment".into(),
                expected.environment_id,
                "--jit-stdin".into(),
            ],
            Some(payload),
        );
        if let Err(error) = result {
            self.note(
                attempt.id,
                if error == HelperFailure::TimedOut {
                    ProviderDiagnostic::HelperTimedOut
                } else {
                    ProviderDiagnostic::StartFailed
                },
            );
            let _ = self.run_resource_command("stop", attempt);
            return Err(ProcessStartFailure::after_spawn_stopped());
        }
        Ok(identity)
    }

    fn inspect(&self, attempt: &RunnerAttempt) -> Result<EnvironmentState, FailureReason> {
        if attempt.execution().is_native() {
            return self.native.inspect(attempt);
        }
        let expected = self.expected(attempt)?;
        let Some(record) = self.inspect_named(&expected.environment_id, Some(attempt.id))? else {
            return Ok(EnvironmentState::Missing);
        };
        if !record.same_owner(self.host, &expected) {
            self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
            return Err(failure("macOS VM ownership mismatch"));
        }
        record.environment_state()
    }

    fn stop(&self, attempt: &RunnerAttempt) -> Result<ProviderStop, FailureReason> {
        if attempt.execution().is_native() {
            return self.native.stop(attempt);
        }
        if self.inspect(attempt)? == EnvironmentState::Missing {
            return Ok(ProviderStop::Stopped);
        }
        if !self.owns(attempt)? {
            self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
            return Err(failure("macOS VM ownership mismatch"));
        }
        self.run_resource_command("stop", attempt)?;
        Ok(
            if matches!(
                self.inspect(attempt)?,
                EnvironmentState::Starting | EnvironmentState::Running
            ) {
                ProviderStop::StillRunning
            } else {
                ProviderStop::Stopped
            },
        )
    }

    fn destroy(&self, attempt: &RunnerAttempt) -> Result<ProviderDestroy, FailureReason> {
        if attempt.execution().is_native() {
            return self.native.destroy(attempt);
        }
        if self.inspect(attempt)? == EnvironmentState::Missing {
            return Ok(ProviderDestroy::Destroyed);
        }
        if !self.owns(attempt)? {
            self.note(attempt.id, ProviderDiagnostic::OwnershipMismatch);
            return Err(failure("macOS VM ownership mismatch"));
        }
        self.run_resource_command("destroy", attempt)?;
        if self.inspect(attempt)? == EnvironmentState::Missing {
            Ok(ProviderDestroy::Destroyed)
        } else {
            self.note(attempt.id, ProviderDiagnostic::CleanupDeferred);
            Ok(ProviderDestroy::Deferred(
                "macOS VM removal is not yet confirmed",
            ))
        }
    }

    fn recover(&self, attempt: &RunnerAttempt) -> Result<EnvironmentState, FailureReason> {
        if attempt.execution().is_native() {
            return self.native.recover(attempt);
        }
        // The deterministic ID closes the create-before-journal crash window.
        self.inspect(attempt)
    }

    fn enumerate_owned(&self, host_id: HostId) -> Vec<EnvironmentIdentity> {
        self.list_records(host_id, None)
            .unwrap_or_default()
            .into_iter()
            .filter(|record| {
                record.protocol_version == PROTOCOL_VERSION && record.host_id == host_id.to_string()
            })
            .filter_map(ResourceRecord::identity)
            .collect()
    }

    fn diagnostics(&self, attempt: &RunnerAttempt) -> Vec<ProviderDiagnostic> {
        self.diagnostics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&attempt.id)
            .cloned()
            .unwrap_or_default()
    }

    fn owns(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
        if attempt.execution().is_native() {
            return self.native.owns(attempt);
        }
        let expected = self.expected(attempt)?;
        Ok(self
            .inspect_named(&expected.environment_id, Some(attempt.id))?
            .is_some_and(|record| record.same_owner(self.host, &expected)))
    }

    fn spawn(
        &self,
        attempt: &RunnerAttempt,
        config: &EncodedJitConfig,
    ) -> Result<u32, ProcessStartFailure> {
        if !attempt.execution().is_native() {
            return Err(ProcessStartFailure::before_spawn(failure(
                "native launch refused for a macOS VM allocation",
            )));
        }
        self.native.spawn(attempt, config)
    }

    fn is_alive(&self, attempt: &RunnerAttempt) -> Result<bool, FailureReason> {
        if attempt.execution().is_native() {
            self.native.is_alive(attempt)
        } else {
            Ok(matches!(
                self.inspect(attempt)?,
                EnvironmentState::Starting | EnvironmentState::Running
            ))
        }
    }

    fn recovered_pid(&self, attempt: &RunnerAttempt) -> Result<Option<u32>, FailureReason> {
        if attempt.execution().is_native() {
            self.native.recovered_pid(attempt)
        } else {
            Ok(None)
        }
    }

    fn completed_successfully(&self, attempt: &RunnerAttempt) -> bool {
        if attempt.execution().is_native() {
            return self.native.completed_successfully(attempt);
        }
        self.record_for(attempt)
            .ok()
            .flatten()
            .is_some_and(|record| record.state == "exited" && record.runner_exit_code == Some(0))
    }

    fn record_terminate_intent(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason> {
        if attempt.execution().is_native() {
            return self.native.record_terminate_intent(attempt);
        }
        write_durable_file(&Self::intent_path(attempt), b"registration-timeout\n")
            .map_err(|_| failure("macOS VM terminate intent could not be journalled"))
    }

    fn has_terminate_intent(&self, attempt: &RunnerAttempt) -> bool {
        if attempt.execution().is_native() {
            self.native.has_terminate_intent(attempt)
        } else {
            Self::intent_path(attempt).is_file()
        }
    }

    fn terminate(&self, attempt: &RunnerAttempt) -> Result<(), FailureReason> {
        if attempt.execution().is_native() {
            self.native.terminate(attempt)
        } else {
            self.stop(attempt).map(|_| ())
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeResponse {
    protocol_version: u16,
    architecture: String,
    virtualization_framework: bool,
    macos_guest_entitlement: bool,
    private_jit_channel: bool,
    fresh_writable_disks: bool,
    resource_limits: bool,
    process_limits: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageResponse {
    protocol_version: u16,
    image: String,
    template_digest: String,
    guest_os: String,
    architecture: String,
    immutable: bool,
    bootstrap_ready: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceRecord {
    protocol_version: u16,
    environment_id: String,
    state: String,
    host_id: String,
    attempt_id: String,
    generation: String,
    image: String,
    template_digest: String,
    guest_os: String,
    architecture: String,
    writable_disk_id: String,
    fresh_writable_disk: bool,
    shared_host_paths: Vec<String>,
    jit_channel: String,
    applied_cpu_millis: u32,
    applied_memory_mib: u32,
    applied_disk_mib: u32,
    applied_process_limit: u32,
    runner_exit_code: Option<i32>,
}

impl ResourceRecord {
    fn same_owner(&self, host: HostId, expected: &ExpectedResource<'_>) -> bool {
        self.protocol_version == PROTOCOL_VERSION
            && self.environment_id == expected.environment_id
            && self.host_id == host.to_string()
            && self.attempt_id == expected.attempt.to_string()
            && self.generation == expected.generation
            && self.image == expected.image.as_str()
            && Some(self.template_digest.as_str()) == expected.image.vm_template_digest()
            && self.guest_os == "macos"
            && self.architecture == host_architecture()
            && !self.writable_disk_id.is_empty()
            && self.fresh_writable_disk
            && self.shared_host_paths.is_empty()
            && self.jit_channel == "private"
    }

    fn limits_match(&self, requested: ResourceLimits) -> bool {
        self.applied_cpu_millis == requested.cpu_millis
            && self.applied_memory_mib == requested.memory_mib
            && self.applied_disk_mib == requested.disk_mib
            && self.applied_process_limit == PROCESS_LIMIT
    }

    fn is_prepared(&self) -> bool {
        self.state == "prepared"
    }

    fn environment_state(&self) -> Result<EnvironmentState, FailureReason> {
        match self.state.as_str() {
            "prepared" | "booting" => Ok(EnvironmentState::Starting),
            "running" => Ok(EnvironmentState::Running),
            "exited" | "stopped" => Ok(EnvironmentState::Exited),
            "missing" => Ok(EnvironmentState::Missing),
            _ => Err(failure("macOS VM helper returned an unknown state")),
        }
    }

    fn identity(self) -> Option<EnvironmentIdentity> {
        let host = HostId::from_uuid(self.host_id.parse().ok()?);
        let attempt = AttemptId::from_uuid(self.attempt_id.parse().ok()?);
        let image = ImageReference::new(self.image).ok()?;
        if self.protocol_version != PROTOCOL_VERSION
            || self.guest_os != "macos"
            || Some(self.template_digest.as_str()) != image.vm_template_digest()
            || self.architecture != host_architecture()
            || self.writable_disk_id.is_empty()
            || !self.fresh_writable_disk
            || !self.shared_host_paths.is_empty()
            || self.jit_channel != "private"
        {
            return None;
        }
        Some(EnvironmentIdentity::Isolated {
            host,
            attempt,
            provider_kind: Backend::VirtualMachine,
            environment_id: self.environment_id,
            resolved_image: image,
            generation: self.generation,
        })
    }
}

struct ExpectedResource<'a> {
    environment_id: String,
    attempt: AttemptId,
    generation: &'a str,
    image: &'a ImageReference,
}

fn prepare_args(
    host: HostId,
    attempt: &RunnerAttempt,
    expected: &ExpectedResource<'_>,
    resources: ResourceLimits,
) -> Vec<String> {
    vec![
        "prepare".into(),
        "--environment".into(),
        expected.environment_id.clone(),
        "--host".into(),
        host.to_string(),
        "--attempt".into(),
        attempt.id.to_string(),
        "--generation".into(),
        expected.generation.to_owned(),
        "--image".into(),
        expected.image.as_str().into(),
        "--template-digest".into(),
        expected
            .image
            .vm_template_digest()
            .expect("validated VM image reference")
            .into(),
        "--architecture".into(),
        host_architecture().into(),
        "--cpu-millis".into(),
        resources.cpu_millis.to_string(),
        "--memory-mib".into(),
        resources.memory_mib.to_string(),
        "--disk-mib".into(),
        resources.disk_mib.to_string(),
        "--process-limit".into(),
        PROCESS_LIMIT.to_string(),
        "--runner-source".into(),
        attempt.runtime_path().to_string_lossy().into_owned(),
        "--fresh-writable-disk".into(),
        "--no-host-shares".into(),
        "--private-jit-channel".into(),
    ]
}

fn environment_name(attempt: AttemptId, generation: &str) -> String {
    let suffix: String = generation
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(12)
        .collect();
    format!("rm-{attempt}-{suffix}")
}

fn host_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => other,
    }
}

fn failure(message: impl Into<String>) -> FailureReason {
    FailureReason::Other(message.into())
}

fn image_helper_failure(error: HelperFailure) -> FailureReason {
    match error {
        HelperFailure::NotInstalled => failure("macOS VM helper is not installed"),
        HelperFailure::PermissionDenied => failure("macOS VM helper permission denied"),
        HelperFailure::StorePermissionDenied => {
            failure("macOS VM helper store is inaccessible to the service account")
        }
        HelperFailure::Missing | HelperFailure::Rejected => {
            failure("macOS VM image is unavailable or incompatible")
        }
        HelperFailure::TemplateMismatch => {
            failure("macOS VM template digest does not match policy")
        }
        HelperFailure::TimedOut => failure("macOS VM helper timed out"),
        HelperFailure::IoFailed => failure("macOS VM helper process I/O failed"),
        HelperFailure::UnexpectedExit => failure("macOS VM helper exited unexpectedly"),
    }
}

fn operation_helper_failure(error: HelperFailure) -> FailureReason {
    match error {
        HelperFailure::NotInstalled => failure("macOS VM helper is not installed"),
        HelperFailure::PermissionDenied => failure("macOS VM helper permission denied"),
        HelperFailure::StorePermissionDenied => {
            failure("macOS VM helper store is inaccessible to the service account")
        }
        HelperFailure::Missing => failure("macOS VM resource is absent"),
        HelperFailure::Rejected => failure("macOS VM helper rejected the operation"),
        HelperFailure::TemplateMismatch => failure("macOS VM template digest mismatch"),
        HelperFailure::TimedOut => failure("macOS VM helper operation timed out"),
        HelperFailure::IoFailed => failure("macOS VM helper process I/O failed"),
        HelperFailure::UnexpectedExit => failure("macOS VM helper exited unexpectedly"),
    }
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.into_iter().map(str::to_owned).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperFailure {
    NotInstalled,
    PermissionDenied,
    /// The helper's closed diagnostic reported that its store cannot be used
    /// from this process context. No helper-provided text is retained.
    StorePermissionDenied,
    Missing,
    Rejected,
    TemplateMismatch,
    TimedOut,
    IoFailed,
    UnexpectedExit,
}

trait HelperCommand: std::fmt::Debug + Send + Sync {
    fn run(&self, args: &[String], stdin: Option<&[u8]>) -> Result<Vec<u8>, HelperFailure>;
}

#[derive(Debug)]
struct SystemHelper {
    program: OsString,
}

impl SystemHelper {
    fn configured() -> Self {
        Self {
            program: std::env::var_os("RUNNER_MANAGER_MACOS_VM_HELPER")
                .unwrap_or_else(|| DEFAULT_HELPER.into()),
        }
    }

    fn invoke(&self, args: &[String], stdin: Option<&[u8]>) -> std::io::Result<Output> {
        let mut command = Command::new(&self.program);
        command
            .arg("--protocol-version")
            .arg(PROTOCOL_VERSION.to_string())
            .args(args);
        invoke_command(command, stdin, HELPER_TIMEOUT)
    }
}

/// Drive stdin, stdout, and process completion concurrently under one deadline.
/// A helper that stops reading JIT input, stops closing stdout, or never exits
/// must not pin the daemon's lifecycle worker indefinitely.
fn invoke_command(
    mut command: Command,
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> std::io::Result<Output> {
    let mut child = command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;

    let stdin_result = if let Some(payload) = stdin {
        let mut pipe = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("helper stdin unavailable"))?;
        let mut payload = payload.to_vec();
        let (send, receive) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let result = (|| {
                pipe.write_all(&payload)?;
                pipe.flush()
            })();
            payload.zeroize();
            let _ = send.send(result);
        });
        Some(receive)
    } else {
        None
    };
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("helper stdout unavailable"))?;
    let (stdout_send, stdout_receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = stdout_send.send(read_bounded_response(stdout));
    });
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("helper stderr unavailable"))?;
    let (stderr_send, stderr_receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = stderr_send.send(read_bounded_stderr(stderr));
    });

    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(helper_timeout());
        }
        thread::sleep(Duration::from_millis(10));
    };

    if let Some(result) = stdin_result {
        receive_until(result, deadline, "helper stdin")?;
    }
    let stdout = receive_until(stdout_receive, deadline, "helper stdout")?;
    let stderr = receive_until(stderr_receive, deadline, "helper stderr")?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn receive_until<T>(
    receiver: mpsc::Receiver<std::io::Result<T>>,
    deadline: Instant,
    channel: &'static str,
) -> std::io::Result<T> {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Err(helper_timeout());
    };
    match receiver.recv_timeout(remaining) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(helper_timeout()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(std::io::Error::other(format!(
            "{channel} worker disconnected"
        ))),
    }
}

fn helper_timeout() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "macOS VM helper exceeded its five-minute operation timeout",
    )
}

fn read_bounded_response(mut reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut response = Vec::new();
    reader
        .by_ref()
        .take((MAX_RESPONSE + 1) as u64)
        .read_to_end(&mut response)?;
    if response.len() > MAX_RESPONSE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "macOS VM helper response exceeded 64 KiB",
        ));
    }
    Ok(response)
}

fn read_bounded_stderr(mut reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut stderr = Vec::new();
    reader
        .by_ref()
        .take((MAX_HELPER_STDERR + 1) as u64)
        .read_to_end(&mut stderr)?;
    if stderr.len() > MAX_HELPER_STDERR {
        stderr.truncate(MAX_HELPER_STDERR);
    }
    Ok(stderr)
}

/// Translate only diagnostics emitted by the helper shipped in this repository.
/// The returned type carries no text, so an alternate helper, guest output, an
/// environment dump, or a credential-shaped value can never cross this seam.
fn closed_helper_diagnostic(stderr: &[u8]) -> Option<HelperFailure> {
    match stderr {
        b"runner-manager-macos-vm: helper store permission denied\n" => {
            Some(HelperFailure::StorePermissionDenied)
        }
        _ => None,
    }
}

impl HelperCommand for SystemHelper {
    fn run(&self, args: &[String], stdin: Option<&[u8]>) -> Result<Vec<u8>, HelperFailure> {
        let output = self
            .invoke(args, stdin)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => HelperFailure::NotInstalled,
                std::io::ErrorKind::PermissionDenied => HelperFailure::PermissionDenied,
                std::io::ErrorKind::TimedOut => HelperFailure::TimedOut,
                _ => HelperFailure::IoFailed,
            })?;
        if output.status.success() {
            return Ok(output.stdout);
        }
        if let Some(failure) = closed_helper_diagnostic(&output.stderr) {
            return Err(failure);
        }
        Err(match output.status.code() {
            Some(66) => HelperFailure::Missing,
            Some(77) => HelperFailure::PermissionDenied,
            Some(78) => HelperFailure::Rejected,
            _ => HelperFailure::UnexpectedExit,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use runner_manager_domain::attempt::RunnerAttempt;
    use runner_manager_domain::execution::{
        AttemptExecution, Backend, ExecutionPolicy, ImageReference, ResourceLimits,
    };
    use runner_manager_domain::model::{AttemptId, HostId};
    use runner_manager_domain::policy::ScalePolicy;
    use runner_manager_github::jit::EncodedJitConfig;
    use runner_manager_testkit::fixtures;
    use serde_json::{Value, json};

    use super::*;

    const TEMPLATE_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_IMAGE: &str = concat!(
        "vm-version:macos-test-v1@sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    #[derive(Debug)]
    struct FakeHelper {
        probe: Mutex<Result<Value, HelperFailure>>,
        image: Mutex<Result<Value, HelperFailure>>,
        inspect_failure: Mutex<Option<HelperFailure>>,
        records: Mutex<BTreeMap<String, Value>>,
        calls: Mutex<Vec<Vec<String>>>,
        jit_inputs: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeHelper {
        fn ready() -> Arc<Self> {
            Arc::new(Self {
                probe: Mutex::new(Ok(ready_probe())),
                image: Mutex::new(Ok(ready_image())),
                inspect_failure: Mutex::new(None),
                records: Mutex::new(BTreeMap::new()),
                calls: Mutex::new(Vec::new()),
                jit_inputs: Mutex::new(Vec::new()),
            })
        }

        fn set_probe(&self, value: Result<Value, HelperFailure>) {
            *self.probe.lock().unwrap() = value;
        }

        fn set_image(&self, value: Value) {
            *self.image.lock().unwrap() = Ok(value);
        }

        fn set_image_failure(&self, failure: HelperFailure) {
            *self.image.lock().unwrap() = Err(failure);
        }

        fn set_inspect_failure(&self, failure: HelperFailure) {
            *self.inspect_failure.lock().unwrap() = Some(failure);
        }

        fn record(&self, environment: &str) -> Option<Value> {
            self.records.lock().unwrap().get(environment).cloned()
        }
    }

    impl HelperCommand for FakeHelper {
        fn run(&self, args: &[String], stdin: Option<&[u8]>) -> Result<Vec<u8>, HelperFailure> {
            self.calls.lock().unwrap().push(args.to_vec());
            match args.first().map(String::as_str) {
                Some("probe") => self
                    .probe
                    .lock()
                    .unwrap()
                    .clone()
                    .map(|value| serde_json::to_vec(&value).unwrap()),
                Some("image") => self
                    .image
                    .lock()
                    .unwrap()
                    .clone()
                    .map(|value| serde_json::to_vec(&value).unwrap()),
                Some("inspect") => {
                    if let Some(failure) = *self.inspect_failure.lock().unwrap() {
                        return Err(failure);
                    }
                    let environment = argument(args, "--environment");
                    self.records
                        .lock()
                        .unwrap()
                        .get(environment)
                        .map(|value| serde_json::to_vec(value).unwrap())
                        .ok_or(HelperFailure::Missing)
                }
                Some("prepare") => {
                    let environment = argument(args, "--environment").to_owned();
                    let value = resource(ResourceFixture {
                        environment: &environment,
                        host: argument(args, "--host"),
                        attempt: argument(args, "--attempt"),
                        generation: argument(args, "--generation"),
                        image: argument(args, "--image"),
                        template_digest: argument(args, "--template-digest"),
                        cpu_millis: argument(args, "--cpu-millis").parse().unwrap(),
                        memory_mib: argument(args, "--memory-mib").parse().unwrap(),
                        disk_mib: argument(args, "--disk-mib").parse().unwrap(),
                        process_limit: argument(args, "--process-limit").parse().unwrap(),
                        state: "prepared",
                        runner_exit_code: None,
                    });
                    self.records.lock().unwrap().insert(environment, value);
                    Ok(b"{}".to_vec())
                }
                Some("start") => {
                    let environment = argument(args, "--environment").to_owned();
                    let payload = stdin.ok_or(HelperFailure::Rejected)?.to_vec();
                    if payload.is_empty() {
                        return Err(HelperFailure::Rejected);
                    }
                    self.jit_inputs.lock().unwrap().push(payload);
                    self.records.lock().unwrap().get_mut(&environment).unwrap()["state"] =
                        json!("running");
                    Ok(b"{}".to_vec())
                }
                Some("stop") => {
                    let environment = argument(args, "--environment");
                    self.records.lock().unwrap().get_mut(environment).unwrap()["state"] =
                        json!("stopped");
                    Ok(b"{}".to_vec())
                }
                Some("destroy") => {
                    let environment = argument(args, "--environment");
                    self.records.lock().unwrap().remove(environment);
                    Ok(b"{}".to_vec())
                }
                Some("list") => Ok(serde_json::to_vec(
                    &self
                        .records
                        .lock()
                        .unwrap()
                        .values()
                        .cloned()
                        .collect::<Vec<_>>(),
                )
                .unwrap()),
                _ => Err(HelperFailure::Rejected),
            }
        }
    }

    fn argument<'a>(args: &'a [String], name: &str) -> &'a str {
        let index = args.iter().position(|arg| arg == name).unwrap();
        &args[index + 1]
    }

    fn ready_probe() -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "architecture": host_architecture(),
            "virtualization_framework": true,
            "macos_guest_entitlement": true,
            "private_jit_channel": true,
            "fresh_writable_disks": true,
            "resource_limits": true,
            "process_limits": true
        })
    }

    fn ready_image() -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "image": TEST_IMAGE,
            "template_digest": TEMPLATE_DIGEST,
            "guest_os": "macos",
            "architecture": host_architecture(),
            "immutable": true,
            "bootstrap_ready": true
        })
    }

    struct ResourceFixture<'a> {
        environment: &'a str,
        host: &'a str,
        attempt: &'a str,
        generation: &'a str,
        image: &'a str,
        template_digest: &'a str,
        cpu_millis: u32,
        memory_mib: u32,
        disk_mib: u32,
        process_limit: u32,
        state: &'a str,
        runner_exit_code: Option<i32>,
    }

    fn resource(fixture: ResourceFixture<'_>) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "environment_id": fixture.environment,
            "state": fixture.state,
            "host_id": fixture.host,
            "attempt_id": fixture.attempt,
            "generation": fixture.generation,
            "image": fixture.image,
            "template_digest": fixture.template_digest,
            "guest_os": "macos",
            "architecture": host_architecture(),
            "writable_disk_id": format!("disk-{}", fixture.environment),
            "fresh_writable_disk": true,
            "shared_host_paths": [],
            "jit_channel": "private",
            "applied_cpu_millis": fixture.cpu_millis,
            "applied_memory_mib": fixture.memory_mib,
            "applied_disk_mib": fixture.disk_mib,
            "applied_process_limit": fixture.process_limit,
            "runner_exit_code": fixture.runner_exit_code
        })
    }

    fn provider(host: HostId, helper: Arc<FakeHelper>) -> MacOsVmProcesses {
        MacOsVmProcesses {
            host,
            native: NativeProcesses::new(),
            helper,
            host_supported: true,
            architecture: host_architecture(),
            diagnostics: Mutex::new(BTreeMap::new()),
        }
    }

    fn isolated_policy() -> ScalePolicy {
        let mut policy = fixtures::policy()
            .repository("acme/widgets")
            .autoscale("mac", 1)
            .build();
        policy
            .set_execution_policy(ExecutionPolicy::Isolated {
                backend: Backend::VirtualMachine,
                image: ImageReference::new(TEST_IMAGE).unwrap(),
                resources: ResourceLimits {
                    cpu_millis: 2_000,
                    memory_mib: 4_096,
                    disk_mib: 32_768,
                },
            })
            .unwrap();
        policy
    }

    fn isolated_attempt(policy: &ScalePolicy, id: u128, root: &std::path::Path) -> RunnerAttempt {
        let runtime = root.join(format!("attempt-{id}"));
        std::fs::create_dir_all(&runtime).unwrap();
        let mut attempt = fixtures::attempt()
            .id(AttemptId::from_u128(id))
            .policy_id(policy.id)
            .runtime_path(runtime.to_string_lossy())
            .build();
        attempt
            .allocate_execution(AttemptExecution::Isolated {
                provider_kind: Backend::VirtualMachine,
                environment_id: None,
                resolved_image: ImageReference::new(TEST_IMAGE).unwrap(),
                generation: format!("generation-{id}"),
            })
            .unwrap();
        attempt
    }

    #[test]
    fn image_remedy_names_the_exact_policy_template() {
        let policy = isolated_policy();
        let remedy = MacOsVmProcesses::policy_remedy(
            &policy,
            ProviderCapability::ImageUnavailableOrIncompatible,
        );
        assert!(remedy.contains(TEST_IMAGE), "{remedy}");
        assert!(remedy.contains("SHA-256"), "{remedy}");
        assert!(!remedy.contains("host isolation status"), "{remedy}");
    }

    #[test]
    fn host_probe_requires_every_security_capability() {
        let helper = FakeHelper::ready();
        let provider = provider(HostId::from_u128(1), Arc::clone(&helper));
        assert_eq!(provider.probe_host(), MacOsVmHostState::Ready);

        for (field, expected) in [
            (
                "macos_guest_entitlement",
                MacOsVmHostState::EntitlementMissing,
            ),
            (
                "private_jit_channel",
                MacOsVmHostState::PrivateChannelUnavailable,
            ),
            (
                "fresh_writable_disks",
                MacOsVmHostState::ResourceLimitsUnavailable,
            ),
            (
                "resource_limits",
                MacOsVmHostState::ResourceLimitsUnavailable,
            ),
            (
                "process_limits",
                MacOsVmHostState::ResourceLimitsUnavailable,
            ),
        ] {
            let mut probe = ready_probe();
            probe[field] = json!(false);
            helper.set_probe(Ok(probe));
            assert_eq!(provider.probe_host(), expected, "field {field}");
        }
    }

    #[test]
    fn helper_response_reader_stops_at_the_documented_limit() {
        let accepted = vec![b'a'; MAX_RESPONSE];
        assert_eq!(
            read_bounded_response(std::io::Cursor::new(&accepted)).unwrap(),
            accepted
        );

        let oversized = vec![b'b'; MAX_RESPONSE + 4096];
        let error = read_bounded_response(std::io::Cursor::new(oversized)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn host_probe_classifies_missing_permission_and_protocol_failures() {
        let helper = FakeHelper::ready();
        let provider = provider(HostId::from_u128(1), Arc::clone(&helper));
        for (failure, expected) in [
            (
                HelperFailure::NotInstalled,
                MacOsVmHostState::HelperNotInstalled,
            ),
            (
                HelperFailure::PermissionDenied,
                MacOsVmHostState::HelperPermissionDenied,
            ),
            (
                HelperFailure::StorePermissionDenied,
                MacOsVmHostState::HelperStorePermissionDenied,
            ),
            (HelperFailure::TimedOut, MacOsVmHostState::HelperTimedOut),
            (HelperFailure::IoFailed, MacOsVmHostState::HelperIoFailed),
            (
                HelperFailure::UnexpectedExit,
                MacOsVmHostState::HelperExitedUnexpectedly,
            ),
            (HelperFailure::Missing, MacOsVmHostState::HelperIncompatible),
            (
                HelperFailure::Rejected,
                MacOsVmHostState::HelperIncompatible,
            ),
        ] {
            helper.set_probe(Err(failure));
            assert_eq!(provider.probe_host(), expected);
        }
        let mut incompatible = ready_probe();
        incompatible["protocol_version"] = json!(PROTOCOL_VERSION + 1);
        helper.set_probe(Ok(incompatible));
        assert_eq!(provider.probe_host(), MacOsVmHostState::HelperIncompatible);
    }

    #[test]
    fn image_must_be_immutable_native_macos_and_same_architecture() {
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        assert_eq!(provider.probe(&policy), ProviderCapability::Ready);

        for (field, bad) in [
            ("template_digest", json!("b".repeat(64))),
            ("guest_os", json!("linux")),
            ("architecture", json!("other")),
            ("immutable", json!(false)),
            ("bootstrap_ready", json!(false)),
        ] {
            let mut image = ready_image();
            image[field] = bad;
            helper.set_image(image);
            assert_eq!(
                provider.probe(&policy),
                ProviderCapability::ImageUnavailableOrIncompatible,
                "field {field}"
            );
        }
    }

    #[test]
    fn image_probe_preserves_helper_failure_classification() {
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));

        for (failure, expected) in [
            (
                HelperFailure::NotInstalled,
                ProviderCapability::NotInstalled,
            ),
            (
                HelperFailure::PermissionDenied,
                ProviderCapability::PermissionDenied,
            ),
            (
                HelperFailure::StorePermissionDenied,
                ProviderCapability::PermissionDenied,
            ),
            (
                HelperFailure::Missing,
                ProviderCapability::ImageUnavailableOrIncompatible,
            ),
            (
                HelperFailure::Rejected,
                ProviderCapability::ImageUnavailableOrIncompatible,
            ),
            (HelperFailure::TimedOut, ProviderCapability::Degraded),
            (HelperFailure::IoFailed, ProviderCapability::Degraded),
            (HelperFailure::UnexpectedExit, ProviderCapability::Degraded),
            (
                HelperFailure::TemplateMismatch,
                ProviderCapability::ImageUnavailableOrIncompatible,
            ),
        ] {
            helper.set_image_failure(failure);
            assert_eq!(provider.probe(&policy), expected);
        }
    }

    #[test]
    fn prepare_requests_a_fresh_limited_disk_without_host_shares() {
        let root = tempfile::tempdir().unwrap();
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        let attempt = isolated_attempt(&policy, 11, root.path());

        let prepared = provider.prepare(&attempt, &policy).unwrap();
        assert!(matches!(
            prepared.identity(),
            Some(EnvironmentIdentity::Isolated { .. })
        ));
        let calls = helper.calls.lock().unwrap();
        let prepare = calls.iter().find(|call| call[0] == "prepare").unwrap();
        for required in [
            "--fresh-writable-disk",
            "--no-host-shares",
            "--private-jit-channel",
            "--cpu-millis",
            "--memory-mib",
            "--disk-mib",
            "--process-limit",
            "--template-digest",
        ] {
            assert!(
                prepare.iter().any(|arg| arg == required),
                "missing {required}"
            );
        }
        assert!(!prepare.iter().any(|arg| arg == "--mount"));
        assert_eq!(
            argument(prepare, "--process-limit"),
            PROCESS_LIMIT.to_string()
        );
        assert_eq!(argument(prepare, "--template-digest"), TEMPLATE_DIGEST);
    }

    #[test]
    fn prepare_rejects_applied_resource_or_process_limit_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));

        for (id, field) in [
            (12, "applied_cpu_millis"),
            (13, "applied_memory_mib"),
            (14, "applied_disk_mib"),
            (15, "applied_process_limit"),
        ] {
            let attempt = isolated_attempt(&policy, id, root.path());
            provider.prepare(&attempt, &policy).unwrap();
            let environment = provider.expected(&attempt).unwrap().environment_id;
            helper
                .records
                .lock()
                .unwrap()
                .get_mut(&environment)
                .unwrap()[field] = json!(1);
            assert!(
                provider.prepare(&attempt, &policy).is_err(),
                "field {field}"
            );
            assert_eq!(
                provider.diagnostics(&attempt),
                vec![ProviderDiagnostic::ResourceLimitMismatch],
                "field {field}"
            );
        }
    }

    #[test]
    fn template_digest_mismatch_is_typed_and_blocks_prepare() {
        let root = tempfile::tempdir().unwrap();
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        let attempt = isolated_attempt(&policy, 16, root.path());
        let mut image = ready_image();
        image["template_digest"] = json!("b".repeat(64));
        helper.set_image(image);

        assert!(provider.prepare(&attempt, &policy).is_err());
        assert_eq!(
            provider.diagnostics(&attempt),
            vec![ProviderDiagnostic::TemplateIdentityMismatch]
        );
    }

    #[test]
    fn helper_timeout_is_a_typed_attempt_diagnostic() {
        let root = tempfile::tempdir().unwrap();
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        let attempt = isolated_attempt(&policy, 17, root.path());
        helper.set_probe(Err(HelperFailure::TimedOut));

        assert!(provider.prepare(&attempt, &policy).is_err());
        assert_eq!(
            provider.diagnostics(&attempt),
            vec![ProviderDiagnostic::HelperTimedOut]
        );
    }

    #[test]
    fn helper_wait_stdout_and_blocked_stdin_share_one_deadline() {
        for (command, input) in [
            (blocking_command(false), None),
            (blocking_command(true), None),
            (blocking_command(false), Some(vec![b'x'; 4 * 1024 * 1024])),
        ] {
            let error = invoke_command(command, input.as_deref(), Duration::from_millis(50))
                .expect_err("helper must time out");
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        }
    }

    #[test]
    fn helper_stderr_accepts_only_a_closed_non_secret_diagnostic() {
        assert_eq!(
            closed_helper_diagnostic(b"runner-manager-macos-vm: helper store permission denied\n"),
            Some(HelperFailure::StorePermissionDenied)
        );

        for untrusted in [
            b"runner output: ACTIONS_RUNNER_INPUT_JITCONFIG=secret\n".as_slice(),
            b"runner-manager-macos-vm: helper store permission denied token=secret\n".as_slice(),
            b"runner-manager-macos-vm: helper store permission denied\nextra guest output\n"
                .as_slice(),
        ] {
            assert_eq!(closed_helper_diagnostic(untrusted), None);
        }
    }

    #[test]
    fn helper_stderr_is_captured_with_a_hard_bound() {
        let oversized = vec![b'x'; MAX_HELPER_STDERR + 4096];
        let captured = read_bounded_stderr(std::io::Cursor::new(oversized)).unwrap();
        assert_eq!(captured.len(), MAX_HELPER_STDERR);
    }

    #[cfg(windows)]
    fn blocking_command(writes_stdout: bool) -> Command {
        let mut command = Command::new("cmd");
        command.args([
            "/C",
            if writes_stdout {
                "echo partial & ping -n 4 127.0.0.1 >NUL"
            } else {
                "ping -n 4 127.0.0.1 >NUL"
            },
        ]);
        command
    }

    #[cfg(not(windows))]
    fn blocking_command(writes_stdout: bool) -> Command {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            if writes_stdout {
                "printf partial; sleep 3"
            } else {
                "sleep 3"
            },
        ]);
        command
    }

    #[test]
    fn attempts_receive_distinct_environment_and_writable_disk_identities() {
        let root = tempfile::tempdir().unwrap();
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        let first = isolated_attempt(&policy, 21, root.path());
        let second = isolated_attempt(&policy, 22, root.path());
        provider.prepare(&first, &policy).unwrap();
        provider.prepare(&second, &policy).unwrap();

        let first_name = provider.expected(&first).unwrap().environment_id;
        let second_name = provider.expected(&second).unwrap().environment_id;
        assert_ne!(first_name, second_name);
        assert_ne!(
            helper.record(&first_name).unwrap()["writable_disk_id"],
            helper.record(&second_name).unwrap()["writable_disk_id"]
        );
    }

    #[test]
    fn prepare_rejects_a_helper_that_reuses_another_attempts_disk() {
        let root = tempfile::tempdir().unwrap();
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        let first = isolated_attempt(&policy, 23, root.path());
        let second = isolated_attempt(&policy, 24, root.path());
        provider.prepare(&first, &policy).unwrap();

        let first_name = provider.expected(&first).unwrap().environment_id;
        let second_expected = provider.expected(&second).unwrap();
        let reused_disk = helper.record(&first_name).unwrap()["writable_disk_id"].clone();
        let mut second_record = resource(ResourceFixture {
            environment: &second_expected.environment_id,
            host: &policy.host_id.to_string(),
            attempt: &second.id.to_string(),
            generation: second_expected.generation,
            image: second_expected.image.as_str(),
            template_digest: TEMPLATE_DIGEST,
            cpu_millis: 2_000,
            memory_mib: 4_096,
            disk_mib: 32_768,
            process_limit: PROCESS_LIMIT,
            state: "prepared",
            runner_exit_code: None,
        });
        second_record["writable_disk_id"] = reused_disk;
        helper
            .records
            .lock()
            .unwrap()
            .insert(second_expected.environment_id, second_record);

        assert!(provider.prepare(&second, &policy).is_err());
        assert_eq!(
            provider.diagnostics(&second),
            vec![ProviderDiagnostic::PrepareFailed]
        );
    }

    #[test]
    fn jit_is_sent_only_on_stdin_and_never_in_helper_arguments() {
        let root = tempfile::tempdir().unwrap();
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        let attempt = isolated_attempt(&policy, 31, root.path());
        let prepared = provider.prepare(&attempt, &policy).unwrap();
        let secret = "encoded-jit-secret-sentinel";
        let config = EncodedJitConfig::new(secret);
        provider
            .start(prepared, &attempt, OneTimeJitHandoff::new(&config))
            .unwrap();

        assert_eq!(&*helper.jit_inputs.lock().unwrap(), &[secret.as_bytes()]);
        assert!(
            helper
                .calls
                .lock()
                .unwrap()
                .iter()
                .flatten()
                .all(|arg| !arg.contains(secret))
        );
        assert_eq!(
            provider.inspect(&attempt).unwrap(),
            EnvironmentState::Running
        );
    }

    #[test]
    fn ownership_mismatch_blocks_stop_and_destroy() {
        let root = tempfile::tempdir().unwrap();
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        let attempt = isolated_attempt(&policy, 41, root.path());
        provider.prepare(&attempt, &policy).unwrap();
        let environment = provider.expected(&attempt).unwrap().environment_id;
        helper
            .records
            .lock()
            .unwrap()
            .get_mut(&environment)
            .unwrap()["generation"] = json!("somebody-elses-generation");

        assert!(provider.stop(&attempt).is_err());
        assert!(provider.destroy(&attempt).is_err());
        assert!(helper.record(&environment).is_some());
        assert_eq!(
            provider.diagnostics(&attempt),
            vec![ProviderDiagnostic::OwnershipMismatch]
        );
    }

    #[test]
    fn unsupported_inspect_is_not_accepted_as_resource_absence() {
        let root = tempfile::tempdir().unwrap();
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        let attempt = isolated_attempt(&policy, 42, root.path());
        provider.prepare(&attempt, &policy).unwrap();

        helper.set_inspect_failure(HelperFailure::Rejected);

        assert!(provider.inspect(&attempt).is_err());
        assert!(provider.destroy(&attempt).is_err());
    }

    #[test]
    fn stop_destroy_and_enumeration_are_idempotent_and_owned() {
        let root = tempfile::tempdir().unwrap();
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        let attempt = isolated_attempt(&policy, 51, root.path());
        let prepared = provider.prepare(&attempt, &policy).unwrap();
        let config = EncodedJitConfig::new("jit");
        let identity = provider
            .start(prepared, &attempt, OneTimeJitHandoff::new(&config))
            .unwrap();
        assert_eq!(provider.enumerate_owned(policy.host_id), vec![identity]);
        assert_eq!(provider.stop(&attempt).unwrap(), ProviderStop::Stopped);
        assert_eq!(provider.stop(&attempt).unwrap(), ProviderStop::Stopped);
        assert_eq!(
            provider.destroy(&attempt).unwrap(),
            ProviderDestroy::Destroyed
        );
        assert_eq!(
            provider.destroy(&attempt).unwrap(),
            ProviderDestroy::Destroyed
        );
        assert!(provider.enumerate_owned(policy.host_id).is_empty());
    }

    #[test]
    fn linux_guest_can_never_be_enumerated_as_native_macos_isolation() {
        let helper = FakeHelper::ready();
        let policy = isolated_policy();
        let provider = provider(policy.host_id, Arc::clone(&helper));
        let environment = "rm-linux-impostor";
        let mut record = resource(ResourceFixture {
            environment,
            host: &policy.host_id.to_string(),
            attempt: &AttemptId::from_u128(61).to_string(),
            generation: "generation-61",
            image: TEST_IMAGE,
            template_digest: TEMPLATE_DIGEST,
            cpu_millis: 2_000,
            memory_mib: 4_096,
            disk_mib: 32_768,
            process_limit: PROCESS_LIMIT,
            state: "running",
            runner_exit_code: None,
        });
        record["guest_os"] = json!("linux");
        helper
            .records
            .lock()
            .unwrap()
            .insert(environment.into(), record);
        assert!(provider.enumerate_owned(policy.host_id).is_empty());
    }
}
