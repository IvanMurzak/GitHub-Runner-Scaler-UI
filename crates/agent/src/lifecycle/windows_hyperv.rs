//! Hyper-V-isolated Windows container execution.
//!
//! Docker is used as the Windows container control plane, but no Docker socket,
//! host directory, device, or credential is exposed to the container.  The
//! verified runner package is copied into a fresh writable layer and the JIT
//! value crosses the boundary once over the attached container stdin.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

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
#[cfg(all(test, windows))]
const BOOTSTRAP_SELF_TEST_INPUT: &str = "runner-manager-windows-job-self-test-v1";
const BOOTSTRAP_REQUEST_PROTOCOL: &str = "runner-manager-windows-job-request-v1";
const BOOTSTRAP_ATTESTATION_PROTOCOL: &str = "runner-manager-windows-job-ready-v1";
const WINDOWS_PROCESS_LIMIT: u32 = 256;
const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
const JOB_LIMIT_FLAGS: u32 = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
const BOOTSTRAP_ATTESTATION_TIMEOUT: Duration = Duration::from_secs(60);
const PREFLIGHT_EXIT_TIMEOUT: Duration = Duration::from_secs(60);

// This script is immutable Docker container metadata. It creates a nested Job
// Object inside the Windows container, installs and queries the active-process
// limit, and only then acknowledges the host. Runner.Listener is created
// suspended, assigned to the job, checked for membership, and resumed. Neither
// breakaway flag is set, so ordinary descendants inherit the nested job.
const BOOTSTRAP: &str = r#"
$ErrorActionPreference='Stop'
$source=@'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public sealed class RunnerManagerJobGuard : IDisposable {
    const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint INFINITE = 0xffffffff;
    const int JobObjectExtendedLimitInformation = 9;
    IntPtr job;

    [StructLayout(LayoutKind.Sequential)]
    struct BasicLimitInformation {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IoCounters {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ExtendedLimitInformation {
        public BasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct StartupInfo {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInformation {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length, IntPtr returnedLength);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool CreateProcess(string applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInfo startupInfo, out ProcessInformation processInformation);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr handle);

    static void Check(bool ok) {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public RunnerManagerJobGuard(uint activeProcessLimit) {
        job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        ExtendedLimitInformation limits = new ExtendedLimitInformation();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        limits.BasicLimitInformation.ActiveProcessLimit = activeProcessLimit;
        int size = Marshal.SizeOf(typeof(ExtendedLimitInformation));
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try {
            Marshal.StructureToPtr(limits, buffer, false);
            Check(SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size));
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public string Attest() {
        int size = Marshal.SizeOf(typeof(ExtendedLimitInformation));
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try {
            Check(QueryInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size, IntPtr.Zero));
            ExtendedLimitInformation limits = (ExtendedLimitInformation)Marshal.PtrToStructure(buffer, typeof(ExtendedLimitInformation));
            uint required = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (limits.BasicLimitInformation.LimitFlags != required) throw new InvalidOperationException("unexpected job limit flags");
            return limits.BasicLimitInformation.ActiveProcessLimit.ToString() + "|" + limits.BasicLimitInformation.LimitFlags.ToString();
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public int Run(string executable, string arguments, string jit) {
        StartupInfo startup = new StartupInfo();
        startup.cb = (uint)Marshal.SizeOf(typeof(StartupInfo));
        ProcessInformation process;
        StringBuilder command = new StringBuilder("\"" + executable + "\" " + arguments);
        string priorJit = Environment.GetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", EnvironmentVariableTarget.Process);
        bool created;
        try {
            if (jit != null) Environment.SetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", jit, EnvironmentVariableTarget.Process);
            created = CreateProcess(null, command, IntPtr.Zero, IntPtr.Zero, true, CREATE_SUSPENDED, IntPtr.Zero, null, ref startup, out process);
        } finally {
            if (jit != null) Environment.SetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", priorJit, EnvironmentVariableTarget.Process);
        }
        Check(created);
        bool assigned = false;
        try {
            Check(AssignProcessToJobObject(job, process.hProcess));
            bool inJob;
            Check(IsProcessInJob(process.hProcess, job, out inJob));
            if (!inJob) throw new InvalidOperationException("runner did not enter process-limit job");
            assigned = true;
            if (ResumeThread(process.hThread) == 0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (WaitForSingleObject(process.hProcess, INFINITE) != 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            uint exitCode;
            Check(GetExitCodeProcess(process.hProcess, out exitCode));
            return unchecked((int)exitCode);
        } finally {
            if (!assigned) TerminateProcess(process.hProcess, 73);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
    }

    public void Dispose() {
        if (job != IntPtr.Zero) {
            CloseHandle(job);
            job = IntPtr.Zero;
        }
    }
}
'@
Add-Type -TypeDefinition $source -Language CSharp
$request=[Console]::In.ReadLine()
$parts=$request.Split('|')
if ($parts.Length -ne 3 -or $parts[0] -ne 'runner-manager-windows-job-request-v1' -or $parts[1] -notmatch '^[0-9a-f]{32}$') { exit 70 }
$limit=0
if (-not [UInt32]::TryParse($parts[2],[ref]$limit) -or $limit -lt 1 -or $limit -gt 4096) { exit 70 }
$guard=[RunnerManagerJobGuard]::new($limit)
try {
    $proof=$guard.Attest()
    [Console]::Out.WriteLine('runner-manager-windows-job-ready-v1|'+$parts[1]+'|'+$proof)
    [Console]::Out.Flush()
    $payload=[Console]::In.ReadToEnd()
    if ([String]::IsNullOrWhiteSpace($payload)) { exit 70 }
    if ($payload -eq 'runner-manager-windows-job-self-test-v1') { exit $guard.Run(($env:WINDIR+'\\System32\\cmd.exe'),'/d /c exit 0',$null) }
    if ($payload -eq 'runner-manager-preflight-v1') { exit $guard.Run('C:\\runner\\bin\\Runner.Listener.exe','--version',$null) }
    try { $code=$guard.Run('C:\\runner\\bin\\Runner.Listener.exe','run',$payload) } finally { $payload=$null }
    exit $code
} finally {
    $guard.Dispose()
}
"#;

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
    limits: Mutex<BTreeMap<AttemptId, ResourceLimits>>,
    diagnostics: Mutex<BTreeMap<AttemptId, Vec<ProviderDiagnostic>>>,
}

impl WindowsHyperVContainers {
    #[must_use]
    pub fn new(host_id: HostId) -> Self {
        Self {
            host_id,
            children: Mutex::new(BTreeMap::new()),
            limits: Mutex::new(BTreeMap::new()),
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

    fn inspect_configuration(name: &str) -> Result<ContainerAttestation, CommandFailure> {
        const FORMAT: &str = "{{.HostConfig.Isolation}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.Memory}}|{{index .HostConfig.StorageOpt \"size\"}}|{{.HostConfig.NetworkMode}}|{{len .Mounts}}|{{.HostConfig.Privileged}}|{{len .HostConfig.Binds}}|{{len .HostConfig.Devices}}|{{.Config.Image}}";
        let result = Self::docker(&os_args(["inspect", "--format", FORMAT, name]))?;
        if !result.success {
            return Err(result.failure());
        }
        ContainerAttestation::parse(result.stdout.trim()).ok_or(CommandFailure::Failed)
    }

    fn configuration_is_exact(
        name: &str,
        image: &ImageReference,
        resources: ResourceLimits,
    ) -> bool {
        Self::inspect_configuration(name)
            .is_ok_and(|found| found == ContainerAttestation::expected(image, resources))
    }

    fn start_attested(name: &str) -> Result<(Child, ChildStdin), ()> {
        let mut child = Command::new("docker")
            .args([
                OsStr::new("start"),
                OsStr::new("--attach"),
                OsStr::new("--interactive"),
                OsStr::new(name),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ())?;
        let Some(mut stdin) = child.stdin.take() else {
            stop_failed_bootstrap(&mut child, name);
            return Err(());
        };
        let Some(stdout) = child.stdout.take() else {
            stop_failed_bootstrap(&mut child, name);
            return Err(());
        };
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let request = format!("{BOOTSTRAP_REQUEST_PROTOCOL}|{nonce}|{WINDOWS_PROCESS_LIMIT}\n");
        if stdin
            .write_all(request.as_bytes())
            .and_then(|()| stdin.flush())
            .is_err()
        {
            stop_failed_bootstrap(&mut child, name);
            return Err(());
        }

        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut stdout = stdout;
            let mut bytes = Vec::with_capacity(256);
            let result = loop {
                if bytes.len() == 1024 {
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bootstrap attestation exceeded limit",
                    ));
                }
                let mut byte = [0_u8; 1];
                match stdout.read(&mut byte) {
                    Ok(0) => {
                        break Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "bootstrap closed before attestation",
                        ));
                    }
                    Ok(_) if byte[0] == b'\n' => {
                        break String::from_utf8(bytes).map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "bootstrap attestation was not UTF-8",
                            )
                        });
                    }
                    Ok(_) => bytes.push(byte[0]),
                    Err(error) => break Err(error),
                }
            };
            let _ = sender.send((result, stdout));
        });

        let received = receiver.recv_timeout(BOOTSTRAP_ATTESTATION_TIMEOUT);
        let Ok((Ok(line), mut stdout)) = received else {
            stop_failed_bootstrap(&mut child, name);
            return Err(());
        };
        let Some(attestation) = JobAttestation::parse(line.trim_end_matches('\r')) else {
            stop_failed_bootstrap(&mut child, name);
            return Err(());
        };
        if attestation
            != (JobAttestation {
                nonce,
                active_process_limit: WINDOWS_PROCESS_LIMIT,
                limit_flags: JOB_LIMIT_FLAGS,
            })
        {
            stop_failed_bootstrap(&mut child, name);
            return Err(());
        }

        // Runner.Listener inherits the attached output handles. Drain them so
        // a verbose action cannot fill the pipe and stall the process tree.
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        });
        Ok((child, stdin))
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
        if !Self::configuration_is_exact(&expected.name, &expected.image, *resources) {
            let _ = Self::docker(&os_args(["rm", "--force", expected.name.as_str()]));
            self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
            return Err(failure(
                "Windows Hyper-V resource or isolation attestation failed",
            ));
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
        let preflight_ok = match Self::start_attested(&expected.name) {
            Ok((mut child, mut stdin)) => {
                let wrote = stdin
                    .write_all(PREFLIGHT_INPUT.as_bytes())
                    .and_then(|()| stdin.flush())
                    .is_ok();
                // ReadToEnd is the payload boundary.
                drop(stdin);
                let ok = wrote && wait_until_exit(&mut child, PREFLIGHT_EXIT_TIMEOUT);
                if !ok {
                    stop_failed_bootstrap(&mut child, &expected.name);
                }
                ok
            }
            Err(()) => false,
        };
        let preflight_record = Self::inspect_record(&expected.name).ok().flatten();
        if !preflight_ok
            || !preflight_record.is_some_and(|record| {
                record.same_owner(&expected)
                    && record.state == "exited"
                    && record.exit_code == Some(0)
            })
        {
            let _ = Self::docker(&os_args(["rm", "--force", expected.name.as_str()]));
            self.note(attempt.id, ProviderDiagnostic::PrepareFailed);
            return Err(failure(
                "Windows Hyper-V image bootstrap compatibility check failed",
            ));
        }

        let identity = self
            .identity_for(attempt, expected.name)
            .ok_or_else(|| failure("Windows Hyper-V identity is invalid"))?;
        self.limits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(attempt.id, *resources);
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
        let Some(resources) = self
            .limits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&attempt.id)
            .copied()
        else {
            self.note(attempt.id, ProviderDiagnostic::StartFailed);
            return Err(ProcessStartFailure::before_spawn(failure(
                "Windows Hyper-V resource attestation is unavailable",
            )));
        };
        if !Self::configuration_is_exact(&expected.name, &expected.image, resources) {
            self.note(attempt.id, ProviderDiagnostic::StartFailed);
            return Err(ProcessStartFailure::before_spawn(failure(
                "Windows Hyper-V resource or isolation attestation failed",
            )));
        }
        // The script is constant container metadata. The JIT value is never an
        // argument, Docker environment setting, label, file, or layer; it is
        // sent only after the nonce-bound Job Object attestation proves the
        // active-process limit and kill-on-close flag. Runner.Listener is then
        // created suspended, assigned, membership-checked, and resumed.
        let (mut child, mut stdin) = Self::start_attested(&expected.name).map_err(|()| {
            self.note(attempt.id, ProviderDiagnostic::StartFailed);
            ProcessStartFailure::after_spawn_stopped()
        })?;
        let write_result = stdin
            .write_all(handoff.consume().expose().as_bytes())
            .and_then(|()| stdin.flush());
        drop(stdin);
        if write_result.is_err() {
            stop_failed_bootstrap(&mut child, &expected.name);
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
                self.limits
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&attempt.id);
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
            self.limits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&attempt.id);
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
        let provider = fields.next()?;
        (provider == PROVIDER_VALUE && fields.next().is_none()).then_some(Self {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContainerAttestation {
    isolation: String,
    nano_cpus: u64,
    memory_bytes: u64,
    storage_size: String,
    network_mode: String,
    mounts: u32,
    privileged: bool,
    binds: u32,
    devices: u32,
    image: ImageReference,
}

impl ContainerAttestation {
    fn expected(image: &ImageReference, resources: ResourceLimits) -> Self {
        Self {
            isolation: "hyperv".into(),
            nano_cpus: u64::from(resources.cpu_millis) * 1_000_000,
            memory_bytes: u64::from(resources.memory_mib) * 1024 * 1024,
            storage_size: format!("{}m", resources.disk_mib),
            network_mode: "nat".into(),
            mounts: 0,
            privileged: false,
            binds: 0,
            devices: 0,
            image: image.clone(),
        }
    }

    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split('|');
        let parsed = Self {
            isolation: fields.next()?.to_owned(),
            nano_cpus: fields.next()?.parse().ok()?,
            memory_bytes: fields.next()?.parse().ok()?,
            storage_size: fields.next()?.to_owned(),
            network_mode: fields.next()?.to_owned(),
            mounts: fields.next()?.parse().ok()?,
            privileged: fields.next()?.parse().ok()?,
            binds: fields.next()?.parse().ok()?,
            devices: fields.next()?.parse().ok()?,
            image: ImageReference::new(fields.next()?).ok()?,
        };
        fields.next().is_none().then_some(parsed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JobAttestation {
    nonce: String,
    active_process_limit: u32,
    limit_flags: u32,
}

impl JobAttestation {
    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split('|');
        if fields.next()? != BOOTSTRAP_ATTESTATION_PROTOCOL {
            return None;
        }
        let nonce = fields.next()?;
        if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let parsed = Self {
            nonce: nonce.to_owned(),
            active_process_limit: fields.next()?.parse().ok()?,
            limit_flags: fields.next()?.parse().ok()?,
        };
        fields.next().is_none().then_some(parsed)
    }
}

fn stop_failed_bootstrap(child: &mut Child, name: &str) {
    let _ = child.kill();
    let _ = WindowsHyperVContainers::docker(&os_args(["stop", "--time", "0", name]));
    let _ = child.wait();
}

fn wait_until_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            _ => return false,
        }
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

#[cfg(any(not(test), windows))]
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
    // Process count is installed inside the container by the pinned bootstrap
    // and proved again before JIT. Native client and Server acceptance remains
    // a separate preview gate; the static host prerequisites are ready here.
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

#[cfg(any(not(test), windows))]
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
    #[cfg(windows)]
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
                Some(output("windows\n")),
            ),
            WindowsHyperVHostState::Ready
        );
        assert_eq!(
            host_probe(output("edition=Core\nhyperv=1\ncontainers=1\n"), None,),
            WindowsHyperVHostState::UnsupportedHost
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=0\ncontainers=1\n"),
                None,
            ),
            WindowsHyperVHostState::HyperVUnavailable
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=0\n"),
                None,
            ),
            WindowsHyperVHostState::ContainersUnavailable
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=1\n"),
                Some(Err(CommandFailure::NotFound)),
            ),
            WindowsHyperVHostState::RuntimeNotInstalled
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=1\n"),
                Some(output("linux\n")),
            ),
            WindowsHyperVHostState::RuntimeInLinuxMode
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=1\n"),
                Some(Err(CommandFailure::PermissionDenied)),
            ),
            WindowsHyperVHostState::RuntimePermissionDenied
        );
        assert_eq!(
            host_probe(
                output("edition=Professional\nhyperv=1\ncontainers=1\n"),
                Some(Err(CommandFailure::Failed)),
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
        assert!(BOOTSTRAP.contains("CREATE_SUSPENDED"));
        assert!(BOOTSTRAP.contains("AssignProcessToJobObject"));
        assert!(BOOTSTRAP.contains("IsProcessInJob"));
        assert!(BOOTSTRAP.contains("JOB_OBJECT_LIMIT_ACTIVE_PROCESS"));
        assert!(BOOTSTRAP.contains("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE"));
        assert!(!BOOTSTRAP.contains("JOB_OBJECT_LIMIT_BREAKAWAY_OK"));
        assert!(!BOOTSTRAP.contains("JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK"));
        assert!(BOOTSTRAP.contains(PREFLIGHT_INPUT));
        assert!(!BOOTSTRAP.contains("$env:ACTIONS_RUNNER_INPUT_JITCONFIG"));
        assert!(!BOOTSTRAP.contains("fixture-jit-value"));
    }

    #[test]
    fn job_attestation_is_typed_nonce_bound_and_exact() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let line = format!(
            "{BOOTSTRAP_ATTESTATION_PROTOCOL}|{nonce}|{WINDOWS_PROCESS_LIMIT}|{JOB_LIMIT_FLAGS}"
        );
        assert_eq!(
            JobAttestation::parse(&line),
            Some(JobAttestation {
                nonce: nonce.into(),
                active_process_limit: WINDOWS_PROCESS_LIMIT,
                limit_flags: JOB_LIMIT_FLAGS,
            })
        );
        for rejected in [
            line.replace(BOOTSTRAP_ATTESTATION_PROTOCOL, "untyped"),
            line.replace(nonce, "short"),
            line.replace(&WINDOWS_PROCESS_LIMIT.to_string(), "255"),
            format!("{line}|extra"),
        ] {
            let parsed = JobAttestation::parse(&rejected);
            assert!(
                parsed
                    != Some(JobAttestation {
                        nonce: nonce.into(),
                        active_process_limit: WINDOWS_PROCESS_LIMIT,
                        limit_flags: JOB_LIMIT_FLAGS,
                    }),
                "{rejected}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn powershell_bootstrap_installs_queries_and_uses_the_nested_job() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let compile_temp = tempfile::tempdir().expect("writable Add-Type directory");
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                BOOTSTRAP,
            ])
            .env("TEMP", compile_temp.path())
            .env("TMP", compile_temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("PowerShell bootstrap starts");
        let mut stdin = child.stdin.take().expect("bootstrap stdin");
        write!(
            stdin,
            "{BOOTSTRAP_REQUEST_PROTOCOL}|{nonce}|{WINDOWS_PROCESS_LIMIT}\n{BOOTSTRAP_SELF_TEST_INPUT}"
        )
        .expect("bootstrap protocol write");
        drop(stdin);
        let success = wait_until_exit(&mut child, BOOTSTRAP_ATTESTATION_TIMEOUT);
        if !success {
            let _ = child.kill();
        }
        let mut stdout = String::new();
        child
            .stdout
            .take()
            .expect("bootstrap stdout")
            .read_to_string(&mut stdout)
            .expect("bootstrap stdout is readable");
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .expect("bootstrap stderr")
            .read_to_string(&mut stderr)
            .expect("bootstrap stderr is readable");
        assert!(success, "bootstrap failed: {stderr}");
        assert_eq!(
            stdout.trim(),
            format!(
                "{BOOTSTRAP_ATTESTATION_PROTOCOL}|{nonce}|{WINDOWS_PROCESS_LIMIT}|{JOB_LIMIT_FLAGS}"
            )
        );
    }

    #[test]
    fn container_attestation_requires_exact_limits_and_no_host_surface() {
        let image =
            ImageReference::new(format!("registry.example/runner@sha256:{}", "a".repeat(64)))
                .unwrap();
        let resources = ResourceLimits {
            cpu_millis: 2500,
            memory_mib: 3072,
            disk_mib: 8192,
        };
        let line = format!(
            "hyperv|2500000000|3221225472|8192m|nat|0|false|0|0|{}",
            image.as_str()
        );
        assert_eq!(
            ContainerAttestation::parse(&line),
            Some(ContainerAttestation::expected(&image, resources))
        );
        for rejected in [
            line.replacen("hyperv", "process", 1),
            line.replacen("2500000000", "2000000000", 1),
            line.replacen("3221225472", "2147483648", 1),
            line.replacen("8192m", "4096m", 1),
            line.replacen("|0|false|0|0|", "|1|false|0|0|", 1),
            line.replacen("|0|false|0|0|", "|0|true|0|0|", 1),
            format!("{line}|extra"),
        ] {
            assert_ne!(
                ContainerAttestation::parse(&rejected),
                Some(ContainerAttestation::expected(&image, resources)),
                "{rejected}"
            );
        }
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
        assert!(!args.iter().any(|arg| arg == "--pids-limit"));
        for forbidden in ["--volume", "--mount", "--device", "--privileged"] {
            assert!(!args.iter().any(|arg| arg == forbidden), "{args:?}");
        }
        assert!(!args.iter().any(|arg| arg.contains("docker.sock")));
    }
}
