//! Contract checks for the manual, privileged d2 native acceptance harness.
//! The script itself is never executed by CI: doing so would alter the host.

use std::fs;
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;

fn repository_file(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::read_to_string(root.join(path)).expect("acceptance asset is readable")
}

#[test]
#[cfg(windows)]
fn container_evidence_contract_executes_under_windows_powershell() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "tests/windows-hyperv-acceptance-contract.ps1",
        ])
        .current_dir(&root)
        .output()
        .expect("Windows PowerShell runs the Hyper-V acceptance contract");
    assert!(
        output.status.success(),
        "Hyper-V acceptance PowerShell contract failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn windows_hyperv_harness_keeps_each_system_effect_explicit_and_reversible() {
    let script = repository_file("scripts/windows-hyperv-acceptance.ps1");
    for phase in [
        "audit",
        "prepare-before-reboot",
        "verify-after-reboot",
        "run-job",
        "recovery-forensics",
        "cleanup",
        "rollback",
    ] {
        assert!(script.contains(phase), "missing phase {phase}");
    }
    for guard in [
        "AllowEnableContainers",
        "AllowSwitchDockerToWindows",
        "AllowPullImage",
        "AllowAdoptMachineCredential",
        "AllowReplaceService",
        "AllowServiceRestart",
        "AllowCreatePolicy",
        "AllowCleanup",
        "AllowRollbackChanges",
    ] {
        assert!(script.contains(guard), "missing opt-in guard {guard}");
    }
    assert!(script.contains("Assert-Elevated"));
    assert!(
        script.contains(
            "Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart"
        )
    );
    assert!(script.contains("Install-WindowsFeature -Name Containers -Restart:$false"));
    assert!(
        !script.contains("Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V")
    );
    assert!(!script.contains("Restart-Computer"));
    assert!(!script.contains("shutdown.exe"));
    assert!(script.contains("-SwitchWindowsEngine"));
    assert!(script.contains("-SwitchLinuxEngine"));
    assert!(script.contains("'prior-service'"));
    assert!(script.contains("'service-prior.toml'"));
    assert!(script.contains("'runner-manager-supervisor.exe'"));
    assert!(script.contains("prior service source backup hash does not match"));
    assert!(script.contains("Find-DefaultServiceRecord"));
    assert!(script.contains("restore_with_default_paths"));
    assert!(script.contains("Get-TomlString $text 'binary'"));
    assert!(script.contains("Get-TomlString $text 'source_binary'"));
    assert!(script.contains("$current.path_name -eq $State.runner_service.path_name"));
    assert!(
        script.contains("$current.executable_sha256 -eq $State.runner_service.executable_sha256")
    );
    assert!(script.contains("Find-AcceptanceRun $selector $dispatchAt"));
    assert!(script.contains("Remove-AcceptanceTrigger $State"));
    assert!(script.contains("'pr', 'edit', [string]$PullRequestNumber"));
    assert!(script.contains("'label', 'delete', $label"));
}

#[test]
fn machine_credential_adoption_is_explicit_bounded_and_reversible() {
    let script = repository_file("scripts/windows-hyperv-acceptance.ps1");
    for needle in [
        "Require-OptIn $AllowAdoptMachineCredential",
        "IvanMurzak/runner-manager/secrets/user-access-token.dpapi",
        "secrets/machine/user-access-token.dpapi",
        "Assert-ProductMachineCredentialAcl $paths.source",
        "Find-AuditedLegacyDefaultBootRecord $State",
        "AreAccessRulesProtected",
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-3-4",
        "[IO.FileMode]::CreateNew",
        "Protect-AdoptedCredential $paths.target",
        "Assert-IsolatedCredentialPathIsPhysical",
        "adopted encrypted credential hash does not match",
        "Remove-AdoptedMachineCredential $State",
    ] {
        assert!(
            script.contains(needle),
            "missing credential adoption contract: {needle}"
        );
    }
    assert!(
        script
            .matches("Remove-AdoptedMachineCredential $State")
            .count()
            >= 2,
        "both cleanup and rollback must remove the adopted credential"
    );
    assert!(script.contains("source_path = $paths.source"));
    assert!(script.contains("target_path = $paths.target"));
    assert!(script.contains("sha256 = $hash"));
    assert!(script.contains(
        "provenance = 'audited product-standard LocalSystem boot service on this machine'"
    ));
    assert!(!script.contains("ConvertTo-SecureString"));
    assert!(!script.contains("CryptUnprotectData"));
}

#[test]
fn legacy_default_boot_credential_migration_is_bound_to_the_audited_scm_record() {
    let script = repository_file("scripts/windows-hyperv-acceptance.ps1");
    for needle in [
        "$current.path_name, [string]$audited.path_name",
        "$current.executable_sha256 -ne $audited.executable_sha256",
        "$audited.account -notin @('LocalSystem', 'NT AUTHORITY\\SYSTEM')",
        "$audited.start_mode -ne 'Auto'",
        "$record.manager -ne 'the Windows Service Control Manager'",
        "$record.account -ne 'local_system'",
        "Join-Path $env:LOCALAPPDATA 'IvanMurzak/runner-manager'",
        "Join-Path $state 'bin/runner-manager.exe'",
        "--service-config-dir",
        "--service-state-dir",
        "--service-runtime-dir",
        "--service-logs-dir",
        "--windows-service-host",
        "Backup-ServiceRecord $State",
    ] {
        assert!(
            script.contains(needle),
            "legacy migration must remain bound to exact product evidence: {needle}"
        );
    }
    assert!(script.contains("[StringComparison]::OrdinalIgnoreCase"));
    assert!(script.contains("the live SCM registration does not exactly match"));
}

#[test]
fn external_output_is_joined_only_after_each_invocation_returns() {
    let script = repository_file("scripts/windows-hyperv-acceptance.ps1");
    for safe_call in [
        "$gitCommit = ((Invoke-External git.exe @('-C', $RepoRoot, 'rev-parse', 'HEAD')) -join '').Trim()",
        "$pr = ($prRaw -join \"`n\") | ConvertFrom-Json",
    ] {
        assert!(
            script.contains(safe_call),
            "external command output must be grouped before PowerShell binds -join: {safe_call}"
        );
    }

    let broken_call = "$gitCommit = (Invoke-External git.exe @('-C', $RepoRoot, 'rev-parse', 'HEAD') -join '').Trim()";
    assert!(
        !script.contains(broken_call),
        "PowerShell would bind -join as an Invoke-External parameter: {broken_call}"
    );
}

#[test]
fn windows_powershell_native_failures_and_run_json_are_normalized_before_matching() {
    let script = repository_file("scripts/windows-hyperv-acceptance.ps1");
    for needle in [
        "$priorErrorActionPreference = $ErrorActionPreference",
        "$ErrorActionPreference = 'Continue'",
        "$output = @(& $FilePath @ArgumentList 2>&1)",
        "$ErrorActionPreference = $priorErrorActionPreference",
        "ConvertFrom-Json -InputObject $payload",
        "foreach ($run in [object[]]$document)",
        "ConvertTo-ScalarString $run.workflowName",
        "ConvertTo-ScalarString $run.displayTitle",
        "ConvertTo-ScalarString $run.createdAt",
        "[Globalization.DateTimeStyles]::RoundtripKind",
        "[StringComparison]::Ordinal",
    ] {
        assert!(
            script.contains(needle),
            "missing WinPS normalization: {needle}"
        );
    }
}

#[test]
fn service_replacement_is_bounded_diagnostic_and_rollback_safe() {
    let script = repository_file("scripts/windows-hyperv-acceptance.ps1");
    for needle in [
        "function Stop-AuditedServiceForReplacement",
        "the service changed after credential adoption",
        "Set-StateProperty $State service_replacement_started $true",
        "$controller.Stop()",
        "AddSeconds(90)",
        "$stuck.process_id -ne $current.process_id",
        "$stuck.path_name -cne $audited.path_name",
        "Require-OptIn $AllowServiceRestart",
        "service-replacement-preflight.json",
        "-EvidencePath (Join-Path $evidence 'service-install.txt')",
        "redacted output was saved",
        "<redacted-github-token>",
        "$State.PSObject.Properties.Name -contains 'service_replacement_started'",
        "Set-StateProperty $State service_replacement_started $false",
    ] {
        assert!(
            script.contains(needle),
            "missing bounded replacement contract: {needle}"
        );
    }

    let transaction = script
        .find("Set-StateProperty $State service_replacement_started $true")
        .expect("replacement transaction is recorded");
    let stop = script
        .find("$controller.Stop()")
        .expect("audited service is stopped");
    let install = script
        .find("Invoke-Runner @('service', 'install', '--start-at', 'boot')")
        .expect("replacement install exists");
    assert!(
        transaction < stop && stop < install,
        "rollback state must be durable before stop, and stop must finish before install"
    );
    assert!(
        script
            .contains("Invoke-Runner @('service', 'install', '--start-at', 'boot') -EvidencePath")
    );
}

#[test]
fn harness_and_workflow_pin_the_production_provider_security_contract() {
    let script = repository_file("scripts/windows-hyperv-acceptance.ps1");
    let workflow = repository_file(".github/workflows/windows-hyperv-native-acceptance.yml");
    let digest = "mcr.microsoft.com/windows/servercore@sha256:22505496dd4229dba63453ba0c6dc31c06fd3e11810e5b8e429aa6b16dab2457";
    assert!(script.contains(digest));
    for needle in [
        "windows-hyper-v-container",
        "HostConfig.Isolation",
        "HostConfig.Binds",
        "HostConfig.Devices",
        "HostConfig.Privileged",
        "ACTIONS_RUNNER_INPUT_JITCONFIG",
        "gh.exe auth token",
        "Stop-Process -Id $before.process_id -Force",
        "provider-owned orphan remained",
        "function Resolve-AcceptanceProfileSelector",
        "profile-status.json",
        "status did not expose exactly one immutable selector",
        "Set-StateProperty $State profile_selector $value",
        "--host-label', 'd2'",
        "'status,conclusion,url'",
        "completed with conclusion '$conclusion' before a provider container appeared",
        "Wait-ProviderContainer $evidence $JobTimeoutSeconds ([string]$run.databaseId)",
    ] {
        assert!(script.contains(needle), "missing evidence check {needle}");
    }
    for needle in [
        "pull_request:",
        "types: [labeled]",
        "github.event.pull_request.number == 77",
        "github.event.pull_request.head.repo.full_name == github.repository",
        "startsWith(github.event.label.name, 'rm-d2-win-x64-d2-')",
        "runs-on: [self-hosted, windows, x64",
        "ACCEPTANCE_SELECTOR: ${{ github.event.label.name }}",
        "^rm-d2-win-x64-(d2-([0-9]{14}-[0-9a-f]{8}))$",
        "QueryInformationJobObject",
        "ActiveProcessLimit -ne 256",
        "0x2000",
        "ACTIONS_RUNNER_INPUT_JITCONFIG",
    ] {
        assert!(workflow.contains(needle), "missing workflow check {needle}");
    }
}

#[test]
fn cancellation_keeps_trigger_and_profile_cleanup_reachable() {
    let script = repository_file("scripts/windows-hyperv-acceptance.ps1");
    let run_job = script
        .split_once("function Invoke-RunJob")
        .expect("run-job function exists")
        .1
        .split_once("function Assert-NoSecrets")
        .expect("run-job function has a bounded body")
        .0;
    let created = run_job
        .find("Set-StateProperty $State trigger_label_created $true")
        .expect("trigger creation is durable");
    let found = run_job
        .find("$run = Find-AcceptanceRun $selector $dispatchAt")
        .expect("the exact-selector run is found");
    let removed = run_job
        .find("Remove-AcceptanceTrigger $State")
        .expect("the trigger is removed before waiting for a container");
    let watched = run_job
        .find("Wait-ProviderContainer $evidence $JobTimeoutSeconds")
        .expect("the run is watched while waiting");
    assert!(created < found && found < removed && removed < watched);
    assert!(script.contains("if ($State.profile_created)"));
    assert!(script.contains("'repo', 'profile', 'remove'"));
    assert!(script.contains("Remove-AcceptanceTrigger $State"));
}

#[test]
fn cleanup_retries_profile_removal_with_redacted_actionable_evidence() {
    let script = repository_file("scripts/windows-hyperv-acceptance.ps1");
    let cleanup = script
        .split_once("function Remove-AcceptanceProfile")
        .expect("bounded profile cleanup helper exists")
        .1
        .split_once("function Assert-ContainerEvidence")
        .expect("profile cleanup helper has a bounded body")
        .0;

    for needle in [
        "AddSeconds(120)",
        "profile-remove-$runStamp-{0:d2}.txt",
        "profile-remove-$runStamp-verify-{0:d2}.txt",
        "-AllowFailure -EvidencePath $removeEvidence",
        "-AllowFailure -EvidencePath $showEvidence",
        "Start-Sleep -Seconds 2",
        "could not be removed within 120 seconds",
        "last redacted command output",
        "active-attempt or local-store error",
    ] {
        assert!(
            cleanup.contains(needle),
            "missing cleanup contract: {needle}"
        );
    }
    assert!(script.contains("Remove-AcceptanceProfile $State"));
}
