#!/usr/bin/env bash
# Repository-owned bridge between disruptive native-host commands and the
# acceptance validator. It never invents evidence: prepare refuses an absent or
# incomplete controller journal, and finalize refuses a missing OS report.
set -euo pipefail

die() { printf 'e2e-host-controller: %s\n' "$*" >&2; exit 1; }

case "${1-}" in
  operation)
    [[ "${RUNNER_MANAGER_E2E_PHYSICAL_HOST:-}" == true ]] || die "native operations require RUNNER_MANAGER_E2E_PHYSICAL_HOST=true"
    operation="${2-}"
    shift 2
    case "$operation" in
      dispatch-job)
        [[ $# -eq 4 ]] || die "dispatch-job REPOSITORY WORKFLOW LABEL SCENARIO"
        gh workflow run "$2" --repo "$1" --field "routing_label=$3" --field "scenario=$4"
        ;;
      observe-run)
        [[ $# -eq 2 ]] || die "observe-run REPOSITORY RUN_ID"
        gh run view "$2" --repo "$1" --json databaseId,status,conclusion,jobs
        ;;
      drain)
        [[ $# -eq 2 ]] || die "drain DATA_DIR OWNER/REPO"
        runner-manager --data-dir "$1" repo set-scale "$2" --enabled false
        ;;
      monitor-status)
        [[ $# -eq 1 ]] || die "monitor-status DATA_DIR"
        runner-manager --data-dir "$1" status --json
        ;;
      add-monitor-only)
        [[ $# -eq 3 ]] || die "add-monitor-only DATA_DIR OWNER/REPO HOST_LABEL"
        runner-manager --data-dir "$1" repo add "$2" --host-label "$3"
        ;;
      daemon-start)
        [[ $# -eq 2 ]] || die "daemon-start DATA_DIR LOG_FILE"
        runner-manager --data-dir "$1" daemon run >"$2" 2>&1 &
        printf '%s\n' "$!"
        ;;
      service-status)
        [[ $# -eq 1 ]] || die "service-status DATA_DIR"
        runner-manager --data-dir "$1" service status
        ;;
      outage-start)
        [[ $# -eq 1 ]] || die "outage-start windows|macos|linux"
        case "$1" in
          windows) powershell.exe -NoProfile -NonInteractive -Command '$ips=(Resolve-DnsName api.github.com -Type A).IPAddress; New-NetFirewallRule -DisplayName RunnerManagerE2EOutage -Direction Outbound -RemoteAddress $ips -Action Block | Out-Null' ;;
          linux) sudo iptables -I OUTPUT 1 -d api.github.com -j REJECT -m comment --comment RunnerManagerE2EOutage ;;
          macos) printf 'block drop out quick to api.github.com\n' | sudo pfctl -a runner-manager-e2e -f -; sudo pfctl -E >/dev/null ;;
          *) die "unknown OS" ;;
        esac
        ;;
      outage-stop)
        [[ $# -eq 1 ]] || die "outage-stop windows|macos|linux"
        case "$1" in
          windows) powershell.exe -NoProfile -NonInteractive -Command 'Remove-NetFirewallRule -DisplayName RunnerManagerE2EOutage' ;;
          linux) sudo iptables -D OUTPUT -d api.github.com -j REJECT -m comment --comment RunnerManagerE2EOutage ;;
          macos) sudo pfctl -a runner-manager-e2e -F rules ;;
          *) die "unknown OS" ;;
        esac
        ;;
      await-jit-expiry)
        [[ $# -eq 0 ]] || die "await-jit-expiry takes no arguments"
        # GitHub JIT configuration expires after one hour. This intentionally
        # uses real time: shortening it would stop being an expiry acceptance.
        sleep 3700
        ;;
      boot-id)
        [[ $# -eq 1 ]] || die "boot-id windows|macos|linux"
        case "$1" in
          windows) powershell.exe -NoProfile -NonInteractive -Command '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToFileTimeUtc()' ;;
          linux) cat /proc/sys/kernel/random/boot_id ;;
          macos) sysctl -n kern.boottime ;;
          *) die "unknown OS" ;;
        esac
        ;;
      reboot)
        [[ "${RUNNER_MANAGER_E2E_CONFIRM_REBOOT:-}" == "${RUNNER_MANAGER_E2E_CHALLENGE:-unset}" ]] || die "reboot requires RUNNER_MANAGER_E2E_CONFIRM_REBOOT equal to this run's challenge"
        case "${1-}" in
          windows) shutdown.exe /r /t 5 /f ;;
          linux|macos) sudo shutdown -r +1 ;;
          *) die "reboot windows|macos|linux" ;;
        esac
        ;;
      process-command-line)
        [[ $# -eq 2 ]] || die "process-command-line windows|macos|linux PID"
        case "$1" in
          windows) powershell.exe -NoProfile -NonInteractive -Command "(Get-CimInstance Win32_Process -Filter 'ProcessId = $2').CommandLine" ;;
          linux) tr '\0' ' ' < "/proc/$2/cmdline" ;;
          macos) ps -ww -p "$2" -o command= ;;
          *) die "unknown OS" ;;
        esac
        ;;
      capture-shipping-processes)
        [[ $# -eq 3 ]] || die "capture-shipping-processes MANAGER_PID LISTENER_PID EVIDENCE_DIR"
        [[ "$1" =~ ^[1-9][0-9]*$ && "$2" =~ ^[1-9][0-9]*$ && "$1" != "$2" ]] || die "two distinct live PIDs are required"
        mkdir -p "$3/security"
        printf '{"manager_pid":%s,"listener_pid":%s}\n' "$1" "$2" > "$3/security/process-inspection.json"
        ;;
      restore-label)
        [[ $# -eq 3 ]] || die "restore-label REPOSITORY RUNNER_ID LABEL"
        gh api --silent --method POST "repos/$1/actions/runners/$2/labels" --input - <<JSON
{"labels":["$3"]}
JSON
        printf '{"label_restored":true,"runner_id":%s}\n' "$2"
        ;;
      legacy-service-enable)
        [[ $# -eq 2 ]] || die "legacy-service-enable windows|macos|linux SERVICE_ID"
        case "$1" in
          windows) powershell.exe -NoProfile -NonInteractive -Command "Start-Service -Name '$2'; if ((Get-Service -Name '$2').Status -ne 'Running') { exit 1 }" ;;
          linux) sudo systemctl start "$2"; systemctl is-active --quiet "$2" ;;
          macos) launchctl kickstart -k "system/$2" ;;
          *) die "unknown OS" ;;
        esac
        printf '{"legacy_enabled":true,"service":"%s"}\n' "$2"
        ;;
      remove-runner)
        [[ $# -eq 2 ]] || die "remove-runner REPOSITORY RUNNER_ID"
        gh api --method DELETE "repos/$1/actions/runners/$2"
        ;;
      runner-inventory)
        [[ $# -eq 2 ]] || die "runner-inventory repos|orgs TARGET"
        gh api "$1/$2/actions/runners?per_page=100"
        ;;
      *) die "unknown native operation: $operation" ;;
    esac
    ;;
  live-suite)
    destination="${2-}"
    os_name="${3-}"
    [[ -n "$destination" && -n "$os_name" ]] || die "live-suite needs a fresh DESTINATION and OS"
    [[ ! -e "$destination" ]] || die "refusing imported or pre-existing evidence: $destination"
    mkdir -p "$destination"
    if [[ "${RUNNER_MANAGER_E2E_PHYSICAL_HOST:-}" != true ]]; then
      printf '{"status":"required_manual","os":"%s","reason":"network isolation, reboot, and two-host contention require a provisioned physical host"}\n' "$os_name" > "$destination/manual-required.json"
      die "REQUIRED MANUAL GATE: this runner is not a provisioned physical acceptance host"
    fi
    # A reboot acceptance must be driven from a distinct controller host: a
    # process running on the managed host cannot reboot itself and then claim
    # it observed service recovery. The repository currently has no fixture
    # workflow or remote-host topology contract. Refuse rather than accepting
    # externally authored facts or turning an arbitrary command into a signing
    # oracle. The operation verbs above are the executable physical primitives;
    # this gate becomes runnable only when that topology is repository-defined.
    printf '{"status":"required_manual","os":"%s","reason":"repository fixture workflow and external reboot/two-host controller topology are not configured"}\n' "$os_name" > "$destination/manual-required.json"
    die "REQUIRED MANUAL GATE: repository-defined external host topology is absent"
    ;;
  finalize)
    report="${2-}"
    destination="${3-}"
    [[ -s "$report" ]] || die "acceptance report was not produced: ${report:-<unset>}"
    mkdir -p "$destination"
    cp "$report" "$destination"/
    ;;
  *)
    die "usage: bash tests/host-controller.sh operation NAME ... | live-suite DESTINATION OS | finalize REPORT DESTINATION"
    ;;
esac
