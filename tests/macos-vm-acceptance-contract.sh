#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
harness="$root/scripts/macos-vm-acceptance.sh"
workflow="$root/.github/workflows/macos-vm-native-acceptance.yml"

bash -n "$harness"
test -f "$workflow"

for required in \
  'audit|run-job|prepare-before-reboot|verify-after-reboot|recovery-forensics|cleanup|rollback' \
  '--allow-service-install' '--allow-profile' '--allow-service-restart' \
  '--allow-cleanup' '--allow-rollback' 'this harness never initiates a reboot' \
  'virtualization_framework' 'fresh_writable_disk' 'shared_host_paths' \
  'applied_process_limit' 'normal_writable_disk_id' 'prepared_boot_epoch' \
  'normal_environment_id' 'reboot_environment_id' 'receipt does not own it' \
  'this reviewed one-time acceptance workflow is pinned to PR 79' \
  'gh label create' 'gh pr edit' 'remove_trigger_label' \
  'helper_sha256' 'local HEAD' 'cancel_recorded_runs' \
  'scan_service_process_no_secrets' 'ps eww -p' \
  'gh[pousr]_' 'runner service install --start-at boot' \
  'kill -9' 'runner status --json' 'helper_command destroy'; do
  grep -F -- "$required" "$harness" >/dev/null || { echo "missing harness contract: $required" >&2; exit 1; }
done

for forbidden in 'sudo reboot' 'shutdown -r' 'launchctl reboot' 'softwareupdate --install' \
  'VZMacOSRestoreImage' 'mapfile ' '-maxdepth' '-mindepth'; do
  if grep -F -- "$forbidden" "$harness" >/dev/null; then
    echo "harness contains forbidden host/image mutation: $forbidden" >&2
    exit 1
  fi
done

for required in 'pull_request:' 'types: [labeled]' 'github.event.pull_request.number == 79' \
  'github.event.pull_request.head.repo.full_name == github.repository' \
  "startsWith(github.event.label.name, 'rm-d3-')" \
  'runs-on: [self-hosted, macos, arm64' \
  'cpu=$(sysctl -n hw.ncpu)' 'process_limit=$(ulimit -u)' 'host_shares=$(mount' \
  'ACTIONS_RUNNER_INPUT_JITCONFIG' 'gh[pousr]_' 'jit_env=absent' \
  'permissions:' 'contents: read'; do
  grep -F -- "$required" "$workflow" >/dev/null || { echo "missing workflow contract: $required" >&2; exit 1; }
done

help=$(bash "$harness" audit --help)
grep -F 'prepare-before-reboot' <<<"$help" >/dev/null
grep -F 'The harness never initiates a' <<<"$help" >/dev/null

echo 'macOS VM native acceptance harness contract passed'
