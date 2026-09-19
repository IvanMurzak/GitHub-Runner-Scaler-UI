#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
harness="$root/scripts/macos-vm-acceptance.sh"
workflow="$root/.github/workflows/macos-vm-native-acceptance.yml"
ci_workflow="$root/.github/workflows/ci.yml"
cli_json_contract="$root/tests/macos-vm-helper-cli-json-contract.sh"

bash -n "$harness"
bash -n "$cli_json_contract"
test -f "$workflow"
grep -F 'run: bash tests/macos-vm-helper-cli-json-contract.sh' "$ci_workflow" >/dev/null

# Bash 3.2 expands every assignment in one `local` command before assigning
# any of them. Execute the harness's real output-path declarations with nounset
# enabled so a future same-command dependency fails on the oldest supported
# macOS shell instead of during a privileged acceptance run.
probe_path_declarations=$(
  awk '
    /^assert_probe_and_image\(\) \{/ { in_function = 1; next }
    in_function && /helper_command probe/ { exit }
    in_function && /^[[:space:]]+local (out|probe|inspected)=/ { print }
  ' "$harness"
)
PROBE_PATH_DECLARATIONS=$probe_path_declarations bash -u <<'BASH'
eval "probe_paths() {
$PROBE_PATH_DECLARATIONS
printf '%s\n%s\n' \"\$probe\" \"\$inspected\"
}"
actual=$(probe_paths '/tmp/runner manager')
expected=$(printf '%s\n%s\n' '/tmp/runner manager/probe.json' '/tmp/runner manager/image.json')
[[ $actual == "$expected" ]]
BASH

# A failed run-job can install the service and exit before ensure_profile writes
# profile_name. Exercise the harness's real receipt reader against that durable
# partial state: cleanup must see an empty optional name instead of crashing.
state_get_definition=$(
  awk '
    /^state_get\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
partial_receipt=$(mktemp)
trap 'rm -f "$partial_receipt"' EXIT
printf '%s\n' '{"schema_version":1,"service_installed":true,"profile_created":false}' >"$partial_receipt"
STATE_GET_DEFINITION=$state_get_definition STATE_PATH=$partial_receipt bash -u <<'BASH'
eval "$STATE_GET_DEFINITION"
state_path=$STATE_PATH
[[ -z $(state_get profile_name) ]]
[[ $(state_get service_installed) == true ]]
BASH

# An existing but empty environments directory is a successful listing. Under
# `set -e`, capture must enter its wait/retry path rather than abort at the
# assignment that invokes environment_dirs.
environment_definitions=$(
  awk '
    /^environment_dirs\(\) \{/ { in_function = 1 }
    /^capture_single_environment\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { in_function = 0 }
  ' "$harness"
)
empty_helper_root=$(mktemp -d)
mkdir "$empty_helper_root/environments"
empty_capture=$(mktemp)
empty_wait_marker=$(mktemp)
rm -f "$empty_wait_marker"
ENVIRONMENT_DEFINITIONS=$environment_definitions HELPER_ROOT=$empty_helper_root \
  CAPTURE_OUTPUT=$empty_capture WAIT_MARKER=$empty_wait_marker bash -u <<'BASH'
set -e
eval "$ENVIRONMENT_DEFINITIONS"
helper_root=$HELPER_ROOT
image='vm-version:test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
disk_mib=1
helper_command() { return 99; }
die() { printf '%s\n' "$*" >&2; exit 42; }
sleep() { printf 'waited\n' >>"$WAIT_MARKER"; SECONDS=$((SECONDS + 10)); }
environment_dirs
set +e
(capture_single_environment "$CAPTURE_OUTPUT" 1) 2>/dev/null
status=$?
set -e
[[ $status -eq 42 ]]
[[ -s $WAIT_MARKER ]]
BASH
rm -rf "$empty_helper_root" "$empty_capture" "$empty_wait_marker"

# launchd teardown is asynchronous. Exercise the real bounded wait through one
# retry, then prove the timeout remains fail closed when the PID never leaves.
wait_service_definition=$(
  awk '
    /^wait_service_absent\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
pid_sentinel=$(mktemp)
wait_marker=$(mktemp)
rm -f "$wait_marker"
WAIT_SERVICE_DEFINITION=$wait_service_definition PID_SENTINEL=$pid_sentinel \
  WAIT_MARKER=$wait_marker bash -u <<'BASH'
set -e
eval "$WAIT_SERVICE_DEFINITION"
service_pid() { [[ -f $PID_SENTINEL ]] && { rm -f "$PID_SENTINEL"; printf '123\n'; }; }
sleep() { printf 'waited\n' >>"$WAIT_MARKER"; SECONDS=$((SECONDS + 1)); }
die() { printf '%s\n' "$*" >&2; exit 42; }
wait_service_absent 5
[[ -s $WAIT_MARKER ]]

service_pid() { printf '123\n'; }
set +e
(wait_service_absent 1) 2>/dev/null
status=$?
set -e
[[ $status -eq 42 ]]
BASH
rm -f "$pid_sentinel" "$wait_marker"

# A profile's immutable selector is the label that must be present on the job.
# Exercise the harness's real derivation for both phases, and prove malformed
# profile names cannot silently produce a trigger label that no profile owns.
profile_selector_definition=$(
  awk '
    /^profile_selector\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
PROFILE_SELECTOR_DEFINITION=$profile_selector_definition bash -u <<'BASH'
eval "$PROFILE_SELECTOR_DEFINITION"
die() { printf '%s\n' "$*" >&2; return 42; }
id=20260919010203-deadbeef
[[ $(profile_selector "d3-$id") == "rm-d3-acceptance-osx-arm64-d3-$id" ]]
[[ $(profile_selector "d3-reboot-$id") == "rm-d3-acceptance-osx-arm64-d3-reboot-$id" ]]
for invalid in \
  "d3-$id-extra" \
  'd3-20260919010203-DEADBEEF' \
  'rm-d3-20260919010203-deadbeef'; do
  if profile_selector "$invalid" >/dev/null 2>&1; then
    printf 'invalid acceptance profile produced a selector: %s\n' "$invalid" >&2
    exit 1
  fi
done
BASH

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
  'kill -9' 'runner status --json' 'helper_command destroy' \
  'wait_service_absent 30'; do
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
  "startsWith(github.event.label.name, 'rm-d3-acceptance-osx-arm64-d3-')" \
  'runs-on: [self-hosted, macos, arm64, "${{ github.event.label.name }}"]' \
  'ACCEPTANCE_SELECTOR: ${{ github.event.label.name }}' \
  '[[ "$ACCEPTANCE_SELECTOR" =~ ^rm-d3-acceptance-osx-arm64-d3-(reboot-)?([0-9]{14}-[0-9a-f]{8})$ ]]' \
  'acceptance_id=${BASH_REMATCH[2]}' \
  'cpu=$(sysctl -n hw.ncpu)' 'process_limit=$(ulimit -u)' 'host_shares=$(mount' \
  'ACTIONS_RUNNER_INPUT_JITCONFIG' 'gh[pousr]_' 'jit_env=absent' \
  'permissions:' 'contents: read'; do
  grep -F -- "$required" "$workflow" >/dev/null || { echo "missing workflow contract: $required" >&2; exit 1; }
done

help=$(bash "$harness" audit --help)
grep -F 'prepare-before-reboot' <<<"$help" >/dev/null
grep -F 'The harness never initiates a' <<<"$help" >/dev/null

echo 'macOS VM native acceptance harness contract passed'
