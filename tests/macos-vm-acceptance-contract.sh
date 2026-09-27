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
python3 - "$workflow" <<'PY'
import os,pathlib,subprocess,sys,tempfile,textwrap
source=pathlib.Path(sys.argv[1]).read_text()
route=source.split('\n  route:\n',1)[1].split('\n  production-provider:\n',1)[0]
assert 'runs-on: rm-macmini-osx-arm64' in route
assert 'github.event.pull_request.number == 79' in route
assert 'github.event.pull_request.head.repo.full_name == github.repository' in route
script=textwrap.dedent(route.split('        run: |\n',1)[1])
with tempfile.TemporaryDirectory(prefix='rm-route-contract-') as temporary:
    output=pathlib.Path(temporary)/'output'
    for prefix,reboot in [('', 'false'),('reboot-', 'true')]:
        output.unlink(missing_ok=True)
        label=f'rm-d3-{prefix}20260927000000-aabbccdd'
        environment=dict(os.environ,TRIGGER_LABEL=label,GITHUB_OUTPUT=str(output))
        subprocess.run(['/bin/bash','-c',script],env=environment,check=True)
        fields=dict(line.split('=',1) for line in output.read_text().splitlines())
        assert fields=={'acceptance_id':'20260927000000-aabbccdd','reboot':reboot,
                        'selector':f'rm-d3-acceptance-osx-arm64-d3-{prefix}20260927000000-aabbccdd'}
    output.unlink()
    invalid=dict(os.environ,TRIGGER_LABEL='rm-d3-unowned',GITHUB_OUTPUT=str(output))
    assert subprocess.run(['/bin/bash','-c',script],env=invalid,capture_output=True).returncode != 0
    assert not output.exists()
PY
grep -F 'run: bash tests/macos-vm-helper-cli-json-contract.sh' "$ci_workflow" >/dev/null

# Execute the actual bounded route wait independently of VM preparation. A
# completed/failed or ambiguous route must never advance to guest acceptance.
route_wait_definition=$(awk '/^wait_for_route\(\) \{/ { active=1 } active { print } active && /^}/ { exit }' "$harness")
route_wait_temp=$(mktemp -d)
ROUTE_WAIT_DEFINITION=$route_wait_definition ROUTE_WAIT_TEMP=$route_wait_temp bash -eu <<'BASH'
eval "$ROUTE_WAIT_DEFINITION"
repository=owner/repo
run_poll_seconds=30
run_wait_timeout_seconds=60
calls=0
die() { printf '%s\n' "$*" >&2; exit 1; }
sleep() { SECONDS=$((SECONDS + $1)); }
gh() {
  calls=$((calls + 1))
  case "$scenario" in
    delayed)
      if [[ $calls == 1 ]]; then
        printf '%s\n' '{"status":"queued","jobs":[{"name":"route","status":"queued"}]}'
      else
        printf '%s\n' '{"status":"in_progress","jobs":[{"name":"route","status":"completed","conclusion":"success"},{"name":"production-provider","status":"queued"}]}'
      fi ;;
    failed) printf '%s\n' '{"status":"completed","jobs":[{"name":"route","status":"completed","conclusion":"failure"}]}' ;;
    missing_guest) printf '%s\n' '{"status":"completed","jobs":[{"name":"route","status":"completed","conclusion":"success"}]}' ;;
    skipped) printf '%s\n' '{"status":"completed","jobs":[{"name":"route","status":"completed","conclusion":"skipped"}]}' ;;
    failed_guest) printf '%s\n' '{"status":"completed","jobs":[{"name":"route","status":"completed","conclusion":"success"},{"name":"production-provider","status":"completed","conclusion":"failure"}]}' ;;
    ambiguous) printf '%s\n' '{"status":"in_progress","jobs":[{"name":"route"},{"name":"route"}]}' ;;
    timeout) printf '%s\n' '{"status":"queued","jobs":[]}' ;;
  esac
}
scenario=delayed
wait_for_route 123 "$ROUTE_WAIT_TEMP"
[[ $calls == 2 && -s $ROUTE_WAIT_TEMP/route-state.json ]]
for scenario in failed missing_guest skipped failed_guest ambiguous timeout; do
  if (wait_for_route 123 "$ROUTE_WAIT_TEMP") >"$ROUTE_WAIT_TEMP/$scenario.log" 2>&1; then
    printf 'route wait unexpectedly accepted %s\n' "$scenario" >&2
    exit 1
  fi
done
BASH
rm "$route_wait_temp/route-state.json" "$route_wait_temp/failed.log" "$route_wait_temp/missing_guest.log" "$route_wait_temp/skipped.log" "$route_wait_temp/failed_guest.log" "$route_wait_temp/ambiguous.log" "$route_wait_temp/timeout.log"
rmdir "$route_wait_temp"
[[ $(grep -Fc 'wait_for_route "$run_id" "$evidence"' "$harness") == 2 ]]
[[ $(grep -Fc '"$environment_wait_timeout_seconds"' "$harness") == 2 ]]

# macOS reports kern.boottime as a struct containing both `sec` and `usec`.
# Execute the harness's real parser so the `sec` suffix in `usec` can never be
# mistaken for the boot epoch, including on the system Bash 3.2 used by macOS.
boot_epoch_definition=$(
  awk '
    /^boot_epoch\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
BOOT_EPOCH_DEFINITION=$boot_epoch_definition bash -u <<'BASH'
eval "$BOOT_EPOCH_DEFINITION"
sysctl() {
  [[ $1 == -n && $2 == kern.boottime ]]
  printf '%s\n' "$SYSCTL_OUTPUT"
}
SYSCTL_OUTPUT='{ sec = 1790020731, usec = 612365 }'
[[ $(boot_epoch) == 1790020731 ]]
SYSCTL_OUTPUT='  { sec = 1790020731, usec = 999999 } Tue Sep 22 03:58:51 2026'
[[ $(boot_epoch) == 1790020731 ]]
SYSCTL_OUTPUT='{ usec = 612365 }'
if boot_epoch >/dev/null; then
  printf 'boot epoch parser accepted output without a seconds field\n' >&2
  exit 1
fi
BASH

# Bash 3.2 expands every assignment in one `local` command before assigning
# any of them. Execute the harness's real output-path declarations with nounset
# enabled so a future same-command dependency fails on the oldest supported
# macOS shell instead of during a privileged acceptance run.
probe_path_declarations=$(
  awk '
    /^assert_probe_and_image\(\) \{/ { in_function = 1; next }
    in_function && /helper_command probe/ { exit }
    in_function && /^[[:space:]]+local (out|probe|inspected|verified)=/ { print }
  ' "$harness"
)
PROBE_PATH_DECLARATIONS=$probe_path_declarations bash -u <<'BASH'
eval "probe_paths() {
$PROBE_PATH_DECLARATIONS
printf '%s\n%s\n%s\n' \"\$probe\" \"\$inspected\" \"\$verified\"
}"
actual=$(probe_paths '/tmp/runner manager')
expected=$(printf '%s\n%s\n%s\n' '/tmp/runner manager/probe.json' '/tmp/runner manager/image.json' '/tmp/runner manager/template-verification.json')
[[ $actual == "$expected" ]]
BASH

# The acceptance service is a user-owned LaunchAgent in gui/501. Its login
# credential and disposable data are deliberately distinct from production.
runner_definition=$(awk '/^runner\(\) \{/ { print; exit }' "$harness")
RUNNER_DEFINITION=$runner_definition bash -u <<'BASH'
eval "$RUNNER_DEFINITION"
runner_manager=record_cli
data_dir='/tmp/private acceptance data'
record_cli() { printf '<%s>\n' "$@"; }
actual=$(runner repo profile list owner/repo)
expected=$(printf '<%s>\n' --data-dir "$data_dir" --use-platform-credential repo profile list owner/repo)
[[ $actual == "$expected" ]]
BASH
grep -F 'service_domain=' "$harness" >/dev/null
service_pid_definition=$(awk '/^service_pid\(\) \{/ { active=1 } active { print } active && /^}/ { exit }' "$harness")
SERVICE_PID_DEFINITION=$service_pid_definition bash -u <<'BASH'
eval "$SERVICE_PID_DEFINITION"
service_domain=gui/501
service_label=owned-test
launchctl() { printf '%s\n' "$LAUNCHCTL_OUTPUT"; }
LAUNCHCTL_OUTPUT=$'state = spawn scheduled\npid = 101\nlast exit code = 78'
[[ -z $(service_pid) ]]
LAUNCHCTL_OUTPUT=$'state = running\npid = 202\nresource coalition = {\nstate = active\n}'
[[ $(service_pid) == 202 ]]
LAUNCHCTL_OUTPUT=$'state = running'
[[ -z $(service_pid) ]]
BASH
grep -F 'auth_runner auth status --start-at login >"$evidence/runner-auth.txt"' "$harness" >/dev/null
if grep -F 'auth_runner auth status --start-at boot' "$harness" >/dev/null; then
  printf 'audit still selects the boot credential scope\n' >&2
  exit 1
fi
grep -F 'login_service service install --start-at login' "$harness" >/dev/null
grep -F 'sudo -n env' "$harness" >/dev/null
if grep -F 'runner service install --start-at boot' "$harness" >/dev/null; then
  printf 'harness still installs a boot service\n' >&2
  exit 1
fi

# Execute the real continuation generator without installing any service.
# The first RunAtLoad must do nothing before reboot; after reboot it must
# preserve failed evidence or complete all phases and remove files before
# bootout (which may terminate its own process).
python3 - "$harness" <<'PY'
import os, pathlib, plistlib, subprocess, sys, tempfile
source = pathlib.Path(sys.argv[1]).read_text()
function = source.split('install_reboot_continuation() {', 1)[1].split('\nverify_reboot() {', 1)[0]
generator = function.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
with tempfile.TemporaryDirectory(prefix='rm-continuation-contract-') as temporary:
    root = pathlib.Path(temporary)
    tools = root / 'tools'; tools.mkdir()
    script = root / 'continuation.sh'; plist = root / 'agent.plist'
    harness = root / 'mock harness.sh'; log = root / 'phases'
    def executable(path, text):
        path.write_text('#!/bin/sh\nset -eu\n' + text); path.chmod(0o700)
    executable(tools / 'sysctl', 'echo "{ sec = 200, usec = 400 }"\n')
    executable(tools / 'launchctl',
               f'[ ! -e "{script}" ] && [ ! -e "{plist}" ]\necho bootout >>"{log}"\n')
    executable(harness, f'echo "$1" >>"{log}"\n')
    args = [str(script), str(plist), 'disposable-recovery', str(harness),
            'owner/repo', 'image', str(root / 'data'), '/binary', '/helper',
            '/store', str(root / 'state.json'), 'ref', '79', '47684',
            str(root), '200', str(tools), str(tools)]
    def generate():
        subprocess.run([sys.executable, '-c', generator, *args], check=True)
        subprocess.run(['/bin/sh', '-n', str(script)], check=True)
        document = plistlib.loads(plist.read_bytes())
        assert document['RunAtLoad'] is True
        assert document['ProgramArguments'][:2] == ['/bin/sh', '-c']
        assert 'attempt' in document['ProgramArguments'][2]
        return document
    generate()
    subprocess.run(['/bin/sh', str(script)], check=True)
    assert not log.exists() and script.exists() and plist.exists(), 'ran before reboot'
    executable(tools / 'sysctl', 'echo "{ sec = 201, usec = 400 }"\n')
    executable(harness, 'exit 46\n')
    failed = subprocess.run(['/bin/sh', str(script)])
    assert failed.returncode == 46 and script.exists() and plist.exists()
    executable(harness, f'echo "$1" >>"{log}"\n')
    subprocess.run(['/bin/sh', str(script)], check=True)
    assert log.read_text().splitlines() == [
        'verify-after-reboot', 'recovery-forensics', 'cleanup', 'rollback', 'bootout']
    assert not script.exists() and not plist.exists()

    # Execute the actual plist bootstrap: an external receipt script can be
    # absent at login, and a failed mount must preserve the recovery artifacts.
    document = generate()
    pending = root / 'pending-script'
    script.rename(pending)
    executable(tools / 'sleep', 'exit 0\n')
    missing = subprocess.run(document['ProgramArguments'], capture_output=True)
    assert missing.returncode == 78 and b'volume unavailable' in missing.stderr
    assert pending.exists() and plist.exists()
    log.unlink()
    executable(tools / 'sleep', f'mv "{pending}" "{script}"\n')
    subprocess.run(document['ProgramArguments'], check=True)
    assert log.read_text().splitlines() == [
        'verify-after-reboot', 'recovery-forensics', 'cleanup', 'rollback', 'bootout']
    assert not script.exists() and not plist.exists() and not pending.exists()

    # Building/signing must remain in the login user's keychain context.
    # Exercise the installer with inert tools, never touching system paths.
    installer = pathlib.Path(sys.argv[1]).parent.parent / 'native/macos-vm-helper/install.sh'
    executable(tools / 'uname', 'echo Darwin\n')
    executable(tools / 'id', 'echo 0\n')
    environment = dict(os.environ, PATH=str(tools) + ':/usr/bin:/bin')
    root_install = subprocess.run(['/bin/sh', str(installer), '--signing-identity', 'test'],
                                  env=environment, capture_output=True)
    assert root_install.returncode == 78
    assert b'without sudo' in root_install.stderr
    operations = root / 'install-operations'
    executable(tools / 'id', 'echo 501\n')
    executable(tools / 'swift',
               f'echo swift >>"{operations}"\ncase "$*" in *--show-bin-path*) echo "{root}";; esac\n')
    executable(tools / 'codesign', f'echo "codesign $*" >>"{operations}"\n')
    executable(tools / 'sudo', f'echo "sudo $*" >>"{operations}"\n')
    subprocess.run(['/bin/sh', str(installer), '--signing-identity', 'test'],
                   env=environment, check=True, capture_output=True)
    steps = operations.read_text().splitlines()
    assert steps[:2] == ['swift', 'swift']
    assert steps[2].startswith('codesign --force')
    assert steps[3].startswith('codesign --verify')
    assert len(steps[4:]) == 4 and all(x.startswith('sudo ') for x in steps[4:])
    assert steps[-1].startswith('sudo install -d -m 0700 -o 501 -g 501 ')
PY

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
trap 'status=$?; rm -f "$partial_receipt"; exit "$status"' EXIT
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

# A newly-created production environment is legitimately `prepared` before the
# helper consumes the private JIT handoff and begins booting. Exercise the real
# capture loop across that transition: all immutable properties are checked on
# all observations, but only running (private JIT acknowledged) completes it.
prepared_helper_root=$(mktemp -d)
mkdir -p "$prepared_helper_root/environments/rm-prepared"
prepared_capture=$(mktemp)
prepared_count=$(mktemp)
prepared_wait_marker=$(mktemp)
printf '0\n' >"$prepared_count"
rm -f "$prepared_wait_marker"
ENVIRONMENT_DEFINITIONS=$environment_definitions HELPER_ROOT=$prepared_helper_root \
  CAPTURE_OUTPUT=$prepared_capture INSPECT_COUNT=$prepared_count \
  WAIT_MARKER=$prepared_wait_marker bash -u <<'BASH'
set -e
eval "$ENVIRONMENT_DEFINITIONS"
helper_root=$HELPER_ROOT
image='vm-version:test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
disk_mib=47684
helper_command() {
  count=$(cat "$INSPECT_COUNT")
  count=$((count + 1))
  printf '%s\n' "$count" >"$INSPECT_COUNT"
  case "$count" in 1) state=prepared;; 2) state=booting;; *) state=running;; esac
  printf '{"protocol_version":1,"guest_os":"macos","architecture":"arm64","image":"%s","template_digest":"%s","state":"%s","fresh_writable_disk":true,"shared_host_paths":[],"jit_channel":"private","applied_cpu_millis":2000,"applied_memory_mib":4096,"applied_disk_mib":47684,"applied_process_limit":512,"writable_disk_id":"disk-1","environment_id":"rm-prepared"}\n' \
    "$image" "${image##*@sha256:}" "$state"
}
die() { printf '%s\n' "$*" >&2; exit 42; }
sleep() { printf 'waited\n' >>"$WAIT_MARKER"; SECONDS=$((SECONDS + 2)); }
environment=$(capture_single_environment "$CAPTURE_OUTPUT" 10)
[[ $environment == rm-prepared ]]
[[ $(cat "$INSPECT_COUNT") -eq 3 ]]
[[ -s $WAIT_MARKER ]]
python3 - "$CAPTURE_OUTPUT" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))['state'] == 'running'
PY
BASH
rm -rf "$prepared_helper_root" "$prepared_capture" "$prepared_count" "$prepared_wait_marker"

# Registration alone can be offline, and a retry can use a new runner ID.
# Exercise the exact pre-crash/reboot job gate, including fail-closed identity.
guest_definition=$(awk '/^wait_for_guest_job\(\) \{/ { capture=1 } capture {print} capture && /^}/ {exit}' "$harness")
guest_evidence=$(mktemp -d)
GUEST_DEFINITION=$guest_definition GUEST_EVIDENCE=$guest_evidence bash -u <<'BASH'
set -e
eval "$GUEST_DEFINITION"
repository=octo/repo
die() { printf '%s\n' "$*" >&2; exit 42; }
sleep() { SECONDS=$((SECONDS + $1)); }
gh() {
  case "$scenario" in
    ready) printf '%s\n' '{"jobs":[{"name":"production-provider","status":"in_progress","runner_id":123}]}' ;;
    foreign) printf '%s\n' '{"jobs":[{"name":"production-provider","status":"in_progress","runner_id":999}]}' ;;
    ended) printf '%s\n' '{"jobs":[{"name":"production-provider","status":"completed","runner_id":123}]}' ;;
    queued) printf '%s\n' '{"jobs":[{"name":"production-provider","status":"queued","runner_id":null}]}' ;;
    ambiguous) printf '%s\n' '{"jobs":[{"name":"production-provider"},{"name":"production-provider"}]}' ;;
  esac
}
scenario=ready
wait_for_guest_job 1 123 "$GUEST_EVIDENCE"
for scenario in foreign ended queued ambiguous; do
  if (wait_for_guest_job 1 123 "$GUEST_EVIDENCE") >"$GUEST_EVIDENCE/$scenario.log" 2>&1; then
    printf 'guest readiness accepted %s\n' "$scenario" >&2
    exit 1
  fi
done
BASH
rm -rf "$guest_evidence"
[[ $(grep -Fc 'wait_for_guest_job "$run_id"' "$harness") == 2 ]]

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
trigger_label_definition=$(
  awk '
    /^trigger_label\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
PROFILE_SELECTOR_DEFINITION=$profile_selector_definition \
  TRIGGER_LABEL_DEFINITION=$trigger_label_definition bash -u <<'BASH'
eval "$PROFILE_SELECTOR_DEFINITION"
eval "$TRIGGER_LABEL_DEFINITION"
die() { printf '%s\n' "$*" >&2; return 42; }
id=20260919010203-deadbeef
[[ $(profile_selector "d3-$id") == "rm-d3-acceptance-osx-arm64-d3-$id" ]]
[[ $(profile_selector "d3-reboot-$id") == "rm-d3-acceptance-osx-arm64-d3-reboot-$id" ]]
[[ $(trigger_label "d3-$id") == "rm-d3-$id" ]]
[[ $(trigger_label "d3-reboot-$id") == "rm-d3-reboot-$id" ]]
[[ $(profile_selector "d3-$id") != "$(trigger_label "d3-$id")" ]]
(( ${#id} == 23 ))
normal_trigger=$(trigger_label "d3-$id")
reboot_trigger=$(trigger_label "d3-reboot-$id")
(( ${#normal_trigger} <= 50 && ${#reboot_trigger} <= 50 ))
for invalid in \
  "d3-$id-extra" \
  'd3-20260919010203-DEADBEEF' \
  'rm-d3-20260919010203-deadbeef'; do
  if profile_selector "$invalid" >/dev/null 2>&1; then
    printf 'invalid acceptance profile produced a selector: %s\n' "$invalid" >&2
    exit 1
  fi
  if trigger_label "$invalid" >/dev/null 2>&1; then
    printf 'invalid acceptance profile produced a trigger label: %s\n' "$invalid" >&2
    exit 1
  fi
done
BASH

# Execute the workflow's real routing script. The short repository label is
# only a unique event trigger; the downstream job must receive the profile's
# exact immutable selector and malformed IDs must fail before it is scheduled.
route_script=$(
  awk '
    /- name: Resolve the exact profile selector/ { in_step = 1 }
    in_step && /^[[:space:]]+run: \|$/ { in_run = 1; next }
    in_run && /^  production-provider:/ { exit }
    in_run { sub(/^          /, ""); print }
  ' "$workflow"
)
route_case() {
  local trigger=$1 expected_id=$2 expected_reboot=$3 expected_selector=$4 output
  output=$(mktemp)
  TRIGGER_LABEL=$trigger GITHUB_OUTPUT=$output bash -euo pipefail -c "$route_script"
  grep -Fx "acceptance_id=$expected_id" "$output" >/dev/null
  grep -Fx "reboot=$expected_reboot" "$output" >/dev/null
  grep -Fx "selector=$expected_selector" "$output" >/dev/null
  rm -f "$output"
}
route_id=20260919010203-deadbeef
route_case "rm-d3-$route_id" "$route_id" false "rm-d3-acceptance-osx-arm64-d3-$route_id"
route_case "rm-d3-reboot-$route_id" "$route_id" true \
  "rm-d3-acceptance-osx-arm64-d3-reboot-$route_id"
for invalid in "rm-d3-$route_id-extra" 'rm-d3-20260919010203-DEADBEEF' "d3-$route_id"; do
  if TRIGGER_LABEL=$invalid GITHUB_OUTPUT=/dev/null bash -euo pipefail -c "$route_script" \
    >/dev/null 2>&1; then
    printf 'invalid workflow trigger routed a job: %s\n' "$invalid" >&2
    exit 1
  fi
done

# Persist the discovered run id before trigger-label removal so the EXIT trap
# can cancel it even when the label cleanup itself fails. The dispatcher must
# propagate that failure despite running inside command substitution.
dispatch_definition=$(
  awk '
    /^dispatch_job\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
dispatch_state=$(mktemp)
DISPATCH_DEFINITION=$dispatch_definition DISPATCH_STATE=$dispatch_state bash -u <<'BASH'
set -o pipefail
eval "$DISPATCH_DEFINITION"
repository=octo/repo
pull_request=79
gh() { :; }
state_set() { printf '%s=%s\n' "$1" "$2" >>"$DISPATCH_STATE"; }
find_run() { printf '17\n'; }
remove_trigger_label() { return 19; }
set +e
output=$(dispatch_job rm-d3-test normal_run_id)
status=$?
set -e
[[ $status -eq 1 && -z $output ]]
grep -Fx 'normal_run_id=17' "$DISPATCH_STATE" >/dev/null
BASH
rm -f "$dispatch_state"

# Profile disable failures must remain visible. Cleanup disables the exact
# receipt-owned profile before touching environments so replacements cannot
# multiply while the destructive work is in progress.
disable_profile_definition=$(
  awk '
    /^disable_profile\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
remove_error=$(mktemp)
DISABLE_PROFILE_DEFINITION=$disable_profile_definition REMOVE_ERROR=$remove_error bash -u <<'BASH'
set -o pipefail
eval "$DISABLE_PROFILE_DEFINITION"
repository=octo/repo
runner() {
  printf 'profile still has one active isolated attempt\n' >&2
  return 19
}
set +e
disable_profile d3-test 2>"$REMOVE_ERROR"
status=$?
set -e
[[ $status -eq 1 ]]
grep -F 'profile still has one active isolated attempt' "$REMOVE_ERROR" >/dev/null
grep -F "could not disable temporary profile 'd3-test'" "$REMOVE_ERROR" >/dev/null
BASH
rm -f "$remove_error"

# Recorded runs must either already be complete or be cancelled successfully.
# An API failure stays visible so cleanup cannot claim success while a run is
# still able to create replacement work.
cancel_runs_definition=$(
  awk '
    /^cancel_recorded_runs\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
cancel_error=$(mktemp)
CANCEL_RUNS_DEFINITION=$cancel_runs_definition CANCEL_ERROR=$cancel_error bash -u <<'BASH'
set -o pipefail
eval "$CANCEL_RUNS_DEFINITION"
repository=octo/repo
state_get() { [[ $1 == normal_run_id ]] && printf '17\n' || printf '\n'; }
gh() {
  if [[ $1 == run && $2 == view ]]; then
    printf 'in_progress\n'
    return
  fi
  [[ $1 == run && $2 == cancel ]]
  return 19
}
set +e
cancel_recorded_runs 2>"$CANCEL_ERROR"
status=$?
set -e
[[ $status -eq 1 ]]
grep -F "could not cancel recorded workflow run '17'" "$CANCEL_ERROR" >/dev/null
BASH
rm -f "$cancel_error"

# Environment ownership is derived from the exact profile id in the receipt and
# the durable attempt journal, not from the first environment id or a global
# "all environments" assumption.
owned_definition=$(
  awk '
    /^owned_environment_dirs\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
ownership_root=$(mktemp -d)
mkdir -p "$ownership_root/data/config" "$ownership_root/helper/environments"
ownership_image="vm-version:test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
python3 - "$ownership_root/data/config/runner-manager.sqlite3" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute('CREATE TABLE attempts (id TEXT PRIMARY KEY, policy_id TEXT NOT NULL)')
    connection.executemany('INSERT INTO attempts VALUES (?, ?)', [
        ('attempt-original', 'profile-owned'),
        ('attempt-replacement', 'profile-owned'),
        ('attempt-unrelated', 'profile-other'),
    ])
PY
for pair in 'rm-original attempt-original' 'rm-replacement attempt-replacement' 'rm-unrelated attempt-unrelated'; do
  set -- $pair
  mkdir "$ownership_root/helper/environments/$1"
  printf '{"environment_id":"%s","attempt_id":"%s","image":"%s","template_digest":"%s"}\n' \
    "$1" "$2" "$ownership_image" "${ownership_image##*@sha256:}" \
    >"$ownership_root/helper/environments/$1/metadata.json"
done
OWNED_DEFINITION=$owned_definition OWNERSHIP_ROOT=$ownership_root \
  OWNERSHIP_IMAGE=$ownership_image bash -u <<'BASH'
set -e
eval "$OWNED_DEFINITION"
data_dir="$OWNERSHIP_ROOT/data"
helper_root="$OWNERSHIP_ROOT/helper"
image=$OWNERSHIP_IMAGE
state_get() { [[ $1 == profile_id ]]; printf 'profile-owned\n'; }
die() { printf '%s\n' "$*" >&2; exit 42; }
owned=$(owned_environment_dirs)
grep -F 'rm-original' <<<"$owned" >/dev/null
grep -F 'rm-replacement' <<<"$owned" >/dev/null
if grep -F 'rm-unrelated' <<<"$owned" >/dev/null; then
  printf 'unrelated environment was classified as receipt-owned\n' >&2
  exit 1
fi
BASH
rm -rf "$ownership_root"

# An ownership-query failure is not the same as an empty owned-resource set.
# This remains explicit even when the EXIT handler has disabled errexit.
owned_count_definition=$(grep -F 'owned_environment_count() {' "$harness")
wait_no_owned_definition=$(
  awk '
    /^wait_no_owned_environments\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
ownership_error=$(mktemp)
OWNED_COUNT_DEFINITION=$owned_count_definition WAIT_NO_OWNED_DEFINITION=$wait_no_owned_definition \
  OWNERSHIP_ERROR=$ownership_error bash -u <<'BASH'
set -o pipefail
eval "$OWNED_COUNT_DEFINITION"
eval "$WAIT_NO_OWNED_DEFINITION"
owned_environment_dirs() { return 19; }
die() { printf '%s\n' "$*" >&2; exit 42; }
SECONDS=0
set +e
(wait_no_owned_environments 60) 2>"$OWNERSHIP_ERROR"
status=$?
set -e
[[ $status -eq 42 ]]
grep -F 'could not verify whether receipt-owned provider VMs remain' "$OWNERSHIP_ERROR" >/dev/null
BASH
rm -f "$ownership_error"

# Replacement environments need not have the first environment id. Exercise
# the real destroy loop with two profile-owned attempts and leave an unrelated
# environment untouched.
destroy_definition=$(
  awk '
    /^destroy_receipt_owned_environments\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
destroy_root=$(mktemp -d)
for environment in rm-original rm-replacement rm-unrelated; do
  mkdir "$destroy_root/$environment"
  printf '{"environment_id":"%s","host_id":"host-1","attempt_id":"attempt-%s","generation":"generation-%s"}\n' \
    "$environment" "$environment" "$environment" >"$destroy_root/$environment/metadata.json"
done
DESTROY_DEFINITION=$destroy_definition DESTROY_ROOT=$destroy_root bash -u <<'BASH'
set -e
eval "$DESTROY_DEFINITION"
owned_environment_dirs() {
  printf '%s\n' "$DESTROY_ROOT/rm-original" "$DESTROY_ROOT/rm-replacement"
}
helper_command() {
  [[ $1 == destroy && $2 == --environment ]]
  rm -rf "$DESTROY_ROOT/$3"
}
die() { printf '%s\n' "$*" >&2; exit 42; }
destroy_receipt_owned_environments
[[ ! -d $DESTROY_ROOT/rm-original ]]
[[ ! -d $DESTROY_ROOT/rm-replacement ]]
[[ -d $DESTROY_ROOT/rm-unrelated ]]
BASH

# Helper destruction failures propagate even while the caller is collecting
# cleanup failures under `set +e`.
DESTROY_DEFINITION=$destroy_definition DESTROY_ROOT=$destroy_root bash -u <<'BASH'
set -o pipefail
eval "$DESTROY_DEFINITION"
mkdir -p "$DESTROY_ROOT/rm-failing"
printf '%s\n' '{"environment_id":"rm-failing","host_id":"host-1","attempt_id":"attempt-1","generation":"generation-1"}' \
  >"$DESTROY_ROOT/rm-failing/metadata.json"
owned_environment_dirs() { printf '%s\n' "$DESTROY_ROOT/rm-failing"; }
helper_command() { return 19; }
die() { printf '%s\n' "$*" >&2; exit 42; }
set +e
destroy_receipt_owned_environments 2>"$DESTROY_ROOT/destroy-error.txt"
status=$?
set -e
[[ $status -eq 1 ]]
grep -F "could not destroy receipt-owned environment 'rm-failing'" \
  "$DESTROY_ROOT/destroy-error.txt" >/dev/null
BASH
rm -rf "$destroy_root"

# Execute the real cleanup body with bounded fakes and assert cancellation,
# trigger removal, profile disable, owned destruction, and purge ordering.
cleanup_definition=$(
  awk '
    /^cleanup\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
cleanup_root=$(mktemp -d)
cleanup_actions=$(mktemp)
CLEANUP_DEFINITION=$cleanup_definition CLEANUP_ACTIONS=$cleanup_actions bash -u <<'BASH'
set -e
eval "$CLEANUP_DEFINITION"
allow_cleanup=true
assert_state_identity() { :; }
require_opt_in() { :; }
cancel_recorded_runs() { printf 'cancel\n' >>"$CLEANUP_ACTIONS"; }
remove_trigger_label() { printf 'label\n' >>"$CLEANUP_ACTIONS"; }
disable_profile() { [[ $1 == d3-owned ]]; printf 'disable\n' >>"$CLEANUP_ACTIONS"; }
destroy_receipt_owned_environments() {
  printf 'destroy\n' >>"$CLEANUP_ACTIONS"
}
wait_no_owned_environments() { :; }
wait_profile_inactive() { [[ $1 == d3-owned ]]; printf 'inactive\n' >>"$CLEANUP_ACTIONS"; }
purge_profile() { [[ $1 == d3-owned ]]; printf 'purge\n' >>"$CLEANUP_ACTIONS"; }
state_get() {
  case "$1" in
    profile_name) printf 'd3-owned\n' ;;
    profile_id) printf 'profile-owned\n' ;;
    *) printf '\n' ;;
  esac
}
state_set() { :; }
cleanup >/dev/null
expected=$(printf 'cancel\nlabel\ndisable\ndestroy\ninactive\npurge')
[[ $(cat "$CLEANUP_ACTIONS") == "$expected" ]]
BASH
rm -rf "$cleanup_root" "$cleanup_actions"

# GitHub cleanup failures remain actionable, but they do not leave the local
# profile enabled. The receipt does not claim complete cleanup until both sides
# have succeeded.
cleanup_actions=$(mktemp)
cleanup_error=$(mktemp)
CLEANUP_DEFINITION=$cleanup_definition CLEANUP_ACTIONS=$cleanup_actions \
  CLEANUP_ERROR=$cleanup_error bash -u <<'BASH'
set -e
eval "$CLEANUP_DEFINITION"
allow_cleanup=true
assert_state_identity() { :; }
require_opt_in() { :; }
cancel_recorded_runs() { printf 'cancel\n' >>"$CLEANUP_ACTIONS"; return 19; }
remove_trigger_label() { printf 'label\n' >>"$CLEANUP_ACTIONS"; return 19; }
disable_profile() { printf 'disable\n' >>"$CLEANUP_ACTIONS"; }
destroy_receipt_owned_environments() { printf 'destroy\n' >>"$CLEANUP_ACTIONS"; }
wait_no_owned_environments() { printf 'no-owned\n' >>"$CLEANUP_ACTIONS"; }
wait_profile_inactive() { printf 'inactive\n' >>"$CLEANUP_ACTIONS"; }
purge_profile() { printf 'purge\n' >>"$CLEANUP_ACTIONS"; }
state_get() {
  case "$1" in
    profile_name) printf 'd3-owned\n' ;;
    profile_id) printf 'profile-owned\n' ;;
    *) printf '\n' ;;
  esac
}
state_set() { printf 'state:%s=%s\n' "$1" "$2" >>"$CLEANUP_ACTIONS"; }
die() { printf '%s\n' "$*" >&2; exit 42; }
set +e
(cleanup) 2>"$CLEANUP_ERROR"
status=$?
set -e
[[ $status -eq 42 ]]
expected=$(printf 'cancel\nlabel\ndisable\ndestroy\nno-owned\ninactive\npurge\nstate:profile_created=false\nstate:profile_name=')
[[ $(cat "$CLEANUP_ACTIONS") == "$expected" ]]
grep -F 'recorded GitHub run or label cleanup was incomplete' "$CLEANUP_ERROR" >/dev/null
if grep -F 'state:cleanup_complete=' "$CLEANUP_ACTIONS" >/dev/null; then
  printf 'cleanup claimed completion after a GitHub cleanup failure\n' >&2
  exit 1
fi
BASH
rm -f "$cleanup_actions" "$cleanup_error"

# The EXIT handler preserves evidence, cancels the recorded run, removes the
# trigger, disables the exact profile, and waits for its capacity to release
# before purge. Exercise the real handler with no external effects.
failure_cleanup_definition=$(
  awk '
    /^run_job_failure_cleanup\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
failure_actions=$(mktemp)
FAILURE_CLEANUP_DEFINITION=$failure_cleanup_definition FAILURE_ACTIONS=$failure_actions bash -u <<'BASH'
set -e
eval "$FAILURE_CLEANUP_DEFINITION"
run_job_cleanup_armed=true
run_job_cleanup_running=false
run_job_cleanup_evidence=/evidence
preserve_failure_evidence() { printf 'evidence\n' >>"$FAILURE_ACTIONS"; }
cancel_recorded_runs() { printf 'cancel\n' >>"$FAILURE_ACTIONS"; }
remove_trigger_label() { printf 'label\n' >>"$FAILURE_ACTIONS"; }
disable_profile() { [[ $1 == d3-owned ]]; printf 'disable\n' >>"$FAILURE_ACTIONS"; }
destroy_receipt_owned_environments() { printf 'destroy\n' >>"$FAILURE_ACTIONS"; }
wait_no_owned_environments() { printf 'no-owned\n' >>"$FAILURE_ACTIONS"; }
wait_profile_inactive() { [[ $1 == d3-owned ]]; printf 'inactive\n' >>"$FAILURE_ACTIONS"; }
purge_profile() { [[ $1 == d3-owned ]]; printf 'purge\n' >>"$FAILURE_ACTIONS"; }
state_get() {
  case "$1" in
    profile_name) printf 'd3-owned\n' ;;
    profile_created) printf 'true\n' ;;
    *) printf '\n' ;;
  esac
}
state_set() { :; }
run_job_failure_cleanup 19 2>/dev/null
expected=$(printf 'cancel\nlabel\ndisable\nevidence\ndestroy\nno-owned\ninactive\npurge')
[[ $(cat "$FAILURE_ACTIONS") == "$expected" ]]
[[ $run_job_cleanup_armed == false && $run_job_cleanup_running == true ]]
BASH
rm -f "$failure_actions"

# Fail closed if the profile cannot be disabled: do not destroy an environment
# or purge a still-enabled profile, because either action can race replacement
# allocation and weaken receipt ownership.
failure_actions=$(mktemp)
failure_error=$(mktemp)
FAILURE_CLEANUP_DEFINITION=$failure_cleanup_definition FAILURE_ACTIONS=$failure_actions \
  FAILURE_ERROR=$failure_error bash -u <<'BASH'
set -e
eval "$FAILURE_CLEANUP_DEFINITION"
run_job_cleanup_armed=true
run_job_cleanup_running=false
run_job_cleanup_evidence=/evidence
preserve_failure_evidence() { printf 'evidence\n' >>"$FAILURE_ACTIONS"; }
cancel_recorded_runs() { printf 'cancel\n' >>"$FAILURE_ACTIONS"; }
remove_trigger_label() { printf 'label\n' >>"$FAILURE_ACTIONS"; }
disable_profile() { printf 'disable\n' >>"$FAILURE_ACTIONS"; return 19; }
destroy_receipt_owned_environments() { printf 'unexpected-destroy\n' >>"$FAILURE_ACTIONS"; }
wait_no_owned_environments() { printf 'unexpected-no-owned\n' >>"$FAILURE_ACTIONS"; }
wait_profile_inactive() { printf 'unexpected-inactive\n' >>"$FAILURE_ACTIONS"; }
purge_profile() { printf 'unexpected-purge\n' >>"$FAILURE_ACTIONS"; }
state_get() {
  case "$1" in
    profile_name) printf 'd3-owned\n' ;;
    profile_created) printf 'true\n' ;;
    *) printf '\n' ;;
  esac
}
state_set() { printf 'unexpected-state-set\n' >>"$FAILURE_ACTIONS"; }
run_job_failure_cleanup 19 2>"$FAILURE_ERROR"
expected=$(printf 'cancel\nlabel\ndisable\nevidence')
[[ $(cat "$FAILURE_ACTIONS") == "$expected" ]]
grep -F 'automatic cleanup was incomplete' "$FAILURE_ERROR" >/dev/null
BASH
rm -f "$failure_actions" "$failure_error"

# Polling is explicitly bounded and low-frequency; no gh run watch subprocess
# can spin against the user API budget indefinitely.
wait_run_definition=$(
  awk '
    /^wait_for_run\(\) \{/ { in_function = 1 }
    in_function { print }
    in_function && /^}/ { exit }
  ' "$harness"
)
wait_evidence=$(mktemp -d)
wait_calls=$(mktemp)
WAIT_RUN_DEFINITION=$wait_run_definition WAIT_EVIDENCE=$wait_evidence WAIT_CALLS=$wait_calls bash -u <<'BASH'
set -e
eval "$WAIT_RUN_DEFINITION"
repository=octo/repo
run_wait_timeout_seconds=90
run_poll_seconds=30
SECONDS=0
gh() {
  printf 'call\n' >>"$WAIT_CALLS"
  case $(wc -l <"$WAIT_CALLS" | tr -d ' ') in
    1) printf '%s\n' '{"status":"queued","conclusion":null}' ;;
    2) printf '%s\n' '{"status":"in_progress","conclusion":null}' ;;
    *) printf '%s\n' '{"status":"completed","conclusion":"success"}' ;;
  esac
}
sleep() { [[ $1 -eq 30 ]]; SECONDS=$((SECONDS + 30)); }
die() { printf '%s\n' "$*" >&2; return 42; }
wait_for_run 17 "$WAIT_EVIDENCE"
[[ $(wc -l <"$WAIT_CALLS" | tr -d ' ') -eq 3 ]]

: >"$WAIT_CALLS"
run_wait_timeout_seconds=60
SECONDS=0
gh() { printf 'call\n' >>"$WAIT_CALLS"; printf '%s\n' '{"status":"queued","conclusion":null}'; }
set +e
wait_for_run 18 "$WAIT_EVIDENCE" 2>"$WAIT_EVIDENCE/timeout-error.txt"
status=$?
set -e
[[ $status -eq 42 ]]
[[ $(wc -l <"$WAIT_CALLS" | tr -d ' ') -eq 2 ]]
grep -F 'did not complete within 60 seconds' "$WAIT_EVIDENCE/timeout-error.txt" >/dev/null
BASH
rm -rf "$wait_evidence" "$wait_calls"

for required in \
  'audit|run-job|prepare-before-reboot|verify-after-reboot|recovery-forensics|cleanup|rollback' \
  '--allow-service-install' '--allow-profile' '--allow-service-restart' \
  '--allow-cleanup' '--allow-rollback' 'this harness never initiates a reboot' \
  'virtualization_framework' 'fresh_writable_disk' 'shared_host_paths' \
  'applied_process_limit' 'normal_writable_disk_id' 'prepared_boot_epoch' \
  'normal_environment_id' 'reboot_environment_id' 'profile_id' \
  'this reviewed one-time acceptance workflow is pinned to PR 79' \
  'gh label create' 'gh pr edit' 'remove_trigger_label' \
  'helper_sha256' 'local HEAD' 'cancel_recorded_runs' \
  'wait_for_run' 'run_wait_timeout_seconds=3600' 'run_poll_seconds=30' \
  'wait_for_registered_runner' 'run_job_failure_cleanup' 'owned_environment_dirs' \
  'wait_profile_inactive' \
  'scan_service_process_no_secrets' 'ps eww -p' \
  'gh[pousr]_' 'login_service service install --start-at login' \
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
  "startsWith(github.event.label.name, 'rm-d3-')" \
  '[[ "$TRIGGER_LABEL" =~ ^rm-d3-(reboot-)?([0-9]{14}-[0-9a-f]{8})$ ]]' \
  'selector="rm-d3-acceptance-osx-arm64-d3-${reboot}${acceptance_id}"' \
  'runs-on: "${{ needs.route.outputs.selector }}"' \
  'ACCEPTANCE_SELECTOR: ${{ needs.route.outputs.selector }}' \
  '[[ "$ACCEPTANCE_ID" =~ ^[0-9]{14}-[0-9a-f]{8}$ ]]' \
  '[[ "$ACCEPTANCE_SELECTOR" =~ ^rm-d3-acceptance-osx-arm64-d3-(reboot-)?${ACCEPTANCE_ID}$ ]]' \
  'cpu=$(sysctl -n hw.ncpu)' 'process_limit=$(ulimit -u)' 'host_shares=$(mount' \
  'APFSContainerReference' 'PhysicalStores.0.DeviceIdentifier' 'ParentWholeDisk' \
  'RM_ACCEPTANCE disk_bytes=$disk_bytes disk_mib=$ACCEPTANCE_DISK_MIB' \
  'ACTIONS_RUNNER_INPUT_JITCONFIG' 'gh[pousr]_' 'jit_env=absent' \
  'permissions:' 'contents: read'; do
  grep -F -- "$required" "$workflow" >/dev/null || { echo "missing workflow contract: $required" >&2; exit 1; }
done

# The optional production smoke job must not enter the disposable VM route.
grep -F "github.event.label.name == 'rm-d3-production-health'" "$workflow" >/dev/null
grep -F "github.event.label.name != 'rm-d3-production-health'" "$workflow" >/dev/null
grep -F 'runs-on: rm-macmini-osx-arm64' "$workflow" >/dev/null
grep -F 'RM_PRODUCTION_ACCEPTANCE os=macos arch=arm64 uid=501 jit_env=absent' "$workflow" >/dev/null

if grep -F -- '--label self-hosted' "$harness" >/dev/null || \
   grep -F -- 'gh run watch' "$harness" >/dev/null; then
  echo 'harness restored mismatched registration labels or an unbounded run watcher' >&2
  exit 1
fi

help=$(bash "$harness" audit --help)
grep -F 'prepare-before-reboot' <<<"$help" >/dev/null
grep -F 'The harness never initiates a' <<<"$help" >/dev/null

echo 'macOS VM native acceptance harness contract passed'
