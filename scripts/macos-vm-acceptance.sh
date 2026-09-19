#!/usr/bin/env bash
set -euo pipefail

# Native Apple-silicon acceptance for the production macOS VM provider.
# The harness is deliberately phase-oriented. It never reboots the host and it
# never downloads or installs a macOS image. Destructive phases require an
# explicit --allow-* switch and act only on the profile/service names recorded
# in the receipt.

usage() {
  cat <<'EOF'
usage: macos-vm-acceptance.sh PHASE --repository OWNER/REPO --image PINNED_IMAGE \
       --data-dir ABSOLUTE_DIR --runner-manager ABSOLUTE_BINARY [options]

PHASE is one of:
  audit, run-job, prepare-before-reboot, verify-after-reboot,
  recovery-forensics, cleanup, rollback

Options:
  --state PATH              durable receipt path
  --workflow-ref REF        ref containing the native acceptance workflow
  --pull-request N          same-repository PR carrying the workflow (default 79)
  --disk-mib N              exact registered template disk size
  --allow-service-install   install the disposable boot LaunchDaemon
  --allow-profile           create/remove the temporary repository profile
  --allow-service-restart   SIGKILL the disposable LaunchDaemon once
  --allow-cleanup           destroy owned leftovers and remove the profile
  --allow-rollback          uninstall the disposable LaunchDaemon and receipt

Run as root on a physical Apple-silicon Mac. The harness never initiates a
reboot. prepare-before-reboot writes a receipt, then the operator reboots the
host manually and runs verify-after-reboot.
EOF
}

die() { printf 'macOS VM acceptance: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command '$1' was not found"; }
require_opt_in() { [[ "$1" == true ]] || die "$3 was refused; re-run this phase with $2 after reviewing audit state"; }

[[ $# -ge 1 ]] || { usage; exit 2; }
phase=$1
shift
case "$phase" in
  audit|run-job|prepare-before-reboot|verify-after-reboot|recovery-forensics|cleanup|rollback) ;;
  *) usage; die "unknown phase '$phase'" ;;
esac

repository=
image=
data_dir=
runner_manager=
helper=/usr/local/bin/runner-manager-macos-vm
helper_root='/Library/Application Support/io.github.IvanMurzak.runner-manager/macos-vm-helper'
state_path='/var/db/runner-manager-d3-acceptance/state.json'
workflow_ref=
pull_request=79
disk_mib=
allow_service_install=false
allow_profile=false
allow_service_restart=false
allow_cleanup=false
allow_rollback=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repository) repository=${2-}; shift 2 ;;
    --image) image=${2-}; shift 2 ;;
    --data-dir) data_dir=${2-}; shift 2 ;;
    --runner-manager) runner_manager=${2-}; shift 2 ;;
    --state) state_path=${2-}; shift 2 ;;
    --workflow-ref) workflow_ref=${2-}; shift 2 ;;
    --pull-request) pull_request=${2-}; shift 2 ;;
    --disk-mib) disk_mib=${2-}; shift 2 ;;
    --allow-service-install) allow_service_install=true; shift ;;
    --allow-profile) allow_profile=true; shift ;;
    --allow-service-restart) allow_service_restart=true; shift ;;
    --allow-cleanup) allow_cleanup=true; shift ;;
    --allow-rollback) allow_rollback=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option '$1'" ;;
  esac
done

[[ $(uname -s) == Darwin ]] || die 'this harness requires macOS'
[[ $(uname -m) == arm64 ]] || die 'native macOS guests are declared only on Apple silicon (arm64)'
[[ $(id -u) -eq 0 ]] || die 'run this harness as root (sudo -E preserves GH_TOKEN for gh)'
[[ $repository =~ ^[^/]+/[^/]+$ ]] || die '--repository must be OWNER/REPO'
[[ $image =~ ^vm-version:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$ ]] || die '--image must be an immutable vm-version reference with a lowercase sha256 digest'
[[ $data_dir == /* ]] || die '--data-dir must be absolute'
[[ $runner_manager == /* && -x $runner_manager ]] || die '--runner-manager must name an executable absolute path'
[[ $helper == /* && -x $helper ]] || die '--helper must name an executable absolute path'
[[ $helper_root == /* && $state_path == /* ]] || die 'helper root and state path must be absolute'
[[ $pull_request =~ ^[0-9]+$ && $pull_request -eq 79 ]] || die 'this reviewed one-time acceptance workflow is pinned to PR 79'
for command in gh git launchctl plutil python3 shasum sysctl; do need "$command"; done

workflow='macos-vm-native-acceptance.yml'
service_tag='d3-native-acceptance'
service_label='io.github.IvanMurzak.runner-manager-selftest-d3-native-acceptance'
state_dir=$(dirname "$state_path")
evidence_root="$state_dir/evidence"
mkdir -p "$state_dir" "$evidence_root"
chmod 700 "$state_dir" "$evidence_root"
export RUNNER_MANAGER_MACOS_VM_HELPER="$helper"
export RUNNER_MANAGER_MACOS_VM_ROOT="$helper_root"
export RUNNER_MANAGER_SERVICE_NAME_TAG="$service_tag"

runner() { "$runner_manager" --data-dir "$data_dir" "$@"; }
helper_command() { "$helper" --protocol-version 1 "$@"; }
boot_epoch() { sysctl -n kern.boottime | sed -E 's/.*sec = ([0-9]+).*/\1/'; }
service_pid() {
  launchctl print "system/$service_label" 2>/dev/null | awk '/^[[:space:]]*pid = / { print $3; exit }'
}

state_get() {
  local key=$1
  python3 - "$state_path" "$key" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
if not p.is_file(): raise SystemExit(3)
v = json.loads(p.read_text())
for part in sys.argv[2].split('.'):
    if not isinstance(v, dict) or part not in v:
        v = None
        break
    v = v[part]
if v is None: print('')
elif isinstance(v, bool): print(str(v).lower())
else: print(v)
PY
}

state_set() {
  local key=$1 value=$2 kind=${3:-string}
  python3 - "$state_path" "$key" "$value" "$kind" <<'PY'
import json, os, pathlib, sys, tempfile
p = pathlib.Path(sys.argv[1]); doc = json.loads(p.read_text())
value = sys.argv[3]
if sys.argv[4] == 'bool': value = value == 'true'
elif sys.argv[4] == 'int': value = int(value)
target = doc
parts = sys.argv[2].split('.')
for part in parts[:-1]: target = target.setdefault(part, {})
target[parts[-1]] = value
fd, tmp = tempfile.mkstemp(dir=p.parent, prefix='.state-', text=True)
with os.fdopen(fd, 'w') as f: json.dump(doc, f, sort_keys=True, indent=2); f.write('\n')
os.chmod(tmp, 0o600); os.replace(tmp, p)
PY
}

assert_state_identity() {
  [[ -f $state_path ]] || die "state '$state_path' is absent; run audit first"
  [[ $(state_get schema_version) == 1 ]] || die 'unrecognized state schema'
  [[ $(state_get repository) == "$repository" ]] || die 'state belongs to another repository'
  [[ $(state_get image) == "$image" ]] || die 'state belongs to another template image'
  [[ $(state_get data_dir) == "$data_dir" ]] || die 'state belongs to another data directory'
  [[ $(state_get runner_manager_sha256) == "$(shasum -a 256 "$runner_manager" | awk '{print $1}')" ]] || die 'runner-manager binary changed after audit'
  [[ $(state_get helper_sha256) == "$(shasum -a 256 "$helper" | awk '{print $1}')" ]] || die 'signed macOS VM helper changed after audit'
}

assert_probe_and_image() {
  local out=$1
  local probe="$out/probe.json"
  local inspected="$out/image.json"
  helper_command probe --json >"$probe"
  helper_command image inspect --image "$image" --json >"$inspected"
  python3 - "$probe" "$inspected" "$image" "${disk_mib:-}" <<'PY'
import json, sys
probe, image = (json.load(open(p)) for p in sys.argv[1:3])
required = ('virtualization_framework','macos_guest_entitlement','private_jit_channel',
            'fresh_writable_disks','resource_limits','process_limits')
assert probe['protocol_version'] == 1 and probe['architecture'] == 'arm64', probe
assert all(probe.get(k) is True for k in required), probe
assert image['protocol_version'] == 1 and image['image'] == sys.argv[3], image
assert image['guest_os'] == 'macos' and image['architecture'] == 'arm64', image
assert image['immutable'] is True and image['bootstrap_ready'] is True, image
assert image['template_digest'] == sys.argv[3].split('@sha256:',1)[1], image
PY
  if [[ -z $disk_mib ]]; then
    local manifest="$helper_root/templates/${image##*@sha256:}/manifest.json"
    [[ -r $manifest ]] || die "registered manifest '$manifest' is unreadable"
    disk_mib=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["identity"]["disk_mib"])' "$manifest")
  fi
  [[ $disk_mib =~ ^[0-9]+$ && $disk_mib -gt 0 ]] || die 'template disk size is invalid'
}

environment_dirs() {
  [[ -d "$helper_root/environments" ]] || return 0
  local directory
  for directory in "$helper_root"/environments/*; do
    [[ -d $directory && ! -L $directory ]] && printf '%s\n' "$directory"
  done
  return 0
}

environment_count() { environment_dirs | awk 'END { print NR+0 }'; }

capture_single_environment() {
  local output=$1 deadline=$((SECONDS + ${2:-300})) listing count envdir
  while (( SECONDS < deadline )); do
    listing=$(environment_dirs)
    count=$(printf '%s\n' "$listing" | awk 'NF { count++ } END { print count+0 }')
    if [[ $count -eq 1 ]]; then
      envdir=$listing
      helper_command inspect --environment "$(basename "$envdir")" --json >"$output"
      python3 - "$output" "$image" "$disk_mib" <<'PY'
import json, sys
r=json.load(open(sys.argv[1]))
assert r['protocol_version']==1 and r['guest_os']=='macos' and r['architecture']=='arm64', r
assert r['image']==sys.argv[2] and r['template_digest']==sys.argv[2].split('@sha256:',1)[1], r
assert r['state'] in ('booting','running') and r['fresh_writable_disk'] is True, r
assert r['shared_host_paths']==[] and r['jit_channel']=='private', r
assert r['applied_cpu_millis']==2000 and r['applied_memory_mib']==4096, r
assert r['applied_disk_mib']==int(sys.argv[3]) and r['applied_process_limit']==512, r
assert r['writable_disk_id'] and r['environment_id'].startswith('rm-'), r
print(r['environment_id'])
PY
      return
    fi
    [[ $count -eq 0 ]] || die 'more than one helper environment exists; refusing ambiguous ownership'
    sleep 2
  done
  die 'no production provider-owned macOS VM appeared before timeout'
}

find_run() {
  local trigger_label=$1 deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    local id
    id=$(gh run list --repo "$repository" --event pull_request --branch "$workflow_ref" --limit 50 \
      --json databaseId,displayTitle,workflowName \
      --jq ".[] | select(.workflowName == \"macOS VM native acceptance\" and .displayTitle == \"macos-vm-$trigger_label\") | .databaseId" | head -1)
    [[ -z $id ]] || { printf '%s\n' "$id"; return; }
    sleep 3
  done
  die "could not find pull-request workflow run for one-time label '$trigger_label'"
}

wait_no_environments() {
  local deadline=$((SECONDS + ${1:-300}))
  while (( SECONDS < deadline )); do
    [[ $(environment_count) -eq 0 ]] && return
    sleep 2
  done
  die 'provider-owned VM remained after the cleanup deadline'
}

wait_service_absent() {
  local deadline=$((SECONDS + ${1:-30}))
  while (( SECONDS < deadline )); do
    [[ -z $(service_pid) ]] && return
    sleep 1
  done
  die 'disposable LaunchDaemon still exists after uninstall'
}

cancel_recorded_runs() {
  local key run_id
  for key in normal_run_id reboot_run_id; do
    run_id=$(state_get "$key")
    [[ -z $run_id ]] || gh run cancel "$run_id" --repo "$repository" >/dev/null 2>&1 || true
  done
}

assert_status_clean() {
  local output=$1
  runner status --json >"$output"
  python3 - "$output" <<'PY'
import json, sys
s=json.load(open(sys.argv[1]))
h=s['host']
assert h['active_ephemeral_attempts']==0, s
assert h['cleanup_blocked_ephemeral_attempts']==0, s
PY
}

scan_no_secrets() {
  local output=$1
  python3 - "$output" "$data_dir" "$helper_root" "$evidence_root" <<'PY'
import os, pathlib, re, sys
report=pathlib.Path(sys.argv[1]); roots=[pathlib.Path(p) for p in sys.argv[2:]]
token_shape=re.compile(rb'gh[pousr]_[A-Za-z0-9_]{20,}')
jit_shape=re.compile(rb'ACTIONS_RUNNER_INPUT_JITCONFIG\s*=')
token=os.environ.get('GH_TOKEN','').encode()
scanned=0
with report.open('w') as out:
  for root in roots:
    if not root.exists(): continue
    for base, dirs, files in os.walk(root):
      dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(base,d))]
      for name in files:
        p=pathlib.Path(base,name)
        try:
          if p.is_symlink() or p.stat().st_size > 16*1024*1024: continue
          data=p.read_bytes(); scanned += 1
        except (OSError, PermissionError): continue
        checks_jit = root != roots[-1]
        if token_shape.search(data) or (checks_jit and jit_shape.search(data)) or (token and token in data):
          raise SystemExit(f'credential-shaped content found in {p}')
  out.write(f'scanned_files={scanned}\nresult=no-jit-or-token-shaped-content\n')
assert scanned > 0
PY
}

scan_service_process_no_secrets() {
  local output=$1 pid
  pid=$(service_pid); [[ -n $pid ]] || die 'cannot scan secrets because the disposable service has no PID'
  ps eww -p "$pid" -o command= | python3 -c '
import os, pathlib, re, sys
data=sys.stdin.buffer.read(); token=os.environ.get("GH_TOKEN","").encode()
if re.search(rb"ACTIONS_RUNNER_INPUT_JITCONFIG\s*=", data) or re.search(rb"gh[pousr]_[A-Za-z0-9_]{20,}", data) or (token and token in data):
    raise SystemExit("credential-shaped content found in the disposable service process")
pathlib.Path(sys.argv[1]).write_text("result=no-jit-or-token-shaped-content\\n")
' "$output"
}

new_acceptance_id() { date -u '+%Y%m%d%H%M%S-'; python3 - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
}

dispatch_job() {
  local label=$1
  gh label create "$label" --repo "$repository" --color 8250df \
    --description "One-time d3 native acceptance trigger for PR $pull_request"
  state_set trigger_label "$label"
  state_set trigger_label_created true bool
  gh pr edit "$pull_request" --repo "$repository" --add-label "$label" >/dev/null
  local run_id
  run_id=$(find_run "$label")
  remove_trigger_label
  printf '%s\n' "$run_id"
}

remove_trigger_label() {
  [[ $(state_get trigger_label_created) == true ]] || return 0
  local label
  label=$(state_get trigger_label)
  gh pr edit "$pull_request" --repo "$repository" --remove-label "$label" >/dev/null || \
    die "could not remove one-time label '$label' from PR $pull_request"
  gh label delete "$label" --repo "$repository" --yes >/dev/null || \
    die "could not delete one-time repository label '$label'"
  state_set trigger_label_created false bool
}

ensure_profile() {
  local profile=$1 label=$2 evidence=$3
  runner repo profile add "$repository" --name "$profile" --host-label d3-acceptance \
    --max-capacity 1 --label self-hosted --label macos --label arm64 --label "$label" \
    --execution isolated --backend virtual-machine --image "$image" \
    --cpu 2000 --memory 4096 --disk "$disk_mib" --enable >"$evidence/profile-add.txt"
}

remove_profile() {
  local profile=$1
  printf 'yes\n' | runner repo profile set-scale "$repository" --profile "$profile" --enabled false >/dev/null 2>&1 || true
  printf 'yes\n' | runner repo profile remove "$repository" --profile "$profile" --purge >/dev/null 2>&1 || true
  if runner repo profile show "$repository" --profile "$profile" >/dev/null 2>&1; then
    die "temporary profile '$profile' still exists after removal"
  fi
}

run_audit() {
  [[ ! -e $state_path ]] || die "state '$state_path' already exists; finish cleanup/rollback first"
  local evidence="$evidence_root/audit-$(date -u +%Y%m%d%H%M%S)"
  mkdir -m 700 "$evidence"
  assert_probe_and_image "$evidence"
  [[ -n ${GH_TOKEN:-} ]] || die 'GH_TOKEN is required so sudo never depends on another account home and the exact token can be scanned from evidence'
  gh auth status --hostname github.com >/dev/null
  runner auth status >"$evidence/runner-auth.txt"
  [[ $(environment_count) -eq 0 ]] || die 'helper store already contains environments; resolve them before acceptance'
  [[ -z $(service_pid) ]] || die "disposable service '$service_label' already exists"
  local pr_json pr_ref pr_owner repo_owner
  pr_json=$(gh pr view "$pull_request" --repo "$repository" --json headRefName,headRepositoryOwner,headRefOid)
  pr_ref=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["headRefName"])' <<<"$pr_json")
  pr_owner=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["headRepositoryOwner"]["login"])' <<<"$pr_json")
  local pr_oid
  pr_oid=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["headRefOid"])' <<<"$pr_json")
  repo_owner=${repository%%/*}
  [[ $pr_owner == "$repo_owner" ]] || die "PR $pull_request is not a same-repository pull request"
  [[ -z $workflow_ref || $workflow_ref == "$pr_ref" ]] || die "--workflow-ref '$workflow_ref' is not PR $pull_request head '$pr_ref'"
  workflow_ref=$pr_ref
  local commit
  commit=$(git -C "$(cd "$(dirname "$0")/.." && pwd)" rev-parse HEAD)
  [[ $commit == "$pr_oid" ]] || die "local HEAD '$commit' is not PR $pull_request head '$pr_oid'"
  python3 - "$state_path" "$repository" "$image" "$data_dir" "$runner_manager" "$helper" "$helper_root" "$workflow_ref" "$disk_mib" "$commit" "$(boot_epoch)" <<'PY'
import hashlib,json,os,pathlib,sys,tempfile
p=pathlib.Path(sys.argv[1]); binary=pathlib.Path(sys.argv[5])
doc={'schema_version':1,'phase':'audited','repository':sys.argv[2],'image':sys.argv[3],
 'data_dir':sys.argv[4],'runner_manager':sys.argv[5],
 'runner_manager_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
 'helper':sys.argv[6],'helper_sha256':hashlib.sha256(pathlib.Path(sys.argv[6]).read_bytes()).hexdigest(),
 'helper_root':sys.argv[7],'workflow_ref':sys.argv[8],
 'disk_mib':int(sys.argv[9]),'git_commit':sys.argv[10],
 'audit_boot_epoch':int(sys.argv[11]),'service_installed':False,'profile_created':False,
 'profile_name':'',
 'pull_request':79,'trigger_label':'','trigger_label_created':False,
 'normal_run_id':'','normal_environment_id':'','normal_writable_disk_id':'','reboot_run_id':'',
 'reboot_environment_id':'','reboot_writable_disk_id':'',
 'prepared_boot_epoch':0,'cleanup_complete':False,'rollback_complete':False}
p.write_text(json.dumps(doc,sort_keys=True,indent=2)+'\n'); os.chmod(p,0o600)
PY
  printf 'Audit passed. Receipt: %s\n' "$state_path"
}

install_service_and_profile() {
  local profile=$1 label=$2 evidence=$3
  require_opt_in "$allow_service_install" --allow-service-install 'installing the disposable boot LaunchDaemon'
  require_opt_in "$allow_profile" --allow-profile 'creating the temporary isolated profile'
  if [[ $(state_get service_installed) != true ]]; then
    runner service install --start-at boot >"$evidence/service-install.txt"
    state_set service_installed true bool
  fi
  local pid
  for _ in {1..30}; do pid=$(service_pid); [[ -z $pid ]] || break; sleep 2; done
  [[ -n $pid ]] || die 'disposable LaunchDaemon did not start'
  if [[ $(state_get profile_created) == true ]]; then die 'receipt already owns a temporary profile; clean it first'; fi
  ensure_profile "$profile" "$label" "$evidence"
  state_set profile_created true bool
  state_set profile_name "$profile"
  state_set unique_label "$label"
}

run_job() {
  assert_state_identity
  [[ $(state_get phase) == audited ]] || die 'run-job requires an audited receipt'
  [[ $(environment_count) -eq 0 ]] || die 'helper store is not empty before run-job'
  workflow_ref=$(state_get workflow_ref); disk_mib=$(state_get disk_mib)
  local acceptance_id profile label evidence run_id env_json before_pid after_pid
  acceptance_id=$(new_acceptance_id | tr -d '\n')
  profile="d3-$acceptance_id"; label="rm-d3-$acceptance_id"
  evidence="$evidence_root/run-$acceptance_id"; mkdir -m 700 "$evidence"
  install_service_and_profile "$profile" "$label" "$evidence"
  run_id=$(dispatch_job "$label")
  state_set normal_run_id "$run_id"
  env_json="$evidence/environment-live.json"
  capture_single_environment "$env_json" 600 >/dev/null
  state_set normal_environment_id "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["environment_id"])' "$env_json")"
  state_set normal_writable_disk_id "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["writable_disk_id"])' "$env_json")"
  require_opt_in "$allow_service_restart" --allow-service-restart 'forcing a disposable LaunchDaemon crash/restart'
  before_pid=$(service_pid); [[ -n $before_pid ]] || die 'LaunchDaemon PID is unavailable'
  kill -9 "$before_pid"
  for _ in {1..60}; do after_pid=$(service_pid); [[ -n $after_pid && $after_pid != "$before_pid" ]] && break; sleep 1; done
  [[ -n ${after_pid:-} && $after_pid != "$before_pid" ]] || die 'launchd did not restart the service with a new PID'
  helper_command inspect --environment "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["environment_id"])' "$env_json")" --json >"$evidence/environment-after-service-crash.json"
  printf '{"old_pid":%s,"new_pid":%s}\n' "$before_pid" "$after_pid" >"$evidence/service-restart.json"
  gh run watch "$run_id" --repo "$repository" --exit-status
  gh run view "$run_id" --repo "$repository" --log >"$evidence/workflow.log"
  grep -F 'RM_ACCEPTANCE guest_os=macos arch=arm64 cpu=2 memory_mib=4096 process_limit=512 host_shares=0 jit_env=absent' "$evidence/workflow.log" >/dev/null || die 'workflow omitted exact guest attestation'
  wait_no_environments 300
  assert_status_clean "$evidence/status-clean.json"
  scan_no_secrets "$evidence/host-secret-scan.txt"
  scan_service_process_no_secrets "$evidence/service-process-secret-scan.txt"
  remove_profile "$profile"; state_set profile_created false bool; state_set profile_name ''
  state_set phase normal-job-verified
  printf 'Live JIT job and service-crash recovery passed. Evidence: %s\n' "$evidence"
}

prepare_reboot() {
  assert_state_identity
  [[ $(state_get phase) == normal-job-verified ]] || die 'prepare-before-reboot requires a verified normal job'
  [[ $(environment_count) -eq 0 ]] || die 'helper store is not empty before reboot preparation'
  workflow_ref=$(state_get workflow_ref); disk_mib=$(state_get disk_mib)
  local acceptance_id profile label evidence run_id env_json disk_id
  acceptance_id=$(new_acceptance_id | tr -d '\n')
  profile="d3-reboot-$acceptance_id"; label="rm-d3-reboot-$acceptance_id"
  evidence="$evidence_root/reboot-$acceptance_id"; mkdir -m 700 "$evidence"
  require_opt_in "$allow_profile" --allow-profile 'creating the reboot-recovery profile'
  ensure_profile "$profile" "$label" "$evidence"
  state_set profile_created true bool; state_set profile_name "$profile"; state_set unique_label "$label"
  run_id=$(dispatch_job "$label"); state_set reboot_run_id "$run_id"
  env_json="$evidence/environment-before-reboot.json"; capture_single_environment "$env_json" 600 >/dev/null
  disk_id=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["writable_disk_id"])' "$env_json")
  [[ $disk_id != "$(state_get normal_writable_disk_id)" ]] || die 'two attempts reused one writable guest disk identity'
  state_set reboot_environment_id "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["environment_id"])' "$env_json")"
  state_set reboot_writable_disk_id "$disk_id"
  state_set prepared_boot_epoch "$(boot_epoch)" int
  state_set phase reboot-prepared
  printf 'Reboot receipt prepared at %s. Reboot macOS manually; this harness never initiates a reboot.\n' "$state_path"
}

verify_reboot() {
  assert_state_identity
  [[ $(state_get phase) == reboot-prepared ]] || die 'verify-after-reboot requires a reboot-prepared receipt'
  local before now evidence run_id profile
  before=$(state_get prepared_boot_epoch); now=$(boot_epoch)
  (( now > before )) || die 'host boot identity did not advance; perform a real macOS reboot first'
  evidence="$evidence_root/reboot-verified-$(date -u +%Y%m%d%H%M%S)"; mkdir -m 700 "$evidence"
  [[ -n $(service_pid) ]] || die 'disposable boot LaunchDaemon did not recover without an interactive start'
  run_id=$(state_get reboot_run_id)
  gh run cancel "$run_id" --repo "$repository" >/dev/null 2>&1 || true
  wait_no_environments 600
  assert_status_clean "$evidence/status-clean.json"
  runner service status >"$evidence/service-status.txt"
  scan_no_secrets "$evidence/host-secret-scan.txt"
  scan_service_process_no_secrets "$evidence/service-process-secret-scan.txt"
  profile=$(state_get profile_name); remove_profile "$profile"
  state_set profile_created false bool; state_set profile_name ''
  state_set verified_boot_epoch "$now" int; state_set phase reboot-verified
  printf 'Full host-reboot recovery passed. Evidence: %s\n' "$evidence"
}

forensics() {
  assert_state_identity
  local evidence="$evidence_root/forensics-$(date -u +%Y%m%d%H%M%S)"
  mkdir -m 700 "$evidence"
  helper_command probe --json >"$evidence/probe.json" || true
  runner service status >"$evidence/service-status.txt" 2>&1 || true
  runner status --json >"$evidence/status.json" 2>&1 || true
  launchctl print "system/$service_label" >"$evidence/launchd.txt" 2>&1 || true
  while IFS= read -r directory; do
    helper_command inspect --environment "$(basename "$directory")" --json >>"$evidence/environments.jsonl" || true
  done < <(environment_dirs)
  scan_no_secrets "$evidence/host-secret-scan.txt"
  printf 'Read-only recovery forensics: %s\n' "$evidence"
}

cleanup() {
  assert_state_identity; require_opt_in "$allow_cleanup" --allow-cleanup 'acceptance cleanup'
  local profile directory metadata environment host attempt generation
  remove_trigger_label
  cancel_recorded_runs
  profile=$(state_get profile_name); [[ -z $profile ]] || remove_profile "$profile"
  state_set profile_created false bool; state_set profile_name ''
  while IFS= read -r directory; do
    metadata="$directory/metadata.json"
    [[ -r $metadata ]] || die "cannot prove ownership for '$directory'"
    read -r environment host attempt generation < <(python3 - "$metadata" <<'PY'
import json,sys
r=json.load(open(sys.argv[1])); print(r['environment_id'],r['host_id'],r['attempt_id'],r['generation'])
PY
)
    [[ $environment == rm-* ]] || die 'refusing to destroy an unrecognized environment'
    case "$environment" in
      "$(state_get normal_environment_id)"|"$(state_get reboot_environment_id)") ;;
      *) die "refusing to destroy environment '$environment' because the receipt does not own it" ;;
    esac
    helper_command destroy --environment "$environment" --host "$host" --attempt "$attempt" --generation "$generation"
  done < <(environment_dirs)
  wait_no_environments 60
  state_set cleanup_complete true bool
  printf 'Owned profiles and helper environments are clean.\n'
}

rollback() {
  assert_state_identity; require_opt_in "$allow_rollback" --allow-rollback 'uninstalling the disposable LaunchDaemon and deleting its receipt'
  [[ $(state_get cleanup_complete) == true ]] || die 'run cleanup successfully before rollback'
  [[ $(state_get profile_created) == false ]] || die 'cleanup the temporary profile before rollback'
  [[ $(environment_count) -eq 0 ]] || die 'cleanup helper environments before rollback'
  if [[ $(state_get service_installed) == true ]]; then runner service uninstall >/dev/null; fi
  wait_service_absent 30
  rm -f "$state_path"
  printf 'Disposable service and receipt rolled back. Evidence remains at %s\n' "$evidence_root"
}

case "$phase" in
  audit) run_audit ;;
  run-job) run_job ;;
  prepare-before-reboot) prepare_reboot ;;
  verify-after-reboot) verify_reboot ;;
  recovery-forensics) forensics ;;
  cleanup) cleanup ;;
  rollback) rollback ;;
esac
