#!/usr/bin/env bash
set -euo pipefail

# Secret-free native Linux acceptance for the production OCI path. GitHub's
# hosted Ubuntu runner gives this job passwordless sudo for fixture setup only;
# Podman and every provider operation remain rootless.

die() {
  echo "native Linux OCI acceptance: $*" >&2
  exit 1
}

[[ "$(uname -s)" == Linux ]] || die "this harness requires native Linux"
[[ "$(id -u)" -ne 0 ]] || die "Podman must execute rootless"
: "${RUNNER_TEMP:?RUNNER_TEMP must identify the hosted runner temporary directory}"
: "${RUNNER_MANAGER_OCI_ACCEPTANCE_IMAGE:?a pinned OCI image digest is required}"
[[ "$RUNNER_MANAGER_OCI_ACCEPTANCE_IMAGE" == *@sha256:* ]] ||
  die "RUNNER_MANAGER_OCI_ACCEPTANCE_IMAGE is not digest pinned"

fixture="$RUNNER_TEMP/runner-manager-oci-acceptance"
image_file="$fixture/rootless-storage.ext4"
mount_point="$fixture/store"
graph_root="$mount_point/graph"
run_root="$fixture/run"
storage_conf="$fixture/storage.conf"
runtime_helper="/usr/local/libexec/runner-manager-oci-native-acceptance"
mounted=false
helper_created=false

cleanup() {
  status=$?
  set +e
  if [[ -x "$runtime_helper" ]]; then
    "$runtime_helper" rm --all --force >/dev/null 2>&1
    "$runtime_helper" system reset --force >/dev/null 2>&1
  fi
  if $mounted; then
    sudo umount "$mount_point"
  fi
  sudo rm -rf "$fixture"
  if $helper_created; then
    sudo rm -f "$runtime_helper"
  fi
  exit "$status"
}
trap cleanup EXIT

rm -rf "$fixture"
[[ ! -e "$runtime_helper" ]] || die "$runtime_helper already exists"
mkdir -p "$mount_point" "$run_root"
truncate -s 1024M "$image_file"
sudo mkfs.ext4 -q -F -m 0 "$image_file"
sudo mount -o loop,nodev,nosuid "$image_file" "$mount_point"
mounted=true
sudo chown "$(id -u):$(id -g)" "$mount_point"
chmod 0700 "$mount_point" "$run_root"
mkdir -p "$graph_root"

cat > "$storage_conf" <<EOF
[storage]
driver = "overlay"
runroot = "$run_root"
graphroot = "$graph_root"
rootless_storage_path = "$graph_root"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
mountopt = "nodev"
EOF

helper_source="$fixture/runtime-helper"
cat > "$helper_source" <<'HELPER'
#!/usr/bin/env bash
set -euo pipefail

storage_conf='__STORAGE_CONF__'
graph_root='__GRAPH_ROOT__'
export CONTAINERS_STORAGE_CONF="$storage_conf"

verify_bounded_store() {
  [[ "$(findmnt -T "$graph_root" -no FSTYPE)" == "ext4" ]] || exit 78
  source="$(findmnt -T "$graph_root" -no SOURCE)"
  [[ "$source" == /dev/loop* ]] || exit 78
  read -r block_size block_count < <(stat -f -c '%S %b' "$graph_root")
  capacity=$((block_size * block_count))
  ((capacity <= 1024 * 1024 * 1024)) || exit 78
}

requested=""
command_name=""
args=()
while (($#)); do
  if [[ "$1" == "--storage-opt" ]]; then
    (($# >= 2)) || exit 64
    [[ "$2" == size=* ]] || exit 64
    requested="${2#size=}"
    shift 2
    continue
  fi
  [[ -n "$command_name" || "$1" == -* ]] || command_name="$1"
  args+=("$1")
  shift
done

verify_bounded_store
if [[ -n "$requested" && "$requested" != "1024m" ]]; then
  echo "bounded store has no slot for requested size $requested" >&2
  exit 69
fi

if [[ -n "$requested" && "$command_name" == "info" ]]; then
  raw="$(podman "${args[@]}")"
  BOUNDED_INFO="$raw" python3 - <<'PY'
import json
import os

info = json.loads(os.environ["BOUNDED_INFO"])
info["runnerManagerStorage"] = {
    "schema": 1,
    "mode": "exclusive-filesystem-pool",
    "requestedMiB": 1024,
    "hardCap": True,
}
print(json.dumps(info, separators=(",", ":")))
PY
  exit 0
fi

exec podman "${args[@]}"
HELPER
sed -i "s|__STORAGE_CONF__|$storage_conf|g; s|__GRAPH_ROOT__|$graph_root|g" "$helper_source"
sudo install -d -m 0755 -o root -g root /usr/local/libexec
sudo install -m 0755 -o root -g root "$helper_source" "$runtime_helper"
helper_created=true
sudo chown root:root "$storage_conf"
sudo chmod 0644 "$storage_conf"

mount_evidence="$(findmnt -T "$mount_point" -no TARGET,SOURCE,FSTYPE,OPTIONS)"
echo "$mount_evidence"
grep -Eq '^/.* /dev/loop[0-9]+ ext4 .*(nodev|nosuid)' <<<"$mount_evidence" ||
  die "bounded store is not the disposable ext4 loop mount"
[[ "$(stat -c '%u:%g %a' "$runtime_helper")" == "0:0 755" ]] ||
  die "runtime helper is not immutable and root-owned"

"$runtime_helper" --storage-opt size=1024m info --format=json > "$fixture/probe.json"
python3 - "$fixture/probe.json" "$graph_root" <<'PY'
import json
import pathlib
import sys

info = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert info["host"]["security"]["rootless"] is True
assert info["host"]["cgroupVersion"] == "v2"
assert {"cpu", "memory", "pids"} <= set(info["host"]["cgroupControllers"])
assert info["store"]["graphRoot"] == sys.argv[2]
assert info["store"]["graphStatus"]["Backing Filesystem"] == "extfs"
assert info["runnerManagerStorage"] == {
    "schema": 1,
    "mode": "exclusive-filesystem-pool",
    "requestedMiB": 1024,
    "hardCap": True,
}
PY

RUNNER_MANAGER_OCI_RUNTIME="$runtime_helper" \
  cargo test -p runner-manager-agent \
    'oci::tests::live_rootless_bounded_storage_acceptance' -- \
    --ignored --exact --nocapture

remaining="$("$runtime_helper" ps --all --quiet)"
[[ -z "$remaining" ]] || die "acceptance containers survived cleanup: $remaining"
if grep -r -a -q 'rm-jit-sentinel-' "$graph_root"; then
  die "a synthetic JIT sentinel survived in bounded runtime storage"
fi
echo "native Linux bounded-store acceptance passed"
