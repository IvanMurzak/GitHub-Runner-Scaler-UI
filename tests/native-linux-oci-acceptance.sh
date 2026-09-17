#!/usr/bin/env bash
set -euo pipefail

# Native Linux acceptance for d1's real rootless OCI adapter. GitHub documents
# that its ordinary Ubuntu hosted runners are fresh VMs with passwordless sudo:
# https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges
# That lets this secret-free job create a disposable quota-capable filesystem.
# containers/storage documents that overlay hard size limits require XFS mounted
# with pquota, and that rootless users may select a dedicated storage.conf:
# https://github.com/containers/storage/blob/main/docs/containers-storage.conf.5.md#quotas

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
image_file="$fixture/rootless-storage.xfs"
mount_point="$fixture/xfs"
run_root="$fixture/runroot"
storage_conf="$fixture/storage.conf"
mounted=false

cleanup() {
  status=$?
  set +e
  podman rm --all --force >/dev/null 2>&1
  podman system reset --force >/dev/null 2>&1
  if $mounted; then
    sudo umount "$mount_point"
  fi
  rm -rf "$fixture"
  exit "$status"
}
trap cleanup EXIT

mkdir -p "$fixture" "$mount_point" "$run_root"
truncate -s 6G "$image_file"
sudo mkfs.xfs -f -q "$image_file"
sudo mount -o loop,pquota "$image_file" "$mount_point"
mounted=true
sudo chown "$(id -u):$(id -g)" "$mount_point"
chmod 0700 "$mount_point" "$run_root"
mkdir -p "$mount_point/graphroot"

cat > "$storage_conf" <<EOF
[storage]
driver = "overlay"
runroot = "$run_root"
graphroot = "$mount_point/graphroot"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
mountopt = "nodev"
EOF
chmod 0600 "$storage_conf"
export CONTAINERS_STORAGE_CONF="$storage_conf"

findmnt -T "$mount_point" -no FSTYPE,OPTIONS | tee "$fixture/mount.txt"
grep -Eq '^xfs .*(pquota|prjquota)' "$fixture/mount.txt" ||
  die "the disposable XFS store is not mounted with project quotas"

podman info --format json > "$fixture/podman-info.json"
python3 - "$fixture/podman-info.json" "$mount_point/graphroot" <<'PY'
import json
import pathlib
import sys

info = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert info["host"]["security"]["rootless"] is True
assert info["host"]["cgroupVersion"] == "v2"
assert {"cpu", "memory", "pids"} <= set(info["host"]["cgroupControllers"])
assert info["store"]["graphRoot"] == sys.argv[2]
assert info["store"]["graphStatus"]["Backing Filesystem"] == "xfs"
assert any(item["size"] >= 65536 for item in info["host"]["idMappings"]["uidmap"])
assert any(item["size"] >= 65536 for item in info["host"]["idMappings"]["gidmap"])
PY

# This is the same pre-JIT hard-cap probe the adapter executes. Do not proceed
# to an unbounded substitute if the installed runtime cannot enforce it.
podman --storage-opt size=1024m info --format json >/dev/null

cargo test -p runner-manager-agent \
  'oci::tests::live_rootless_native_acceptance' -- \
  --ignored --exact --nocapture

# The Rust fixture owns normal and orphan cleanup. This independent sweep makes
# a leaked owned container fail the job before the disposable store is removed.
remaining="$(podman ps --all --quiet)"
[[ -z "$remaining" ]] || die "acceptance containers survived cleanup: $remaining"
