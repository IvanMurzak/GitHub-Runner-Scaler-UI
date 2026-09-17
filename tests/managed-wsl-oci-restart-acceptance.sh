#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "managed WSL OCI restart acceptance: $*" >&2
  exit 1
}

[[ "$(uname -s)" == Linux ]] || die "this harness requires Linux"
grep -qi microsoft /proc/sys/kernel/osrelease || die "this harness requires WSL2"
[[ "$(id -u)" -eq 0 ]] || die "run this harness as WSL root"

phase="${1:-}"
source_root="${2:-}"
managed_user="${3:-}"
[[ "$phase" =~ ^(setup|seed|remount|recover|cleanup)$ ]] ||
  die "phase must be setup, seed, remount, recover, or cleanup"
[[ -n "$managed_user" ]] || die "managed user is required"

managed_uid="$(id -u "$managed_user")"
managed_gid="$(id -g "$managed_user")"
managed_home="$(getent passwd "$managed_user" | cut -d: -f6)"
[[ "$managed_uid" -ne 0 ]] || die "Podman must execute rootless"

fixture="$managed_home/.local/share/runner-manager-wsl-oci-restart"
image_file="/var/lib/runner-manager-wsl-oci-restart.ext4"
mount_point="$fixture/store"
graph_root="$mount_point/graph"
run_root="$fixture/run"
cargo_target="$managed_home/.cache/runner-manager-wsl-oci-restart-target"
storage_conf="$fixture/storage.conf"
runtime_helper="/usr/local/libexec/runner-manager-oci-restart-acceptance"
acceptance_image="docker.io/library/ubuntu@sha256:496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4"

as_managed() {
  runuser -u "$managed_user" -- env \
    HOME="$managed_home" USER="$managed_user" LOGNAME="$managed_user" \
    XDG_RUNTIME_DIR="/run/user/$managed_uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$managed_uid/bus" \
    CONTAINERS_STORAGE_CONF="$storage_conf" \
    "$@"
}

verify_mount() {
  evidence="$(findmnt -T "$graph_root" -no TARGET,SOURCE,FSTYPE,OPTIONS)"
  echo "$evidence"
  grep -Eq '^/home/.* /dev/loop[0-9]+ ext4 .*(nodev|nosuid)' <<<"$evidence" ||
    die "bounded store is not the disposable ext4 loop mount"
}

write_helper() {
  cat > "$runtime_helper" <<'HELPER'
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
  ((block_size * block_count <= 1024 * 1024 * 1024)) || exit 78
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
  sed -i "s|__STORAGE_CONF__|$storage_conf|g; s|__GRAPH_ROOT__|$graph_root|g" "$runtime_helper"
  chown root:root "$runtime_helper"
  chmod 0755 "$runtime_helper"
}

run_test() {
  test_name="$1"
  cargo_bin="$managed_home/.cargo/bin/cargo"
  [[ -x "$cargo_bin" ]] || cargo_bin="$(command -v cargo)"
  as_managed env \
    CARGO_TARGET_DIR="$cargo_target" \
    RUNNER_MANAGER_OCI_RUNTIME="$runtime_helper" \
    RUNNER_MANAGER_OCI_ACCEPTANCE_IMAGE="$acceptance_image" \
    RUNNER_MANAGER_OCI_RESTART_FIXTURE="$fixture" \
    "$cargo_bin" test -p runner-manager-agent "$test_name" -- \
      --ignored --exact --nocapture
}

case "$phase" in
  setup)
    [[ -n "$source_root" && -f "$source_root/Cargo.toml" ]] || die "repository root is required"
    [[ ! -e "$runtime_helper" ]] || die "$runtime_helper already exists"
    [[ ! -e "$image_file" ]] || die "$image_file already exists"
    rm -rf "$fixture"
    mkdir -p "$mount_point" "$run_root" "$cargo_target"
    chown -R "$managed_uid:$managed_gid" "$fixture"
    chown -R "$managed_uid:$managed_gid" "$cargo_target"
    truncate -s 1024M "$image_file"
    mkfs.ext4 -q -F -m 0 "$image_file"
    mount -o loop,nodev,nosuid "$image_file" "$mount_point"
    chown "$managed_uid:$managed_gid" "$mount_point"
    chmod 0700 "$mount_point" "$run_root" "$cargo_target"
    install -d -m 0700 -o "$managed_uid" -g "$managed_gid" "$graph_root"
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
    chown root:root "$storage_conf"
    chmod 0644 "$storage_conf"
    install -d -m 0755 -o root -g root /usr/local/libexec
    write_helper
    verify_mount
    ;;
  seed)
    cd "$source_root"
    run_test 'oci::tests::live_rootless_managed_wsl_restart_seed'
    resource_count="$(as_managed "$runtime_helper" ps --all --quiet | sed '/^$/d' | wc -l)"
    [[ "$resource_count" -eq 4 ]] || die "seed did not leave four provider resources"
    awk '{print $22}' /proc/1/stat > "$fixture/pid1-start-before"
    cat /proc/sys/kernel/random/boot_id > "$fixture/windows-session-boot-id"
    chown "$managed_uid:$managed_gid" "$fixture/pid1-start-before" "$fixture/windows-session-boot-id"
    # A loop filesystem has a cache inside the WSL filesystem cache. Flush both
    # layers so terminating the distribution tests recovery from durable state,
    # not loss of deliberately unwritten fixture setup.
    sync -f "$mount_point"
    blockdev --flushbufs "$(findmnt -T "$graph_root" -no SOURCE)"
    sync "$image_file"
    ;;
  remount)
    [[ -f "$image_file" && -x "$runtime_helper" ]] || die "seed fixture is absent"
    if ! mountpoint -q "$mount_point"; then
      mount -o loop,nodev,nosuid "$image_file" "$mount_point"
    fi
    before="$(cat "$fixture/pid1-start-before")"
    after="$(awk '{print $22}' /proc/1/stat)"
    [[ "$before" != "$after" ]] || die "PID 1 did not restart across wsl --terminate"
    [[ "$(cat "$fixture/windows-session-boot-id")" == "$(cat /proc/sys/kernel/random/boot_id)" ]] ||
      die "the WSL VM rebooted; this harness must not substitute a host reboot"
    printf '%s\n' "$after" > "$fixture/pid1-start-after"
    rm -rf "$run_root"
    install -d -m 0700 -o "$managed_uid" -g "$managed_gid" "$run_root"
    install -d -m 0700 -o "$managed_uid" -g "$managed_gid" "/run/user/$managed_uid"
    verify_mount
    ;;
  recover)
    cd "$source_root"
    run_test 'oci::tests::live_rootless_managed_wsl_restart_recover'
    cargo_bin="$managed_home/.cargo/bin/cargo"
    [[ -x "$cargo_bin" ]] || cargo_bin="$(command -v cargo)"
    as_managed env CARGO_TARGET_DIR="$cargo_target" \
      "$cargo_bin" test -p runner-manager-agent \
        'lifecycle::tests::isolated_restart_at_each_transition_adopts_or_destroys_one_resource' -- \
        --exact --nocapture
    cat "$fixture/recovery-complete"
    ;;
  cleanup)
    set +e
    if [[ -x "$runtime_helper" ]] && mountpoint -q "$mount_point"; then
      as_managed "$runtime_helper" rm --all --force >/dev/null 2>&1
      as_managed "$runtime_helper" system reset --force >/dev/null 2>&1
    fi
    mountpoint -q "$mount_point" && umount "$mount_point"
    rm -rf "$fixture" "$cargo_target"
    rm -f "$image_file" "$runtime_helper"
    ;;
esac
