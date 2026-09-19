#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
package="$root/native/macos-vm-helper"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/runner-manager-macos-vm-json.XXXXXX")
trap 'rm -rf "$fixture"' EXIT

swift build --package-path "$package"
binary=$(swift build --package-path "$package" --show-bin-path)/runner-manager-macos-vm
architecture=$(uname -m)

python3 - "$fixture" "$architecture" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
architecture = sys.argv[2]
artifacts = {
    "Disk.img": b"disk fixture\n",
    "AuxiliaryStorage": b"auxiliary fixture\n",
    "HardwareModel": b"hardware model fixture\n",
}
identity = {
    "architecture": architecture,
    "auxiliary_storage_sha256": hashlib.sha256(artifacts["AuxiliaryStorage"]).hexdigest(),
    "bootstrap_port": 22022,
    "bootstrap_protocol": 1,
    "disk_mib": 32768,
    "disk_sha256": hashlib.sha256(artifacts["Disk.img"]).hexdigest(),
    "guest_os": "macos",
    "hardware_model_sha256": hashlib.sha256(artifacts["HardwareModel"]).hexdigest(),
    "process_limit": 512,
    "process_limit_mechanism": "rlimit_nproc_dedicated_uid",
    "schema_version": 1,
    "version": "cli-json-contract-v1",
}
identity_json = json.dumps(identity, separators=(",", ":"), sort_keys=True).encode()
digest = hashlib.sha256(b"runner-manager-macos-vm-template-v1\n" + identity_json).hexdigest()
image = f"vm-version:{identity['version']}@sha256:{digest}"
template = root / "templates" / digest
template.mkdir(parents=True)
for name, contents in artifacts.items():
    (template / name).write_bytes(contents)
(template / "manifest.json").write_text(json.dumps({
    "bootstrap_ready": True,
    "identity": identity,
    "image": image,
    "immutable": True,
    "template_digest": digest,
}, separators=(",", ":"), sort_keys=True))
(root / "image.txt").write_text(image)
PY

image=$(cat "$fixture/image.txt")
RUNNER_MANAGER_MACOS_VM_ROOT="$fixture" \
  "$binary" --protocol-version 1 image inspect --image "$image" --json > "$fixture/response.json"

python3 - "$fixture/response.json" "$image" "$architecture" <<'PY'
import json
import pathlib
import sys

response = json.loads(pathlib.Path(sys.argv[1]).read_text())
image = sys.argv[2]
architecture = sys.argv[3]
expected_keys = {
    "protocol_version",
    "image",
    "template_digest",
    "guest_os",
    "architecture",
    "immutable",
    "bootstrap_ready",
}
assert set(response) == expected_keys, response
assert response["protocol_version"] == 1, response
assert response["image"] == image, response
assert response["template_digest"] == image.split("@sha256:", 1)[1], response
assert response["guest_os"] == "macos", response
assert response["architecture"] == architecture, response
assert response["immutable"] is True, response
assert response["bootstrap_ready"] is True, response
PY

echo 'macOS VM helper CLI JSON contract passed'
