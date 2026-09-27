#!/bin/sh
set -eu

usage() {
    cat >&2 <<'EOF'
usage: ./install.sh --signing-identity IDENTITY

Builds, signs, verifies, and installs runner-manager-macos-vm. Use '-' only
for local development; native acceptance requires the operator's production
code-signing identity.
Run as the logged-in owner. Only installation uses interactive sudo; building
and signing use the owner's existing login keychain.
EOF
    exit 64
}

[ "$(uname -s)" = Darwin ] || { echo 'install.sh requires macOS' >&2; exit 78; }
[ "$(id -u)" -ne 0 ] || { echo 'run install.sh as the logged-in owner without sudo; installation will request sudo when needed' >&2; exit 78; }
[ "$#" -eq 2 ] || usage
[ "$1" = --signing-identity ] || usage
identity=$2
[ -n "$identity" ] || usage

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
swift build --package-path "$package_dir" -c release
binary=$(swift build --package-path "$package_dir" -c release --show-bin-path)/runner-manager-macos-vm
codesign --force --options runtime \
    --entitlements "$package_dir/runner-manager-macos-vm.entitlements" \
    --sign "$identity" "$binary"
codesign --verify --strict --verbose=2 "$binary"

sudo install -d -m 0755 /usr/local/libexec /usr/local/bin
sudo install -m 0755 "$binary" /usr/local/libexec/runner-manager-macos-vm
sudo ln -sfn ../libexec/runner-manager-macos-vm /usr/local/bin/runner-manager-macos-vm
store='/Library/Application Support/io.github.IvanMurzak.runner-manager/macos-vm-helper'
sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" "$store" "$store/templates" "$store/environments"

echo 'installed /usr/local/libexec/runner-manager-macos-vm'
echo 'next: register a bootstrap-ready, digest-pinned template as documented in docs/macos-vm-helper.md'
