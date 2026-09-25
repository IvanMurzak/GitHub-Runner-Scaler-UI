#!/bin/sh
set -eu

usage() {
    cat >&2 <<'EOF'
usage: sudo ./install.sh --signing-identity IDENTITY

Builds, signs, verifies, and installs runner-manager-macos-vm. Use '-' only
for local development; native acceptance requires the operator's production
code-signing identity.
EOF
    exit 64
}

[ "$(uname -s)" = Darwin ] || { echo 'install.sh requires macOS' >&2; exit 78; }
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

install -d -m 0755 /usr/local/libexec /usr/local/bin
install -m 0755 "$binary" /usr/local/libexec/runner-manager-macos-vm
ln -sfn ../libexec/runner-manager-macos-vm /usr/local/bin/runner-manager-macos-vm
install -d -m 0700 '/Library/Application Support/io.github.IvanMurzak.runner-manager/macos-vm-helper/templates'
install -d -m 0700 '/Library/Application Support/io.github.IvanMurzak.runner-manager/macos-vm-helper/environments'

echo 'installed /usr/local/libexec/runner-manager-macos-vm'
echo 'next: register a bootstrap-ready, digest-pinned template as documented in docs/macos-vm-helper.md'
