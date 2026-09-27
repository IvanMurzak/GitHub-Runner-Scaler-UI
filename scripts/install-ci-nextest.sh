#!/usr/bin/env bash
set -euo pipefail

# install-action bootstraps jq/curl/tar through apt + sudo on minimal Linux/WSL.
# Install the same pinned tool from its supported locked source package instead,
# without modifying system packages, sudo policy, or the user's installed tools.
: "${RUNNER_TEMP:?a job-owned RUNNER_TEMP is required}"
: "${GITHUB_PATH:?the job path file is required}"
[[ $RUNNER_TEMP == /* && $RUNNER_TEMP != / ]] || { printf 'RUNNER_TEMP must be an absolute job directory\n' >&2; exit 2; }
nextest_root="$RUNNER_TEMP/runner-manager-nextest"
nextest_version=0.9.146
CARGO_BUILD_JOBS=2 cargo install --locked --version "$nextest_version" --root "$nextest_root" cargo-nextest
installed_version=$("$nextest_root/bin/cargo-nextest" nextest --version)
[[ $installed_version == "cargo-nextest $nextest_version" || $installed_version == "cargo-nextest $nextest_version "* ]] || {
  printf 'installed nextest does not match the pinned version\n' >&2
  exit 1
}
printf '%s\n' "$nextest_root/bin" >>"$GITHUB_PATH"
printf '%s\n' "$installed_version"
