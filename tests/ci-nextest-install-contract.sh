#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
export RUNNER_TEMP="$temporary/runner temp"
export GITHUB_PATH="$temporary/job-path"
export CI_NEXTEST_FAKE_BINARY="$root/tests/fixtures/ci-nextest/fake-cargo-nextest.sh"
export CI_NEXTEST_ARGUMENTS="$temporary/arguments"
mkdir -p "$RUNNER_TEMP"
touch "$GITHUB_PATH"
cargo() {
  [[ $CARGO_BUILD_JOBS == 2 ]]
  printf '%s\n' "$@" >"$CI_NEXTEST_ARGUMENTS"
  [[ $1 == install && $2 == --locked && $3 == --version && $4 == 0.9.146 && $5 == --root && $7 == cargo-nextest ]]
  [[ ${CI_NEXTEST_FAIL_INSTALL:-false} != true ]] || return 23
  mkdir -p "$6/bin"
  cp "$CI_NEXTEST_FAKE_BINARY" "$6/bin/cargo-nextest"
  chmod 755 "$6/bin/cargo-nextest"
}
export -f cargo
bash "$root/scripts/install-ci-nextest.sh" >"$temporary/success.log"
[[ $(cat "$GITHUB_PATH") == "$RUNNER_TEMP/runner-manager-nextest/bin" ]]
[[ $(cat "$CI_NEXTEST_ARGUMENTS") == "$(printf '%s\n' install --locked --version 0.9.146 --root "$RUNNER_TEMP/runner-manager-nextest" cargo-nextest)" ]]
cp "$GITHUB_PATH" "$temporary/original-path"
for scenario in install_failure wrong_version; do
  if [[ $scenario == install_failure ]]; then
    export CI_NEXTEST_FAIL_INSTALL=true CI_NEXTEST_FAKE_VERSION=0.9.146
  else
    export CI_NEXTEST_FAIL_INSTALL=false CI_NEXTEST_FAKE_VERSION=9.9.9
  fi
  if bash "$root/scripts/install-ci-nextest.sh" >"$temporary/$scenario.log" 2>&1; then
    printf 'nextest setup unexpectedly accepted %s\n' "$scenario" >&2
    exit 1
  fi
  cmp "$GITHUB_PATH" "$temporary/original-path"
done
if rg '\bsudo\b|apt-get' "$root/scripts/install-ci-nextest.sh" | rg -v '^#'; then
  printf 'unprivileged setup contains a privileged command\n' >&2
  exit 1
fi
printf 'Unprivileged CI nextest installation contract passed\n'
