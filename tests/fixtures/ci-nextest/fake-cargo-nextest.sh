#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 && $1 == nextest && $2 == --version ]]
printf 'cargo-nextest %s (contract fixture)\n' "${CI_NEXTEST_FAKE_VERSION:-0.9.146}"
