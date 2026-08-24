#!/usr/bin/env bash
set -euo pipefail

die() { printf 'shippable-mutant-guard: %s\n' "$*" >&2; exit 1; }

if grep -R -E 'RUNNER_MANAGER_TEST_MUTANT|test-mutants' \
  crates/domain/src crates/domain/Cargo.toml crates/agent/Cargo.toml >/dev/null; then
  die "a public feature or environment-controlled domain mutant remains in source"
fi

if [[ "${1-}" != --scan-only ]]; then
  cargo build --workspace --all-features
fi

binary=target/debug/runner-manager
[[ -f "$binary" ]] || binary=target/debug/runner-manager.exe
[[ -f "$binary" ]] || die "all-features runner-manager binary is absent"

if grep -a -E \
  'RUNNER_MANAGER_TEST_MUTANT|skip_checksum_comparison|accept_missing_checksum|reuse_job_workspace|skip_workspace_cleanup|start_with_revoked_credential|ignore_in_flight_attempts' \
  "$binary" >/dev/null; then
  die "a test-only mutant marker was linked into the shippable binary"
fi

printf 'shippable-mutant-guard: all-features binary is clean\n'
