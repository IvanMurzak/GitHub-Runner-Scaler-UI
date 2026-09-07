#!/usr/bin/env bash
set -euo pipefail

die() { printf 'shippable-mutant-guard: %s\n' "$*" >&2; exit 1; }

if grep -R -E 'RUNNER_MANAGER_TEST_MUTANT|test-mutants' \
  crates/domain/src crates/domain/Cargo.toml crates/agent/Cargo.toml >/dev/null; then
  die "a public feature or environment-controlled domain mutant remains in source"
fi

# ----------------------------------------------------------------------------
# The same rule, extended to the two crates the managed WSL host feature lives
# in (b3-acceptance-docs: "extend ... guards for every new private/public
# command").
#
# `crates/agent/src` is deliberately NOT in this list: its mutants are the ones
# the acceptance suite injects, they live inside `#[cfg(test)]` controls, and the
# binary scan below is what proves none of them ships. These two crates have no
# mutant of any kind, and this is what keeps it that way -- `wsl install` is a
# transaction that installs a binary and issues a credential, and an
# environment-controlled branch through it would be worth more to an attacker
# than to a test.
if grep -R -E 'RUNNER_MANAGER_TEST_MUTANT|test-mutants' \
  crates/platform/src crates/platform/Cargo.toml \
  crates/app/src crates/app/Cargo.toml >/dev/null; then
  die "an environment-controlled mutant or a public mutant feature reached the platform or CLI crate"
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

# ----------------------------------------------------------------------------
# The WSL adapter's test double is a mutant of the same kind, by a different
# name.
# ----------------------------------------------------------------------------
# `ScriptedRunner` answers `wsl.exe` and `schtasks.exe` from a table instead of
# starting them, and `WslHost::with_runner` is the seam that injects it. Both
# are ordinary `pub` items rather than `#[cfg(test)]` ones, because the
# acceptance suites in three crates need them -- so nothing in the type system
# stops the shipping binary from reaching one, and "the provisioning transaction
# ran against a fake Task Scheduler" is exactly the class of thing this file
# exists to make impossible.
#
# Today the linker drops both: the binary only ever constructs
# `HostCommandRunner`, through `WslHost::on_this_host`. This turns that fact
# into a gate, so a future edit that wires a fake into a shipping code path
# fails here rather than in production.
if grep -a -E 'ScriptedRunner|RecordedRequest' "$binary" >/dev/null; then
  die "the WSL adapter's test double was linked into the shippable binary"
fi

printf 'shippable-mutant-guard: all-features binary is clean\n'
