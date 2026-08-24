#!/usr/bin/env bash
# Repository-owned bridge between disruptive native-host commands and the
# acceptance validator. It never invents evidence: prepare refuses an absent or
# incomplete controller journal, and finalize refuses a missing OS report.
set -euo pipefail

die() { printf 'e2e-host-controller: %s\n' "$*" >&2; exit 1; }

case "${1-}" in
  prepare)
    source_dir="${2-}"
    destination="${3-}"
    os_name="${4-}"
    [[ -n "$source_dir" && -d "$source_dir" ]] || die "native controller evidence source is absent: ${source_dir:-<unset>}"
    [[ -n "$destination" && -n "$os_name" ]] || die "prepare needs SOURCE DESTINATION OS"
    marker="$source_dir/controller.json"
    [[ -f "$marker" ]] || die "missing controller.json"
    grep -qF '"controller":"runner-manager-e2e-host-controller/v1"' "$marker" || die "controller.json was not produced by the repository controller"
    grep -qF "\"os\":\"$os_name\"" "$marker" || die "controller.json belongs to another OS"
    for scenario in successful_jit_job network_outage_recovery jit_expiry_recovery policy_disable_drain boot_start_recovery organization_scoped_job monitor_only_demand two_host_contention; do
      [[ -f "$source_dir/$scenario.json" ]] || die "missing causal journal for $scenario"
    done
    [[ -f "$source_dir/rollback.json" ]] || die "missing ordered rollback journal"
    [[ -s "$source_dir/security/jit-marker.txt" ]] || die "missing JIT leak marker"
    for category in logs database snapshots crash-reports cli-output; do
      [[ -d "$source_dir/security/secret-scan-root/$category" ]] || die "missing secret-scan category $category"
    done
    mkdir -p "$destination"
    cp -R "$source_dir"/. "$destination"/
    ;;
  finalize)
    report="${2-}"
    destination="${3-}"
    [[ -s "$report" ]] || die "acceptance report was not produced: ${report:-<unset>}"
    mkdir -p "$destination"
    cp "$report" "$destination"/
    ;;
  *)
    die "usage: bash tests/host-controller.sh prepare SOURCE DESTINATION OS | finalize REPORT DESTINATION"
    ;;
esac
