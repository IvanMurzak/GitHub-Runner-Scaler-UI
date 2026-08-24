# End-to-end acceptance evidence

`cargo test -p runner-manager-e2e -- --ignored --nocapture` emits one JSON
report for the current OS under `target/e2e-reports/`. With any of the four
fixture inputs absent it prints one `SKIP` line and succeeds.

The suite deliberately does not pretend that a subprocess can reboot its host,
isolate the host network, or create a second physical machine. The native host
controller performs those operations and supplies its evidence directory with
`RUNNER_MANAGER_E2E_EVIDENCE_DIR` (default: `.e2e-evidence/<os>`).

The directory contains these schema-1 JSON records:

- `successful_jit_job.json`
- `network_outage_recovery.json`
- `jit_expiry_recovery.json`
- `policy_disable_drain.json`
- `boot_start_recovery.json`
- `organization_scoped_job.json`
- `monitor_only_demand.json`
- `two_host_contention.json`
- `rollback.json`

Each scenario record names its scenario, OS and scope, includes non-empty
`observed_evidence`, and records the three mandatory post-conditions:
`registered_runners_after: 0`, `runtime_directories_after: 0`, and
`legacy_label_reused: false`. The rollback record separately proves label
restore, drain, terminal attempts, and legacy re-enable in that order.

`security/` contains schema-1 JSON evidence for `two_job_contamination`,
`runner_package_integrity`, `revoked_token_rejection`, `workspace_removal`, and
`restart_duplicate_poll`. Every record names its gate and OS, contains
non-empty `observed_evidence`, and records the exact
`control_removed_failure` observed during the deliberate mutation. It also
contains `jit-marker.txt`,
`secret-scan-root/` (logs, database, snapshots, crash reports and CLI output),
and `config-and-sqlite/`. The suite scans those artifacts with the real product
token and JIT marker, and includes mutation checks showing the scanners reject
deliberately injected values.

The product token is used only to drive and inspect runner-manager. The fixture
token is used only by the controller to edit/dispatch the disposable workflow
and by the suite for a read-only fixture-reachability check. Do not widen the
product token to make fixture setup pass.
