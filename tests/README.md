# End-to-end acceptance evidence

`cargo test -p runner-manager-e2e -- --ignored --nocapture` emits one JSON
report for the current OS under `target/e2e-reports/`. With any of the four
fixture inputs absent it prints one `SKIP` line and succeeds.

The suite deliberately does not pretend that a subprocess can reboot its host,
isolate the host network, or create a second physical machine. The native host
controller performs those operations. CI always starts with a nonexistent,
job-private evidence path and runs
`cargo run -p runner-manager-e2e --example e2e-host-controller -- run-live-suite DIR`.
The command rejects an existing directory, so imported journals can never be
promoted into live evidence. When the four GitHub fixture inputs exist, an
absent physical topology is a failing `required_manual` gate rather than a
skip.
It HMAC-SHA-256 authenticates every scenario and rollback journal with the
separate `RUNNER_MANAGER_E2E_EVIDENCE_KEY` authority. The GitHub fixture token
is explicitly rejected as that key. Every seal is bound to the current GitHub
run ID, run attempt, commit SHA, OS, architecture, a fresh 256-bit CI
challenge, a unique nonce, issue time, and a five-minute expiry. The validator
checks all bindings before decoding facts and atomically consumes each nonce;
wrong-run, expired, forged, edited, and replayed journals fail.

Hosted runners are classified as `required_manual` for network isolation,
reboot, and two-host contention. When fixture inputs are present this
classification fails the E2E job and therefore cannot masquerade as a passing
live report. Only a host explicitly provisioned with
`RUNNER_MANAGER_E2E_PHYSICAL_HOST=true` may seal controller output.
The current repository does not define the disposable fixture workflow inputs,
a controller host that survives rebooting the managed host, or a second-host
observation transport. Until those contracts are added, even a physical host
terminates `required_manual` before any journal is signed. The repository-owned
operation verbs remain available for that future sequencer; arbitrary external
JSON is never accepted as a substitute.

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
- `security/process-inspection.json` (live manager and listener PIDs only before sealing)

Each scenario record is a deny-unknown-fields typed causal journal stamped
`runner-manager-e2e-host-controller/v1`. Scenario-specific facts include real
run/job/runner/attempt identifiers and ordered timestamps. Every record also
contains independent GitHub and local observations: registered runner IDs,
legacy-label runner IDs, and runtime-directory paths must all be empty. The
validator rejects mismatched fact variants, impossible ordering, fabricated
controller names, wrong targets, and incomplete postconditions.

The rollback journal records four successful, non-overlapping timestamped
commands against the fixture target in this exact order: restore label, drain,
verify terminal, re-enable legacy. Its independent final observations must see
the same typed legacy runner ID and label, no managed runner, and no runtime
directory. The recorded commands are the exact repository controller and
shipping CLI verbs, including target, runner ID, label, OS, and service ID.

Security gates are not accepted from prose files. The suite executes exact
repository negative-control tests for two-job contamination, checksum mismatch
and absent checksum, revoked-token state/remediation/no-start behavior,
successful and failed workspace cleanup, duplicate queued polling, and native
OS process-list inspection. For the five required product controls it then
rebuilds the relevant package with the `test-mutants` feature, injects one named
mutant at the production decision seam, and requires the exact same gate test
to fail. Release builds do not compile these seams. A receipt is valid only
when the expected package and exact test filter ran successfully and matched
one test.

`security/` contains `jit-marker.txt`,
`secret-scan-root/` (logs, database, snapshots, crash reports and CLI output),
and `config-and-sqlite/`. All five artifact categories, every evidence field,
command output, and the completed report are scanned with the real product
token, fixture token, evidence key, and JIT marker before serialization or
printing. The controller independently re-reads the native command lines for
the supplied live PIDs and seals only observations containing the shipping
`runner-manager` and `Runner.Listener` executable names. The platform
canonical redactor must also leave the report unchanged; deliberate exact-value
and credential-shaped leaks prove both controls fail closed.

CI sets `RUNNER_MANAGER_E2E_EVIDENCE_DIR` and
`RUNNER_MANAGER_E2E_DATA_DIR`, runs the suite, finalizes the report through the
same repository command, and uploads `e2e-report-<os>` for 30 days.

The product token is used only to drive and inspect runner-manager. The fixture
token is used only by the controller to edit/dispatch the disposable workflow
and by the suite for a read-only fixture-reachability check. Do not widen the
product token to make fixture setup pass.
