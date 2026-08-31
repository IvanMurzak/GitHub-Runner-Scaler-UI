# Security and recovery

## Revised trust boundary

Disposable mode keeps the current guarantee: a hostile workflow cannot leave a
workspace for a later attempt because the complete attempt directory is
removed.

Persistent mode deliberately gives up that guarantee for one configured
repository. The retained `_work` directory is an input to later jobs. It may
contain executables, compiler outputs, dependency caches, generated source,
repository credentials accidentally written by a workflow, or files created by
a previous branch. The product must present persistence as a trusted-workflow
optimization, not as equivalent isolation with faster startup.

Persistent mode is rejected for organization policies because a runner may
accept jobs from more than one repository. It is also inappropriate for
untrusted fork or pull-request workflows on a personal host.

## Data classification

| Data | Disposable mode | Persistent mode |
|---|---|---|
| Runner package copy | Removed with attempt | Recreated per attempt, removed after attempt |
| Encoded JIT configuration | Restrictive handoff, deleted immediately | Same, never retained in slot |
| Process and runner identity sidecars | Removed with attempt | Removed before slot release |
| `_work` checkout and build outputs | Removed with attempt | Retained in stable slot |
| Verified package cache | Existing state cache policy | Existing state cache policy |
| Diagnostics | Existing redacted logs path | Existing redacted logs path |

The persistent cleanup allowlist contains exactly `_work`. Adding any second
retained runner-root entry requires a new security decision and tests.

## Threats and controls

| Threat | Control | Acceptance evidence |
|---|---|---|
| Two attempts use one slot concurrently. | Allocate the lowest free slot from uncleaned journal rows while holding the host allocation lock. Journal before external effects and enforce a partial unique index for uncleaned persistent leases. | Concurrency, cleanup-failure, and restart tests prove unique uncleaned `(policy, slot)` pairs. |
| A stale process continues writing after slot release. | Preserve current process identity verification and termination ordering. Persistent cleanup runs only after the process is authoritatively gone. | Recycled-PID, recovered-process, and crash-boundary tests. |
| JIT or runner identity survives into the next job. | Retain only `_work`; remove all other slot-root entries and verify absence before marking the attempt cleaned. | Secret scan and two-job sidecar contamination test. |
| A workflow replaces `_work` with a junction or symlink to escape cleanup. | Refuse non-directory and link-like `_work`; never recursively follow a reparse point or symlink; quarantine the slot. | Windows junction and Unix symlink adversarial tests. |
| A configured path overlaps config, secrets, logs, package cache, the host runner root, another repository, or a broad filesystem root. | Shared lexical and canonical overlap validation; reject roots and ancestor or descendant overlap. | Table-driven cross-platform validator tests. |
| A network path disappears or changes identity during a job. | Reject UNC and configured remote-share paths. | Windows UNC and device-path rejection tests. |
| `%SystemDrive%\rman` is writable by unrelated local users. | Disable inherited write grants and admit `SYSTEM`, Administrators, and the selected login or foreground identity as required. Reconcile the selected identity when service mode changes. Report existing broad ACLs rather than silently trusting them. | Privileged Windows ACL test and service smoke test for boot and login modes. |
| A previous job poisons a compiler or dependency cache. | Persistent mode is explicit and carries a trusted-workflow warning in CLI, TUI, and README. It is repository-scoped only. | Snapshot and command-output tests assert the warning. |
| Path change causes the agent to delete old operator data. | Refuse active changes and never move or delete old directories. | Sentinel files survive mode, root, policy removal, and rollback tests. |
| Corrupt SQLite changes cleanup mode for an old path. | Load-time shape validation and immutable attempt workspace kind; unknown values fail closed. | Corrupt-row tests for every invalid field combination. |
| Cleanup partly fails and the slot is reused anyway. | Attempt remains not-cleaned and continues to hold the slot through the unique lease index; it does not count as active host capacity. Recovery retries the same cleanup. | Injected deletion failures, capacity assertions, and restart tests. |

## Safe path handling

Every deletion operates from a journaled validated root and a fixed child name.
No destructive command receives a shell-built string, environment-expanded
glob, unresolved relative path, or repository-controlled path fragment.

Before persistent cleanup:

1. Derive the journaled root from the exact stored runtime path and slot. If the
   policy still exists, require its configured root to agree.
2. Verify the runtime is exactly `<root>/sN` for the journaled slot.
3. Verify canonical containment without following a link outside the root.
4. Enumerate direct slot-root entries.
5. Preserve a real `_work` directory only.
6. Remove other entries with literal filesystem APIs.
7. Verify sensitive sidecars and runner executables are absent.
8. Mark cleaned and release the slot only after every check passes.

If any containment or link check fails, do not attempt broad cleanup. Record a
redacted actionable error and leave the attempt unresolved for operator review.

## Recovery rules

- Startup completes existing attempt recovery before creating new attempts.
- Migrated attempts are ephemeral and use their stored absolute path.
- A persistent attempt's journaled slot remains leased across daemon restart.
- A terminal persistent attempt is not cleaned until the allowlist cleanup
  succeeds.
- Unknown-policy attempts retain current fail-closed ownership behavior.
- A repository path setting cannot change while any attempt for that policy is
  active or unresolved.
- A host root setting cannot change while any ephemeral attempt is active or
  unresolved.

## Operator-visible warnings

CLI and TUI must state all of the following before persistent mode is saved:

- files under `_work` will be used by later jobs;
- executable and generated content can cross branch and job boundaries;
- do not enable it for untrusted fork or pull-request workflows;
- changing or disabling persistence does not delete old directories;
- workflow checkout configuration can still delete caches, including
  Git-ignored files, unless `actions/checkout` cleanup is disabled.

The warning is not a modal on every run. It appears in mutation preview, success
output, settings detail, and README guidance.

## Security gates

- Disposable two-job contamination tests remain unchanged and green.
- Persistent two-job tests prove intended `_work` retention and unintended
  runner-state removal simultaneously.
- JIT values and credentials are absent from SQLite, slot roots, logs, status
  JSON, TUI snapshots, and crash reports.
- Symlink, junction, overlap, root-path, traversal, UNC, and deletion-failure
  cases fail closed.
- No cleanup test writes outside its temporary approved root.
- A real Windows service creates and cleans `%SystemDrive%\rman` without broad
  local-user write access.
