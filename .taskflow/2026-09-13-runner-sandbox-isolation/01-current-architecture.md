# Current architecture

## Repository policy and storage

`ScalePolicy` already owns repository configuration including cache and
workspace policy (`crates/domain/src/policy.rs:938-964`). New policies always
start with an ephemeral workspace (`crates/domain/src/policy.rs:1053-1078`).
Persisted policies flatten workspace kind and path into validated fields
(`crates/domain/src/policy.rs:993-1017`), and load reconstructs the domain value
while rechecking repository/organization scope (`crates/domain/src/policy.rs:1089-1125`).

Schema migration 0003 added `policies.workspace_mode/workspace_path` and
`attempts.workspace_mode/workspace_slot`; old rows become ephemeral
(`crates/domain/src/store/migrations/0003_workspace_locations.sql:32-61`). A
new isolation policy therefore needs a forward-only migration and load-time
shape validation, not an edit to an existing migration.

The Repository Settings read model already owns workspace state and routes its
save through the CLI handler (`crates/app/src/tui/settings.rs:275-297`,
`crates/app/src/tui/settings.rs:376-407`). This is the natural UI seam for an
isolation selector, image/profile field, capability result and refusal reason.

The CLI currently rejects a second policy with the same target
(`crates/app/src/cli/policy.rs:542-552`), and mutations find a policy by target
alone (`crates/app/src/cli/policy.rs:1171-1184`). The database, however, keys
policies only by policy ID and has no target uniqueness constraint
(`crates/domain/src/store/migrations/0001_initial_schema.sql:43-68`).

Reconciliation already supports several policies watching one target, polls the
target once, then tallies each policy against its own labels
(`crates/agent/src/reconcile.rs:79-87`,
`crates/agent/src/reconcile.rs:1990-2053`). The daemon groups equal targets and
refreshes the full group (`crates/app/src/cli/daemon.rs:1103-1133`,
`crates/app/src/cli/daemon.rs:1203-1223`). Multi-profile work therefore extends
identity, routing, commands, TUI and budget accounting without replacing target
polling.

Current label matching follows GitHub's superset rule: every job-required label
must exist on the policy (`crates/domain/src/policy.rs:357-401`). Two profiles
with overlapping broad labels can both count one job, so merely removing the CLI
duplicate check would be incorrect.

## Attempt allocation and launch

The current allocator chooses between a unique disposable directory and a
persistent repository slot (`crates/agent/src/lifecycle.rs:2522-2546`). A
disposable runtime is a unique child under the host runner root
(`crates/agent/src/lifecycle.rs:2620-2652`). Package materialization copies the
cached GitHub runner tree directly into that runtime
(`crates/agent/src/lifecycle.rs:401-432`).

After allocation is journalled, lifecycle materializes the runner, requests a
JIT registration and directly calls the process supervisor
(`crates/agent/src/lifecycle.rs:2769-2858`). `NativeProcesses::spawn` resolves
`Runner.Listener(.exe)` inside the runtime and builds a native `SpawnSpec`
(`crates/agent/src/lifecycle.rs:1494-1543`). `SpawnSpec` ultimately calls
`std::process::Command::spawn` with the host working directory and environment
(`crates/platform/src/process.rs:552-600`).

Therefore current ephemeral mode provides file-lifetime separation, not an OS
environment boundary. It does not isolate installed interpreters, package
managers, the Windows registry, host services/processes, devices or the kernel.
The README states the same narrower guarantee: ephemeral cleanup removes the
workspace, while persistent mode is explicitly “not isolation”
(`README.md:455-475`, `README.md:500-509`).

## Cleanup and recovery

An ephemeral attempt deletes the complete runtime tree; a persistent attempt
scrubs everything except `_work` (`crates/agent/src/lifecycle.rs:2328-2350`).
An attempt journals a native `process_id`, runtime path and immutable workspace
allocation (`crates/domain/src/attempt.rs:597-614`,
`crates/domain/src/attempt.rs:646-659`). These fields cannot identify or safely
recover a container/VM. Isolation needs an immutable environment allocation and
provider-owned identity in the attempt journal.

The current JIT handoff is deliberately kept out of arguments and the reusable
spawn spec, then inserted only at the final native spawn boundary
(`crates/platform/src/process.rs:625-653`). Any provider abstraction must retain
that property and must not write the JIT document into container labels, VM
metadata, command lines, image layers or durable provider records.

## WSL topology

Managed WSL is already a second Linux host, not a Windows runner launched through
an emulation call. Installation places a Linux binary and systemd service inside
the distribution, with its own credential, capacity, policies and label
(`README.md:269-275`, `README.md:303-317`). Commands addressed to `wsl:NAME` are
executed by that Linux host (`README.md:369-384`). Consequently WSL should reuse
the Linux isolation provider inside the guest; Windows should not remotely own
each WSL container lifecycle.

## Change seams

1. Add named profile identity and an immutable unique selector; commands select
   `(target, profile)` rather than target alone.
2. Add isolation policy types next to `WorkspacePolicy`, but keep isolation and
   workspace retention as separate facts.
3. Add policy/attempt columns through a new migration and the existing named
   persisted structs.
4. Replace the direct native-process assumption below `LifecycleLauncher` with
   an `IsolationProvider`/environment handle while retaining reconciliation.
5. Extend Repository Settings and CLI through shared handlers, as workspace
   settings already do.
6. Extend status/readiness with host capability and per-attempt provider state.
