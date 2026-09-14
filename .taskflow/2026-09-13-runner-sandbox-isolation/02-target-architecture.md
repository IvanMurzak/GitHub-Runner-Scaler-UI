# Target architecture

## Product model

Model one target with one or more named runner profiles. Keep workspace
retention and execution isolation orthogonal inside each profile:

```text
RepositoryTarget { target, installation_id }
  RunnerProfile[] {
    id, name, immutable_selector, optional_labels,
    capacity, enabled, workspace_policy,
    execution_policy:
      Native
      Isolated {
        backend: Auto | Oci | WindowsHyperVContainer | VirtualMachine,
        image: pinned provider-specific image reference,
        resources: cpu/memory/disk limits,
      }
  }
```

`Auto` means “select a provider that satisfies the declared isolation contract”,
never “fall back to native”. A stored unknown backend or malformed image fails
closed on load. V1 permits `Isolated` only for repository profiles and only with
an ephemeral workspace. A future persistent cache must be a separate explicit
mount/volume allowlist, not reuse of the entire `_work` tree.

The image reference is resolved to an immutable digest/version before GitHub JIT
registration. Status shows requested reference, resolved identity, provider and
capability state. Secrets never form part of the image/profile.

## Provider boundary

The agent owns a platform-neutral provider contract selected by the profile:

```text
probe(profile) -> Capability
prepare(attempt, profile, runner_package) -> PreparedEnvironment
start(prepared, one_time_jit_handoff) -> EnvironmentIdentity
inspect(identity) -> Starting | Running | Exited | Missing
stop(identity, grace) -> Stopped | StillRunning
destroy(identity) -> Destroyed | Deferred(reason)
recover(journalled_identity) -> inspect/adopt/stop/destroy
enumerate_owned(host_id) -> provider resources bearing authenticated ownership
diagnostics(identity) -> bounded redacted bootstrap/provider events
```

`NativeProcesses` becomes the implementation of a native provider instead of
the definition of process lifetime. OCI, Hyper-V and macOS VM adapters live at
the platform boundary. Reconciliation continues to reason about attempts and
capacity; it does not learn Docker, Hyper-V or Virtualization.framework APIs.

Provider ownership identifiers must contain only non-secret product host and
attempt IDs. Destructive operations require both the durable journal and a
provider resource that independently matches product ownership. Enumeration is
for orphan discovery, never sole authority to delete.

## Attempt journal

Add an immutable allocation value:

```text
AttemptExecution
  Native { process_identity }
  Isolated {
    provider_kind,
    environment_id,
    resolved_image,
    generation,
  }
```

The allocation is journalled before the provider performs an external effect.
The environment ID is filled through a crash-safe prepare transition before the
runner can start. Native process PID/start token remains inside the native
variant. An isolated attempt is not considered cleaned until the environment is
confirmed absent, even if `Runner.Listener` has exited.

## Launch sequence

1. Match queued demand to exactly one explicit profile selector.
2. Resolve profile and provider capability; fail before JIT on unavailable,
   unpinned or incompatible images.
3. Allocate and journal an ephemeral attempt plus provider intent.
4. Create the sandbox with resource/network/mount restrictions and journal its
   provider identity.
5. Materialize the verified GitHub runner package inside the environment, or
   verify the pinned image contains the expected runner version.
6. Request JIT only after the environment is ready to start.
7. Deliver JIT through a one-time in-guest channel and start `Runner.Listener`.
8. Supervise provider state plus GitHub state. Capacity remains leased until
   the environment is gone and cleanup is recorded.
9. Stop and destroy the entire sandbox after the one job, verify absence, then
   clean the attempt.

Preparing before JIT avoids consuming a registration for image pulls, VM boots
or capability failures. Pull/install work may be cached by content digest at the
host level, but each writable execution layer is new.

## Configuration and UX

Add shared CLI/TUI operations conceptually equivalent to:

```text
runner-manager repo profile add OWNER/REPO --name native --execution native
runner-manager repo profile add OWNER/REPO --name py-isolated \
  --execution isolated --backend auto --image <reference>
runner-manager repo profile set-execution OWNER/REPO --profile py-isolated --mode isolated \
  --backend auto --image <reference> [--cpu N --memory SIZE --disk SIZE]
runner-manager host isolation status [--json]
```

Existing `repo add` creates profile `default`. Legacy mutation commands without
`--profile` operate only when exactly one profile exists; with several they
refuse ambiguity and list valid names.

Repository Settings selects a profile, then shows its immutable selector,
copyable `runs-on`, mode, selected/resolved backend, image reference,
resource limits and a live preflight. Saving `isolated` is refused while the
repository has uncleaned attempts, matching workspace mutation fencing. Enabling
scaling is refused when required isolation is unavailable. Runtime loss after
enablement leaves the policy enabled-but-blocked with an actionable status; it
does not launch natively.

Status distinguishes `unsupported`, `not installed`, `permission denied`,
`image unavailable/incompatible`, `degraded`, and `ready`. It must not collapse
these to a generic process-start failure.

Mutation fences count attempts for the selected `PolicyId` only. A busy native
profile must not block editing its idle isolated sibling, and no edit may change
the immutable execution allocation of an already journalled attempt.

## Compatibility invariants

1. Existing rows migrate to native profile `default`; upgrades never silently isolate or stop
   an existing policy.
2. Existing native attempts recover with their current process identity.
3. Isolated policies never call the native provider after provider failure.
4. The guest OS/architecture is included in capability and routing truth.
5. Capacity counts prepared, running and cleanup-deferred environments.
6. Disabling a policy drains current work before destroying its environment.
7. No host directory, device or runtime socket is mounted unless a future policy
   explicitly declares and validates it.
8. Every resolvable queued job is claimed by zero or one profile, never two.
