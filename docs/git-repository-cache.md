# Git repository cache for native runners

## Contract

Git checkout caching is an opt-in tool in `caches.toml`, alongside dependency
caches. Configure the host default with `host cache set-tool git --state on`, or
override one repository with `repo cache set-tool OWNER/REPO git --state on`.
`off` disables it and `default` clears the override. The Host and Repository
Settings screens call those same CLI handlers. Changes reach future launches
without restarting the daemon. Disabling the host's entire cache system also
disables this tool. Root selection, cache size limits, measurements and LRU
pruning are shared with existing caches.

Support is deliberately scoped to native repository policies, standard GitHub
HTTPS checkout and `_work/<repository>/<repository>`. The initial checkout uses
the workflow's normal authentication. Organization policies cannot identify a
single repository before a job starts, and isolated providers do not mount host
caches, so neither uses this integration. Custom checkout paths, SSH origins,
custom Git servers, submodules and LFS payloads use ordinary checkout. Workflows
that manually clone into an empty working directory should keep the tool off.

## Lifecycle

1. Native cache preparation leases a namespace using the existing cache lease.
   If Git caching is enabled, record a bounded repository-only plan in `_diag`.
2. A cold cache leaves the workspace empty. A warm cache seeds only `.git` into
   an empty standard workspace, initializing fresh metadata and copying immutable
   objects without hardlinks. Old tags, branches and branch configuration are
   excluded; shallow boundaries are retained for the copied history. The new
   repository has its own objects and no alternates.
   Existing populated persistent workspaces remain untouched.
3. `actions/checkout` authenticates, fetches and checks out its exact requested
   ref/commit. Its normal cleanup remains enabled. The cached HEAD never decides
   the workflow's final revision. The runner's default workspace preparation
   preserves pre-existing directories; an explicitly requested workspace wipe
   can remove the seed and fall back to a cold checkout. See upstream
   [PipelineDirectoryManager](https://github.com/actions/runner/blob/v2.338.0/src/Runner.Worker/PipelineDirectoryManager.cs).
4. Native destruction, after process termination has been settled by existing
   reconciliation and before deleting the workspace, checks the configuration
   again and captures the standard checkout. A bare local clone excludes source
   configuration, credentials, hooks and working files.
5. Merge immutable objects and shallow boundaries from the previous snapshot so
   concurrent cold jobs do not discard each other's useful objects or require
   intentionally absent parents. Validate with `git fsck`, publish
   a new UUID generation through an atomic pointer, then retire the old one.
   The origin is verified against the policy's repository and contains no auth.

The normal namespace lease pins a cache against pruning while seeding/capture
runs. Capture re-pins the effective namespace if configuration changed during
the job. A per-repository lock serializes Git copies and publication without
holding the global dependency-cache lock during expensive operations. A lock
that cannot be acquired quickly skips the optimization. Cached Git stores stay
separate by repository even inside an explicitly shared dependency namespace.
The configuration uses the existing per-repository trust boundary; it is not
isolation against an untrusted native workflow with access to the host.

## Failure and storage behavior

Git commands cannot use network transports or interactive credentials, inherited
Git environment overrides are removed, global/system Git configuration and
hooks are disabled, and child processes have a bounded wait. Git output is not
copied into service diagnostics. Metadata is bounded and versioned. Directory
symlinks/reparse points and external object stores are refused. An unsupported
or failed cache operation falls back to normal checkout/cleanup.

An already seeded workspace remains valid after replacement or deletion of its
cache. Failed publication leaves the last good pointer intact. Cancellation or
a crash can leave an unreferenced generation/staging directory; it is part of
the namespace's measured usage and eligible for the existing idle-namespace LRU
cleanup. The common cap is a periodic soft limit, like other dependency caches,
and temporary snapshot copies can exceed it during publication. This feature
does not promise a speedup when local disk copying costs more than a shallow
network fetch; assess it on the repositories that benefit.

## Validation

Cross-platform tests use actual Git to cover cold/warm operation, shallow and
detached PR history, incremental fetch, independent objects, source credential
and hook exclusion, retained persistent files, merged publications and refused
origins/alternates. Unix tests also refuse a symlinked workspace. CLI and TUI
tests verify inheritance, persistence, keyboard/mouse reachability, constrained
layouts and identical configuration writes.

Review also exposed a Unix lock-release race when concurrent subprocess creation
temporarily duplicates a locked descriptor. The owner now explicitly unlocks
before closing; a regression test holds a duplicate open and verifies immediate
handoff without releasing the next owner's lock.

The opt-in acceptance test runs the official `actions/checkout` bundle pinned
to `3d3c42e5aac5ba805825da76410c181273ba90b1`. It warms the cache through native
launch/capture, removes the first workspace, prepares a second ephemeral
workspace, deletes the cache to prove independence, and runs checkout against a
private local transport. The requested PR commit is absent before fetch and
must be the exact HEAD afterwards, with no previous job's build files retained.
Linux CI runs this explicitly; it can also run manually on Windows and WSL with
`RUNNER_MANAGER_CHECKOUT_ACTION` pointing at that pinned checkout and Node on PATH.
