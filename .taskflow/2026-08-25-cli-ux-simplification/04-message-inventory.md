# Message inventory

Every user-visible string this work changes. `before` is `c3ae616` verbatim.
This document exists so the copy is reviewable on its own, separately from the
mechanics, and so a task specification can name a string instead of describing
it.

## 1. `repo add` — autoscaling policy

**Before** (`crates/app/src/cli/policy.rs:359-374`):

```text
Added repo policy for IvanMurzak/AI-Game-Dev-App in pending; scaling is disabled.
Routing label: rm-ivanpc-win-x64
Next: runner-manager repo set-scale IvanMurzak/AI-Game-Dev-App --enabled true
```

**After**, disabled (no `--enabled`):

```text
Added IvanMurzak/AI-Game-Dev-App. Max 6 runners on this machine; scaling is off.
Routing label: rm-ivanpc-win-x64   (from host label `ivanpc`)

  1. Add `runs-on: rm-ivanpc-win-x64` to the workflow.
  2. Turn it on:  runner-manager repo set IvanMurzak/AI-Game-Dev-App --enabled
```

**After**, armed (`--enabled`):

```text
Added IvanMurzak/AI-Game-Dev-App. Max 6 runners on this machine; scaling is ON.
Routing label: rm-ivanpc-win-x64   (from host label `ivanpc`)

  1. Add `runs-on: rm-ivanpc-win-x64` to the workflow.
  2. Keep the agent running across reboots:  runner-manager service install

warning: fork and untrusted pull-request workflows must not run on a personal
host until you explicitly accept that trust boundary.
```

The word `pending` is gone from the result line. It is a `PolicyState` variant
(`crates/domain/src/policy.rs`), correct and internal; `scaling is off` says the
same thing to the reader. `pending` remains in `repo list` and `status`, where
the reader is looking at states.

## 2. `repo add` — monitor-only

**Before** (`policy.rs:378-391`, plus `auth.rs:139-154`):

```text
Added repo policy for IvanMurzak/AI-Game-Dev-App in pending; scaling is disabled.
Monitor-only: no routing label is reserved and no runner will ever be started for this policy.

`Administration: Read and write` is NOT a narrow self-hosted-runner permission.
The same grant also permits DELETING, RENAMING and TRANSFERRING the repository, and
adding and removing collaborators. Watching grants exactly the same set.

Promote it with: runner-manager repo set-capacity IvanMurzak/AI-Game-Dev-App --max-capacity N
```

**After**, first policy against this installation (D4) — the three sentences are
unchanged, and move **below** the next step:

```text
Added IvanMurzak/AI-Game-Dev-App in monitor-only mode: it is shown in the
dashboard, and no runner will ever be started for it.

  Start runners for it:  runner-manager repo set IvanMurzak/AI-Game-Dev-App --max-capacity N --enabled

`Administration: Read and write` is NOT a narrow self-hosted-runner permission.
The same grant also permits DELETING, RENAMING and TRANSFERRING the repository, and
adding and removing collaborators. Watching grants exactly the same set.
```

**After**, installation already acknowledged:

```text
Added IvanMurzak/AI-Game-Dev-App in monitor-only mode: it is shown in the
dashboard, and no runner will ever be started for it.

  Start runners for it:  runner-manager repo set IvanMurzak/AI-Game-Dev-App --max-capacity N --enabled

note: this still uses the `Administration: Read and write` grant you approved.
      runner-manager auth status  explains what that permits.
```

## 3. `repo set` results

**Before** (`policy.rs:667-694`):

```text
IvanMurzak/AI-Game-Dev-App max capacity is now 6; scaling remains disabled.
Routing label: rm-ivanpc-win-x64
```
```text
Scaling enabled for IvanMurzak/AI-Game-Dev-App.
```

**After**, one block for the whole mutation rather than one per field:

```text
IvanMurzak/AI-Game-Dev-App: max 6 runners, scaling ON.
Routing label: rm-ivanpc-win-x64
```

The disable path keeps its wording, which is careful for a reason
(`policy.rs:693`) and is not shortened:

```text
IvanMurzak/AI-Game-Dev-App is draining with 2 active runner(s); busy runners were
not terminated. Cache and historical diagnostics were preserved.
```

## 4. Monitor-only cannot be armed

**Before** (`policy.rs:623-631`):

```text
error: monitor-only policies cannot be enabled; no routing label or capacity is reserved
  try: runner-manager repo set-capacity IvanMurzak/AI-Game-Dev-App --max-capacity N
```

**After** — same refusal, one-command remedy:

```text
error: IvanMurzak/AI-Game-Dev-App is monitor-only, so there is nothing to enable:
       no capacity and no routing label are reserved for it.
  try: runner-manager repo set IvanMurzak/AI-Game-Dev-App --max-capacity N --enabled
```

**New**, at parse time, for `repo add X --enabled` with no capacity (D1):

```text
error: --enabled needs --max-capacity: without a capacity the policy is
       monitor-only (it never starts a runner), and there is nothing to enable.
  try: runner-manager repo add IvanMurzak/AI-Game-Dev-App --max-capacity N --enabled
```

## 4a. Duplicate `add` (found during review)

**Before** (`policy.rs:226-227`) — already correct, but its remedy is gone:

```text
error: a policy for IvanMurzak/AI-Game-Dev-App already exists. Nothing was changed.
```

**After** — same refusal, with the command that does what they meant:

```text
error: a policy for IvanMurzak/AI-Game-Dev-App already exists. Nothing was changed.
  try: runner-manager repo set IvanMurzak/AI-Game-Dev-App --max-capacity N --enabled
```

This matters more after D1 than before it. An operator who typed
`repo add X --max-capacity 6 --enabled` and got it slightly wrong will
re-run the same command; today they meet a refusal with no way forward.

## 4b. No derivable host label (found during review, D3)

Only on a machine where neither `COMPUTERNAME` nor `HOSTNAME` is set:

```text
error: this machine reports no name, so there is no routing label to derive.
  try: runner-manager host set-label <name>    (then re-run this command)
```

The tool must not fall back to a constant here — every such machine would
derive the identical label. See
[`02-target-architecture.md`](02-target-architecture.md#the-fallback-must-not-be-defaulted-from).

## 4c. `auth status` gains the grant (found during review, D4)

`auth status` currently never names the permission, so D4's pointer would point
at nothing. Appended to the authenticated report:

```text
This credential's App installation grants:

  Actions                               Read and write   read queued jobs, register runners
  Administration                        Read and write   mint runner registration tokens
  ...

`Administration: Read and write` is NOT a narrow self-hosted-runner permission.
The same grant also permits DELETING, RENAMING and TRANSFERRING the repository, and
adding and removing collaborators. Watching grants exactly the same set.
```

The permission rows come from `PERMISSIONS` (`auth.rs:87-110`), the same
constant `write_disclosure` renders, so the two cannot drift.

## 5. `host show`

**Before** (`crates/app/src/cli/host.rs:472-479`) — two lines shown for context:

```text
Host: IvanPC (windows x64)
  id                        0193f2c1-...
  host_capacity             1
```

**After** — two lines inserted:

```text
Host: IvanPC (windows x64)
  id                        0193f2c1-...
  host label                ivanpc
  routing label             rm-ivanpc-win-x64
  host_capacity             1
```

## 6. `host set-label` (new)

```text
Host label is now `office`.
Routing label for new policies: rm-office-linux-x64
```

With existing policies, a warning that does not refuse:

```text
Host label is now `office`.
Routing label for new policies: rm-office-linux-x64
warning: 3 existing policies keep the label they were created with. `repo list`
         shows each one's routing label; re-add a policy to move it.
```

## 7. `service install` while an agent runs

**Before** (`crates/platform/src/service.rs:508` + `crates/platform/src/lock.rs:106`):

```text
error: cannot install the service while an agent is already running on this host: the
single-instance agent lock (C:\...\state\agent.lock) is already held on this host by
process 6212 (C:\...\runner-manager.exe), holding since 2026-08-24T02:42:01Z. Only one
agent may reconcile policies on a host. Stop the other agent, or wait for it to exit;
the operating system releases this lock when that process ends, including after a
crash, so there is never anything to clean up by hand.
  try: runner-manager service status
```

**After** — same refusal, same facts, an actionable remedy:

```text
error: an agent is already running on this host, and only one may reconcile
       policies at a time.
       process 6212, C:\...\runner-manager.exe, running since 2026-08-24T02:42:01Z.
       The OS releases the lock when that process ends, including after a crash,
       so there is never a lock file to clean up by hand.
  try: stop it (Ctrl+C in its terminal, or `Stop-Process -Id 6212`), then
       runner-manager service install
```

`Stop-Process -Id` on Windows, `kill` elsewhere. Where the holder is unknown,
the second `try:` line is omitted and the lock path is named instead.

## 8. Swapped noun and verb (new, D7)

```text
error: unrecognized subcommand 'add'
  try: runner-manager repo add IvanMurzak/AI-Game-Dev-App
```

## 9. Unknown flag (D7)

**Before** — clap's default:

```text
error: unexpected argument '--enabled' found

  tip: to pass '--enabled' as a value, use '-- --enabled'
```

**After**:

```text
error: unexpected argument '--enabled' found

  this command accepts: --host-label, --max-capacity, --enabled
```

## 10. Platform capability warnings

**Before** (`policy.rs:400-406`), printed on every `add` on a non-Linux host:

```text
warning: container actions and service containers require a Linux host.
```

**After** — unchanged text, but demoted below the next-step block so it does not
sit between the result and the action. It stays on every `add`: it is a
statement about what workflows will do on this machine, and a reader adding a
second repository has the same need to know as the first.

## Not changed

| String | Where | Why |
|---|---|---|
| `TRUST_WARNING` | `policy.rs:20` | Fires once, at arming. Correct placement. |
| `write_disclosure` (25 lines) | `auth.rs:158` | `auth login` only. D4 does not touch it. |
| `write_grant_consequences` (3 sentences) | `auth.rs:139` | Character for character. D4 changes when it prints, never what it says. |
| The drain wording | `policy.rs:693` | Deliberately promises nothing about termination. |
| `LockKind::advice`'s crash sentence | `lock.rs:112-116` | Stops operators deleting lock files by hand. |
| Every `README.md` disclosure section | `README.md` | Gated by `crates/app/tests/readme_disclosure.rs`. |
