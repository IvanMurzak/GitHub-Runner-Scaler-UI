---
id: "c1-lock-remedy"
title: "service install names the process holding the lock and how to stop it"
group: "C"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 2
complexity: 3
security_critical: false
production_touching: false
model_hint: "fast"
taskflow_refs: ["02-target-architecture.md", "04-message-inventory.md"]
---

## Goal

Turn the session's second dead end into an instruction. D6. The refusal stays;
only the remedy changes.

## Scope & seams

**Files:** `crates/platform/src/service.rs`, `crates/platform/src/lock.rs`, and
whichever CLI mapper attaches the `try:` line for `ServiceError::LockHeld`
(`crates/app/src/cli/service.rs`) — **that CLI file is this task's only reach
outside group C, and no other task touches it.**

`LockError::Held` (`crates/platform/src/lock.rs:167-178`) already carries
`kind`, `path`, and `holder: Option<LockHolder>`, and the transcript proves the
holder was known: PID, binary path and hold time all printed. This is a
formatting change, not a plumbing one — do not add a field to carry information
the error already has.

Target text is in
[`04-message-inventory.md`](../04-message-inventory.md#7-service-install-while-an-agent-runs).

Three constraints:

1. **`try: runner-manager service status` is replaced, not supplemented.** It
   points at a command that reports the registration, which is not what is
   wrong.
2. **The stop command is platform-correct:** `Stop-Process -Id <pid>` on
   Windows, `kill <pid>` elsewhere. Selected at compile time, like the rest of
   `crates/platform`.
3. **`holder: None` is not "nobody".** `lock.rs:172-177` says so explicitly. In
   that case omit the stop line and name the lock file instead; never print
   `Stop-Process -Id ` with nothing after it.

`LockKind::advice` (`lock.rs:106-120`) keeps its sentence about the OS releasing
the lock including after a crash. That sentence is what stops an operator
deleting a lock file by hand.

`install` keeps taking the lock as step 2 of its documented order and holding it
for the whole operation (`crates/platform/src/service.rs:3242-3260`). **Do not
relax the refusal.**

## Definition of Done

1. With the single-instance lock held by a known holder, `service install`
   fails with the same class as today, and stderr names the process id, the
   binary path, the hold time, and the platform's stop command.
2. Stderr does **not** contain `runner-manager service status`.
3. With `holder: None`, the message names the lock file and omits the stop
   command; asserted by a test that constructs that error value directly.
4. `crates/app/tests/cli_command_surface.rs`'s
   `daemon_run_refuses_a_second_instance_without_prompting` still passes — this
   task changes `service install`'s message, not `daemon run`'s behaviour.
5. The existing platform test that asserts `ServiceError::LockHeld` is raised
   (`service.rs:6644-6651`) still passes.
6. `cargo test -p runner-manager-platform -p runner-manager-app` passes.
