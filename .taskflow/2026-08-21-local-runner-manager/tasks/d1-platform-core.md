---
id: "d1-platform-core"
title: "Platform core: OS/architecture matrix, application-data paths, single-instance lock, process control, restrictive handoff, redacting log sink"
group: "D"
sequence: 1
repo: "."
depends_on: ["a1-workspace-ci-foundation"]
importance: 9
complexity: 6
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["05-infrastructure.md", "07-security.md", "01-current-architecture.md", "03-control-flows.md"]
---

## Goal

Provide the six host primitives every other crate assumes exist. Each is small
on its own, which is why they are one task; together they are the entire
surface where "works on my machine" becomes "works on Windows, macOS, and
Linux".

## Scope & seams

Owns `crates/platform/src/{os,paths,lock,process,logging}.rs`. The secret store
is `d2` and the service installer is `d3`; both build on this.

**1. OS and architecture matrix.** Detect host OS and architecture, and
validate them against GitHub's documented support matrix
(`01-current-architecture.md`): Windows 10/11 and Server 2016/2019/2022,
macOS 11.0+, and the nine listed Linux distributions; x64 on all three, ARM64 on
all three as **public preview**, ARM32 on Linux only. Expose a warning — not a
rejection — for ARM64, because the persona's Apple Silicon Mac mini is an ARM64
host. Also expose the fact that container actions and service containers require
Linux, so `f2` can surface that limitation on macOS and Windows policies
(`01-current-architecture.md`, edge case 2).

**2. Application-data directories.** Resolve platform-standard locations for
`config/`, `state/`, `runtime/`, and `logs/`. No repository or runner material
is stored in the current working directory by default.

**3. Single-instance lock.** A host-wide lock that prevents two agents on one
machine from reconciling the same policy, held across the process lifetime,
released on crash rather than leaking, and reporting who holds it. Also provide
the host-wide **allocation** lock `e1` takes before creating each runtime.

**4. Process control.** Spawn, observe, and terminate a child process, with a
stable process identity that survives being written to the journal and read
back after a restart — a bare PID is not sufficient identity after a reboot,
because PIDs are reused.

**5. Restrictive handoff.** Create a temporary file with restrictive
permissions on each OS, for the JIT configuration handoff, plus its guaranteed
deletion. JIT data must never be passed as a command-line argument, because a
process listing would reveal it (`07-security.md`, threat table). The primitive
lives here; `e3` uses it.

**6. Redacting log sink.** Structured allowlist logging with **unconditional**
redaction of tokens, `Authorization` and other credential headers, JIT blobs,
and paths. Allowlist, not denylist: a value that is not explicitly permitted is
redacted, so a field added later cannot leak by default.

## Definition of Done

- Contract tests for paths, lock, process control, temp-file permissions, and
  the log sink pass natively on Windows, macOS, and Linux in CI.
- The support matrix accepts every documented OS/architecture pair, warns on
  ARM64, rejects an undocumented pair, and reports the Linux-only container
  limitation.
- Two processes contending for the single-instance lock produce exactly one
  holder; the loser gets an actionable message naming the holder. Killing the
  holder releases the lock without manual cleanup.
- A spawned child is observable and terminable; its recorded identity is
  re-resolvable after a simulated restart and does **not** match a recycled PID
  belonging to a different process.
- A temp file created for handoff is unreadable by other local users on each
  OS, and is deleted on both the success and the failure path.
- A secret-injection log scan with tokens, credential headers, and a JIT blob
  routed through the sink finds none of them in the output; a newly added
  unlisted field is redacted by default.
