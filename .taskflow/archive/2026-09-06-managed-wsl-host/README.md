# Managed WSL host

Status: completed 2026-09-07; all derived tasks merged with green checks and
the feature subsequently shipped in release 0.4.0. Archived 2026-09-11.

## Problem

`runner-manager` can manage the operating system on which its binary is running,
but a Windows workstation commonly has a second useful execution environment:
a WSL2 Linux distribution. Today an operator must install a second binary,
service, credential and Windows keep-alive task by hand. That setup is neither
discoverable nor reproducible on another workstation.

The product must make a WSL2 distribution a first-class managed host while
keeping its GitHub credential independent from the Windows host. The released
feature will be used to adopt the existing `Ubuntu` installation on `IvanPC`,
publish release `0.4.0`, and replace the hand-created keep-alive task.

## Locked owner decisions

- **D1 — 2026-09-06:** This is a source feature in `runner-manager`, not a local
  provisioning script or token-sync service.
- **D2 — 2026-09-06:** One physical Windows workstation may serve Windows and
  Linux jobs concurrently; each environment runs its own daemon and capacity
  policy.
- **D3 — 2026-09-06:** Windows and each WSL host use independently issued
  GitHub App credentials. Credentials are never copied from the active Windows
  store and are never kept in a Windows staging store.
- **D4 — 2026-09-06:** The first release supports any installed, named WSL2
  distribution that has systemd and the released Linux architecture; Ubuntu is
  not hard-coded.
- **D5 — 2026-09-06:** Provisioning is idempotent and adopts an existing Linux
  runner-manager data directory, credential and service without deleting them.
- **D6 — 2026-09-06:** Workload tools such as Docker are diagnosed, not silently
  installed. The provider owns runner-manager and lifecycle prerequisites, not
  arbitrary job dependencies.
- **D7 — 2026-09-06:** After green tests the feature is released as `0.4.0` and
  installed on this workstation. The existing manual keep-alive task is removed
  only after the product-managed host is healthy.

## Summary

Add a Windows-only WSL provider controller and a global host selector. The
controller discovers WSL2 distributions, installs the exact matching Linux
binary, brokers an independent GitHub device flow directly into the Linux
machine secret store over stdin, installs the Linux boot service, and registers
a per-distribution Windows login task that starts and keeps WSL alive. Existing
commands are then usable against that host, so policies are configured through
the product rather than by hand.

## Document map

- [01-current-architecture.md](01-current-architecture.md) — verified behavior
  and seams.
- [02-target-architecture.md](02-target-architecture.md) — public contract and
  component design.
- [03-security-and-lifecycle.md](03-security-and-lifecycle.md) — credential,
  process and migration guarantees.
- [ROADMAP.md](ROADMAP.md) — execution ledger and release gates.

## Review outcome

The 2026-09-06 adversarial review closed three design defects: a Windows login
task cannot honestly promise pre-login boot availability; a task cannot safely
compose `systemctl` and a keep-alive through shell text; and `uninstall` could be
mistaken for WSL distribution deletion. The target now states login availability,
uses a hidden Linux hold command with no shell, and calls the non-destructive
operation `detach`.
