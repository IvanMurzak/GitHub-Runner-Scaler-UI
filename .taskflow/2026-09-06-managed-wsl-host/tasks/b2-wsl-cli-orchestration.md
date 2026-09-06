---
id: "b2-wsl-cli-orchestration"
title: "Expose managed WSL hosts through install, status, detach and host routing"
group: "B"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["a1-wsl-platform-adapter", "b1-credential-broker"]
importance: 10
complexity: 10
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "03-security-and-lifecycle.md"]
---

## Goal

Deliver the public, idempotent workflow that turns a named WSL2 distribution
into a second runner-manager host and routes existing commands to it.

## Scope & seams

- Add the documented `wsl list/install/status/detach` commands and global
  `--host local|wsl:NAME` selector with backwards-compatible local default.
- Implement the ordered convergent install transaction from target architecture,
  including preflight-before-auth, exact-version Linux binary, independent auth
  only when needed, optional capacity, Linux service install, lifecycle task,
  provider record and read-back verification.
- Add hidden Linux `wsl-host hold`: verify/start the systemd unit through literal
  process argv and remain signal-responsive until the Windows task stops.
- Proxy existing commands to the exact selected Linux binary, preserving
  stdio/exit code. Intercept WSL `auth login` for brokered flow.
- Status text/JSON distinguish provider record, WSL availability, Linux binary,
  auth, service, lifecycle task, capacity and workload prerequisite diagnostics
  such as Docker. Never infer health from the record alone.
- Detach only the owned Windows task and non-secret provider record.

## Definition of Done

1. CLI help and parse tests cover the entire surface, local compatibility,
   multiple distro names and non-Windows errors.
2. A fake adapter proves exact stage ordering, no mutation/auth before complete
   preflight, preservation/adoption of healthy credential/config/service, and
   safe resumability after every injected failure.
3. Capacity is changed only when explicitly supplied; all policy and runtime-root
   state is preserved.
4. Proxy tests prove exact argv/stdin/stdout/stderr/exit propagation and special
   handling of WSL login without exposing secrets.
5. Hold/task tests prove login-start semantics, systemd start, signal shutdown
   and no shell execution.
6. Status and detach tests prove real-state verification, drift reporting,
   Docker-as-diagnostic behavior, foreign task safety and no Linux deletion.
7. App/platform tests, all-feature workspace build, format and clippy pass.

