---
id: "e2-runner-package-cache"
title: "Runner package cache: mandatory SHA-256 verification, fail-closed on absent checksum, 30-day freshness, prune guard"
group: "E"
sequence: 2
repo: "."
depends_on: ["c3-rest-inventory-gateway", "d1-platform-core", "b1-domain-core"]
importance: 8
complexity: 6
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["05-infrastructure.md", "07-security.md", "01-current-architecture.md"]
---

## Goal

Get the GitHub runner application onto the host in a way that is verifiable and
does not silently rot. Two failure modes drive this task: a tampered package
executes arbitrary code on the operator's machine, and a stale package makes
every job start failing on a long-lived host for a reason nobody will guess.

## Scope & seams

Owns `crates/agent/src/package.rs`. Consumes `c3`'s runner-download metadata
and `d1`'s paths.

**Selection.** Take download metadata from GitHub only, and select the entry
matching this host's OS and architecture — never a hardcoded URL.

**Verification is mandatory and fails closed.** Verify the published SHA-256
before extraction. `sha256_checksum` is an **optional** field in GitHub's
response schema; when it is absent, refuse to install and require an
operator-pinned digest instead of installing an unverified package
(`05-infrastructure.md`). "No checksum published" must never degrade into "skip
the check".

**Immutable versioned cache.** Extract to a versioned cache directory that is
never mutated in place. Each JIT runtime is a copy or link from that cache plus
a unique workspace (`e3`). Runner binaries and approved tool caches are retained
separately from job workspaces.

**Freshness (30 days).** GitHub rejects runners older than 30 days from the
latest release and plans to block them at registration
(`01-current-architecture.md`, edge case 7). Re-check the published version on
a bounded interval and before **each cold start**, and download a newer package
when the cached version is more than 30 days behind. A version-rejection
response is **terminal and operator-actionable**, not a retryable error — a
retry loop here turns a fixable condition into a silent outage.

**Prune guard.** A cached version may be pruned only when no active attempt
references it.

## Definition of Done

- The selected package matches the host OS and architecture, and an unsupported
  pair is refused before any download.
- A package whose bytes do not match the published SHA-256 is rejected and not
  extracted; the partially downloaded file is removed.
- Metadata with no `sha256_checksum` refuses to install and names the
  operator-pinned-digest remedy; supplying a pinned digest then succeeds.
- A cache entry is never mutated after extraction; a second install of the same
  version is a no-op.
- A cached version more than 30 days behind triggers a refresh before a cold
  start; a version-rejection response surfaces as terminal with an operator
  action and produces no retry.
- Pruning refuses to remove a version referenced by a non-terminal attempt, and
  succeeds once that attempt is terminal.
- Job workspaces are never stored inside the package cache.
