# Runner workspace location tasks

These immutable specs derive from the reviewed architecture at `ce7945d`.
ROADMAP.md is the only live execution-state record. Task files never receive a
status field or execution notes.

## Conflict groups

| Group | Conflict domain | Ordered tasks |
|---|---|---|
| A | Domain types and SQLite persistence | `a1`, then `a2` |
| B | Platform path resolution and Windows directory security | `b1`, then `b2` |
| C | Agent allocation, materialization, cleanup, and recovery | `c1`, then `c2`, then `c3` |
| D | CLI mutations, service integration, and read models | `d1` |
| E | TUI settings and path editing | `e1` |
| F | Cross-platform and security acceptance gates | `f1` |
| G | User documentation and README contract tests | `g1` |

Tasks in one group run by ascending `sequence`. Different groups may overlap
only after every declared dependency has merged and verification has completed.

## Immutable IDs

| ID | Outcome |
|---|---|
| `a1-workspace-domain` | Pure host, policy, attempt, and path contracts |
| `a2-workspace-store` | Migration 3, durable leases, and atomic mutation guards |
| `b1-runner-path-platform` | Platform defaults and operational path preflight |
| `b2-windows-root-acl` | Restrictive Windows default-root access |
| `c1-effective-runtime-root` | Effective disposable root without isolation regression |
| `c2-persistent-slot-allocation` | Stable exclusive persistent slot allocation |
| `c3-persistent-cleanup-recovery` | Allowlist cleanup, quarantine, and restart recovery |
| `d1-workspace-cli-read-models` | Complete CLI, service, status, and shared mutation surface |
| `e1-workspace-tui` | Host and repository path editing in the dashboard |
| `f1-workspace-security-acceptance` | Cross-platform, migration, concurrency, and security gates |
| `g1-readme-workspace-guidance` | User-first README commands and cache guidance |
