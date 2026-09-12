# Task specifications

These specifications are immutable after execution starts. Group letters are
conflict domains; sequence is strict within a group. Complexity 1-4 maps to
`fast`, 5-7 to `mid`, 8-10 to `top`, raised one tier for production/security.

| Group | Conflict domain |
|---|---|
| A | Windows service launcher, supervisor, installer and status |
| B | WSL heartbeat, fence, supervisor and recovery |
| C | TUI snapshot and rendering |
| D | Cross-cutting acceptance, packaging and documentation |

Owner gate **OG1** applies before any real distribution termination test: the
test must target a disposable named distribution and prove every other
distribution is untouched. The implementation has no forced automatic path.

