---
id: "g1-tui-shell-input"
title: "TUI shell: explicit terminal setup, merged event stream, reducer, focus model, key bindings, copy affordance"
group: "G"
sequence: 1
repo: "."
depends_on: ["f1-cli-auth-host-status"]
importance: 8
complexity: 8
security_critical: false
production_touching: false
model_hint: "top"
taskflow_refs: ["03-control-flows.md", "02-target-architecture.md", "08-user-workflows.md", "01-current-architecture.md"]
---

## Goal

Build the interactive foundation the three TUI screens sit on, and get the two
things right that a default Ratatui setup gets wrong: mouse events, which
Crossterm does not emit unless explicitly enabled, and text selection, which
mouse capture takes away.

## Scope & seams

Owns `crates/app/src/tui/{mod,shell}.rs`. Renders `f1`'s presentation state; it
never calls GitHub and never blocks on disk (`03-control-flows.md`, flow 6.3).

**Terminal setup, explicitly** (`03-control-flows.md`, flow 6.1). Enable raw
mode, the alternate screen, and `EnableMouseCapture`, and build Crossterm with
the `bracketed-paste` and `event-stream` features. `ratatui::init()` alone
enables **none** of these and produces a mouse-dead TUI — the requirement is
keyboard *and* mouse as first-class controls, so this is a correctness issue,
not a nicety. Restore the terminal on every exit path, including panic.

**Merged event stream.** Merge Crossterm key, mouse, resize, paste, and focus
events with application timer and agent events into a single stream feeding one
reducer. Focused controls dispatch **the same command handlers the CLI uses**
(`02-target-architecture.md`, principle 5) — the TUI never opens a second
configuration path.

**Copy affordance** (flow 6.2). Mouse capture suppresses the terminal's own
text selection, so provide an explicit copy affordance **and** a key that
releases mouse capture. Without both, the "copy-safe diagnostics" requirement
becomes unsatisfiable the moment mouse capture is switched on.

**Key bindings** (flow 6.5). Every screen is reachable by a single key from
every other screen, and **no key is bound twice**:

| Key | Action | | Key | Action |
|---|---|---|---|---|
| `d` | Dashboard | | `/` | Type-to-filter in the focused table |
| `r` | Repositories | | `F5` | Refresh |
| `n` | Runners | | `?` | Key help |
| `s` | Settings for the selected repository | | `Esc` | Close a modal, then a subscreen |
| `h` | Host settings | | `q` | Exit TUI **without stopping a running daemon** |
| `a` | Activity and errors, from any screen | | | |

**Accessibility floor**, applied by the shell so no screen can opt out: mouse,
arrows, `Tab`/`Shift-Tab`, `Enter`, `Esc`, and single-key shortcuts all work;
**no mouse-only action exists**; status uses text, icons, and colour together
so colour alone never encodes busy, error, or ownership; a small terminal shows
a deliberate compact layout and key-help overlay rather than clipped controls.

**Redaction at the render boundary.** No screen may display the user access
token, an Actions-service admin token, a message-queue token, an encoded JIT
configuration, or a command line containing any of them. Enforce it here, once,
rather than per screen.

## Definition of Done

- Mouse clicks are received and dispatched — a test or recorded session proves
  capture is actually enabled, not merely requested.
- Bracketed paste and focus events arrive; resize re-lays out without clipping.
- The terminal is restored on normal exit, on error exit, and on panic.
- Reducer tests cover key, mouse, resize, paste, timer, and agent events.
- A binding test asserts every screen is reachable in one key from every other
  screen and that no key is bound twice.
- `q` exits the TUI and leaves an already running daemon running, asserted.
- Releasing mouse capture restores native terminal selection, and the copy
  affordance works while capture is on.
- A frame-budget test passes, and rendering performs no network or blocking
  disk I/O — asserted structurally, not by timing alone.
- A small-terminal snapshot shows the compact layout with the key-help overlay
  and no clipped control.
- A redaction test drives every sensitive value through presentation state and
  finds none of them in any rendered frame.
