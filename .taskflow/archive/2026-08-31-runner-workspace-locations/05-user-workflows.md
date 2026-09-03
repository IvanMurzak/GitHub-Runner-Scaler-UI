# User workflows

## UX principles

1. Show the effective path before asking the operator to change it.
2. Name whether a value is default, configured, or repository-specific.
3. Preview destructive risk, but never imply old data will be deleted.
4. Use the same vocabulary and validation in CLI, TUI, status, and README.
5. Keep the safe disposable mode one action away from persistent mode.
6. Make path errors actionable by printing the exact command that fixes them.

## Journey 1: inspect the host default

The operator runs:

```powershell
runner-manager host show
```

Windows output includes:

```text
runner root              C:\rman
runner root source       platform-default
active ephemeral paths   0
```

On a non-C system drive, the displayed value uses that drive. Output never
hard-codes a path the process did not resolve.

In TUI, `h` opens Host Settings and shows the same effective path and source
without entering edit mode.

## Journey 2: change the global disposable root

CLI:

```powershell
runner-manager host set-runtime-root --path "<GLOBAL_RUNNER_ROOT>"
```

Success output:

```text
Runner root configured.
Previous: C:\rman (platform-default)
Current:  <GLOBAL_RUNNER_ROOT> (configured)
New ephemeral attempts will use this path. No existing directory was moved or deleted.
```

Reset:

```powershell
runner-manager host reset-runtime-root
```

TUI Host Settings flow:

1. Press `h`.
2. Focus `Runner root`.
3. Press Enter to edit, type or paste an absolute path, then Enter to accept.
4. Read inline validation and the effective-path preview.
5. Focus `Save host settings` and confirm.
6. Use `Reset to platform default` to clear the override.

If an affected attempt is active, CLI and TUI show the count and make no
change. The operator drains or waits, then retries.

## Journey 3: enable persistence for one repository

CLI:

```powershell
runner-manager repo set-workspace OWNER/REPO `
  --mode persistent `
  --path "<REPOSITORY_WORKSPACE_ROOT>"
```

Before saving, output names the cross-job trust boundary. Success output shows:

```text
Workspace mode: persistent
Workspace root: <REPOSITORY_WORKSPACE_ROOT>
Slots: created on demand as s1, s2, ...
Retained: each slot's _work directory
Disposable: runner binaries, JIT handoff, and lifecycle files
No existing directory was moved or deleted.
```

TUI repository flow:

1. Open Repositories and select `OWNER/REPO`.
2. Open Repository Settings.
3. See current mode, effective path, and active or cleanup-blocked slot leases.
4. Toggle `Workspace mode` to `persistent`.
5. Enter or paste the repository root.
6. Read the trust warning and path preview.
7. Confirm the policy mutation.

The path control is hidden in ephemeral mode but the effective host runner root
remains visible. Organization Settings explains why persistent mode is
unavailable instead of showing a disabled unexplained control.

## Journey 4: return a repository to disposable mode

CLI:

```powershell
runner-manager repo set-workspace OWNER/REPO --mode ephemeral
```

The command refuses active or cleanup-blocked attempts. On success it prints
the old persistent path and states that every retained slot remains on disk. It
also prints the effective host runner root that future attempts will use.

TUI provides the same preview and result. There is no checkbox that deletes old
slots as a side effect.

## Journey 5: preserve a build cache

The repository workflow disables checkout cleanup only after persistent mode is
configured:

```yaml
- uses: actions/checkout@v7
  with:
    clean: false
```

The first job writes a Git-ignored cache under its checkout. A later job leasing
the same slot can consume it. Concurrent jobs use other slots and do not share
that cache until they later lease the same slot.

README guidance must present the repository command and checkout setting
together. It must also say that `clean: false` does not create persistence on
its own.

## Journey 6: resolve an invalid path

Examples and required messages:

| Input | Result |
|---|---|
| Relative `build\runners` | Refuse: absolute path required. |
| Windows `\\server\share\runners` | Refuse: network and UNC paths unsupported. |
| `C:\` | Refuse: filesystem root is too broad. |
| Config or state directory | Refuse: overlaps protected application data. |
| Another repository's root | Refuse and name the conflicting target. |
| Existing file | Refuse: directory required. |
| Unwritable parent | Refuse and show `host set-runtime-root` or `repo set-workspace` remediation. |
| Active affected attempt | Refuse with active count; change nothing. |

TUI renders the same message inline and preserves the operator's draft for
correction.

## TUI interaction requirements

- Keyboard typing, Backspace, Delete, Home, End, arrows, paste, Escape cancel,
  and Enter accept work in path controls.
- Mouse selects and focuses path controls but is not required for completion.
- Compact terminals scroll or clip secondary explanation, never the current
  value, error, or save control.
- Paths are horizontally scrollable during editing and copyable from detail
  view.
- A saved value survives context recreation and daemon restart.
- Settings screens never enumerate repository file names.

## Status and activity

Repository detail and activity rows distinguish:

```text
ephemeral attempt       C:\rman\a1b2c3d4e5f6
persistent attempt      D:\ci-cache\project\s2
slot cleanup complete   retained _work, removed runner state
slot cleanup blocked    slot s2 quarantined; remediation available
```

Status JSON uses structured mode, source, root, slot, and lease fields rather
than asking consumers to parse a display string.

## README acceptance

The final README must contain:

- the Windows default `%SystemDrive%\rman` with `C:\rman` as an example;
- one complete global root command using `<GLOBAL_RUNNER_ROOT>`;
- one complete repository persistent command using
  `<REPOSITORY_WORKSPACE_ROOT>`;
- the command to return to ephemeral mode;
- the `actions/checkout` `clean: false` example;
- the trust warning and non-deletion behavior;
- Commands block entries matching the real Clap surface.
