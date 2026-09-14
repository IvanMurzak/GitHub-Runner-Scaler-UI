# Label-routed runner profiles

## Required behavior

One repository can own simultaneous configurations:

| Profile | Execution | Capacity | Immutable selector |
|---|---|---:|---|
| `native` | host process | 2 | `rm-home-win-x64-native` |
| `py-isolated` | required sandbox | 4 | `rm-home-win-x64-py-isolated` |

Jobs in the same workflow choose independently:

```yaml
jobs:
  native:
    runs-on: [rm-home-win-x64-native]
    steps:
      - uses: ./path/to/action
  isolated:
    runs-on: [rm-home-win-x64-py-isolated]
    steps:
      - uses: ./path/to/action
```

Workflow filename and action do not choose the environment; each job's
`runs-on` does.

## Unambiguous matching

The current superset predicate (`crates/domain/src/policy.rs:357-401`) means two
profiles sharing a broad host label can both match a job requesting only that
label. Different optional label sets alone are insufficient.

1. Every autoscaling profile owns one derived, non-overridable selector unique
   within its repository target on this host.
2. A job matches only when it explicitly requires that selector and all other
   required labels are available on the profile.
3. A selector cannot be another profile's optional label.
4. A job requiring two profile selectors matches neither and reports an error.
5. A job without a known selector is not guessed and starts no runner.
6. Reconciliation blocks and reports any job tallied by two profiles.

## Identity and migration

Add case-insensitive `ProfileName` and a unique index on
`(host_id, target_scope, target_slug, profile_name)`. Existing rows become
`default`; their current immovable label remains the selector, preserving
existing workflows. New selectors use
`rm-<host>-<os>-<arch>-<profile>`. `PolicyId` remains attempt and capacity
identity. Renaming is excluded from V1 because it changes workflow routing.

New selectors are derived from the validated profile name and requested host
identity, never accepted as arbitrary input. Profile/label writes also prove
that no selector in the target is reused as another profile's optional label;
load performs the same fail-closed validation.

The schema has no target uniqueness constraint
(`crates/domain/src/store/migrations/0001_initial_schema.sql:43-68`); the broad
refusal is in CLI (`crates/app/src/cli/policy.rs:542-552`). Replace it with
composite profile uniqueness.

## Polling and capacity

Retain one GitHub poll per target, then tally each profile against the shared
reading. This already exists (`crates/agent/src/reconcile.rs:79-87`,
`crates/app/src/cli/daemon.rs:1122-1133`). Host capacity stays shared; profile
capacity is independent. Request-budget projection deduplicates equal targets.

`runs-on` expressions such as `${{ matrix.runner }}` remain unresolvable to
the current demand reader (`crates/agent/src/reconcile.rs:89-96`). Automatic
scaling therefore requires a static selector; CLI/TUI preview and docs state it.

## CLI and TUI

```text
repo profile add OWNER/REPO --name native --execution native ...
repo profile add OWNER/REPO --name py-isolated --execution isolated ...
repo profile set-execution OWNER/REPO --profile py-isolated ...
repo profile set-scale OWNER/REPO --profile py-isolated ...
repo profile remove OWNER/REPO --profile py-isolated
```

`repo add` remains shorthand for `default`. Commands without `--profile` work
only when exactly one profile exists; otherwise they list names/selectors and
refuse ambiguity.

TUI repository navigation groups profile rows below each repository. Runner
Profile Settings controls name/selector display, copyable `runs-on`, execution
mode, backend/image/resources, capacity, labels, workspace and diagnostics.
Creation previews the selector; deletion drains only the selected profile.

## Acceptance

1. Native and isolated jobs in one workflow create exactly one runner each.
2. The same local action observes the correct environment in both jobs.
3. Isolation failure blocks only its profile; native demand continues.
4. Shared optional labels cannot duplicate demand.
5. Missing/multiple selectors start no runner and show a remedy.
6. Existing databases and workflows behave identically after migration.
7. Additional profiles do not increase target polling cost.
8. CLI/TUI cannot mutate the wrong profile, including case variants.
