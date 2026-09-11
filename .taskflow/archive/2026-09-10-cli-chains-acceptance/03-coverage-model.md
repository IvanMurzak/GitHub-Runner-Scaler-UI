# 03 Coverage Model

## Coverage units

A “combination” is a named initial state plus an ordered action list and its
expected observations. Merely permuting two read-only commands does not count.
A generated case is retained only when it contributes at least one of:

- a previously uncovered compatible mutating-action pair;
- a boundary or refusal class;
- a restart/persistence transition;
- a repo/org/host interaction;
- a security or recovery invariant.

The checked-in coverage manifest records each case and the contribution that
justifies it. This prevents a large numeric count made of semantically duplicate
recipes.

## State-machine rules

The reference model implements a pure transition function:

```text
(model, action) -> (expected exit class, expected observation, next model)
```

On a refusal, `next model` equals `model`. On success, only the fields owned by
the action may change. Reads never change model state. The real command is run
between calculating the expectation and observing the result, so production
state is never used to derive its own expected value.

Names, labels, and paths come from small equivalence-class sets containing
ordinary, repeated, boundary, case-sensitive, and invalid values. Capacity
values include zero, one, the product default, a normal configured value, and
`u16::MAX`. The action constructor enforces CLI syntax; domain-invalid values
remain available so refusal paths are covered.

## Core invariants

- A failed mutation is atomic in the modelled database and filesystem state.
- Reads are idempotent and agree across human output, JSON, and the `Store`
  projection where those views overlap.
- Repository and organization policies never overwrite one another.
- A duplicate add does not replace or arm the existing policy.
- Monitor-only, pending, enabled, draining, and repair-required distinctions are
  preserved through unrelated commands.
- The derived host label is present exactly once and cannot be removed through
  label commands.
- Capacity and workspace changes obey active-attempt and path-overlap guards.
- Non-purge removal preserves diagnostics; purge follows its documented active
  attempt guard.
- GitHub discovery is read-only and bounded to the expected request set.
- Fixture tokens, device codes, JIT values, and canaries never reach command
  output, logs, configuration files, or SQLite dumps.
- No case touches paths outside its resolved temporary roots or the loopback
  fixture endpoint.

## Replay and diagnostics

Case identifiers are stable (`local-0001`, `wsl-0001`, and so on). A failure
prints the identifier, generation seed/version, pre-state, actions already run,
expected transition, observed exit/output/state, and fake call history. The
default test always runs the complete corpus. A developer may select one stable
identifier for diagnosis without regenerating or shrinking the corpus.

## Command accountability

The leaf manifest is generated from the same reviewed command list asserted by
`crates/app/tests/cli_command_surface.rs`. Each leaf names its responsible test
track and evidence location. A leaf may be excluded from generated execution
only with a concrete safety reason and an existing dedicated test reference;
“not modelled” alone is not a valid classification.
