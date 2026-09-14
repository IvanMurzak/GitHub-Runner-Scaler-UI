# Adversarial review findings

Reviewed 2026-09-13 against repository code, cross-document invariants and the
authoritative sources linked from `03-platform-strategy.md`.

## Result

No P0 broken guarantee remains. Confirmed P1/P2 findings were corrected without
altering D1-D9.

## Corrected P1 findings

1. Selector uniqueness was underspecified under GitHub's superset matching
   (`crates/domain/src/policy.rs:357-401`). Selectors are now derived,
   non-overridable and explicitly required by each job.
2. CLI rejects duplicate targets and later selects the first target match
   (`crates/app/src/cli/policy.rs:542-552`,
   `crates/app/src/cli/policy.rs:1171-1184`). Every operation must select
   `(target, profile)` or refuse ambiguity.
3. Mutation fencing was target-wide. It is now scoped to selected `PolicyId`, so
   a busy native profile cannot block an idle isolated sibling.
4. Expression-based `runs-on` cannot be resolved by current demand reading
   (`crates/agent/src/reconcile.rs:89-96`). UX now requires a static selector.
5. Provider observability lacked a bounded redacted diagnostics channel.
6. Four-platform feasibility was stated too strongly; native gates now decide
   when each backend is supported.

## Corrected P2 findings

- Threat-boundary wording reflects locked D6.
- README, document map and ROADMAP review status agree.
- ROADMAP remains the sole live state record; integration landing remains empty.

## Conclusion

The architecture is internally consistent and ready for immutable task
derivation. Native platform acceptance is task evidence, not a planning
assumption.

