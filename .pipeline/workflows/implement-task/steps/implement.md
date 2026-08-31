# Implement the task

## Goal

Implement the run's single task, including tests and documentation required by
its acceptance criteria, and commit the result locally in the run worktree.

## Inputs

- The task text supplied to the run. It may be free-form text, a GitHub issue,
  or a path to an immutable task spec under `.taskflow/`.
- A clean run worktree based on `origin/main`.

If there is no task text, stop and report that the pipeline cannot invent its
own scope.

## Steps

1. Enter and verify the worktree as required by the shared preamble. Require a
   clean `git status --porcelain` before starting.
2. Establish the acceptance criteria:
   - For an issue reference, read it with `gh issue view` (read-only).
   - For a `.taskflow/.../tasks/*.md` path, read the complete task, its
     `depends_on`, and every architecture/decision document it explicitly
     references. Treat the task file as immutable during implementation.
   - For free-form text, resolve ambiguity from repository evidence where safe.
     Stop only when a product decision would materially change the result.
3. Inspect the affected crates, existing tests, root workspace configuration,
   and relevant CI or release workflow. Keep changes within the task boundary;
   do not fold unrelated cleanup into the implementation.
4. Implement the behavior and tests together. Cover the success path and the
   meaningful boundary/failure cases. Preserve the project's security posture:
   secrets stay out of output and persistence, validation fails closed, and
   filesystem/service changes remain explicit and recoverable.
5. Run focused tests while iterating, any extra validation required by the task,
   and finally the complete local gate from the preamble. Fix every regression
   introduced by the branch. If a platform-only or credential-backed required
   test cannot run locally, document exactly what was not run and why; never
   claim it passed.
6. Review `git diff` for generated files, secrets, debug output, accidental
   task-spec edits, and unrelated changes. Run `cargo fmt` if formatting is the
   only remaining issue, then repeat `cargo fmt --check`.
7. Commit one coherent change, or a small number of dependency-ordered commits.
   Use the repository's concise commit style (a conventional prefix such as
   `fix:`, `feat:`, `test:`, or `docs:` is appropriate). Do not push.

## Success criteria

- The task's acceptance criteria are satisfied with appropriate automated tests.
- The full local gate and every runnable task-specific gate pass.
- `git status --porcelain` is empty and
  `git log --oneline origin/main..HEAD` is non-empty.
- The run branch has not been pushed and no PR was created.
- The report lists commands run and any explicitly deferred environment-only
  checks.
