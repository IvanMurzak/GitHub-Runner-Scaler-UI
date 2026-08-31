# Simplify the branch

## Goal

Run the `simplify` skill over code changed by the branch, keep only clear
quality improvements that preserve behavior, and commit them locally.

## Inputs

- `git log --oneline origin/main..HEAD` is non-empty.
- `git status --porcelain` is empty.

## Steps

1. Enter and verify the worktree. Stop if either input precondition fails.
2. Invoke the `simplify` skill with `$worktree_path` as its explicit target.
   Wait for its final result and confirm that its scope is the changed code in
   `origin/main...HEAD` inside this worktree, not the main checkout.
3. Inspect every edit. Keep changes that make the implementation materially
   clearer, smaller, less repetitive, or more efficient without changing the
   task's behavior, public contract, security boundaries, or locked Taskflow
   decisions. Revert speculative abstraction, unrelated cleanup, test weakening,
   and changes made only for stylistic churn.
4. If edits survive, run focused tests and the complete local gate. Repair or
   revert any cleanup that fails validation, then commit the result locally with
   a `refactor:` (or otherwise accurate) message. If nothing improves the code,
   create no empty commit.

## Success criteria

- The skill examined the branch's changed code in the run worktree and its
  report states what it changed, including a no-change outcome.
- Surviving cleanups preserve the acceptance criteria, pass the full local gate,
  and are committed.
- `git status --porcelain` is empty.
- Nothing was pushed and no PR was created.
