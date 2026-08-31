# Code review with fixes

## Goal

Run the `code-review` skill at `high` effort with `--fix` over the complete run
branch diff, validate every applied fix, and commit the fixes locally.

## Inputs

- `git log --oneline origin/main..HEAD` is non-empty.
- `git status --porcelain` is empty.

## Steps

1. Enter and verify the worktree. Stop if either input precondition fails.
2. Invoke the `code-review` skill as `high --fix $worktree_path`. The explicit
   worktree path is mandatory because a skill may start from the main checkout.
   Wait for the skill's final result; do not treat a background launch message
   as completion.
3. Confirm from the skill's scope report that it reviewed
   `origin/main...HEAD` in this worktree. `main...HEAD` is acceptable only when
   local `main` and `origin/main` resolve to the same commit. Re-run with the
   explicit path if the scope is wrong.
4. Inspect `git status`, `git diff`, and `git rev-parse --show-toplevel` after
   the review. Ensure all edits are in the worktree. Remove any mutation planted
   only to test the review (flipped conditions, disabled assertions, markers, or
   similar residue).
5. Evaluate findings against the task's acceptance criteria and repository
   evidence. Apply valid fixes; do not broaden product scope or alter immutable
   `.taskflow` task specs. If a suggested fix is rejected, record the concrete
   reason.
6. If the tree changed, run focused tests and the complete local gate. Repair or
   revert any review edit that makes the gate fail. Then commit the surviving
   fixes locally with an appropriate `fix:` or `refactor:` message. If there are
   no valid fixes, create no empty commit.

## Success criteria

- The skill reviewed the worktree's complete branch diff at high effort with
  `--fix`, and the report states its finding count.
- Every surviving fix is tested, passes the full local gate, and is committed.
- `git status --porcelain` is empty.
- Nothing was pushed and no PR was created.
