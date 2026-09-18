# Code review with fixes

## Goal

Independently review the complete run branch diff at high effort, validate
every applied fix, and commit fixes locally. This step runs in a fresh Codex
executor, separate from the implement executor.

## Inputs

- `git log --oneline "origin/$BASE_BRANCH..HEAD"` is non-empty.
- `git status --porcelain` is empty.

## Steps

1. Enter and verify the worktree. Read `BASE_BRANCH` from the worktree env
   file; require `origin/$BASE_BRANCH` to exist and both inputs to pass.
2. Review `git diff "origin/$BASE_BRANCH...HEAD"` and the task's acceptance
   criteria at high reasoning effort. Inspect all changed production and test
   code, call sites, migration/load/write behavior, error paths, and platform
   boundaries that the task affects. An available review skill may assist, but
   the fresh executor's own full-diff review is sufficient.
3. Report the reviewed base and head SHAs, the files and commits covered, and
   the finding count with severity and concrete evidence for each finding.
   Recheck the diff scope against `git log --oneline
   "origin/$BASE_BRANCH..HEAD"`. Stop if any changed file was omitted.
4. Inspect `git status`, `git diff`, and `git rev-parse --show-toplevel`
   after review. Keep all edits in the worktree. Remove any mutation planted
   only to test review behavior.
5. Evaluate findings against the task and repository evidence. Apply valid
   fixes within scope; record a concrete reason for any rejected suggestion.
   Never edit immutable Taskflow task specs or ROADMAP.
6. If the tree changed, run focused tests and the complete local gate. Repair
   or revert any review edit that fails validation. Commit surviving fixes
   locally with an accurate message. If there are no valid fixes, create no
   empty commit.

## Success criteria

- A fresh Codex review executor covered the complete integration-base diff at
  high effort and reported its finding count and scope.
- Every surviving fix is tested, passes the full local gate, and is committed.
- `git status --porcelain` is empty.
- Nothing was pushed and no PR was created.
