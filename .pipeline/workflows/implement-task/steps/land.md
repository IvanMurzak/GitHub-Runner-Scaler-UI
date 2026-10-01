# Land: publish and verify CI

## Goal

Publish the reviewed branch as a pull request against the run's `BASE_BRANCH`
and verify the complete GitHub check rollup. The Taskflow scheduler owns merge.

## Context

- This is the only step allowed to push or create/update a PR.
- Both `.github/workflows/ci.yml` and `.github/workflows/e2e.yml` run for PRs.
- Never merge, force-push, use `--admin`, or bypass branch protection.
- A dirty `.pipeline/` tree is not expected or exempted.

## Inputs

- `git log --oneline "origin/$BASE_BRANCH..HEAD"` is non-empty.
- `git status --porcelain` is empty.
- `gh auth status` exits 0.

## Steps

1. Enter and verify the worktree and input preconditions. Read `BASE_BRANCH`
   from the worktree env file; require `origin/$BASE_BRANCH` to exist.
2. Look for an existing open PR for `$WORKTREE_BRANCH` with
   `gh pr view "$WORKTREE_BRANCH" --json number,state,url,baseRefName`.
   Reuse it only if it targets `$BASE_BRANCH`.
3. Run `git fetch origin "$BASE_BRANCH"`. If
   `git merge-base --is-ancestor "origin/$BASE_BRANCH" HEAD` fails, run
   `git rebase "origin/$BASE_BRANCH"`. On conflict, abort and report paths.
   After a successful rebase, run the complete local gate again. Stop if it
   fails. Never rewrite an already published branch.
4. Run `git push -u origin "$WORKTREE_BRANCH"` for a new PR. For a resumed
   PR, push only when the remote head is an ancestor of local HEAD; otherwise
   stop and report the divergent head.
5. If no PR exists, run
   `gh pr create --base "$BASE_BRANCH" --head "$WORKTREE_BRANCH"` with a
   concise title and a body explaining behavior, validation, and the Taskflow
   task or issue reference. Capture the PR number and URL.
6. Run `pipeline ci-wait --pr "$pr" --repo "$worktree_path" --timeout 540 --json`
   without piping it. Capture its output and exit code separately. Exit 0
   means all reported checks passed. A timeout may exit 1 with JSON
   `status: "timeout"` even while checks are only pending; when the current
   PR head still has pending checks and zero failures, repeat the wait at most
   ten times. Treat exit 3 (pending) the same way. For a terminal exit 1 with
   failed checks, report names and links; if the same check fails on the base
   branch for the same reason, follow the executor's out-of-scope blocker
   protocol. For exit 2 or 4, report the CLI or missing-check condition and
   stop. Never infer success from a timeout: require a fresh exit-0 result
   for the current published PR head.
7. Verify `gh pr view "$pr" --json state,baseRefName,headRefOid,url` reports
   an `OPEN` PR against `$BASE_BRANCH` at this step's published head.
8. Report PR number/URL, published head SHA, and final check totals.

## Success criteria

- The PR is `OPEN` against `$BASE_BRANCH` at the published head.
- `pipeline ci-wait` returned 0 for that PR head.
- No GitHub write occurred before `land`; no merge or bypass occurred.
