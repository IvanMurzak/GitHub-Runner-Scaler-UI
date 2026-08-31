# Land: publish, verify CI, squash-merge

## Goal

Publish the final reviewed branch, create or reuse its pull request, wait for the
complete GitHub check rollup, and squash-merge into `main` only when every check
passes.

## Context

- This is the only step allowed to push, create/update a PR, or merge.
- Both `.github/workflows/ci.yml` and `.github/workflows/e2e.yml` run for pull
  requests. `pipeline ci-wait --pr` observes the combined PR check rollup;
  neither workflow may be ignored.
- The repository's landed PR history is linear, so use squash merge. Never use
  `--admin` and never bypass branch protection.
- A non-zero `gh pr merge` can occur after a server-side merge succeeded. Always
  verify the PR state before deciding that the merge failed.
- This step and all preceding steps have `self_improve: false`; therefore a
  dirty `.pipeline/` tree is not expected or exempted.

## Inputs

- `git log --oneline origin/main..HEAD` is non-empty.
- `git status --porcelain` is empty.
- `gh auth status` exits 0.

## Steps

1. Enter and verify the worktree and all input preconditions.
2. Look for an existing open PR for `$WORKTREE_BRANCH` with
   `gh pr view "$WORKTREE_BRANCH" --json number,state,url`. Reuse it on a
   resumed run; otherwise mark that a PR must be created.
3. Refresh and integrate the base:
   - Run `git fetch origin main`.
   - If `git merge-base --is-ancestor origin/main HEAD` succeeds, continue.
   - Otherwise run `git rebase origin/main`. On a conflict, abort the rebase and
     stop with the conflicting paths; this frozen landing step must not invent a
     conflict resolution.
   - After any successful rebase, run the complete local gate again.
4. Publish the current branch state:
   - For a new PR, run `git push -u origin "$WORKTREE_BRANCH"`.
   - For a resumed PR, compare local and remote heads. Push only when they
     differ; use `--force-with-lease` only when the rebase rewrote already
     published commits. Never use an unguarded force push.
5. If no PR exists, create one with
   `gh pr create --base main --head "$WORKTREE_BRANCH"`. Use a concise title
   that will also make a good squash commit. The body must explain what and why,
   summarize validation, link the Taskflow task when applicable, and say
   `Closes #N` when the input names an issue. Capture the PR number and URL.
6. Run the built-in CI gate without piping it:

   ```bash
   out=$(pipeline ci-wait --pr "$pr" --repo "$worktree_path" \
     --timeout 540 --json)
   code=$?
   ```

   A single executor call may be time-limited, so repeat at most ten times only
   when `code=3` (still pending). Interpret terminal codes as follows:
   - `0`: all reported checks passed; continue to merge.
   - `1`: a check failed; do not merge. Report failed check names and links.
   - `2`: CLI/usage/`gh` failure; report the output and stop.
   - `3`: repeat, up to the bounded limit; then report pending checks and stop.
   - `4`: no checks appeared within the grace period; verify Actions triggered,
     report the condition, and stop.
7. With a `code=0` result from this step in hand, run
   `gh pr merge "$pr" --squash --delete-branch`. Capture output and exit code.
   Never pass `--admin`. On any non-zero result, query
   `gh pr view "$pr" --json state,mergeCommit,url`: continue only if the state
   is `MERGED` and `mergeCommit` is non-null; otherwise report the refusal and
   stop without retrying blindly.
8. Best-effort only: if `$PROJECT_ROOT` is clean, currently on `main`, and its
   `main` is not checked out by another active operation, run
   `git -C "$PROJECT_ROOT" pull --ff-only`. A cleanup failure does not change a
   confirmed server-side merge into a failed task.
9. Report the PR number/URL, squash commit SHA, final check totals, and any
   best-effort cleanup warning.

## Success criteria

- The PR is `MERGED` with a non-null squash commit.
- The merge occurred only after `pipeline ci-wait` returned 0 in this step for
  this PR's current head.
- The PR used squash merge and no administrative bypass.
- No GitHub write occurred before `land`.
