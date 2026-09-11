---
name: implement-task-pipeline-is-frozen
description: implement-task pipeline freezes every step (self_improve false); retrospective prompts omit frozen_files, so batch passes must refuse and relay fixes for main-checkout review
metadata:
  type: project
---

`.pipeline/workflows/implement-task` sets `self_improve: false` on all four steps, so every step body and `_shared/worktree-preamble.md` are frozen. The Tier-2 retrospective prompt still routes its doc-actionable feedback to the improver and passes NO `frozen_files` list (the `retrospective` action shape has none). Derive frozen files from `pipeline.yml` yourself before editing.

**Why:** The author wants workflow changes reviewed from the main checkout (PIPELINE.md says so explicitly). Edits in the run worktree would never reach main: there is no `worktree-finalize` hook, and `worktree-destroy.py` force-removes the slot on `completed`. On a `halted` run the slot is kept for resume, and `land` requires `git status --porcelain` to be empty. Tracked `.pipeline/` edits would therefore block the resume, or leak into the task PR. Plugin §17 says a frozen step's problems go to the human-only bucket.

**How to apply:** In batch mode on this pipeline, change nothing. Refuse the batch, verify each problem against the source, and read the MAIN checkout's copy (if main already has the fix, say so instead of relaying). Relay exact replacement text anchored on main's wording so a human can apply it there. Also point out that UNCOMMITTED edits on main never reach a run, because each run executes the copy in its worktree, which is checked out from a commit. The manager's prompt may name a frozen file as "the doc-actionable target" and still say "never edit frozen files"; the frozen rule wins. Grep cannot see feedback files (`.feedback/.gitignore` hides them from ripgrep), so use Glob and Read.

Relayed so far (all 2026-09-10):
- Run 01a08db3, first pass: code-review Step 3 scope-by-git, a pre-existing-gate-failure rule, the simplify Step 2 rewrite, a `PP_TASK` var for task text on resume, and the implement taskflow-spec gap.
- Run 01a08e0a: an implement upstream re-check (`git fetch origin main` plus `HEAD..origin/main` after Step 2 and before the commit; halt when upstream already satisfies the task).
- Run 01a08db3, end-of-run pass (merged as PR #64): preamble rule 1 must prefix EVERY shell call, because fresh shells drop cwd and env (land-02). Also the code-review Step 3 case where the skill reports only file and line totals: match them against `git diff --stat origin/main...HEAD`. Main had a commit-list variant only.

One run can get several retrospectives over the same feedback folder, and the same files come back each time. A repeat within one run ID therefore proves nothing, so check main. A repeat from a NEW run means the fix has not been applied yet.
