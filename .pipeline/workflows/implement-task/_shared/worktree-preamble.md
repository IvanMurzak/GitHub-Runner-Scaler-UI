# Worktree and repository discipline — binds every step

This run uses `isolation: run`. The pipeline CLI provisions one external git
worktree before `implement`; every step shares that checkout and its local
`worktree-<run>` branch. The dispatch provides:

- `$worktree_path` — absolute path to the run checkout.
- `$worktree_env_file` — dotenv file containing `WORKTREE_PATH`,
  `WORKTREE_BRANCH`, `PROJECT_ROOT`, `BASE_BRANCH`, and slot metadata.

Rules for every step:

1. **Enter and verify the worktree first.** Start the first shell call with:

   ```bash
   cd "$worktree_path" && set -a && source "$worktree_env_file" && set +a
   ```

   Before writing, verify that `git rev-parse --show-toplevel` is the worktree,
   the current branch equals `$WORKTREE_BRANCH`, and that branch starts with
   `worktree-`. Never edit the main checkout at `$PROJECT_ROOT`.

2. **Keep GitHub writes in `land`.** `implement`, `code-review`, and `simplify`
   may read an explicitly referenced issue, but must not push, create/update a
   PR, merge, or otherwise mutate GitHub. They commit changes locally.

3. **Use this repository's sources of truth.** Read the task first, then inspect
   the root `README.md`, `Cargo.toml`, relevant crates/tests, and the workflows
   under `.github/workflows/` as needed. If the task points to
   `.taskflow/<set>/tasks/<task>.md`, read that task and the architecture files
   it references; do not weaken or silently reinterpret its locked decisions.
   Do not import build commands or architecture conventions from another
   repository.

4. **Run the full ordinary local gate from the worktree root:**

   ```bash
   cargo metadata --locked --format-version 1 >/dev/null
   cargo fmt --check
   cargo build --workspace --all-features
   bash tests/assert-no-shippable-mutants.sh --scan-only
   cargo clippy --all-targets -- -D warnings
   cargo test --workspace
   ```

   Narrow tests are useful while iterating, but do not replace this final gate.
   Follow additional commands named by the task. Do not run ignored privileged
   installer or fixture-backed end-to-end tests unless the task requires them
   and the necessary privileges/credentials are available; compilation plus the
   GitHub rollup is the default authority for those environments.

5. **Preserve command status.** Do not pipe a command when its exit code decides
   success. Capture output and status separately when both are needed.

6. **Keep scratch data inside the worktree** and leave it untracked. Do not
   write task artifacts into `$PROJECT_ROOT`, `.pipeline/.runtime`, or a shared
   temp directory.
