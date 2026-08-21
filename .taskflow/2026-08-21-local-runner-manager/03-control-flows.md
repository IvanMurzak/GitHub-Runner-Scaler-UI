# Control flows

## 1. Add a repository from CLI

1. Operator runs `runner-manager auth login`. The tool starts the device flow
   with its built-in public `client_id`, prints the verification URL and user
   code, polls for completion, and stores the returned user access token in the
   machine-scoped secret store (D13). If the published App is not yet installed
   on any repository, it prints the installation URL.
2. Operator runs `runner-manager host set-capacity 2` if the host default is
   not acceptable.
3. Operator runs `runner-manager repo add OWNER/REPO --host-label home-win
   --max-capacity 1`, or `runner-manager org add ORG --host-label home-win
   --max-capacity 1` for an organization-scoped policy (D18). Omitting
   `--max-capacity` creates a monitor-only policy instead (D19): the command
   stops after recording the target and the flow ends here.
4. The command confirms the target is installed for the App, validates the
   host OS/architecture against GitHub's supported matrix, validates
   `min_capacity <= max_capacity`, derives the host-scoped routing label, checks
   the projected REST budget, and writes a transaction to local SQLite. **No
   remote object is created** — after D4 there is nothing to create at add
   time, which removes the partial-creation failure mode entirely. The policy is
   created in `pending`; scaling is never enabled by `add` (D20).
5. It prints the routing label to use in `runs-on` and the next command;
   secrets are never echoed.
6. `runner-manager repo set-scale OWNER/REPO --enabled true` moves the policy
   to `active`.
7. `daemon run` loads the active policy and starts its demand-polling loop.

Failure: a missing installation, duplicate policy, invalid capacity, an
inverted `min_capacity`/`max_capacity` pair, or an unavailable GitHub API
leaves no active policy. Because `add` creates nothing remotely, there is no
partial remote state to repair; `repair_required` survives only for a policy
whose local transaction is inconsistent.

## 2. Demand to job completion

1. The host agent polls queued workflow runs for each active policy's target
   and resolves their jobs, on a bounded interval that shares the REST budget
   with inventory refresh.
2. It counts the queued jobs whose `runs-on` matches this policy's routing
   labels. That count is the demand signal.
3. **No acquisition step exists.** Nothing reserves a job for this host, so a
   second host serving the same labels may start a runner for the same job.
   `01-current-architecture.md` edge case 6 records the consequence and the
   bounding controls.
4. The agent calculates desired capacity, clamps it against both
   `max_capacity` and remaining `host_capacity` headroom, and takes the
   host-wide allocation lock before creating each local runtime.
5. It downloads/verifies the cached runner package if required, creates
   `runtime/<policy-id>/<attempt-id>/`, and requests a JIT configuration from
   `POST /repos|orgs/…/actions/runners/generate-jitconfig` with the policy's
   routing labels.
6. The agent writes the JIT config only to a restrictive temporary file,
   launches the runner process, then removes the file immediately after
   successful handoff. The JIT config is never passed as a command-line
   argument.
7. The runner accepts one job, or finds none and exits on its idle timeout —
   the surplus case from step 3. The dashboard changes its lifecycle state from
   `starting` to `busy` using process state plus GitHub telemetry, and shows an
   idle-exit distinctly from a failure.
8. On exit, the agent preserves redacted diagnostics, removes the workspace
   and JIT artifacts, and marks the attempt terminal.

Failure: a JIT request, download checksum, process start, or runner exit before
job acceptance is retried with bounded exponential backoff while the job
remains assigned. A runner-version rejection and an absent published checksum
are terminal, operator-actionable conditions, not retryable errors. The agent
never reports a job as complete; GitHub remains the source of truth for
workflow outcome.

## 3. Agent restart and offline operation

1. A single-instance lock prevents two agents on one host from reconciling the
   same policy.
2. On startup, the agent reads the lifecycle journal, discovers child
   processes, and reconciles them with GitHub before creating new runners.
3. If GitHub is unreachable, it starts no new JIT runner, retains existing
   runner processes, reports `offline` in TUI/CLI, and backs off with jitter.
   The offline state states that queued jobs are cancelled by GitHub after 24
   hours, so a prolonged outage loses queued work.
4. When connectivity returns, it resumes demand polling. Because demand is
   recomputed from the current queued-job set on every poll rather than
   accumulated from a message stream, a reconnect cannot double-count work — the
   acknowledgement bookkeeping the scale-set model required does not exist.

## 4. Token and JIT expiry

1. The stored user access token does not expire, because the published App
   opts out of user-token expiration (D3). There is no refresh token and no
   client secret, so there is nothing for the agent to renew and nothing for a
   server to hold. The token is revoked by the user uninstalling the App or
   revoking the authorization on GitHub.
2. No derived GitHub credential exists. D4 removed the two-stage
   Actions-service chain — registration token, admin token and tenant URL, and
   per-session message-queue token — so the user access token is the only
   credential the agent holds, and nothing needs periodic renewal.
3. Expired or unauthorized REST responses trigger one refresh under a
   single-flight mutex, then one retry. A 403 following repeated 401s indicates
   GitHub's temporary authentication lockout, not a permissions change; the
   agent backs off without further refresh attempts and reports it distinctly
   from `authentication_failed`.
4. An expired JIT config is discarded, its runtime directory is removed, and a
   new JIT config is requested only if current demand still requires capacity.
5. A revoked or invalidated user token, or an App uninstalled from a
   repository, moves the affected policies to `authentication_failed`; the TUI
   gives a precise remediation command — `auth login` or the installation URL —
   and the agent creates no runners.

## 5. Disable scaling

1. CLI or TUI asks for explicit confirmation when active runners exist.
2. The policy becomes `draining`: no new JIT runners are created, busy runners
   finish normally, and queued demand is left visible.
3. When active local runners reach zero, demand polling for the policy stops
   and the policy becomes `disabled`.
4. Deleting a policy requires an explicit `repo remove --purge`; disabling
   never deletes cache or historical diagnostics.

## 6. TUI input loop

1. Terminal setup explicitly enables raw mode, the alternate screen, and
   `EnableMouseCapture`, and builds Crossterm with the `bracketed-paste` and
   `event-stream` features. `ratatui::init()` alone enables none of these and
   would produce a mouse-dead TUI. Crossterm's key, mouse, resize, paste, and
   focus events are merged with application timer and agent events into a
   single event stream.
2. Because mouse capture suppresses the terminal's own text selection, the TUI
   provides an explicit copy affordance and a key to release mouse capture, so
   the "copy-safe diagnostics" requirement stays satisfiable.
3. Ratatui renders immutable presentation state; rendering never calls GitHub
   or blocks on disk.
4. Focused controls expose the same command handler used by CLI.
5. Key bindings. Every screen is reachable by a single key from every other
   screen, and no key is bound twice:

   | Key | Action |
   |---|---|
   | `d` | Dashboard |
   | `r` | Repositories |
   | `n` | Runners |
   | `s` | Settings for the selected repository |
   | `h` | Host settings |
   | `a` | Activity and errors, from any screen |
   | `/` | Type-to-filter in the focused table |
   | `F5` | Refresh |
   | `?` | Key help |
   | `Esc` | Close a modal, then a subscreen |
   | `q` | Exit TUI without stopping an already running daemon |
