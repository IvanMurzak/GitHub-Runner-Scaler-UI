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
   --max-capacity 1`.
4. The command confirms the repository is installed for the App, validates the
   host OS/architecture against GitHub's supported matrix, validates
   `min_capacity <= max_capacity`, creates or resolves its host-owned scale
   set, and writes a transaction to local SQLite. The policy is created in
   `pending`; scaling is not enabled.
5. It prints the scale-set name to use in `runs-on` and the next command;
   secrets are never echoed.
6. `runner-manager repo set-scale OWNER/REPO --enabled true` moves the policy
   to `active`.
7. `daemon run` loads the active policy and starts its long-poll session.

Failure: a missing installation, duplicate policy, invalid capacity, an
inverted `min_capacity`/`max_capacity` pair, or an unavailable GitHub API
leaves no active policy. A partially created remote scale set is recorded as
`repair_required` and the command prints an explicit repair operation rather
than silently retrying destructive deletion.

## 2. Demand to job completion

1. The host agent sends its `max_capacity` in the scale-set long poll as the
   `X-ScaleSetMaxCapacity` header.
2. GitHub returns a message containing `statistics.TotalAssignedJobs` and any
   `JobAvailable` messages.
3. For every `JobAvailable` message the agent calls `AcquireJobs` with the
   message's runner-request identifiers **before** reconciling capacity. An
   unacquired assignment is cancelled and requeued by GitHub up to three times
   with incremental delays, then stalls.
4. The agent calculates desired capacity, clamps it against both
   `max_capacity` and remaining `host_capacity` headroom, and takes the
   host-wide allocation lock before creating each local runtime.
5. It downloads/verifies the cached runner package if required, creates
   `runtime/<policy-id>/<attempt-id>/`, and asks the Actions service for a
   scale-set JIT config through the `ScaleSetGateway`.
6. The agent writes the JIT config only to a restrictive temporary file,
   launches the runner process, then removes the file immediately after
   successful handoff. The JIT config is never passed as a command-line
   argument.
7. The runner accepts one job. The dashboard changes its lifecycle state from
   `starting` to `busy` using process state plus GitHub telemetry.
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
4. When connectivity returns, it re-establishes the Actions-service credential
   chain and resumes long polling. It does not replay an already acknowledged message as
   a new capacity count; `DeleteMessage` acknowledges, and the last processed
   message id is passed to the next `GetMessage`.

## 4. Token and JIT expiry

1. The stored user access token does not expire, because the published App
   opts out of user-token expiration (D3). There is no refresh token and no
   client secret, so there is nothing for the agent to renew and nothing for a
   server to hold. The token is revoked by the user uninstalling the App or
   revoking the authorization on GitHub.
2. The Actions-service credential chain is derived from the user token and is
   two-stage: the user token mints a runner registration token, which is
   exchanged for an Actions-service admin token and tenant URL. That admin
   token is refreshed 60 seconds before its expiry. Each message session
   additionally carries its own message-queue token with an independent refresh
   path.
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
3. When active local runners reach zero, the scale-set session stops and the
   policy becomes `disabled`.
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
