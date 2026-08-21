# User workflows and UX gates

## Persona: home-host operator

The operator owns a Windows PC and an Apple Silicon Mac mini. They want jobs to
run only on the appropriate local machine, do not want idle persistent runners,
and expect both machines to resume work by themselves after a reboot.

### Journey 0: install

1. Run one install command for the platform: the install script
   (`curl -fsSL ... | sh`, or `irm ... | iex` on Windows), `npm i -g
   runner-manager`, `brew install <tap>/runner-manager`, `scoop install
   <bucket>/runner-manager`, or `cargo install runner-manager`.
2. Run `runner-manager --version` to confirm.

**Release gate:** One command installs a working binary on each supported OS
from a machine that has never built the product, with **no security prompt**.
Every documented path runs through a terminal, so neither Gatekeeper nor
SmartScreen is triggered on any of them.

### Journey 1: first repository by CLI

Precondition: the binary is installed. Nothing else. The user has no GitHub
App, no private key, and no token.

1. Run `runner-manager auth login`. It prints a verification URL and a short
   user code, and waits.
2. In the browser: open `github.com/login/device`, enter the code, approve.
3. The tool prints the installation URL; in the browser, choose the
   repositories to install the published App on.
4. Run `runner-manager repo add OWNER/REPO --host-label home-win
   --max-capacity 1`.
5. Copy the printed scale-set name into the repository workflow's `runs-on`.
6. Run `runner-manager repo set-scale OWNER/REPO --enabled true`.
7. Run `runner-manager service install` (or `runner-manager daemon run`).

**Release gate:** Onboarding from a clean machine to an authenticated tool is
at most **3 user actions** (D3): one command, one code entry, one repository
selection. The user never creates a GitHub App, never chooses permissions, and
never handles a key file. Reaching a running autoscaled repository takes at
most 4 further `runner-manager` invocations — steps 4, 6, 7 plus the initial
`auth login`. Step 5 is an edit in the repository and is not counted. The add
command must explain a missing installation or invalid capacity in one
screenful without exposing credentials.

### Journey 2: inspect active work in TUI

1. Run `runner-manager tui`.
2. See aggregate in-progress workflows, assigned jobs, online/busy runners,
   host capacity used and total, and agent health on the first frame.
3. Press `r` or click **Repositories**.
4. Select a repository, using `/` to filter if the list is long, and press
   `Enter` for its detail with the in-progress workflow count in parentheses.
5. Press `n` or click **Runners** to filter by host-owned, busy, or external
   runner.
6. Press `?` to inspect all key bindings; press `q` to exit without stopping
   the daemon.

**Release gate:** Dashboard-to-repository detail is at most 3 keyboard actions
or 2 mouse actions, excluding intra-list row navigation; type-to-filter must
reach any repository in one additional action regardless of list length.

### Journey 3: change limits in TUI

1. Press `h` for **Host settings**; the current `host_capacity` and the current
   total in use across policies are both shown.
2. Edit `host_capacity` and confirm.
3. Press `r`, select a repository, press `s` for its **Settings**.
4. Toggle scale enabled and set `max_capacity`; the current value is shown
   before editing.
5. Review the generated scale-set name and local host identity.
6. Confirm the policy.

**Release gate:** At most 5 focused form actions per settings screen, plus at
most two confirmations on the disable path — the policy confirmation and the
active-runner drain confirmation. Disabling with active work states "draining"
and gives the count of active runners; it never promises immediate termination.
Both limits always display their current value before an edit.

### Journey 4: host is offline

1. TUI status changes to **Offline - no new runners will start**.
2. Operator opens the error panel with `a` from any screen, or from the status
   bar.
3. The panel identifies the last successful GitHub contact, retry delay, local
   remediation, and a warning that GitHub cancels queued jobs after 24 hours.
4. When the network returns, the agent resumes and the UI records recovery.

**Release gate:** Offline condition is discoverable from every screen in one
action and never presented as zero workload or successful scale-down. The
24-hour queue-cancellation bound is stated, not implied.

### Journey 5: host reboots unattended

1. The machine reboots with nobody logged in.
2. The boot-start service starts the agent, which reads the user access token
   from the machine-scoped secret store.
3. The agent reconciles the journal against GitHub and resumes long polling.
4. `runner-manager service status` reports the start mode, the resolved binary
   path, and the last successful GitHub contact.

**Release gate:** On each supported OS, the agent resumes work after a reboot
with no interactive login. `service status` reports a stale binary path as an
error rather than appearing healthy.

### Accessibility and visual rules

- Mouse, arrows, `Tab`/`Shift-Tab`, `Enter`, `Esc`, and single-key shortcuts
  are supported; no mouse-only action exists, and every screen has a key.
- Because mouse capture disables native terminal selection, an explicit copy
  affordance and a capture-release key are always available.
- Status uses text, icons, and color together; color alone never encodes busy,
  error, or ownership.
- Tables maintain focus, selected row, sort order, and scroll position through
  refreshes where the selected item still exists.
- Small terminals show a deliberate compact layout and key-help overlay rather
  than clipped controls.
- Loading, empty, unauthorized, rate-limited, and offline states have distinct
  content and actionable commands.
