# User workflows and UX gates

## Persona: home-host operator

The operator owns a Windows PC and an Apple Silicon Mac mini. They want jobs to
run only on the appropriate local machine, do not want idle persistent runners,
and expect both machines to resume work by themselves after a reboot.

### Journey 0: install

1. Run one install command for the platform: `npm i -g <package>`,
   `brew install <tap>/<name>`, `scoop install <bucket>/<name>`, or
   `cargo install <crate>`.
2. Run `runner-manager --version` to confirm.

**Release gate:** One command installs a working binary on each supported OS
from a machine that has never built the product, with no security prompt and no
manual quarantine or SmartScreen step. Operators who instead use the README
download buttons get a documented one-line quarantine-removal note beside them.

### Journey 1: first repository by CLI

Precondition: the binary is installed and the GitHub App private key is
available locally.

1. Run `runner-manager auth configure`.
2. Select the already-installed GitHub App installation.
3. Run `runner-manager repo add OWNER/REPO --host-label home-win
   --max-capacity 1`.
4. Copy the printed scale-set name into the repository workflow's `runs-on`.
5. Run `runner-manager repo set-scale OWNER/REPO --enabled true`.
6. Run `runner-manager service install` (or `runner-manager daemon run`).

**Release gate:** At most 4 `runner-manager` invocations after the GitHub App
exists and its key is available locally — steps 1, 3, 5, 6. Step 2 is a
selection inside step 1's command and step 4 is an edit in the repository;
neither is counted. The add command must explain a missing installation or
invalid capacity in one screenful without exposing credentials.

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
2. The boot-start service starts the agent, which reads the private key from
   the machine-scoped secret store.
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
