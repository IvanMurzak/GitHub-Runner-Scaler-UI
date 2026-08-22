// owner: f1-cli-auth-host-status
//
// ----------------------------------------------------------------------------
// TWO RELEASE GATES, MEASURED OVER THE REAL BINARY'S REAL OUTPUT.
// ----------------------------------------------------------------------------
// `07-security.md`: "`auth login` prints the same statement before opening the
//   browser." -- a gate about ORDER, so it is measured as byte offsets.
// `08-user-workflows.md`: "Onboarding from a clean machine to an authenticated
//   tool is at most 3 user actions (D3)." -- a gate about a NUMBER, so it is
//   measured by counting.
//
// The unit tests in `crates/app/src/cli/auth.rs` measure the same two things
// over a transcript built from the product's own writers. They cannot measure
// the third thing, which is the one that matters most here: that `login`
// actually calls those writers, in that order, around the network steps. That
// is what this file adds, and it is why the fixture answers on a socket rather
// than being substituted in.
//
// The action parser below is a deliberate second copy of the one in `auth.rs`'s
// test module. `crates/app` is a `[[bin]]` with no `[lib]` target -- `a1` owns
// the manifest -- so an integration test cannot import it. Two independent
// readings of one output is what a gate wants anyway: if they ever disagree,
// one of them fails.

mod support;

use support::{FakeGithub, Outcome, run, runner_manager_against};

/// D3's budget: one command, one code entry, one repository selection.
const ONBOARDING_ACTIONS: usize = 3;

const DISCLOSURE_HEADING: &str = "What you are about to grant";
const DISCLOSURE_CLOSING: &str = "neither of which needs this project's cooperation.";
const CRITICAL_PERMISSION: &str = "Administration: Read and write";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Action {
    index: usize,
    total: usize,
    text: String,
}

/// `Action N of M: text` — this file's own reading of the transcript.
fn actions_in(transcript: &str) -> Vec<Action> {
    let mut found = Vec::new();
    for line in transcript.lines() {
        let Some(rest) = line.trim_start().strip_prefix("Action ") else {
            continue;
        };
        let Some((counts, text)) = rest.split_once(':') else {
            continue;
        };
        let Some((index, total)) = counts.trim().split_once(" of ") else {
            continue;
        };
        let total = total.split_whitespace().next().unwrap_or_default();
        let (Ok(index), Ok(total)) = (index.trim().parse(), total.parse()) else {
            continue;
        };
        found.push(Action {
            index,
            total,
            text: text.trim().to_string(),
        });
    }
    found
}

/// A clean machine, a fake GitHub that approves at once, and no installation
/// anywhere — the exact preconditions Journey 1 states.
fn clean_machine_login() -> (tempfile::TempDir, FakeGithub, Outcome) {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    github.with_device_code();
    github.with_approval();
    github.with_no_installations();

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "login"]);
        command
    });
    (data_dir, github, outcome)
}

// ---------------------------------------------------------------------------
// The three-action gate
// ---------------------------------------------------------------------------

#[test]
fn a_clean_machine_reaches_an_authenticated_tool_in_three_actions() {
    let (_data_dir, _github, outcome) = clean_machine_login();
    assert_eq!(
        outcome.code, 0,
        "the login must succeed; stdout was:\n{}\nstderr:\n{}",
        outcome.stdout, outcome.stderr
    );

    let actions = actions_in(&outcome.stdout);
    assert!(
        !actions.is_empty(),
        "no actions were counted in the login transcript, so any count read from it would \
         be vacuous. Transcript:\n{}",
        outcome.stdout
    );
    assert_eq!(
        actions.len(),
        ONBOARDING_ACTIONS,
        "D3's release gate is three user actions from a clean machine to an authenticated \
         tool. Counted {} in:\n{}",
        actions.len(),
        outcome.stdout
    );
    for action in &actions {
        assert_eq!(
            action.total, ONBOARDING_ACTIONS,
            "an action announcing a budget of {} would let a fourth step in under the same \
             headline number",
            action.total
        );
    }
    for (position, action) in actions.iter().enumerate() {
        assert_eq!(
            action.index,
            position + 1,
            "the numbering must be dense and ascending: {actions:#?}"
        );
    }

    // The three actions are the three D3 names, in order.
    assert!(
        actions[0].text.contains("runner-manager auth login"),
        "action 1 is the one command: {:?}",
        actions[0].text
    );
    assert!(
        actions[1].text.contains("/login/device"),
        "action 2 is the code entry, on GitHub's device page: {:?}",
        actions[1].text
    );
    assert!(
        actions[2].text.contains("installations/new"),
        "action 3 is the repository selection: {:?}",
        actions[2].text
    );
}

/// D3's first action is *one command*. A transcript that asked the operator to
/// run a second one would still be three lines, and would still be wrong.
#[test]
fn exactly_one_of_the_three_actions_is_a_command_to_run() {
    let (_data_dir, _github, outcome) = clean_machine_login();
    let actions = actions_in(&outcome.stdout);
    let commands = actions
        .iter()
        .filter(|action| action.text.contains("runner-manager "))
        .count();
    assert_eq!(
        commands, 1,
        "D3 budgets one command, one code entry, one repository selection. Actions naming \
         a `runner-manager` command: {commands}. Actions:\n{actions:#?}"
    );
}

/// The counter is shown to be capable of rejecting the failure it guards
/// against, over a transcript of the same shape.
#[test]
fn the_action_count_would_reject_a_fourth_step() {
    let (_data_dir, _github, outcome) = clean_machine_login();
    let mut inflated = outcome.stdout.clone();
    inflated.push_str("Action 4 of 3: run `runner-manager auth confirm`.\n");

    let actions = actions_in(&inflated);
    assert_eq!(
        actions.len(),
        ONBOARDING_ACTIONS + 1,
        "the parser must see a fourth action if one is printed, or the count above is a \
         spelling check over three lines that happen to exist"
    );
    assert!(
        actions.len() > ONBOARDING_ACTIONS,
        "and four must be over the budget of three"
    );
}

// ---------------------------------------------------------------------------
// The D21 disclosure gate
// ---------------------------------------------------------------------------

/// Measured the way `a3` measures the README's copy: the **whole** disclosure
/// section has to end before the first thing a reader can act on.
#[test]
fn the_disclosure_is_complete_before_the_browser_step() {
    let (_data_dir, _github, outcome) = clean_machine_login();
    let transcript = &outcome.stdout;

    let heading = transcript.find(DISCLOSURE_HEADING).unwrap_or_else(|| {
        panic!(
            "`auth login` must print the D21 disclosure. Without it every offset below is \
             measured against nothing. Transcript:\n{transcript}"
        )
    });
    let closing = transcript.find(DISCLOSURE_CLOSING).unwrap_or_else(|| {
        panic!(
            "the disclosure's closing sentence marks the END of the section; a start-only \
             check would pass for a disclosure interleaved with the login prompt. \
             Transcript:\n{transcript}"
        )
    });
    let device_page = transcript
        .find("/login/device")
        .expect("the browser step must print the device page");
    let user_code = transcript
        .find("WDJB-MJHT")
        .expect("the browser step must print the user code");

    assert!(heading < closing, "the section must be measured end to end");
    assert!(
        closing < device_page,
        "the whole disclosure must end before the URL the operator will open. A reader who \
         stops at the first thing they can act on must already have passed all of it. \
         Transcript:\n{transcript}"
    );
    assert!(
        closing < user_code,
        "and before the code they will type. Transcript:\n{transcript}"
    );
}

/// The strongest form of "before": the disclosure has to be **emitted and
/// flushed** before the device-flow request is issued, not merely printed above
/// it in the same buffer.
///
/// The fixture answers nothing at all, so the very first request fails. The
/// disclosure must still be there in full, and the transcript must contain no
/// browser step to have preceded.
#[test]
fn the_disclosure_survives_a_login_that_never_reaches_github() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    // Deliberately no routes: every request 404s.

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "login"]);
        command
    });

    assert_ne!(outcome.code, 0, "the login cannot have succeeded");
    assert!(
        outcome.stdout.contains(DISCLOSURE_HEADING) && outcome.stdout.contains(DISCLOSURE_CLOSING),
        "a login that dies against GitHub must still have disclosed in full -- that is what \
         makes the ordering structural rather than cosmetic. Transcript:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        !outcome.stdout.contains("Action 2 of"),
        "and there must be no browser step, since no device code was ever obtained:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("Action 1 of"),
        "the command the operator already ran is still action 1 of 3:\n{}",
        outcome.stdout
    );
}

/// The disclosure is not merely present: it says the thing a consent screen
/// does not.
#[test]
fn the_disclosure_names_the_grant_and_its_consequences() {
    let (_data_dir, _github, outcome) = clean_machine_login();
    let transcript = &outcome.stdout;
    let (start, _) = (
        transcript
            .find(DISCLOSURE_HEADING)
            .expect("the disclosure must be present"),
        (),
    );
    let end = transcript
        .find(DISCLOSURE_CLOSING)
        .expect("the disclosure must be present")
        + DISCLOSURE_CLOSING.len();
    let section = &transcript[start..end];

    assert!(
        section.contains(CRITICAL_PERMISSION),
        "the exact grant must be named inside the section:\n{section}"
    );
    for consequence in ["DELETING", "RENAMING", "TRANSFERRING"] {
        assert!(
            section.contains(consequence),
            "`07-security.md` names three consequences of `{CRITICAL_PERMISSION}`, and \
             {consequence} is one of them. A permission table without them is the \
             disclosure GitHub's own screen already gives.\n{section}"
        );
    }
    assert!(
        section.contains("monitor-only"),
        "D21's accepted cost is that this binds a dashboard-only user too:\n{section}"
    );
}

// ---------------------------------------------------------------------------
// What the login is not allowed to print
// ---------------------------------------------------------------------------

/// `07-security.md` splits the two codes: the user code is shown by design, the
/// device code never is. Both halves are asserted, because a login that showed
/// neither would pass a one-sided check while being unusable.
#[test]
fn the_login_shows_the_user_code_and_never_the_device_code() {
    let (_data_dir, _github, outcome) = clean_machine_login();
    let everything = outcome.both();

    assert!(
        everything.contains("WDJB-MJHT"),
        "the user code is displayed by design, and a login that hid it could not be \
         completed:\n{everything}"
    );
    assert!(
        !everything.contains(&support::fixture_device_code()),
        "the device code must never be displayed:\n{everything}"
    );
    assert!(
        !everything.contains(&support::fixture_token()),
        "and neither must the token:\n{everything}"
    );
}

/// The phishing control: exactly one URL is offered for the code, and it is
/// GitHub's own device page.
#[test]
fn the_login_offers_one_place_to_type_the_code() {
    let (_data_dir, _github, outcome) = clean_machine_login();
    let actions = actions_in(&outcome.stdout);
    let code_entry = &actions[1].text;
    assert!(code_entry.contains("/login/device"), "got: {code_entry}");

    // The section between the code-entry action and the next one must not offer
    // a second address.
    let start = outcome
        .stdout
        .find("Action 2 of")
        .expect("the browser step");
    let end = outcome
        .stdout
        .find("Signed in.")
        .unwrap_or(outcome.stdout.len());
    let prompt = &outcome.stdout[start..end];
    assert_eq!(
        prompt.matches("http").count(),
        1,
        "the prompt must offer exactly one URL; a second is a second place somebody might \
         type the code:\n{prompt}"
    );
    assert!(
        prompt.contains("only on that page"),
        "and it must say the code goes nowhere else:\n{prompt}"
    );
}
