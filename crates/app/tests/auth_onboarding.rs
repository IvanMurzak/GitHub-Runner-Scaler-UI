// owner: f1-cli-auth-host-status
//
// ----------------------------------------------------------------------------
// ONE RELEASE GATE AND ONE DELIBERATE ABSENCE, OVER THE REAL BINARY'S OUTPUT.
// ----------------------------------------------------------------------------
// `08-user-workflows.md`: "Onboarding from a clean machine to an authenticated
//   tool is at most 3 user actions (D3)." -- a gate about a NUMBER, so it is
//   measured by counting.
//
// The absence is the other half. `auth login` used to open with a
// twenty-five-line permission table, above the one code the operator came to
// type. The table is the same on every run and for every user, so repeating it
// there taught the reader to scroll past it -- and a disclosure that is
// habitually skipped is not one. It moved to `README.md`, which
// `readme_disclosure.rs` pins ahead of every install command, and to
// `auth status --permissions`, which needs no credential and no request.
//
// So this file asserts that the login screen is SHORT and carries none of that
// text, and `auth_states.rs` asserts that `auth status --permissions` carries
// all of it. Neither assertion is safe alone: the first one passing while the
// second fails is how a disclosure gets deleted by accident.
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

const CRITICAL_PERMISSION: &str = "Administration: Read and write";

/// Every line the old disclosure block contributed, and nothing else.
///
/// Each of these is asserted to be present in `auth status --permissions` by
/// `auth_states.rs`, so an absence found here means `login` stopped printing
/// it, not that the product stopped saying it.
const GRANT_TEXT: [&str; 7] = [
    CRITICAL_PERMISSION,
    "DELETING",
    "RENAMING",
    "TRANSFERRING",
    "collaborators",
    "Repository -> Metadata",
    "Organization -> Self-hosted runners",
];

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
    assert_eq!(
        actions[3].index, 4,
        "and the extra one must be read as the fourth action rather than as noise, or the \
         parser could be hiding a step instead of counting it"
    );
}

// ---------------------------------------------------------------------------
// The login screen carries none of the grant text
// ---------------------------------------------------------------------------

/// The permission table is gone from the screen it used to open.
///
/// Every needle is one the old block put there, and every one of them is
/// asserted present in `auth status --permissions` by
/// `auth_states.rs::the_permission_report_carries_the_whole_grant`. Read the
/// two together: this one alone would also pass for a build that deleted the
/// disclosure outright.
#[test]
fn the_login_screen_carries_no_permission_table() {
    let (_data_dir, _github, outcome) = clean_machine_login();
    let everything = outcome.both();
    for needle in GRANT_TEXT {
        assert!(
            !everything.contains(needle),
            "`auth login` must not print `{needle}`. The table is identical on every run and              for every user, and it sat above the one code the operator came for. It lives in              README.md and in `auth status --permissions` now. Transcript:
{everything}"
        );
    }
}

/// The point of the removal, stated as a number.
///
/// The old transcript on a clean machine ran past forty lines before the code
/// appeared. A budget stops "just one more paragraph" from arriving one
/// paragraph at a time, which is how the block being removed here got its
/// twenty-five lines in the first place.
#[test]
fn the_code_is_reached_within_a_dozen_lines() {
    let (_data_dir, _github, outcome) = clean_machine_login();
    let transcript = &outcome.stdout;
    let position = transcript
        .lines()
        .position(|line| line.contains("WDJB-MJHT"))
        .unwrap_or_else(|| {
            panic!(
                "the login must print the user code somewhere:
{transcript}"
            )
        });
    assert!(
        position <= 12,
        "the user code is the only thing on this screen the operator has to act on, and it          appeared on line {position}. Everything above it is what they read first.          Transcript:
{transcript}"
    );
}

/// A login that dies before reaching GitHub still says which store it was
/// signing in to, and still counts the command as action 1.
///
/// The fixture answers nothing at all, so the very first request fails. What is
/// being pinned is that the output written before the network is the *useful*
/// output — the failure names a store the operator can act on — rather than a
/// disclosure they have read before.
#[test]
fn a_login_that_never_reaches_github_still_says_where_it_was_signing_in() {
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
        outcome.stdout.contains("Credential store:"),
        "the store this sign-in chose is the one thing the operator cannot see for          themselves, so it is written before the first request:
{}
stderr:
{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        !outcome.stdout.contains("Action 2 of"),
        "and there must be no browser step, since no device code was ever obtained:
{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("Action 1 of"),
        "the command the operator already ran is still action 1 of 3:
{}",
        outcome.stdout
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
