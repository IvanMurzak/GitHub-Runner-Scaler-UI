// ----------------------------------------------------------------------------
// `host set-poll-interval`, THROUGH THE REAL BINARY.
// ----------------------------------------------------------------------------
// The idle interval lives in `config/polling.toml` and the active one in the
// host row, and the daemon re-reads both every pass. These tests hold the
// operator's half: the command writes exactly those, refuses what the daemon
// would refuse without writing anything, and `status` and `host show` report
// the result.

mod support;

use std::path::{Path, PathBuf};

use support::{Outcome, run, runner_manager};

/// `Failure::InvalidArgument`.
const INVALID_ARGUMENT: i32 = 9;

fn cli(data_dir: &Path, args: &[&str]) -> Outcome {
    run({
        let mut command = runner_manager(data_dir);
        command.args(args);
        command
    })
}

fn settings_file(data_dir: &Path) -> PathBuf {
    data_dir.join("config").join("polling.toml")
}

fn polling(data_dir: &Path) -> serde_json::Value {
    let status = cli(data_dir, &["status", "--json"]);
    assert_eq!(status.code, 0, "{}", status.both());
    let document: serde_json::Value =
        serde_json::from_str(&status.stdout).expect("status --json is JSON");
    document["polling"].clone()
}

#[test]
fn host_set_poll_interval_round_trips_through_polling_toml_and_the_host_row() {
    let data = tempfile::tempdir().unwrap();

    let defaults = polling(data.path());
    assert_eq!(defaults["idle_interval_secs"], 10, "{defaults}");
    assert_eq!(defaults["active_interval_secs"], 60, "{defaults}");
    assert_eq!(defaults["measured"], serde_json::Value::Null);

    let idle = cli(data.path(), &["host", "set-poll-interval", "--idle", "5s"]);
    assert_eq!(idle.code, 0, "{}", idle.both());
    assert!(
        idle.stdout.contains("idle poll interval:   10s -> 5s"),
        "{}",
        idle.stdout
    );
    assert!(settings_file(data.path()).exists());
    assert_eq!(polling(data.path())["idle_interval_secs"], 5);

    let active = cli(
        data.path(),
        &["host", "set-poll-interval", "--active", "2m"],
    );
    assert_eq!(active.code, 0, "{}", active.both());
    let after = polling(data.path());
    assert_eq!(after["active_interval_secs"], 120, "{after}");
    assert_eq!(
        after["idle_interval_secs"], 5,
        "the idle interval is untouched"
    );

    let prose = cli(data.path(), &["status"]);
    assert_eq!(prose.code, 0, "{}", prose.both());
    assert!(
        prose
            .stdout
            .contains("projected if no poll were answered 304, of 2500 this host may spend"),
        "{}",
        prose.stdout
    );

    let shown = cli(data.path(), &["host", "show"]);
    assert_eq!(shown.code, 0, "{}", shown.both());
    assert!(
        shown.stdout.contains("idle interval             5s"),
        "{}",
        shown.stdout
    );
    assert!(
        shown.stdout.contains("active interval           120s"),
        "{}",
        shown.stdout
    );
}

#[test]
fn host_set_poll_interval_refuses_what_the_daemon_would_refuse_and_writes_nothing() {
    let data = tempfile::tempdir().unwrap();

    for (args, why) in [
        (&["--idle", "4s"][..], "under the idle floor"),
        (&["--active", "29"][..], "under the active floor"),
        (
            &["--idle", "90s"][..],
            "an idle interval longer than the active one",
        ),
        (&["--idle", "ten"][..], "not a duration"),
    ] {
        let mut full = vec!["host", "set-poll-interval"];
        full.extend_from_slice(args);
        let refused = cli(data.path(), &full);
        assert_ne!(refused.code, 0, "{why}: {}", refused.both());
        assert!(
            !settings_file(data.path()).exists(),
            "{why}: a refusal must write nothing"
        );
    }
    let refused = cli(data.path(), &["host", "set-poll-interval", "--idle", "4s"]);
    assert_eq!(refused.code, INVALID_ARGUMENT, "{}", refused.both());

    let neither = cli(data.path(), &["host", "set-poll-interval"]);
    assert_ne!(neither.code, 0, "one of --idle or --active is required");

    let unchanged = polling(data.path());
    assert_eq!(unchanged["idle_interval_secs"], 10);
    assert_eq!(unchanged["active_interval_secs"], 60);
}
