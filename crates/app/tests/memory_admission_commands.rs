// ----------------------------------------------------------------------------
// `host set-memory-margin`, THROUGH THE REAL BINARY.
// ----------------------------------------------------------------------------
// Memory admission (0.4.53) is configured in `config/memory.toml`, which the
// daemon reads at every start it decides. These tests hold the operator's
// half: the command writes exactly that file, refuses what is not a size
// without writing anything, and `status` and `host show` report the result.

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
    data_dir.join("config").join("memory.toml")
}

fn memory(data_dir: &Path) -> serde_json::Value {
    let status = cli(data_dir, &["status", "--json"]);
    assert_eq!(status.code, 0, "{}", status.both());
    let document: serde_json::Value =
        serde_json::from_str(&status.stdout).expect("status --json is JSON");
    document["memory"].clone()
}

#[test]
fn host_set_memory_margin_round_trips_through_memory_toml_status_and_host_show() {
    let data = tempfile::tempdir().unwrap();

    let defaults = memory(data.path());
    assert_eq!(defaults["enabled"], true, "on by default: {defaults}");
    assert_eq!(defaults["margin_bytes"], 1u64 << 30, "{defaults}");
    assert_eq!(defaults["waiting"], serde_json::json!([]));

    let set = cli(data.path(), &["host", "set-memory-margin", "2GiB"]);
    assert_eq!(set.code, 0, "{}", set.both());
    assert!(
        set.stdout
            .contains("memory admission: on, margin 1.0 GiB -> on, margin 2.0 GiB"),
        "{}",
        set.stdout
    );
    assert!(settings_file(data.path()).exists());
    assert_eq!(memory(data.path())["margin_bytes"], 2u64 << 30);

    let off = cli(data.path(), &["host", "set-memory-margin", "off"]);
    assert_eq!(off.code, 0, "{}", off.both());
    let after = memory(data.path());
    assert_eq!(after["enabled"], false, "{after}");
    assert_eq!(after["margin_bytes"], 2u64 << 30, "the margin is kept");
    let shown = cli(data.path(), &["host", "show"]);
    assert_eq!(shown.code, 0, "{}", shown.both());
    assert!(
        shown.stdout.contains("memory admission          off"),
        "{}",
        shown.stdout
    );

    let on = cli(data.path(), &["host", "set-memory-margin", "on"]);
    assert_eq!(on.code, 0, "{}", on.both());
    let prose = cli(data.path(), &["status"]);
    assert_eq!(prose.code, 0, "{}", prose.both());
    assert!(
        prose
            .stdout
            .contains("memory admission          on, margin 2.0 GiB"),
        "{}",
        prose.stdout
    );
}

#[test]
fn host_set_memory_margin_refuses_what_is_not_a_size_and_writes_nothing() {
    let data = tempfile::tempdir().unwrap();
    for value in ["lots", "1 parsec", "1.2.3G", "GiB"] {
        let refused = cli(data.path(), &["host", "set-memory-margin", value]);
        assert_eq!(
            refused.code,
            INVALID_ARGUMENT,
            "{value}: {}",
            refused.both()
        );
        assert!(
            !settings_file(data.path()).exists(),
            "{value}: a refusal must write nothing"
        );
    }
    let missing = cli(data.path(), &["host", "set-memory-margin"]);
    assert_ne!(missing.code, 0, "a value is required");
    assert_eq!(memory(data.path())["enabled"], true);
}
