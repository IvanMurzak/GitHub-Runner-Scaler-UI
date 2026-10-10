// ----------------------------------------------------------------------------
// `host doctor`, `host prepare` and `host required-tools`, THROUGH THE BINARY.
// ----------------------------------------------------------------------------
// What a check finds depends on the machine the suite runs on, so these tests
// hold only what is true everywhere: the document's shape, the `host_unfit`
// exit for a required tool that cannot exist, that `prepare` changes nothing
// without consent, the required-tools file, and that the hidden elevated copy
// touches no local state. Each check's own logic is unit-tested against fake
// facts in `cli::doctor`.

mod support;

use std::path::Path;

use support::{Outcome, run, runner_manager};

/// `Failure::HostUnfit`.
const HOST_UNFIT: i32 = 25;
/// `Failure::InvalidArgument`.
const INVALID_ARGUMENT: i32 = 9;
/// `Failure::NotFound`.
const NOT_FOUND: i32 = 10;

const MISSING_TOOL: &str = "rm-doctor-tool-that-is-never-installed";

fn host(data_dir: &Path, args: &[&str]) -> Outcome {
    run({
        let mut command = runner_manager(data_dir);
        command.arg("host").args(args);
        command
    })
}

fn finding<'a>(report: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    report["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .find(|finding| finding["id"] == id)
        .unwrap_or_else(|| panic!("{id} is missing from {report}"))
}

#[test]
fn host_doctor_reports_the_versioned_document_and_exits_unfit_on_a_required_failure() {
    let data = tempfile::tempdir().unwrap();
    let set = host(data.path(), &["required-tools", "--set", MISSING_TOOL]);
    assert_eq!(set.code, 0, "{}", set.both());

    let doctor = host(data.path(), &["doctor", "--json"]);
    assert_eq!(doctor.code, HOST_UNFIT, "{}", doctor.both());
    let report: serde_json::Value =
        serde_json::from_str(&doctor.stdout).expect("stdout is exactly the JSON document");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["perspective"], "operator");
    let tools = finding(&report, "host.required_tools");
    assert_eq!(tools["severity"], "required");
    assert_eq!(tools["status"], "fail");
    assert!(
        tools["detail"].as_str().unwrap().contains(MISSING_TOOL),
        "{tools}"
    );
    assert!(
        doctor.stderr.contains("host.required_tools") && doctor.stderr.contains("host prepare"),
        "the failure names the check and the command that fixes it:\n{}",
        doctor.stderr
    );
    for field in [
        "id", "title", "platform", "severity", "status", "detail", "fix", "remedy",
    ] {
        assert!(tools.get(field).is_some(), "{field} missing from {tools}");
    }

    let text = host(data.path(), &["doctor"]);
    assert_eq!(text.code, HOST_UNFIT, "{}", text.both());
    assert!(text.stdout.starts_with("Host doctor ("), "{}", text.stdout);
    assert!(text.stdout.contains("\nSummary\n"), "{}", text.stdout);

    let cleared = host(data.path(), &["required-tools", "--clear"]);
    assert_eq!(cleared.code, 0, "{}", cleared.both());
    let doctor = host(data.path(), &["doctor", "--json"]);
    let report: serde_json::Value = serde_json::from_str(&doctor.stdout).unwrap();
    assert_eq!(
        finding(&report, "host.required_tools")["status"],
        "not_applicable"
    );
}

#[test]
fn host_prepare_without_a_terminal_or_yes_changes_nothing() {
    let data = tempfile::tempdir().unwrap();
    let journal = data.path().join("config").join("host-prepare.json");

    // Whatever this machine needs, a run with nobody to confirm and no `--yes`
    // either finds nothing to do or refuses -- and in both cases records no
    // change, because it made none.
    let prepare = host(data.path(), &["prepare"]);
    assert!(
        prepare.code == INVALID_ARGUMENT && prepare.stderr.contains("nothing was changed")
            || prepare.stdout.contains("Nothing to apply."),
        "{}",
        prepare.both()
    );
    assert!(
        !journal.exists(),
        "a refused prepare wrote {}",
        journal.display()
    );

    let unknown = host(data.path(), &["prepare", "--only", "no.such_check"]);
    assert_eq!(unknown.code, INVALID_ARGUMENT, "{}", unknown.both());
    assert!(
        unknown.stderr.contains("host.required_tools"),
        "{}",
        unknown.both()
    );

    let revert = host(data.path(), &["prepare", "--revert", "windows.long_paths"]);
    assert_eq!(revert.code, NOT_FOUND, "{}", revert.both());
    assert!(
        revert.stderr.contains("nothing to revert"),
        "{}",
        revert.both()
    );
    assert!(!journal.exists());
}

#[test]
fn host_required_tools_round_trip_under_the_data_dir() {
    let data = tempfile::tempdir().unwrap();
    let file = data.path().join("config").join("required-tools.json");

    let set = host(data.path(), &["required-tools", "--set", "git, node,git"]);
    assert_eq!(set.code, 0, "{}", set.both());
    assert!(set.stdout.contains("git, node"), "{}", set.stdout);
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(stored["tools"], serde_json::json!(["git", "node"]));

    for refused in ["../bin/git", "C:\\tools\\git", "git;rm"] {
        let outcome = host(data.path(), &["required-tools", "--set", refused]);
        assert_eq!(
            outcome.code,
            INVALID_ARGUMENT,
            "{refused}: {}",
            outcome.both()
        );
    }
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(
        stored["tools"],
        serde_json::json!(["git", "node"]),
        "a refused name must leave the list as it was"
    );

    let shown = host(data.path(), &["required-tools"]);
    assert!(shown.stdout.contains("git, node"), "{}", shown.stdout);

    let cleared = host(data.path(), &["required-tools", "--clear"]);
    assert_eq!(cleared.code, 0, "{}", cleared.both());
    assert!(!file.exists());
    assert!(cleared.stdout.contains("none"), "{}", cleared.stdout);
}

#[test]
fn the_elevated_copy_reports_through_its_file_and_touches_no_local_state() {
    let scratch = tempfile::tempdir().unwrap();
    let data = scratch.path().join("data");
    let result = scratch.path().join("result.json");
    let request = serde_json::json!({
        "setup": {
            "os": "linux",
            "perspective": "operator",
            "service": null,
            "runner_roots": [],
            "capacity": 1,
            "required_tools": [],
            "runner_path": null,
            "probe_dir": scratch.path(),
            "data_root": null,
        },
        "apply": [],
        "revert": [],
    })
    .to_string();

    let outcome = host(
        &data,
        &[
            "prepare",
            "--elevated-request",
            &request,
            "--elevated-result",
            result.to_str().unwrap(),
        ],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.both());
    assert_eq!(std::fs::read_to_string(&result).unwrap(), "[]");
    assert!(
        !data.exists(),
        "the elevated copy must not resolve or create the data directory: {}",
        data.display()
    );

    let malformed = host(
        &data,
        &[
            "prepare",
            "--elevated-request",
            "{not json",
            "--elevated-result",
            scratch.path().join("never.json").to_str().unwrap(),
        ],
    );
    assert_eq!(malformed.code, 2, "{}", malformed.both());
    assert!(!scratch.path().join("never.json").exists());
}

#[test]
fn host_forget_local_archives_the_configuration_and_deletes_nothing() {
    let data = tempfile::tempdir().unwrap();
    // Any command creates the four directories; this one leaves a database.
    let shown = host(data.path(), &["show"]);
    assert_eq!(shown.code, 0, "{}", shown.both());
    let config = data.path().join("config");
    std::fs::write(config.join("service.toml"), b"an earlier install's record").unwrap();
    let before: Vec<_> = std::fs::read_dir(&config)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(before.len() >= 2, "{before:?}");

    let forgotten = host(data.path(), &["forget-local"]);
    assert_eq!(forgotten.code, 0, "{}", forgotten.both());
    assert!(
        forgotten
            .stdout
            .contains("Archived this account's unused local configuration"),
        "{}",
        forgotten.both()
    );
    let left: Vec<_> = std::fs::read_dir(&config)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(left.len(), 1, "only the archive is left: {left:?}");
    let archive = &left[0];
    assert!(
        archive
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("forgotten-"),
        "{archive:?}"
    );
    for name in &before {
        assert!(
            archive.join(name).exists(),
            "{name:?} was moved, not deleted"
        );
    }
    assert_eq!(
        std::fs::read(archive.join("service.toml")).unwrap(),
        b"an earlier install's record"
    );

    // A second run finds nothing new and leaves the first archive alone.
    let again = host(data.path(), &["forget-local"]);
    assert_eq!(again.code, 0, "{}", again.both());
    assert!(archive.join("service.toml").exists());
}
