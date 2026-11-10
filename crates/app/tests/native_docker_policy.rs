//! `host docker-policy`: settings round-trip and the violation report, through
//! the real binary. What the proxy checks is covered by the agent's own tests.

use std::path::Path;
use std::process::{Command, Output};

fn manager(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_runner-manager"))
        .arg("--data-dir")
        .arg(root)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn ok(root: &Path, args: &[&str]) -> String {
    let result = manager(root, args);
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

#[test]
fn the_policy_defaults_to_audit_and_its_settings_round_trip() {
    let root = tempfile::tempdir().unwrap();
    let shown = ok(root.path(), &["host", "docker-policy", "show"]);
    assert!(shown.starts_with("Docker policy: audit"), "{shown}");
    assert!(
        shown.contains("none beyond each job's own attempt"),
        "{shown}"
    );

    ok(
        root.path(),
        &["host", "docker-policy", "set-mode", "--mode", "enforce"],
    );
    ok(
        root.path(),
        &["host", "docker-policy", "allow-path", "/srv/datasets"],
    );
    let shown = ok(root.path(), &["host", "docker-policy", "show"]);
    assert!(shown.starts_with("Docker policy: enforce"), "{shown}");
    assert!(shown.contains("/srv/datasets"), "{shown}");

    ok(
        root.path(),
        &["host", "docker-policy", "disallow-path", "/srv/datasets"],
    );
    let shown = ok(root.path(), &["host", "docker-policy", "show"]);
    assert!(!shown.contains("/srv/datasets"), "{shown}");

    assert!(
        !manager(
            root.path(),
            &["host", "docker-policy", "allow-path", "relative"]
        )
        .status
        .success(),
        "a relative path is refused"
    );
    assert!(
        !manager(
            root.path(),
            &["host", "docker-policy", "set-mode", "--mode", "loose"]
        )
        .status
        .success()
    );
}

#[test]
fn the_report_summarises_recorded_violations_by_repository_and_rule() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        ok(root.path(), &["host", "docker-policy", "report"])
            .contains("No Docker policy violation recorded")
    );
    let log = root.path().join("state/docker-policy/violations.jsonl");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(
        &log,
        concat!(
            r#"{"at":"2026-11-10T00:00:00Z","attempt":"a","repository":"o/r","rule":"host_path","detail":"/etc is outside the job's own directories","refused":false}"#,
            "\n",
            r#"{"at":"2026-11-10T00:01:00Z","attempt":"a","repository":"o/r","rule":"host_path","detail":"/root is outside the job's own directories","refused":true}"#,
            "\n",
        ),
    )
    .unwrap();
    let report = ok(root.path(), &["host", "docker-policy", "report"]);
    assert!(report.contains("o/r"), "{report}");
    assert!(report.contains("host_path"), "{report}");
    assert!(report.contains("2 (1 refused)"), "{report}");
    assert!(report.contains("[refused]"), "{report}");
}
