//! `host protect-path`: the list round-trips through the real binary, refuses
//! what every job needs, and says when the service does not enforce it yet.

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

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn protected_paths_round_trip_and_refuse_what_every_job_needs() {
    let root = tempfile::tempdir().unwrap();
    let list = manager(root.path(), &["host", "protect-path", "list"]);
    assert!(list.status.success());
    assert!(
        stdout(&list).contains("No protected path."),
        "{}",
        stdout(&list)
    );

    let added = manager(root.path(), &["host", "protect-path", "add", "/srv/keys"]);
    if cfg!(any(windows, target_os = "macos")) {
        assert!(
            !added.status.success(),
            "no platform equivalent: refused, not ignored"
        );
        return;
    }
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(stdout(&added).contains("service install --start-at boot"));
    let list = stdout(&manager(root.path(), &["host", "protect-path", "list"]));
    assert!(list.contains("/srv/keys"), "{list}");
    assert!(list.contains("No service is registered"), "{list}");

    for refused in ["/", "/usr", "relative"] {
        assert!(
            !manager(root.path(), &["host", "protect-path", "add", refused])
                .status
                .success(),
            "{refused}"
        );
    }
    let own = root.path().join("state");
    assert!(
        !manager(
            root.path(),
            &["host", "protect-path", "add", own.to_str().unwrap()]
        )
        .status
        .success(),
        "the service's own directories cannot be protected"
    );

    assert!(
        manager(
            root.path(),
            &["host", "protect-path", "remove", "/srv/keys"]
        )
        .status
        .success()
    );
    assert!(
        stdout(&manager(root.path(), &["host", "protect-path", "list"]))
            .contains("No protected path.")
    );
}
