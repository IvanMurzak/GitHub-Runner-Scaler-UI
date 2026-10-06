// ----------------------------------------------------------------------------
// `host env`: THE HOST'S runner.env, THROUGH THE REAL BINARY.
// ----------------------------------------------------------------------------
// The file is what the daemon reads at every native launch
// (`runner_manager_platform::runner_env`). These tests hold the operator's
// half: that `set`, `unset` and `show` read and write exactly that file under
// `--data-dir`, refuse what the daemon would refuse, and never print a value
// anywhere but `host env show`.

mod support;

use std::path::Path;

use support::{Outcome, run, runner_manager};

fn host(data_dir: &Path, args: &[&str]) -> Outcome {
    run({
        let mut command = runner_manager(data_dir);
        command.arg("host").args(args);
        command
    })
}

fn runner_env_file(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("config").join("runner.env")
}

#[test]
fn host_env_set_show_and_unset_round_trip_through_runner_env() {
    let data = tempfile::tempdir().unwrap();
    for assignment in [
        "ELECTRON_CACHE=/cache/electron",
        "npm_config_cache=/cache/npm",
        "ELECTRON_CACHE=/cache/electron-2",
    ] {
        let outcome = host(data.path(), &["env", "set", assignment]);
        assert_eq!(outcome.code, 0, "{}", outcome.both());
    }
    assert_eq!(
        std::fs::read_to_string(runner_env_file(data.path())).unwrap(),
        "ELECTRON_CACHE=/cache/electron-2\nnpm_config_cache=/cache/npm\n",
        "set must replace a variable in place and append a new one"
    );

    let shown = host(data.path(), &["env", "show"]);
    assert_eq!(shown.code, 0, "{}", shown.both());
    assert!(
        shown.stdout.contains("  ELECTRON_CACHE=/cache/electron-2"),
        "{}",
        shown.stdout
    );
    assert!(
        shown.stdout.contains("TMPDIR, TEMP, TMP"),
        "{}",
        shown.stdout
    );

    let removed = host(data.path(), &["env", "unset", "ELECTRON_CACHE"]);
    assert_eq!(removed.code, 0, "{}", removed.both());
    let shown = host(data.path(), &["env", "show"]);
    assert!(!shown.stdout.contains("ELECTRON_CACHE"), "{}", shown.stdout);

    let settings = host(data.path(), &["show"]);
    assert_eq!(settings.code, 0, "{}", settings.both());
    assert!(
        settings.stdout.contains("1 variable(s)"),
        "`host show` must say how many variables runners get:\n{}",
        settings.stdout
    );
    assert!(
        !settings.stdout.contains("/cache/npm"),
        "`host show` printed a runner.env value:\n{}",
        settings.stdout
    );
}

#[test]
fn host_env_refuses_what_the_daemon_would_refuse_and_writes_nothing() {
    let data = tempfile::tempdir().unwrap();
    for assignment in [
        "TMP=/elsewhere",
        "ACTIONS_RUNNER_INPUT_JITCONFIG=forged",
        "1NAME=value",
        "NO_EQUALS_SIGN",
    ] {
        let outcome = host(data.path(), &["env", "set", assignment]);
        assert_ne!(outcome.code, 0, "{assignment} was accepted");
        for value in ["/elsewhere", "forged"] {
            assert!(
                !outcome.both().contains(value),
                "a refusal echoed the value: {}",
                outcome.both()
            );
        }
    }
    assert!(
        !runner_env_file(data.path()).exists(),
        "a refused assignment created runner.env"
    );
}

#[test]
fn a_hand_broken_runner_env_is_reported_without_its_values() {
    let data = tempfile::tempdir().unwrap();
    let path = runner_env_file(data.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let secret = "ghp_notarealtokenbutshapedlikeone";
    std::fs::write(&path, format!("GOOD=1\n{secret}\n")).unwrap();

    let settings = host(data.path(), &["show"]);
    assert_eq!(
        settings.code,
        0,
        "`host show` must still work: {}",
        settings.both()
    );
    assert!(
        settings.stdout.contains("unusable") && settings.stdout.contains("line 2"),
        "{}",
        settings.stdout
    );
    assert!(!settings.both().contains(secret), "{}", settings.both());

    let set = host(data.path(), &["env", "set", "OTHER=1"]);
    assert_ne!(set.code, 0, "a set over a broken file must not rewrite it");
    assert!(!set.both().contains(secret), "{}", set.both());
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("GOOD=1\n{secret}\n")
    );
}
