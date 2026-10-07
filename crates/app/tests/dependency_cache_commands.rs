// ----------------------------------------------------------------------------
// `host cache`, `repo cache`, `org cache`: caches.toml THROUGH THE REAL BINARY.
// ----------------------------------------------------------------------------
// The file is what the daemon reads at every native launch
// (`runner_manager_agent::dependency_caches`). These tests hold the operator's
// half: every command reads and writes exactly that file under `--data-dir`,
// refuses what the daemon would refuse without writing anything, and
// `status`/`host show` report the result.

mod support;

use std::path::{Path, PathBuf};

use support::{Outcome, run, runner_manager};

fn cli(data_dir: &Path, args: &[&str]) -> Outcome {
    run({
        let mut command = runner_manager(data_dir);
        command.args(args);
        command
    })
}

fn caches_file(data_dir: &Path) -> PathBuf {
    data_dir.join("config").join("caches.toml")
}

fn ok(outcome: &Outcome) {
    assert_eq!(outcome.code, 0, "{}", outcome.both());
}

#[test]
fn host_cache_settings_round_trip_through_caches_toml() {
    let data = tempfile::tempdir().unwrap();
    let shown = cli(data.path(), &["host", "cache", "show"]);
    ok(&shown);
    assert!(
        shown.stdout.contains("Dependency caches: on"),
        "{}",
        shown.stdout
    );
    assert!(
        shown.stdout.contains("npm_config_cache=<namespace>/npm"),
        "{}",
        shown.stdout
    );
    assert!(
        shown
            .stdout
            .contains("RUNNER_TOOL_CACHE=<namespace>/_slots/<n>/tool-cache"),
        "{}",
        shown.stdout
    );
    assert!(
        !caches_file(data.path()).exists(),
        "show must not write the file"
    );

    ok(&cli(data.path(), &["host", "cache", "set-max-size", "5"]));
    ok(&cli(
        data.path(),
        &["host", "cache", "set-tool", "cargo", "--state", "on"],
    ));
    ok(&cli(
        data.path(),
        &["host", "cache", "set-tool", "playwright", "--state", "off"],
    ));
    ok(&cli(
        data.path(),
        &["host", "cache", "set-enabled", "--enabled", "false"],
    ));
    let text = std::fs::read_to_string(caches_file(data.path())).unwrap();
    for expected in [
        "enabled = false",
        "max_size_gib = 5",
        "cargo = true",
        "playwright = false",
    ] {
        assert!(text.contains(expected), "{expected} missing from:\n{text}");
    }

    let root = data.path().join("cache-root");
    std::fs::create_dir(&root).unwrap();
    let root_text = root.to_str().unwrap();
    ok(&cli(
        data.path(),
        &["host", "cache", "set-root", "--path", root_text],
    ));
    let shown = cli(data.path(), &["host", "cache", "show"]);
    ok(&shown);
    assert!(
        shown.stdout.contains("Dependency caches: off"),
        "{}",
        shown.stdout
    );
    assert!(
        shown.stdout.contains(&format!("{root_text} (configured)")),
        "{}",
        shown.stdout
    );
    assert!(shown.stdout.contains("5.0 GiB"), "{}", shown.stdout);

    ok(&cli(
        data.path(),
        &["host", "cache", "set-enabled", "--enabled", "true"],
    ));
    ok(&cli(
        data.path(),
        &["host", "cache", "set-tool", "cargo", "--state", "default"],
    ));
    ok(&cli(data.path(), &["host", "cache", "reset-root"]));
    let text = std::fs::read_to_string(caches_file(data.path())).unwrap();
    assert!(!text.contains("enabled"), "{text}");
    assert!(!text.contains("cargo"), "{text}");
    assert!(!text.contains("root"), "{text}");
    assert!(text.contains("playwright = false"), "{text}");

    let settings = cli(data.path(), &["host", "show"]);
    ok(&settings);
    assert!(
        settings.stdout.contains("dependency caches"),
        "`host show` must name the caches:\n{}",
        settings.stdout
    );
    let status = cli(data.path(), &["status", "--json"]);
    ok(&status);
    let document: serde_json::Value = serde_json::from_str(&status.stdout).unwrap();
    assert_eq!(document["caches"]["enabled"], serde_json::Value::Bool(true));
    assert_eq!(
        document["caches"]["max_bytes"],
        serde_json::Value::from(5_u64 * 1024 * 1024 * 1024)
    );
}

#[test]
fn host_cache_refuses_what_the_daemon_would_refuse_and_writes_nothing() {
    let data = tempfile::tempdir().unwrap();
    // Absolute on every platform, so only the space can be what is refused.
    let spaced = data.path().join("has space").join("cache");
    let inside = data.path().join("state").join("cache");
    let cases: [(Vec<&str>, &str); 6] = [
        (
            vec!["host", "cache", "set-root", "--path", "relative/cache"],
            "absolute path without spaces",
        ),
        (
            vec![
                "host",
                "cache",
                "set-root",
                "--path",
                spaced.to_str().unwrap(),
            ],
            "absolute path without spaces",
        ),
        // A root inside the application data tree would be removed with it.
        (
            vec![
                "host",
                "cache",
                "set-root",
                "--path",
                inside.to_str().unwrap(),
            ],
            "application",
        ),
        (
            vec!["host", "cache", "set-tool", "not-a-tool", "--state", "on"],
            "is not a cache this version knows",
        ),
        (
            vec![
                "repo",
                "cache",
                "set-namespace",
                "o/r",
                "--shared",
                "Not Valid",
            ],
            "not a valid shared namespace",
        ),
        (
            vec!["repo", "cache", "set-tool", "o/r", "nope", "--state", "off"],
            "is not a cache this version knows",
        ),
    ];
    for (args, expected) in cases {
        let outcome = cli(data.path(), &args);
        assert_ne!(
            outcome.code,
            0,
            "{args:?} was accepted:\n{}",
            outcome.both()
        );
        assert!(
            outcome.both().contains(expected),
            "{args:?} was refused for another reason than {expected:?}:\n{}",
            outcome.both()
        );
    }
    assert!(
        !caches_file(data.path()).exists(),
        "a refused change created caches.toml"
    );

    // A hand-broken file is named, and nothing rewrites it.
    std::fs::create_dir_all(data.path().join("config")).unwrap();
    std::fs::write(caches_file(data.path()), "[tools]\nnot-a-tool = true\n").unwrap();
    let outcome = cli(data.path(), &["host", "cache", "set-max-size", "1"]);
    assert_ne!(outcome.code, 0);
    assert!(outcome.both().contains("caches.toml"), "{}", outcome.both());
    assert_eq!(
        std::fs::read_to_string(caches_file(data.path())).unwrap(),
        "[tools]\nnot-a-tool = true\n"
    );
}

/// A configured cache root and a runner root may not overlap in either
/// direction: the prune would measure workspaces, and cleanup remove caches.
#[test]
fn a_runner_root_over_the_cache_root_is_refused() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("cache-root");
    std::fs::create_dir(&root).unwrap();
    let root_text = root.to_str().unwrap();
    ok(&cli(
        data.path(),
        &["host", "cache", "set-root", "--path", root_text],
    ));
    let outcome = cli(
        data.path(),
        &["host", "set-runtime-root", "--path", root_text],
    );
    assert_ne!(outcome.code, 0, "{}", outcome.both());
    assert!(
        outcome.both().contains("dependency-cache root"),
        "{}",
        outcome.both()
    );
}

#[test]
fn repo_and_org_cache_settings_scope_one_target() {
    let data = tempfile::tempdir().unwrap();
    ok(&cli(
        data.path(),
        &[
            "repo",
            "cache",
            "set-namespace",
            "Octo/App",
            "--shared",
            "js",
        ],
    ));
    ok(&cli(
        data.path(),
        &[
            "repo", "cache", "set-tool", "octo/app", "npm", "--state", "off",
        ],
    ));
    ok(&cli(
        data.path(),
        &[
            "repo",
            "cache",
            "set-enabled",
            "octo/other",
            "--enabled",
            "false",
        ],
    ));
    let text = std::fs::read_to_string(caches_file(data.path())).unwrap();
    assert!(text.contains("[targets.\"octo/app\"]"), "{text}");
    assert!(text.contains("namespace = \"js\""), "{text}");

    let shown = cli(data.path(), &["repo", "cache", "show", "octo/app"]);
    ok(&shown);
    assert!(
        shown.stdout.contains("state                     on"),
        "{}",
        shown.stdout
    );
    assert!(
        shown
            .stdout
            .contains(&format!("_shared{}js", std::path::MAIN_SEPARATOR)),
        "{}",
        shown.stdout
    );
    assert!(
        shown
            .stdout
            .contains("npm               off  (this target)"),
        "{}",
        shown.stdout
    );
    let other = cli(data.path(), &["repo", "cache", "show", "octo/other"]);
    assert!(
        other
            .stdout
            .contains("off: caches are turned off for this target"),
        "{}",
        other.stdout
    );

    let org = cli(data.path(), &["org", "cache", "show", "acme"]);
    ok(&org);
    assert!(
        org.stdout.contains("off: organization policies"),
        "{}",
        org.stdout
    );
    ok(&cli(
        data.path(),
        &["org", "cache", "set-enabled", "acme", "--enabled", "true"],
    ));
    ok(&cli(
        data.path(),
        &["org", "cache", "set-namespace", "acme", "--own"],
    ));
    ok(&cli(
        data.path(),
        &["org", "cache", "set-tool", "acme", "cargo", "--state", "on"],
    ));
    let org = cli(data.path(), &["org", "cache", "show", "acme"]);
    assert!(
        org.stdout.contains("state                     on"),
        "{}",
        org.stdout
    );
    assert!(
        org.stdout
            .contains(&format!("_org{}acme", std::path::MAIN_SEPARATOR)),
        "{}",
        org.stdout
    );

    ok(&cli(
        data.path(),
        &["repo", "cache", "set-namespace", "octo/app", "--own"],
    ));
    let text = std::fs::read_to_string(caches_file(data.path())).unwrap();
    assert!(!text.contains("namespace"), "{text}");
}

#[test]
fn host_cache_prune_measures_and_keeps_what_fits() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("cache-root");
    let namespace = root.join("octo").join("app");
    std::fs::create_dir_all(namespace.join("npm")).unwrap();
    std::fs::write(namespace.join("npm").join("blob"), vec![0_u8; 4096]).unwrap();
    // What a launch leaves: only a marked namespace is ever measured or pruned.
    std::fs::write(namespace.join(".last-used"), b"").unwrap();
    ok(&cli(
        data.path(),
        &[
            "host",
            "cache",
            "set-root",
            "--path",
            root.to_str().unwrap(),
        ],
    ));
    let pruned = cli(data.path(), &["host", "cache", "prune"]);
    ok(&pruned);
    assert!(
        pruned.stdout.contains("1 namespace(s)"),
        "{}",
        pruned.stdout
    );
    assert!(
        pruned.stdout.contains("removed nothing"),
        "{}",
        pruned.stdout
    );
    assert!(namespace.join("npm").join("blob").is_file());
    assert!(root.join(".usage.json").is_file());

    let shown = cli(data.path(), &["host", "cache", "show"]);
    assert!(shown.stdout.contains("octo/app"), "{}", shown.stdout);
    let status = cli(data.path(), &["status"]);
    assert!(
        status.stdout.contains("dependency caches"),
        "{}",
        status.stdout
    );
    assert!(
        status.stdout.contains("4 KiB of 20.0 GiB"),
        "{}",
        status.stdout
    );
}

/// `repo cache show` says which caches `runner.env` takes over, as the daemon
/// would at launch.
#[test]
fn repo_cache_show_marks_a_cache_runner_env_takes_over() {
    let data = tempfile::tempdir().unwrap();
    ok(&cli(
        data.path(),
        &["host", "env", "set", "NPM_CONFIG_CACHE=/operator/npm"],
    ));
    let shown = cli(data.path(), &["repo", "cache", "show", "o/r"]);
    ok(&shown);
    assert!(
        shown
            .stdout
            .contains("npm               off  (set by runner.env or the service)"),
        "{}",
        shown.stdout
    );
}
