// owner: d3-service-installers

//! The installer smoke tests are `#[ignore]`d, and `cargo test --workspace`
//! therefore reports success without having run one of them.
//!
//! That is the right default — a developer's laptop must not have services
//! registered on it — but it means the whole of `d3`'s *"verified by privileged
//! installer smoke tests on native CI runners"* rests on one job in one YAML
//! file. Delete the job and nothing goes red: the tests still compile, the
//! matrix still passes, and the Definition-of-Done item quietly stops being
//! checked by anything.
//!
//! So the wiring is asserted here, and this test is **not** `#[ignore]`d.
//! `a1` set the precedent with `crates/app/tests/release_workflow.rs`, which
//! asserts that release.yml reaches ci.yml rather than reimplementing its
//! matrix, for the same reason: a gate that can vanish silently is not a gate.
//!
//! This asserts wiring, not results. Whether the job passed is CI's answer, not
//! this file's.

use std::path::{Path, PathBuf};

/// The workflow this test is about.
fn ci_workflow() -> (PathBuf, String) {
    // crates/platform -> repository root.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/platform has two ancestors")
        .to_path_buf();
    let path = root.join(".github/workflows/ci.yml");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
    // An unreadable or empty file would satisfy every `contains` below by
    // being empty, so the size is checked before anything is looked for.
    assert!(
        source.len() > 500,
        "{} is suspiciously short; the assertions below would pass vacuously",
        path.display()
    );
    (path, source)
}

#[test]
fn ci_runs_the_privileged_installer_smoke_tests_by_name() {
    let (path, source) = ci_workflow();

    assert!(
        source.contains("service-install:"),
        "{} no longer declares the `service-install` job, so nothing in this repository \
         registers a real service any more and d3's installer Definition-of-Done item is \
         verified by nothing.",
        path.display()
    );

    // The command itself, not merely the job name: a job that had been edited
    // down to `cargo test --workspace` would run the ignored tests not at all
    // while still being called `service-install`.
    assert!(
        source.contains("--test privileged_service_installer"),
        "{} declares a `service-install` job that does not run \
         `--test privileged_service_installer`.",
        path.display()
    );
    assert!(
        source.contains("--ignored"),
        "{}'s installer job must pass `--ignored`; without it libtest runs none of the tests \
         in that file and reports success.",
        path.display()
    );
}

#[test]
fn ci_builds_the_fixture_service_host_before_running_the_smoke_tests() {
    // This one is here because its absence already cost a CI run.
    // `cargo test --test <name>` selects one target and builds no examples, so
    // the fixture service host the restart measurement starts is simply not
    // there unless something builds it by name. The tests fail loudly when it
    // is missing rather than skipping — but a red job that has to be diagnosed
    // from a stack trace is worth less than a test that names the missing step.
    let (path, source) = ci_workflow();
    assert!(
        source.contains("--example service_host_fixture"),
        "{}'s installer job must build the fixture service host by name before running the \
         smoke tests. `cargo test --test privileged_service_installer` does not build \
         examples, and `--examples` builds a libtest harness under a different name rather \
         than the service host.",
        path.display()
    );
    let lines: Vec<_> = source.lines().map(str::trim).collect();
    let binary_build = lines
        .iter()
        .position(|line| *line == "cargo build -p runner-manager")
        .unwrap_or_else(|| {
            panic!(
                "{}'s installer job must build the shipping runner-manager binary before the \
                 privileged regression installs and starts its exact production service entrypoint.",
                path.display()
            )
        });
    let privileged_test = lines
        .iter()
        .position(|line| line.contains("--test privileged_service_installer"))
        .expect("the privileged test command was asserted above");
    assert!(
        binary_build < privileged_test,
        "{}'s installer job must build the shipping runner-manager binary before the privileged \
         regression installs and starts its exact production service entrypoint.",
        path.display()
    );
}

#[test]
fn ci_checks_that_no_self_test_fixture_survives_the_installer_job() {
    let (path, source) = ci_workflow();
    assert!(
        source.contains("runner-manager-selftest"),
        "{}'s installer job must assert that no fixture registration survives. A leaked \
         privileged service is the worst outcome this job can have, and it is the outcome a \
         failing test leaves behind.",
        path.display()
    );
    assert!(
        source.contains("if: always()"),
        "{}'s leak check must run even when the tests failed -- which is precisely when a \
         fixture would have been left behind.",
        path.display()
    );
}

#[test]
fn every_test_in_the_privileged_file_is_ignored_by_default() {
    // The complement of the two tests above. They guard the job that runs these
    // tests; this guards the property that makes the job necessary -- that an
    // ordinary `cargo test` never registers a service on somebody's machine.
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/privileged_service_installer.rs"),
    )
    .expect("the privileged test file is readable");

    let tests = source.matches("\n#[test]").count();
    let ignored = source.matches("\n#[ignore").count();
    assert!(
        tests > 0,
        "no `#[test]` found; this test would assert nothing"
    );
    assert_eq!(
        tests, ignored,
        "every test that registers a real service must be `#[ignore]`d, or `cargo test \
         --workspace` starts doing it on developers' machines. Found {tests} tests and \
         {ignored} ignore attributes."
    );
}
