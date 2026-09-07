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
fn ci_checks_that_the_real_default_runner_root_was_put_back() {
    // `b2`'s boot test is the one place in this repository that deliberately
    // creates and re-permissions the machine's own `%SystemDrive%\rman`,
    // because `04-security-recovery.md`'s security gate is worded about that
    // directory rather than about a temporary stand-in. It reverts the change,
    // and the claim that the revert is real is worth exactly as much as the
    // check that runs afterwards -- which is the same argument the fixture leak
    // check above rests on.
    let (path, source) = ci_workflow();
    assert!(
        source.contains("the runner-root rollback did not restore this host"),
        "{}'s installer job must assert that the real default runner root was put back. The \
         boot-mode privileged test creates it on purpose; without this step a rollback that \
         silently stopped working would leave a re-permissioned directory on every host that \
         ran the suite, and nothing would say so.",
        path.display()
    );
    // Two `if: always()` steps now, and the count is what keeps this from
    // passing on the strength of the fixture leak check's one.
    assert!(
        source.matches("if: always()").count() >= 2,
        "{}'s runner-root check must run even when the tests failed -- which is precisely when \
         a rollback would have been skipped.",
        path.display()
    );
}

/// Every privileged file in this crate, by the name `cargo test --test` selects
/// it with.
///
/// One list rather than one constant per file: the three assertions below are
/// the same three whichever facility a file touches, and a new privileged file
/// that is added without an entry here is a file nothing runs.
const PRIVILEGED_TESTS: [&str; 2] = ["privileged_service_installer", "privileged_wsl_lifecycle"];

#[test]
fn every_test_in_a_privileged_file_is_ignored_by_default() {
    // The complement of the tests above. They guard the job that runs these
    // tests; this guards the property that makes the job necessary -- that an
    // ordinary `cargo test` never registers a service, or a scheduled task, on
    // somebody's machine.
    for name in PRIVILEGED_TESTS {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/{name}.rs"));
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));

        let tests = source.matches("\n#[test]").count();
        let ignored = source.matches("\n#[ignore").count();
        assert!(
            tests > 0,
            "no `#[test]` found in {name}; this test would assert nothing"
        );
        assert_eq!(
            tests, ignored,
            "every test in {name} that changes this machine must be `#[ignore]`d, or \
             `cargo test --workspace` starts doing it on developers' machines. Found \
             {tests} tests and {ignored} ignore attributes."
        );
    }

    // And the list is checked against the directory rather than trusted. Its
    // whole claim is that "a new privileged file added without an entry here is
    // a file nothing runs", which is only true if a file missing from it says
    // so -- otherwise a second WSL or installer suite could be added, never be
    // asked for by name in ci.yml, never be checked for `#[ignore]`, and
    // nothing would go red.
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let entries = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", directory.display()));
    for entry in entries.flatten() {
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let Some(name) = file_name.strip_suffix(".rs") else {
            continue;
        };
        // This file is the guard rather than one of the guarded: it runs on
        // every machine, by design, and registers nothing.
        if !name.starts_with("privileged_") || name == "privileged_tests_are_wired_into_ci" {
            continue;
        }
        assert!(
            PRIVILEGED_TESTS.contains(&name),
            "tests/{file_name} is a privileged test file that `PRIVILEGED_TESTS` does not \
             name, so nothing checks that it is `#[ignore]`d and nothing checks that \
             ci.yml's `service-install` job asks for it by name. Add it to the list and \
             give it a wiring assertion."
        );
    }
}

/// The WSL lifecycle smoke tests (`b3`) are wired the same way the installer
/// ones are, and are covered by the same leak check.
///
/// The second half is the load-bearing one. A `runner-manager-wsl-…` task that
/// survived a failed run would be invisible to a leak check that greps for
/// `runner-manager-selftest`, so the fixture distribution name those tests
/// derive their task name from has to carry that string. Asserting it here,
/// against the file itself, is what keeps the two from drifting apart.
#[test]
fn ci_runs_the_privileged_wsl_lifecycle_tests_and_the_leak_check_can_see_their_fixtures() {
    let (path, source) = ci_workflow();
    assert!(
        source.contains("--test privileged_wsl_lifecycle"),
        "{} must run the WSL lifecycle smoke tests by name. They are the only place in \
         this repository where Task Scheduler is asked to accept the document \
         `LifecycleTask::xml` renders, and being `#[ignore]`d they run nowhere else.",
        path.display()
    );

    let wsl = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/privileged_wsl_lifecycle.rs"),
    )
    .expect("the privileged WSL test file is readable");
    assert!(
        wsl.contains("const FIXTURE_PREFIX: &str = \"runner-manager-selftest-wsl-\";"),
        "the WSL fixture prefix must start with `runner-manager-selftest`, which is what \
         {}'s leak check greps for. A fixture named anything else could survive a failed \
         run and nothing would say so.",
        path.display()
    );
    assert!(
        source.contains("runner-manager-selftest"),
        "{}'s leak check must still grep for the fixture marker",
        path.display()
    );
}
