// owner: b3-acceptance-docs

//! The WSL lifecycle task against **the real Task Scheduler on this machine**.
//!
//! `crates/app/src/cli/wsl_acceptance.rs` drives the whole managed-WSL feature
//! over scripted controls, on every platform, unprivileged. That proves the
//! ordering, the convergence and the refusals. What a scripted `schtasks.exe`
//! cannot prove is the one thing this file is for: that the document
//! [`LifecycleTask::xml`] renders is a document Task Scheduler **accepts**, that
//! the registration it produces reads back as this product's, and that
//! `detach` really removes it.
//!
//! Three rules make that safe enough to be worth doing, and they are the same
//! three `privileged_service_installer.rs` states:
//!
//! 1. **Every task is named from a fixture distribution.** The name is derived
//!    from `runner-manager-selftest-wsl-<tag>`, which no operator's WSL
//!    distribution is called, so the task name cannot collide with a real one.
//!    It also carries `runner-manager-selftest`, which is the string ci.yml's
//!    leak check greps for.
//! 2. **[`TaskFixture`] removes the registration in `Drop`**, so a panic, an
//!    assertion failure or an early return cleans up exactly as a passing test
//!    does, and it goes at `schtasks.exe` directly rather than through the
//!    library call that may be the thing that broke.
//! 3. **Nothing here names a task it did not create.** Every destructive step
//!    checks the fixture prefix first.
//!
//! # Why they are `#[ignore]`d
//!
//! An ordinary `cargo test --workspace` on a developer's laptop must not create
//! scheduled tasks. These run only when asked for by name, which is what
//! `.github/workflows/ci.yml`'s `service-install` job does, and
//! `privileged_tests_are_wired_into_ci.rs` is what keeps that job honest.
//!
//! # What these tests do **not** prove
//!
//! **Not that a WSL distribution comes up.** No hosted runner has one, the
//! feature's own promise is about availability *after a logon*, and a test
//! process cannot log a user in. Nothing here starts the task, and nothing here
//! installs, provisions or touches a real distribution: the fixture
//! distribution deliberately does not exist, which is also what makes the
//! preflight assertion below safe to run anywhere.

#![cfg(windows)]

use runner_manager_platform::service::TaskPrincipal;
use std::ffi::OsString;

use runner_manager_platform::wsl::exec::{CommandRequest, CommandRunner, HostCommandRunner};
use runner_manager_platform::wsl::probe::{WslExecutable, WslInvoker, probe_readiness};
use runner_manager_platform::wsl::task::{
    LIFECYCLE_TASK_PREFIX, LifecycleTask, LifecycleTaskControl, LifecycleTaskIdentity,
    PRODUCT_MARKER,
};

/// The prefix every fixture distribution name carries, spelled out once so that
/// [`TaskFixture`] can refuse to delete anything else.
const FIXTURE_PREFIX: &str = "runner-manager-selftest-wsl-";

/// The Linux path the fixture task's action names. Nothing reads it: the task
/// is never started.
const LINUX_BINARY: &str = "/usr/local/bin/runner-manager";

/// A disposable distribution name, and the task identity derived from it.
fn fixture_distribution(tag: &str) -> String {
    let tag: String = tag
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("{FIXTURE_PREFIX}{tag}")
}

/// One disposable scheduled task, removed in `Drop` whatever happened.
struct TaskFixture {
    distribution: String,
    identity: LifecycleTaskIdentity,
}

impl TaskFixture {
    fn new(tag: &str) -> Self {
        let distribution = fixture_distribution(tag);
        let identity =
            LifecycleTaskIdentity::for_distribution(&distribution).expect("a usable fixture name");
        assert!(
            identity.name().starts_with(LIFECYCLE_TASK_PREFIX),
            "the derived task name must be the product's own shape: {}",
            identity.name()
        );
        assert!(
            identity.name().contains("runner-manager-selftest"),
            "the derived task name must carry the fixture marker ci.yml greps for, or a \
             leaked registration would be invisible to the leak check: {}",
            identity.name()
        );
        // Nothing may be there before this test starts. If something is, it is
        // a leak from an earlier run and removing it silently would hide that.
        assert!(
            !task_exists(identity.name()),
            "a task named {} already exists; an earlier run leaked it",
            identity.name()
        );
        Self {
            distribution,
            identity,
        }
    }

    fn identity(&self) -> &LifecycleTaskIdentity {
        &self.identity
    }

    /// The product's own task document for this fixture distribution.
    fn task(&self) -> LifecycleTask {
        LifecycleTask::new(
            self.identity.clone(),
            TaskPrincipal::current().expect("an interactive session has a principal"),
            &WslExecutable::locate(),
            LINUX_BINARY,
        )
    }
}

impl Drop for TaskFixture {
    fn drop(&mut self) {
        // Rule 3, applied where it matters most: the cleanup path refuses to
        // delete a name that is not a fixture's, even here.
        assert!(
            self.distribution.starts_with(FIXTURE_PREFIX),
            "refusing to remove a task that is not this file's fixture"
        );
        schtasks(&["/Delete", "/TN", self.identity.name(), "/F"]);
    }
}

/// Runs `schtasks.exe` directly, for the arrangements and the cleanups that
/// must not go through the code under test.
fn schtasks(arguments: &[&str]) -> bool {
    let request =
        CommandRequest::new("schtasks.exe").args(arguments.iter().copied().map(OsString::from));
    HostCommandRunner
        .run(&request)
        .map(|output| output.success())
        .unwrap_or(false)
}

fn task_exists(name: &str) -> bool {
    schtasks(&["/Query", "/TN", name, "/FO", "CSV", "/NH"])
}

// ---------------------------------------------------------------------------
// The document Task Scheduler accepts
// ---------------------------------------------------------------------------

#[test]
#[ignore = "registers a real Windows scheduled task; run explicitly"]
fn the_rendered_task_is_one_task_scheduler_accepts_reads_back_and_removes() {
    let fixture = TaskFixture::new("round-trip");
    let control = LifecycleTaskControl::new(&HostCommandRunner);

    control
        .register(&fixture.task())
        .expect("Task Scheduler accepts the document this build renders");
    assert!(
        task_exists(fixture.identity().name()),
        "the registration must be visible to `schtasks` itself, not only to the library \
         that made it"
    );

    let registered = control
        .query(fixture.identity())
        .expect("Task Scheduler answers")
        .expect("the task this test just registered");
    assert!(
        registered.is_product_owned(),
        "the exported description must carry {PRODUCT_MARKER}, or `detach` would refuse \
         to remove a task this product created"
    );
    assert!(registered.enabled(), "a freshly registered task is enabled");
    assert!(
        registered.command().to_lowercase().ends_with("wsl.exe"),
        "the action starts wsl.exe and nothing else: {}",
        registered.command()
    );
    for expected in ["--distribution", "--user", "root", "--exec", "wsl-host"] {
        assert!(
            registered.arguments().contains(expected),
            "the argument string Task Scheduler round-tripped is missing {expected:?}: {}",
            registered.arguments()
        );
    }
    for shell in ["cmd", "&&", "|", ";", "powershell"] {
        assert!(
            !registered.arguments().contains(shell),
            "no shell text may survive into the registered action, and {shell:?} did: {}",
            registered.arguments()
        );
    }

    // Idempotent: registering again replaces rather than accumulates.
    control
        .register(&fixture.task())
        .expect("re-registration replaces the task in place");
    assert!(task_exists(fixture.identity().name()));

    let detached = control
        .detach(fixture.identity())
        .expect("the product's own task is removed");
    assert!(detached.removed);
    assert_eq!(detached.name, fixture.identity().name());
    assert!(
        !task_exists(fixture.identity().name()),
        "after `detach` the registration is gone from Task Scheduler itself"
    );

    // Convergent: detaching a task that is not there is not a failure.
    let again = control
        .detach(fixture.identity())
        .expect("a second detach is convergent");
    assert!(!again.removed);
}

// ---------------------------------------------------------------------------
// A task this product did not create
// ---------------------------------------------------------------------------

#[test]
#[ignore = "creates a real Windows scheduled task; run explicitly"]
fn a_task_this_product_did_not_create_is_neither_replaced_nor_removed() {
    let fixture = TaskFixture::new("foreign");
    let control = LifecycleTaskControl::new(&HostCommandRunner);

    // Made by hand, under exactly the name this build derives. This is the
    // situation `02-target-architecture.md` describes on the target
    // workstation, where a keep-alive task already exists.
    assert!(
        schtasks(&[
            "/Create",
            "/TN",
            fixture.identity().name(),
            "/TR",
            "cmd.exe /c exit",
            "/SC",
            "ONCE",
            "/ST",
            "23:59",
            "/F",
        ]),
        "the arrangement itself must succeed, or this test proves nothing"
    );

    let registered = control
        .query(fixture.identity())
        .expect("Task Scheduler answers")
        .expect("the hand-made task");
    assert!(
        !registered.is_product_owned(),
        "a task with no {PRODUCT_MARKER} in its description is not this product's"
    );

    let refused = control
        .register(&fixture.task())
        .expect_err("registering over a foreign task must refuse");
    assert_eq!(refused.kind(), "foreign_task", "{refused}");
    let refused = control
        .detach(fixture.identity())
        .expect_err("detaching a foreign task must refuse");
    assert_eq!(refused.kind(), "foreign_task", "{refused}");

    assert!(
        task_exists(fixture.identity().name()),
        "and after both refusals the operator's own task is still there"
    );
    // `Drop` removes it, and it is this file's own arrangement rather than
    // something an operator made, so removing it there is correct.
}

// ---------------------------------------------------------------------------
// The distribution seam
// ---------------------------------------------------------------------------

#[test]
#[ignore = "runs the real wsl.exe; run explicitly"]
fn a_distribution_that_is_not_installed_is_refused_before_anything_is_started() {
    // The fixture distribution deliberately does not exist. Whether this host
    // has WSL at all is not this test's business: what must hold either way is
    // that the preflight refuses, with a sentence, and starts nothing.
    let distribution = fixture_distribution("absent");
    let executable = WslExecutable::locate();
    let invoker = WslInvoker::new(&HostCommandRunner, &executable);

    let refused = probe_readiness(&invoker, &distribution)
        .expect_err("a distribution nobody installed can never be ready");
    let message = refused.to_string();
    assert!(
        message.contains(&distribution) || message.contains("wsl.exe"),
        "the refusal must name what was asked for or the program that could not answer: \
         {message}"
    );
    assert!(
        !task_exists(
            LifecycleTaskIdentity::for_distribution(&distribution)
                .expect("a usable fixture name")
                .name()
        ),
        "a refused preflight registers nothing"
    );
}
