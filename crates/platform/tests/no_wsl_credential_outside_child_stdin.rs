// owner: a1-wsl-platform-adapter

//! `03-security-and-lifecycle.md` item 3, as a test.
//!
//! > The credential document crosses the Windows/Linux boundary only through an
//! > anonymous stdin pipe. It is absent from argv, environment, provider
//! > records, logs, errors, status JSON, temporary files and scheduled-task XML.
//!
//! Each module in `crates/platform/src/wsl` has unit tests for its own half of
//! that sentence. This file is the one that drives a recognisable canary
//! through the *whole* adapter and then looks everywhere else for it — which is
//! the only arrangement that can catch a leak through a path no single module
//! owns.
//!
//! The canaries are three, because the product has three secrets with different
//! shapes and a scan that only knew about one would pass while another leaked:
//! a user access token, a refresh token, and an encoded JIT configuration.

use std::path::Path;

use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::service::TaskPrincipal;
use runner_manager_platform::wsl::artifact::{BinaryInstaller, LinuxBinaryPath};
use runner_manager_platform::wsl::exec::{
    ChildInput, CommandOutput, CommandRequest, CommandRunner, PipedInput, ScriptedRunner,
};
use runner_manager_platform::wsl::probe::{LinuxCommand, WslExecutable, WslInvoker};
use runner_manager_platform::wsl::record::WslProviderRecord;
use runner_manager_platform::wsl::task::{
    LifecycleTask, LifecycleTaskControl, LifecycleTaskIdentity,
};
use secrecy::{ExposeSecret, SecretString};

/// The three values that must not escape.
///
/// Assembled from fragments so that this source file does not itself contain a
/// string that a secret scanner would flag, which is the same trick
/// `crates/platform/src/secrets.rs`'s fixtures use.
fn canaries() -> [String; 3] {
    [
        format!("{}{}", "ghu_", "a1WslCanaryAccessNotARealToken00"),
        format!("{}{}", "ghr_", "a1WslCanaryRefreshNotARealToken0"),
        format!("{}{}", "eyJ", "a1WslCanaryJitConfigNotARealOne="),
    ]
}

/// The stored credential document, as the broker would hand it over.
fn credential_document() -> SecretString {
    let [access, refresh, jit] = canaries();
    SecretString::from(format!(
        "{{\"schema\":1,\"access_token\":\"{access}\",\"refresh_token\":\"{refresh}\",\
         \"jit_config\":\"{jit}\"}}"
    ))
}

/// Every place a canary must not be, as one string to search.
fn assert_clean(what: &str, haystack: &str) {
    for canary in canaries() {
        assert!(
            !haystack.contains(&canary),
            "the credential leaked into {what}:\n{haystack}"
        );
    }
}

/// Reads every file under `root`, so a scan cannot miss one by not knowing its
/// name.
fn every_file_under(root: &Path, found: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            every_file_under(&path, found);
        } else if let Ok(bytes) = std::fs::read(&path) {
            found.push((
                path.display().to_string(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
    }
}

#[test]
fn the_credential_reaches_the_child_and_nothing_but_the_child() {
    let runner =
        ScriptedRunner::new().always("auth receive", CommandOutput::exited(0, "stored\n", ""));
    let executable = WslExecutable::at("wsl.exe");
    let invoker = WslInvoker::new(&runner, &executable);

    invoker
        .exec_ok(
            "hand the credential to the Linux binary",
            LinuxCommand::new("Ubuntu", "/usr/local/bin/runner-manager")
                .args(["auth", "receive", "--start-at", "boot"])
                .with_input(ChildInput::Piped(PipedInput::from_secret_text(
                    &credential_document(),
                ))),
        )
        .expect("the scripted distribution accepts it");

    // It went where it was supposed to go...
    let piped = String::from_utf8(runner.piped_input()).expect("the document is UTF-8");
    for canary in canaries() {
        assert!(
            piped.contains(&canary),
            "the credential did not reach the child's stdin at all: {piped}"
        );
    }

    // ...and nowhere else. `command_lines` is program plus argv, which is
    // exactly what a process listing shows.
    assert_clean("the argument vector", &runner.command_lines().join("\n"));
    assert_clean(
        "the recorded requests' Debug output",
        &format!("{:?}", runner.recorded()),
    );
}

#[test]
fn the_credential_is_not_in_the_debug_output_of_the_request_that_carries_it() {
    // The type-level control: `PipedInput`'s `Debug` prints a length. A
    // `tracing` field, an `anyhow` context, or a `dbg!` left in by mistake all
    // go through this one implementation.
    let request = CommandRequest::new("wsl.exe")
        .arg("--distribution")
        .arg("Ubuntu")
        .with_input(ChildInput::Piped(PipedInput::from_secret_text(
            &credential_document(),
        )));
    assert_clean("CommandRequest's Debug output", &format!("{request:?}"));
    assert!(
        format!("{request:?}").contains("<redacted;"),
        "the redacted form should still be recognisable"
    );
}

#[test]
fn a_credential_that_would_reach_the_command_line_refuses_the_launch_and_is_not_quoted() {
    let document = credential_document();
    let runner = ScriptedRunner::new();
    let request = CommandRequest::new("wsl.exe")
        .arg("--exec")
        .arg(format!("--credential={}", document.expose_secret()))
        .with_input(ChildInput::Piped(PipedInput::from_secret_text(&document)));

    let error = runner
        .run(&request)
        .expect_err("the payload is also in argument 1");
    assert_eq!(
        runner.call_count(),
        0,
        "the refusal must happen before anything is recorded or launched"
    );
    // The refusal names *where* it found it and never repeats *what* it found:
    // an error message is one of the places item 3 lists.
    assert_clean("the refusal message", &error.to_string());
    assert_clean("the refusal's Debug output", &format!("{error:?}"));
    assert!(error.to_string().contains("argument 1"), "{error}");
}

#[test]
fn nothing_this_adapter_writes_to_disk_contains_the_credential() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let paths = AppPaths::rooted_at(root.path());
    let document = credential_document();

    // 1. Hand the credential over, exactly as the provisioning transaction
    //    would, through a runner that records everything.
    let runner = ScriptedRunner::new()
        .always("auth receive", CommandOutput::exited(0, "stored\n", ""))
        .always("/Query", CommandOutput::exited(1, "", ""))
        .always(
            "--version",
            CommandOutput::exited(0, "runner-manager 0.4.0\n", ""),
        );
    let executable = WslExecutable::at("wsl.exe");
    let invoker = WslInvoker::new(&runner, &executable);
    invoker
        .exec_ok(
            "hand the credential to the Linux binary",
            LinuxCommand::new("Ubuntu", "/usr/local/bin/runner-manager")
                .args(["auth", "receive", "--start-at", "boot"])
                .with_input(ChildInput::Piped(PipedInput::from_secret_text(&document))),
        )
        .expect("stored");

    // 2. Register the lifecycle task, which writes a document to a temporary
    //    file for `schtasks /XML` to read.
    let identity = LifecycleTaskIdentity::for_distribution("Ubuntu").expect("a usable name");
    let task = LifecycleTask::new(
        identity.clone(),
        TaskPrincipal::named("IVANPC\\IvanD"),
        &executable,
        "/usr/local/bin/runner-manager",
    );
    assert_clean("the scheduled-task document", &task.xml());
    LifecycleTaskControl::with_executable(&runner, "schtasks.exe")
        .register(&task)
        .expect("registered");

    // 3. Write the provider record.
    WslProviderRecord::new("Ubuntu", identity.name(), "0.4.0", chrono::Utc::now())
        .write(&paths)
        .expect("written");

    // 4. Everything under the application root, whatever it is called.
    let mut files = Vec::new();
    every_file_under(root.path(), &mut files);
    assert!(
        !files.is_empty(),
        "the scan found no files at all, so it would pass vacuously"
    );
    for (path, contents) in &files {
        assert_clean(&format!("the file {path}"), contents);
    }

    // 5. And nothing that was passed to a program.
    assert_clean("the argument vectors", &runner.command_lines().join("\n"));
}

#[test]
fn an_archive_install_never_puts_its_payload_in_an_argument_either() {
    // The artifact path pipes bytes through the same `ChildInput`, and a
    // release archive is not a secret — but the property that a piped payload
    // never becomes an argument is one control, not two, and this is the test
    // that says it holds for the caller that moves the most data.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let archive = directory.path().join("archive.tar.gz");
    let [access, _, _] = canaries();
    // A file whose *contents* are recognisable, so that a step which wrote it
    // into the distribution by name — rather than piping it — would be visible.
    std::fs::write(&archive, access.as_bytes()).expect("write the archive");
    let digest =
        runner_manager_platform::wsl::artifact::sha256_of_file(&archive).expect("hashable");

    let sums = format!("{digest}  runner-manager-0.4.0-x86_64-unknown-linux-gnu.tar.gz\n");
    let target = runner_manager_platform::wsl::artifact::linux_target(
        "Ubuntu",
        runner_manager_domain::model::Arch::X64,
    )
    .expect("published");
    let artifact =
        runner_manager_platform::wsl::artifact::select_exact_release(&sums, &target, "0.4.0")
            .expect("published");

    let runner = ScriptedRunner::new().always(
        "--version",
        CommandOutput::exited(0, "runner-manager 0.4.0\n", ""),
    );
    let executable = WslExecutable::at("wsl.exe");
    let invoker = WslInvoker::new(&runner, &executable);
    BinaryInstaller::new(&invoker, "Ubuntu", LinuxBinaryPath::default())
        .install(&archive, &artifact, &target)
        .expect("installed");

    assert_clean(
        "the install's argument vectors",
        &runner.command_lines().join("\n"),
    );
    assert_eq!(
        String::from_utf8_lossy(&runner.piped_input()),
        access,
        "the archive should have gone through the pipe and only the pipe"
    );
}

#[test]
fn only_the_exec_module_may_read_a_piped_payload_back() {
    // A structural gate, in the spirit of
    // `privileged_tests_are_wired_into_ci.rs`: the runtime tests above prove
    // that today's code does not leak, and this one makes the *next* edit that
    // would go red rather than quiet. `PipedInput::expose_bytes` is the single
    // accessor for the bytes; if a new module starts calling it, that module
    // has to be reviewed against item 3 on purpose.
    let wsl = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/wsl");
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&wsl).expect("the wsl module is there") {
        let path = entry.expect("readable").path();
        if path.file_name().is_some_and(|name| name == "exec.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("readable");
        if source.contains("expose_bytes") {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "these modules read a piped payload back, which only `exec.rs` should do: {offenders:?}"
    );
}

#[test]
fn the_wsl_adapter_emits_no_diagnostics_at_all() {
    // `03-security-and-lifecycle.md` item 3 lists logs among the places the
    // credential must not appear, and the adapter's answer is the strongest
    // one available: it emits no `tracing` event whatsoever, so there is no
    // event that could carry a field.
    //
    // This is a tripwire, not a prohibition. A later task that wants a
    // diagnostic here should add one *and* delete this test on purpose, having
    // checked that what it records is a program name, an argument, or a bound
    // -- never a `PipedInput`. Deleting it by accident is what it prevents.
    let wsl = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/wsl");
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&wsl).expect("the wsl module is there") {
        let path = entry.expect("readable").path();
        let source = std::fs::read_to_string(&path).expect("readable");
        if source.contains("tracing::") {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "these modules emit diagnostics, which must be reviewed against          `03-security-and-lifecycle.md` item 3 before this test is removed: {offenders:?}"
    );
}
