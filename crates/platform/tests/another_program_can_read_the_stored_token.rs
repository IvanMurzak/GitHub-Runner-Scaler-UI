// owner: d2-machine-secret-store

//! The macOS grant, tested the only way that means anything: by having a
//! **different program** read the value back.
//!
//! # The failure this stands against
//!
//! A keychain grants an item per *application*, and it identifies an unsigned
//! one by the hash of the binary. Replacing the binary is what an upgrade is,
//! so an item granted to the copy that wrote it locks out the copy that
//! replaces it — the daemon reads `errSecAuthFailed` from the credential it is
//! supposed to own, exits `13`, and launchd restarts it every fifteen seconds.
//! That happened twice on a real host, on 0.1.15 and again on 0.1.17.
//!
//! `secrets.rs` fixes it by creating the item with an access that names no
//! application, which Security.framework reads as *any* application. The reason
//! that is not a widening is set out on `grants_every_application`: what keeps
//! an ordinary local user out of these two keychains is the System Keychain's
//! root-only master key and a `0700` directory, neither of which this touches.
//!
//! # Why `/usr/bin/security` is the second program
//!
//! An in-process check cannot express the property at all — this process is the
//! program that wrote the item, so it is the one caller certain to be granted
//! access under either design. The test needs a reader that is unambiguously
//! *not* this binary, and `security(1)` is one that is on every macOS host, is
//! not built by this repository, and cannot accidentally inherit anything from
//! it.
//!
//! A wrong grant does not fail here, it *waits*: the keychain asks the person
//! at the desk to approve the read. So the child is given a deadline and killed
//! when it passes one, and a test that would have hung is a test that fails.

#![cfg(target_os = "macos")]

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use runner_manager_platform::secrets::{
    PlatformSecretStore, ROOTED_KEYCHAIN_PASSWORD, SecretScope, SecretStore as _,
};
use secrecy::SecretString;

/// The keychain service, spelled out rather than borrowed.
///
/// `secrets.rs` composes it from `crate::paths`, and `security(1)` has to be
/// given the same string. Writing it here is the same independent-oracle
/// argument `the_product_identity_is_the_one_paths_defines` makes: a change
/// that moved the item would otherwise move this test with it.
const SERVICE: &str = "io.github.IvanMurzak.runner-manager";
/// The account half of the item's identity.
const ACCOUNT: &str = "user-access-token";

/// Long enough for a keychain call on a loaded CI host, short enough that a
/// waiting prompt is reported as a failure rather than a hung job.
const DEADLINE: Duration = Duration::from_secs(30);

/// Shaped like a real `ghu_` token and unmistakably not one, assembled at run
/// time so the literal is in no compiled artifact. See
/// `no_token_outside_the_store.rs`, which depends on that.
fn fixture_token() -> String {
    format!("{}{}", "ghu_", "d2GrantFixtureNotARealOne0000000")
}

#[test]
fn a_program_that_did_not_write_the_item_can_still_read_it() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let store = PlatformSecretStore::rooted_at(SecretScope::Machine, root.path())
        .expect("a rooted machine-scoped store resolves");

    let token = fixture_token();
    store
        .store(&SecretString::from(token.clone()))
        .expect("the token is stored");

    // The keychain this store created is locked with a constant this crate
    // publishes; `security` is told it rather than being left to prompt for it,
    // because an unlock prompt would be indistinguishable from the access
    // prompt this test exists to prove does not happen.
    let keychain = store.guard();
    let unlock = run_with_deadline(
        Command::new("/usr/bin/security")
            .arg("unlock-keychain")
            .arg("-p")
            .arg(ROOTED_KEYCHAIN_PASSWORD)
            .arg(&keychain),
    );
    assert!(
        unlock.timed_out.not_reached(),
        "`security unlock-keychain` did not finish within {DEADLINE:?}"
    );
    assert!(
        unlock.status_success,
        "`security unlock-keychain` failed: {}",
        unlock.stderr
    );

    let read = run_with_deadline(
        Command::new("/usr/bin/security")
            .arg("find-generic-password")
            .arg("-w")
            .arg("-s")
            .arg(SERVICE)
            .arg("-a")
            .arg(ACCOUNT)
            .arg(&keychain),
    );

    assert!(
        read.timed_out.not_reached(),
        "`security find-generic-password` did not finish within {DEADLINE:?}. That is what a \
         per-application grant looks like from the outside: the keychain is waiting for somebody \
         to approve a read by a program the item does not name, which on a daemon's host is \
         nobody. See `grants_every_application` in secrets.rs."
    );
    assert!(
        read.status_success,
        "another program was refused the stored token: {}",
        read.stderr
    );
    assert_eq!(
        read.stdout.trim_end_matches('\n'),
        token,
        "the value another program read back is not the one that was stored"
    );
}

/// Whether the deadline was reached, as a type rather than a bare `bool` so
/// that the assertion above cannot read the sense of it backwards.
struct Deadline(bool);

impl Deadline {
    fn not_reached(&self) -> bool {
        !self.0
    }
}

/// What a child said, and whether it said it in time.
struct Finished {
    timed_out: Deadline,
    status_success: bool,
    stdout: String,
    stderr: String,
}

/// Runs a command, killing it if it outlives [`DEADLINE`].
///
/// `Command::output` would block forever on a child waiting behind a keychain
/// panel, which is precisely the state under test, so the wait is polled.
fn run_with_deadline(command: &mut Command) -> Finished {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("security(1) is present on every macOS host");

    let started = Instant::now();
    let status = loop {
        match child.try_wait().expect("the child can be waited on") {
            Some(status) => break Some(status),
            None if started.elapsed() >= DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }

    Finished {
        timed_out: Deadline(status.is_none()),
        status_success: status.is_some_and(|status| status.success()),
        stdout,
        stderr,
    }
}
