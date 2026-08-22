// owner: d2-machine-secret-store

//! The Definition of Done's reboot item: *"A machine-scoped value written
//! before a simulated reboot is readable by a process running with no
//! interactive login session."*
//!
//! # What "simulated reboot" means here, and what it does not
//!
//! A reboot is not something a test suite can have, so this reproduces the two
//! properties of one that the store actually depends on:
//!
//! 1. **No in-process state carries over.** The value is written by this
//!    process and read by a *different* one, which resolves the store from
//!    scratch. Nothing cached, nothing inherited, no handle passed along.
//! 2. **No login session.** The child is spawned with its environment cleared
//!    down to what the operating system needs to load a binary at all, and on
//!    Unix it calls `setsid(2)` before `exec`, so it is a session leader with
//!    no controlling terminal. Every variable a desktop session sets — `HOME`,
//!    `XDG_RUNTIME_DIR`, `DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`, `USERPROFILE`,
//!    `LOCALAPPDATA` — is gone, and the child asserts that before it reads
//!    anything.
//!
//! **What it is not** is a service in Windows session 0, or a LaunchDaemon, or
//! a systemd unit with `PrivateUsers=`. Reaching any of those from `cargo test`
//! means installing a service, which is `d3`'s territory and needs privileges
//! CI does not hand an unprivileged test process. So the claim this file
//! supports is precisely: *a machine-scoped store does not depend on any
//! session-derived environment, and its value survives into a process that has
//! none*. The complementary half — that the store's **location** is not under
//! any per-user or per-session directory, which is the thing that would
//! actually break at boot — is asserted in `secrets.rs` by
//! `the_machine_store_is_not_under_the_home_directory`.
//!
//! # Why the child is this same binary
//!
//! There is no second executable to spawn, and adding one would mean a new
//! `[[bin]]` in a manifest that `a1` owns. `libtest` can be asked for one test
//! by name, so the child re-runs this file with `--exact --ignored` and lands
//! in [`child_reads_the_machine_scoped_store`], which is `#[ignore]`d precisely
//! so that an ordinary `cargo test` never runs it without a store to read.

use std::path::PathBuf;
use std::process::Command;

use runner_manager_platform::secrets::{
    PlatformSecretStore, SecretScope, SecretStore as _, SecretStoreError,
};
use secrecy::{ExposeSecret as _, SecretString};

/// Where the parent tells the child to look. A path, not a value.
const ROOT_VARIABLE: &str = "RUNNER_MANAGER_SECRET_STORE_ROOT";

/// What the child prints when it has read the value back. The parent looks for
/// this rather than for an exit code alone, because a child that failed to
/// start also exits non-zero and the two want different diagnoses.
const CHILD_SUCCESS: &str = "child-read-the-machine-scoped-store";

/// Shaped like a real `ghu_` token and unmistakably not one. Assembled at run
/// time so the literal is in no source file and no compiled artifact; see
/// `no_token_outside_the_store.rs`, which depends on that.
fn fixture_token() -> SecretString {
    SecretString::from(format!("{}{}", "ghu_", "d2RebootFixtureNotARealOne000000"))
}

/// The variables a process needs to load a binary at all, and nothing else.
///
/// Everything omitted here is omitted deliberately. `USERPROFILE`,
/// `LOCALAPPDATA` and `APPDATA` are the Windows per-user roots; `HOME` is the
/// Unix one; `XDG_RUNTIME_DIR` is cleared by the system when a session ends,
/// which is the exact event a boot-time service starts before.
#[cfg(windows)]
const CARRIED_OVER: &[&str] = &[
    "SystemRoot",
    "windir",
    "SystemDrive",
    "PATH",
    "PATHEXT",
    "ComSpec",
    "NUMBER_OF_PROCESSORS",
];

#[cfg(unix)]
const CARRIED_OVER: &[&str] = &["PATH"];

/// Variables whose absence the child asserts before it reads anything.
///
/// Without this the test would still pass if `env_clear` were removed by
/// accident, and would then be measuring nothing at all.
#[cfg(windows)]
const MUST_BE_ABSENT: &[&str] = &[
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "HOMEPATH",
    "HOMEDRIVE",
    "USERNAME",
    "SESSIONNAME",
];

#[cfg(unix)]
const MUST_BE_ABSENT: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "XDG_RUNTIME_DIR",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
    "SSH_AUTH_SOCK",
];

#[test]
fn a_machine_scoped_value_is_readable_by_a_process_with_no_login_session() {
    let root = tempfile::TempDir::new().expect("a temporary directory");

    let store = PlatformSecretStore::rooted_at(SecretScope::Machine, root.path())
        .expect("the machine-scoped store resolves");
    store
        .store(&fixture_token())
        .expect("the token is written before the simulated reboot");

    let executable = std::env::current_exe().expect("this test binary has a path");
    let mut command = Command::new(&executable);
    command
        .arg("child_reads_the_machine_scoped_store")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture");

    command.env_clear();
    for key in CARRIED_OVER {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.env(ROOT_VARIABLE, root.path());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: `setsid` is async-signal-safe, takes no arguments, and
        // touches no memory this process owns. It is called between `fork` and
        // `exec`, which is the only place `pre_exec` runs, and a failure --
        // `EPERM` when the child is already a process-group leader -- is not a
        // reason to abandon the launch, only a reason not to have the stronger
        // property.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    let output = command.output().expect("the child test process starts");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        output.status.success() && stdout.contains(CHILD_SUCCESS),
        "a process with no login session could not read the machine-scoped store.\n\
         status: {}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status
    );

    // The value itself must not be how the child reported success, or this test
    // would be the leak it exists to rule out.
    let token = fixture_token().expose_secret().to_string();
    assert!(
        !stdout.contains(&token) && !stderr.contains(&token),
        "the child printed the token"
    );
}

/// The other half of the test above. Never run by an ordinary `cargo test`:
/// `#[ignore]` keeps it out, and without [`ROOT_VARIABLE`] there is nothing for
/// it to read anyway.
#[test]
#[ignore = "spawned by a_machine_scoped_value_is_readable_by_a_process_with_no_login_session"]
fn child_reads_the_machine_scoped_store() {
    let Some(root) = std::env::var_os(ROOT_VARIABLE).map(PathBuf::from) else {
        panic!("{ROOT_VARIABLE} is unset, so this child has no store to read");
    };

    // Assert the premise before the conclusion. A child that still had a login
    // session would read the store perfectly well and prove nothing.
    for key in MUST_BE_ABSENT {
        assert!(
            std::env::var_os(key).is_none(),
            "this process still has {key} set, so it is not a process with no login session"
        );
    }

    let store = PlatformSecretStore::rooted_at(SecretScope::Machine, &root)
        .expect("the machine-scoped store resolves without a session");

    let loaded = match store.load() {
        Ok(Some(secret)) => secret,
        Ok(None) => panic!("the machine-scoped store is empty in a process with no session"),
        Err(SecretStoreError::Corrupt { detail, .. }) => {
            panic!("the machine-scoped store could not be read back: {detail}")
        }
        Err(error) => panic!("the machine-scoped store could not be reached: {error}"),
    };

    assert_eq!(
        loaded.expose_secret(),
        fixture_token().expose_secret(),
        "the value read back is not the value written before the simulated reboot"
    );

    // Only ever the marker, never the value.
    println!("{CHILD_SUCCESS}");
}
