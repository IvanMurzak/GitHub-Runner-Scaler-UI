// owner: d2-machine-secret-store

//! The Definition of Done's last item: *"A repository-wide scan of fixtures,
//! databases, logs, and snapshots after a full store-and-load cycle finds no
//! token-shaped value outside the store."*
//!
//! It is `07-security.md`'s release gate applied to this module: *"The user
//! access token and the encoded JIT configuration are absent from logs,
//! databases, snapshots, crash reports, and CLI output."*
//!
//! # The one property that makes the scan mean anything
//!
//! **The token is assembled at run time and appears in no source file.**
//! [`fixture_token`] concatenates two fragments with `format!`, so the whole
//! string exists only in this process's heap. A `const`, or `concat!`, would be
//! folded into the compiled binary and — worse — would sit in this file, so a
//! scan of the repository would find it here and every future maintainer would
//! "fix" the scan by excluding the file that was proving something.
//!
//! Every other fixture token in this crate is built the same way, for the same
//! reason.
//!
//! # Why there is a positive control
//!
//! A scan that walks nothing reports nothing, and reads exactly like a scan
//! that walked everything and found nothing. So before the real assertion runs,
//! the token is deliberately planted in the state directory and the scan is
//! required to find it. If that fails, the test fails there — with a message
//! saying the scan is blind — instead of passing quietly for the rest of this
//! product's life.
//!
//! The second defence is a floor on the number of files examined, **per root**.
//! It was one number over both roots together, and in that form it could not
//! catch the case it named — a walk that reached the repository and nothing
//! else cleared a floor the repository already satisfied four times over. Per
//! root it bites: a walk that missed a tree fails on the tree it missed, and
//! says which one.
//!
//! # Why this is its own test binary
//!
//! `logging::install` installs a **global** subscriber and can be called once
//! per process, so a unit test in `secrets.rs` could not both install it and
//! leave the rest of the suite able to. The second file here,
//! `crates/github/tests/no_secret_reaches_the_logs.rs`, documents the deeper
//! reason for the same layout: `tracing` caches callsite interest process-wide,
//! and a capture running concurrently with other tests through the same
//! callsites is destroyed by the concurrency rather than by the ordering. Only
//! one test in this binary logs anything, and the other neither installs a sink
//! nor touches a callsite.
//!
//! # What is not scanned, and why
//!
//! `.git/` and `target/` are skipped. `.git/` holds compressed objects in which
//! no plaintext search means anything, and `target/` is several gigabytes of
//! build artifacts that cannot contain a value this process assembled at run
//! time. Everything else under the repository root is read byte for byte —
//! fixtures, snapshots, TOML, the taskflow documents — together with the whole
//! of the disposable application-data tree the cycle ran against, which is
//! where `config/`, the SQLite database, `state/`, `runtime/` and the rotating
//! `logs/` live.

use std::path::{Path, PathBuf};

use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::secrets::{
    ActiveStore, PlatformSecretStore, SecretScope, SecretStore as _,
};
use secrecy::{ExposeSecret as _, SecretString};

/// Shaped like a real `ghu_` token, unmistakably not one, and — the part that
/// matters — never written down. See this file's documentation.
fn fixture_token() -> SecretString {
    SecretString::from(format!("{}{}", "ghu_", "d2ScanFixtureNotARealOne00000000"))
}

/// Directory names the repository walk does not descend into.
const NOT_SCANNED: &[&str] = &[".git", "target"];

/// A floor on how much of the **repository** the scan must have looked at.
///
/// An earlier version of this constant was one number over both roots
/// together, documented as catching "the walk reaches the repository but not
/// the application-data tree". It could not: the repository alone holds well
/// over a hundred files and the floor was 60, so that exact case cleared it
/// comfortably. The floor is now per root, which is what makes the claim true —
/// a walk that reached one tree and not the other now fails on the tree it
/// missed, and says which one.
///
/// The number is a floor and not a count. It is deliberately well under the
/// current total so that adding or removing a file is not a test change, and
/// deliberately well over the handful a collapsed walk would return.
const MINIMUM_REPOSITORY_FILES: usize = 90;

/// The same floor for the application-data tree, which is far smaller.
///
/// After the positive control is removed, the only file the cycle leaves under
/// it is the rotating log — `config/`, `state/` and `runtime/` are empty
/// directories. So one is the honest floor here, and it still catches the case
/// the constant above cannot: a walk that never descended into the workspace at
/// all. The stronger statement about that tree is made separately, by requiring
/// the log to contain what the cycle pushed at the sink.
const MINIMUM_WORKSPACE_FILES: usize = 1;

#[test]
fn a_full_cycle_leaves_no_token_shaped_value_outside_the_store() {
    let token = fixture_token();
    let needle = token.expose_secret().to_string();

    // The application-data tree the cycle runs against: `config/`, `state/`,
    // `runtime/` and `logs/`, in a disposable root.
    let workspace = tempfile::TempDir::new().expect("a temporary directory");
    let paths = AppPaths::rooted_at(workspace.path());
    paths
        .create_all()
        .expect("the four directories are created");

    // The store lives somewhere else on purpose. On Linux a machine-scoped
    // store holds its value in plaintext under a `0600` file, by design and by
    // `05-infrastructure.md`; scanning the store itself would be asserting that
    // the store does not store anything.
    let store_root = tempfile::TempDir::new().expect("a temporary directory");

    let guard = runner_manager_platform::logging::install(&paths, "trace")
        .expect("the redacting sink installs");

    run_a_full_cycle(&token, store_root.path());

    // Flush the background log writer. Without this the scan can run before the
    // events it is meant to inspect have reached the file, which would make a
    // clean result mean nothing.
    drop(guard);

    // Before anything is asserted about what the logs do *not* contain, prove
    // they contain something. A sink that wrote nothing -- a filter that
    // rejected every event, a writer whose thread never flushed -- would sail
    // through the assertion below, and the whole point of pushing the value at
    // it in five shapes would be lost. This is the same defence
    // `crates/github/tests/no_secret_reaches_the_logs.rs` calls its callsite
    // markers, and it is there because that file's scan was once blind.
    let written = concatenated_logs(paths.logs_dir());
    assert!(
        written.contains("secret_store_selftest"),
        "the log sink wrote none of the events this cycle pushed at it, so the scan below \
         is not inspecting anything. {} holds:\n{written}",
        paths.logs_dir().display()
    );
    assert!(
        written.contains("[redacted]"),
        "the sink emitted the injected events without redacting anything, which cannot be \
         right for a field that is not on the allowlist:\n{written}"
    );

    let repository = repository_root();
    let roots: [(&str, &Path, usize); 2] = [
        (
            "the repository",
            repository.as_path(),
            MINIMUM_REPOSITORY_FILES,
        ),
        (
            "the application-data tree",
            workspace.path(),
            MINIMUM_WORKSPACE_FILES,
        ),
    ];

    // ---- the positive control ---------------------------------------------
    //
    // Plant the value where a leaked one would land -- beside the SQLite
    // database, in `state/` -- and require the scan to find it. A scan that
    // cannot fail is not evidence.
    let planted = paths.state_dir().join("planted-by-the-positive-control.db");
    std::fs::write(&planted, format!("attempt_journal|{needle}|end")).expect("planted");

    let (hits, _) = scan(workspace.path(), needle.as_bytes());
    assert!(
        hits.contains(&planted),
        "the scan did not find a value planted at {} -- it is blind, and the assertions \
         below prove nothing",
        planted.display()
    );
    std::fs::remove_file(&planted).expect("the control is removed");

    // ---- the real assertion -----------------------------------------------
    //
    // Per root, so that a walk which reached one tree and not the other fails
    // on the tree it missed and says which one. Over both roots at once, that
    // case cleared any floor the larger tree already satisfied on its own.
    let mut hits = Vec::new();
    for (name, root, floor) in roots {
        let (found, scanned) = scan(root, needle.as_bytes());
        assert!(
            scanned >= floor,
            "the scan examined only {scanned} files under {name} ({}), fewer than the {floor} \
             it must reach; it did not inspect what it was meant to",
            root.display()
        );
        hits.extend(found);
    }

    assert!(
        hits.is_empty(),
        "a token-shaped value survives outside the store, in:\n{}",
        hits.iter()
            .map(|path| format!("  {}", path.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Store, report, load, mis-load, and purge — with the value pushed at the log
/// sink in every shape a careless caller could push it.
///
/// The point is not that this module logs the token; it does not. The point is
/// that the scan is run against a tree in which something *tried* to, so that a
/// clean result is a statement about the sink and the store together rather
/// than about a quiet afternoon.
fn run_a_full_cycle(token: &SecretString, store_root: &Path) {
    for scope in [SecretScope::Machine, SecretScope::User] {
        let store = PlatformSecretStore::rooted_at(scope, store_root)
            .expect("the store resolves under an explicit root");

        store.store(token).expect("the token is stored");

        let active = ActiveStore::of(&store, scope.start_mode());
        tracing::info!(
            event = "secret_store_selftest",
            scope = scope.as_str(),
            start_mode = %active.start_mode(),
            "the active store was reported"
        );
        // What `host show` would print. If any of these rendered the value, the
        // scan below would find it in `logs/`.
        tracing::info!(
            event = "secret_store_selftest",
            reason = %active,
            "the active store, rendered"
        );
        tracing::info!(
            event = "secret_store_selftest",
            reason = %store.location(),
            "the location, rendered"
        );
        tracing::info!(
            event = "secret_store_selftest",
            reason = ?store,
            "the store, through Debug"
        );
        if let Ok(protection) = store.protection() {
            tracing::info!(
                event = "secret_store_selftest",
                reason = %protection,
                "the protection, rendered"
            );
        }

        let loaded = store
            .load()
            .expect("the store is readable")
            .expect("a value was stored");
        assert_eq!(loaded.expose_secret(), token.expose_secret());

        // Three shapes a careless caller reaches for, pushed at the sink on
        // purpose. `07-security.md`'s threat table calls the control
        // "structured allowlist logging with unconditional redaction"; this is
        // the injection half of its secret-injection log scan.
        let exposed = token.expose_secret();
        tracing::info!(
            event = "secret_store_selftest",
            token = %exposed,
            "a field that is not on the allowlist"
        );
        tracing::error!(
            event = "secret_store_selftest",
            reason = ?format!("{{\"access_token\":\"{exposed}\"}}"),
            "an error body carrying a credential"
        );
        tracing::info!("Authorization: Bearer {exposed}");

        store.delete().expect("the token is purged");
        assert!(
            store.load().expect("readable").is_none(),
            "a purged store is empty"
        );
    }
}

/// Everything the rotating sink wrote, in one string.
///
/// `tracing_appender::rolling::daily` names its file after the date, so the
/// directory is read rather than a path guessed.
fn concatenated_logs(directory: &Path) -> String {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return String::new();
    };
    let mut text = String::new();
    for entry in entries.flatten() {
        if let Ok(contents) = std::fs::read_to_string(entry.path()) {
            text.push_str(&contents);
        }
    }
    text
}

/// The repository root, from this crate's manifest directory.
fn repository_root() -> PathBuf {
    // `crates/platform` -> `crates` -> the workspace root.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent()
        .and_then(Path::parent)
        .expect("crates/platform is two levels below the workspace root")
        .to_path_buf();
    assert!(
        root.join("Cargo.lock").is_file(),
        "{} does not look like the workspace root",
        root.display()
    );
    root
}

/// Every file under `roots` whose bytes contain `needle`, and how many were
/// examined.
fn scan(root: &Path, needle: &[u8]) -> (Vec<PathBuf>, usize) {
    let mut hits = Vec::new();
    let mut scanned = 0usize;
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };

            if kind.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if NOT_SCANNED.contains(&name.as_ref()) {
                    continue;
                }
                pending.push(path);
                continue;
            }
            // Symlinks are not followed: on this walk they can only lead back
            // out of the tree, and a loop would hang the suite.
            if !kind.is_file() {
                continue;
            }

            scanned += 1;
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if bytes.windows(needle.len()).any(|window| window == needle) {
                hits.push(path);
            }
        }
    }

    (hits, scanned)
}

/// A guard on the guard: if the two fragments above are ever joined into one
/// literal, this file becomes its own hit and the scan starts excluding itself.
#[test]
fn the_fixture_token_is_in_no_source_file() {
    let needle = fixture_token().expose_secret().to_string();
    let crates = repository_root().join("crates");
    let (hits, scanned) = scan(crates.as_path(), needle.as_bytes());

    assert!(
        scanned > 10,
        "the walk over crates/ found only {scanned} files"
    );
    assert!(
        hits.is_empty(),
        "the fixture token is written down in {:?}, which makes the repository scan \
         meaningless -- assemble it from fragments at run time instead",
        hits
    );
}
