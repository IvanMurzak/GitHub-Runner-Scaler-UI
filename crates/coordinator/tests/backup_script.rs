//! `deploy/coordinator/backup.sh`, against a database in use: what the copy
//! holds, and what is kept. Needs the `sqlite3` command, which the backup image
//! installs; where a machine has none there is nothing to run it with.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

use rusqlite::Connection;

fn run_backup(database: &Path, backups: &Path) -> std::process::Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/coordinator/backup.sh");
    Command::new("sh")
        .arg(script)
        .arg("once")
        .env("COORDINATOR_DB", database)
        .env("COORDINATOR_BACKUP_DIR", backups)
        .output()
        .expect("sh runs")
}

fn copies(backups: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(backups)
        .expect("listed")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("utf-8")
        })
        .collect();
    names.sort();
    names
}

#[test]
fn a_database_in_use_is_copied_whole_and_the_last_seven_are_kept() {
    if Command::new("sqlite3").arg("-version").output().is_err() {
        eprintln!("skipped: no sqlite3 command");
        return;
    }
    let dir = tempfile::tempdir().expect("a directory");
    let database = dir.path().join("coordinator.db");
    let backups = dir.path().join("backups");
    std::fs::create_dir(&backups).expect("created");
    // Open throughout, as the coordinator's is, with rows only in its WAL.
    let live = Connection::open(&database).expect("opened");
    live.pragma_update(None, "journal_mode", "WAL")
        .expect("WAL");
    live.pragma_update(None, "wal_autocheckpoint", 0)
        .expect("no checkpoint");
    live.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1), (2), (3);")
        .expect("written");
    for day in 1..=8 {
        std::fs::write(
            backups.join(format!("coordinator-202001{day:02}T000000Z.db")),
            "old",
        )
        .expect("written");
    }

    let output = run_backup(&database, &backups);

    assert!(output.status.success(), "{output:?}");
    let kept = copies(&backups);
    assert_eq!(kept.len(), 7, "{kept:?}");
    assert!(!kept.contains(&"coordinator-20200101T000000Z.db".to_string()));
    assert!(!kept.contains(&"coordinator-20200102T000000Z.db".to_string()));
    let copy = Connection::open(backups.join(kept.last().expect("the newest"))).expect("opened");
    let rows: i64 = copy
        .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
        .expect("read");
    assert_eq!(rows, 3, "what the WAL held is in the copy");
    live.execute("INSERT INTO t VALUES (4)", [])
        .expect("still writable");
}

/// The daily loop, which is what runs: a failure there must stop the copy just
/// as it does for `once`, or an empty file replaces a good one.
#[test]
fn the_daily_loop_keeps_no_copy_of_a_database_it_could_not_read() {
    if Command::new("sqlite3").arg("-version").output().is_err() {
        eprintln!("skipped: no sqlite3 command");
        return;
    }
    let dir = tempfile::tempdir().expect("a directory");
    let backups = dir.path().join("backups");
    std::fs::create_dir(&backups).expect("created");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/coordinator/backup.sh");
    let mut running = Command::new("sh")
        .arg(script)
        .env("COORDINATOR_DB", dir.path().join("missing.db"))
        .env("COORDINATOR_BACKUP_DIR", &backups)
        .env("COORDINATOR_BACKUP_RETRY_SECS", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("sh runs");

    std::thread::sleep(std::time::Duration::from_millis(2500));
    let _ = running.kill();
    let said = running.wait_with_output().expect("collected").stderr;

    assert!(
        String::from_utf8_lossy(&said).contains("failed; trying again"),
        "the loop ran: {}",
        String::from_utf8_lossy(&said)
    );
    assert_eq!(copies(&backups), Vec::<String>::new());
}

/// A setting that would remove every copy is refused before anything happens.
#[test]
fn a_keep_count_of_zero_in_any_spelling_is_refused() {
    let dir = tempfile::tempdir().expect("a directory");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/coordinator/backup.sh");
    for keep in ["0", "00", "08", "x", ""] {
        let output = Command::new("sh")
            .arg(&script)
            .arg("once")
            .env("COORDINATOR_DB", dir.path().join("missing.db"))
            .env("COORDINATOR_BACKUP_DIR", dir.path())
            .env("COORDINATOR_BACKUP_KEEP", keep)
            .output()
            .expect("sh runs");
        assert_eq!(output.status.code(), Some(2), "{keep:?}");
    }
}

#[test]
fn a_failed_backup_removes_nothing_and_leaves_nothing_that_looks_like_one() {
    if Command::new("sqlite3").arg("-version").output().is_err() {
        eprintln!("skipped: no sqlite3 command");
        return;
    }
    let dir = tempfile::tempdir().expect("a directory");
    let backups = dir.path().join("backups");
    std::fs::create_dir(&backups).expect("created");
    for day in 1..=8 {
        std::fs::write(
            backups.join(format!("coordinator-202001{day:02}T000000Z.db")),
            "old",
        )
        .expect("written");
    }

    let output = run_backup(&dir.path().join("missing.db"), &backups);

    assert!(!output.status.success());
    assert_eq!(copies(&backups).len(), 8);
}
