//! Bounded retention for the redacted summaries written after runner attempts.
//!
//! These live outside the disposable workspace, so removing that workspace
//! never removed its `<attempt UUID>.log`. Only that exact filename shape is
//! eligible here; rotating service logs, other files, directories and links
//! are left alone. No runtime or dependency-cache directory is walked.

use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Keep at most this many completed-attempt summaries.
pub const MAX_ATTEMPT_LOGS: usize = 1_000;
/// Even a quiet host need not keep summaries indefinitely.
pub const ATTEMPT_LOG_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// A failed removal is retried on the next maintenance pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Summaries successfully unlinked.
    pub removed: usize,
    /// Summaries still present because their removal failed.
    pub failed: usize,
}

/// Remove expired summaries and the oldest ones above the count limit.
///
/// Missing directories are normal before the first attempt. Other enumeration
/// errors are returned rather than reporting an incomplete scan as success.
pub fn prune_attempt_logs(directory: &Path, now: SystemTime) -> io::Result<PruneReport> {
    prune(directory, now, MAX_ATTEMPT_LOGS, ATTEMPT_LOG_MAX_AGE)
}

fn prune(
    directory: &Path,
    now: SystemTime,
    limit: usize,
    max_age: Duration,
) -> io::Result<PruneReport> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(PruneReport::default()),
        Err(error) => return Err(error),
    };
    let mut logs = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".log")) else {
            continue;
        };
        // Only the canonical spelling produced by AttemptId's Display.
        if !uuid::Uuid::try_parse(id).is_ok_and(|uuid| uuid.to_string() == id) {
            continue;
        }
        // DirEntry::file_type does not follow symlinks/junctions.
        if !entry.file_type()?.is_file() {
            continue;
        }
        let modified = entry.metadata()?.modified()?;
        logs.push((modified, entry.path()));
    }
    logs.sort();
    let excess = logs.len().saturating_sub(limit);
    let mut report = PruneReport::default();
    for (index, (modified, path)) in logs.into_iter().enumerate() {
        let expired = now.duration_since(modified).is_ok_and(|age| age >= max_age);
        if index < excess || expired {
            match fs::remove_file(path) {
                Ok(()) => report.removed += 1,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => report.failed += 1,
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn summary(root: &Path, id: u128, modified: SystemTime) -> PathBuf {
        let path = root.join(format!("{}.log", uuid::Uuid::from_u128(id)));
        let file = fs::File::create(&path).unwrap();
        file.set_modified(modified).unwrap();
        path
    }

    #[test]
    fn removes_old_summaries_and_bounds_recent_history_without_touching_other_files() {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let expired = summary(root.path(), 1, now - ATTEMPT_LOG_MAX_AGE);
        let excess = summary(root.path(), 2, now - Duration::from_secs(20));
        let recent = summary(root.path(), 3, now - Duration::from_secs(10));
        let newest = summary(root.path(), 4, now);
        let service = root.path().join("runner-manager.service.log.2020-01-01");
        let unrelated = root.path().join("customer.log");
        fs::write(&service, "service diagnostics").unwrap();
        fs::write(&unrelated, "not an attempt summary").unwrap();
        let directory = root
            .path()
            .join(format!("{}.log", uuid::Uuid::from_u128(5)));
        fs::create_dir(&directory).unwrap();

        let report = prune(root.path(), now, 2, ATTEMPT_LOG_MAX_AGE).unwrap();
        assert_eq!(
            report,
            PruneReport {
                removed: 2,
                failed: 0
            }
        );
        assert!(!expired.exists());
        assert!(!excess.exists());
        for kept in [recent, newest, service, unrelated, directory] {
            assert!(kept.exists(), "{} was removed", kept.display());
        }
    }

    #[test]
    fn expires_a_quiet_hosts_history_and_tolerates_clock_rollback_and_missing_directory() {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let expired = summary(root.path(), 1, now - ATTEMPT_LOG_MAX_AGE);
        let future = summary(root.path(), 2, now + Duration::from_secs(60));
        let report = prune_attempt_logs(root.path(), now).unwrap();
        assert_eq!(report.removed, 1);
        assert!(!expired.exists());
        assert!(future.exists());
        assert_eq!(
            prune_attempt_logs(&root.path().join("missing"), now).unwrap(),
            PruneReport::default()
        );
    }

    #[cfg(unix)]
    #[test]
    fn never_follows_a_summary_shaped_symlink() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let target = summary(outside.path(), 1, now - ATTEMPT_LOG_MAX_AGE);
        let link = root
            .path()
            .join(format!("{}.log", uuid::Uuid::from_u128(2)));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            prune_attempt_logs(root.path(), now).unwrap(),
            PruneReport::default()
        );
        assert!(link.symlink_metadata().is_ok());
        assert!(target.exists());
    }

    #[cfg(windows)]
    #[test]
    fn an_unremovable_summary_does_not_block_other_cleanup_and_is_retried() {
        use std::os::windows::fs::OpenOptionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let locked = summary(root.path(), 1, now - ATTEMPT_LOG_MAX_AGE);
        let removable = summary(root.path(), 2, now - ATTEMPT_LOG_MAX_AGE);
        let handle = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&locked)
            .unwrap();
        let report = prune_attempt_logs(root.path(), now).unwrap();
        assert_eq!(
            report,
            PruneReport {
                removed: 1,
                failed: 1
            }
        );
        assert!(locked.exists());
        assert!(!removable.exists());
        drop(handle);
        assert_eq!(prune_attempt_logs(root.path(), now).unwrap().removed, 1);
        assert!(!locked.exists());
    }
}
