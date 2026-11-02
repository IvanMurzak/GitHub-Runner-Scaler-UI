//! Shared daily scheduler for the TUI and daemon. Missing settings opt old installs in.
use super::{CliError, Context, Failure, UpdateArgs};
use runner_manager_platform::lock::{HostLock, LockError, LockKind};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DAY: u64 = 24 * 60 * 60;
#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    enabled: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self { enabled: true }
    }
}

fn failure(error: impl std::fmt::Display) -> CliError {
    CliError::new(Failure::LocalState, error.to_string())
}
pub fn enabled(context: &Context) -> Result<bool, CliError> {
    match std::fs::read_to_string(context.paths().config_dir().join("updates.toml")) {
        Ok(text) => toml::from_str::<Settings>(&text)
            .map(|s| s.enabled)
            .map_err(failure),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(failure(e)),
    }
}
pub fn set_enabled(context: &Context, enabled: bool, out: &mut dyn Write) -> Result<(), CliError> {
    let path = context.paths().config_dir().join("updates.toml");
    let mut file =
        tempfile::NamedTempFile::new_in(context.paths().config_dir()).map_err(failure)?;
    file.write_all(
        toml::to_string(&Settings { enabled })
            .map_err(failure)?
            .as_bytes(),
    )
    .map_err(failure)?;
    file.as_file().sync_all().map_err(failure)?;
    file.persist(path).map_err(failure)?;
    writeln!(out, "Automatic daily updates: {enabled}").map_err(failure)
}
fn due(now: u64, last: Option<u64>) -> bool {
    last.is_none_or(|last| now < last || now - last >= DAY)
}
fn tick(context: &Context) -> Result<(), CliError> {
    tick_with(context, |enabled, report| {
        super::update::perform(
            context,
            &UpdateArgs {
                check: !enabled,
                force: false,
            },
            report,
            true,
        )
    })
}

fn tick_with(
    context: &Context,
    update: impl FnOnce(bool, &mut Vec<u8>) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let _lock = match HostLock::try_acquire(context.paths(), LockKind::Update) {
        Ok(lock) => lock,
        Err(LockError::Held { .. }) => return Ok(()),
        Err(error) => return Err(failure(error)),
    };
    let enabled = enabled(context)?;
    let stamp = context.paths().state_dir().join("update-last-check");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(failure)?
        .as_secs();
    let last = std::fs::read_to_string(&stamp)
        .ok()
        .and_then(|s| s.parse().ok());
    if !due(now, last) {
        return Ok(());
    }
    // Persist the attempt before networking: outages and crashes cannot cause a busy retry loop.
    std::fs::write(&stamp, now.to_string()).map_err(failure)?;
    let mut report = Vec::new();
    let result = update(enabled, &mut report);
    if let Err(error) = &result {
        let _ = writeln!(report, "Update failed: {error}");
    }
    std::fs::write(
        context.paths().state_dir().join("update-status.txt"),
        report,
    )
    .map_err(failure)?;
    result
}

pub struct Worker {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Worker {
    pub fn start(context: Context) -> Self {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            loop {
                // Give startup and terminal setup time to finish before checking.
                let (mutex, wake) = &*signal;
                let guard = mutex.lock().unwrap_or_else(|e| e.into_inner());
                let (guard, _) = wake
                    .wait_timeout_while(guard, Duration::from_secs(60), |stop| !*stop)
                    .unwrap_or_else(|e| e.into_inner());
                if *guard {
                    break;
                }
                drop(guard);
                if let Err(error) = tick(&context) {
                    tracing::warn!(%error, "automatic update check failed");
                }
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let (mutex, wake) = &*self.stop;
        *mutex.lock().unwrap_or_else(|e| e.into_inner()) = true;
        wake.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_settings_enable_updates() {
        assert!(toml::from_str::<Settings>("").unwrap().enabled);
        assert!(
            !toml::from_str::<Settings>("enabled = false")
                .unwrap()
                .enabled
        );
    }
    #[test]
    fn daily_schedule_survives_restart_and_clock_rollback() {
        assert!(due(100, None));
        assert!(!due(100 + DAY - 1, Some(100)));
        assert!(due(100 + DAY, Some(100)));
        assert!(due(99, Some(100)));
    }
    fn fixture() -> (tempfile::TempDir, Context) {
        let dir = tempfile::tempdir().unwrap();
        let context = Context::resolve(Some(dir.path()), &mut Vec::new()).unwrap();
        (dir, context)
    }
    #[test]
    fn absent_setting_is_enabled_and_explicit_opt_out_survives_reload() {
        let (_dir, context) = fixture();
        assert!(enabled(&context).unwrap());
        set_enabled(&context, false, &mut Vec::new()).unwrap();
        assert!(!enabled(&context).unwrap());
        tick_with(&context, |install, _| {
            assert!(!install);
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn failed_attempt_is_durable_and_two_processes_share_the_schedule() {
        let (dir, context) = fixture();
        assert!(
            tick_with(&context, |install, _| {
                assert!(install);
                Err(failure("offline"))
            })
            .is_err()
        );
        let other = Context::resolve(Some(dir.path()), &mut Vec::new()).unwrap();
        tick_with(&other, |_, _| panic!("already checked today")).unwrap();
        assert!(
            std::fs::read_to_string(context.paths().state_dir().join("update-status.txt"))
                .unwrap()
                .contains("offline")
        );
    }
    #[test]
    fn held_update_lock_prevents_checks_without_consuming_schedule() {
        let (_dir, context) = fixture();
        let lock = HostLock::try_acquire(context.paths(), LockKind::Update).unwrap();
        tick_with(&context, |_, _| panic!("another updater owns the lock")).unwrap();
        drop(lock);
        let mut called = false;
        tick_with(&context, |_, _| {
            called = true;
            Ok(())
        })
        .unwrap();
        assert!(called);
    }
    #[test]
    fn malformed_setting_never_silently_enables_updates() {
        let (_dir, context) = fixture();
        std::fs::write(
            context.paths().config_dir().join("updates.toml"),
            "enabled = nope",
        )
        .unwrap();
        assert!(tick_with(&context, |_, _| panic!("invalid settings")).is_err());
    }
}
