//! The runner-manager builds on this host, as its heartbeat tells the
//! coordinator (0.4.64): the build the service runs, the installed binary it
//! was installed from (what `runner-manager` on this machine's command line
//! usually is), whether that binary's channel can be updated by the service,
//! and the WSL distributions this machine manages.
//!
//! Reading them takes files and a `--version` run, so it is never done on the
//! heartbeat's own thread: the heartbeat takes the last reading, and a reading
//! older than [`REFRESH`] starts a new one on a thread of its own.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use runner_manager_domain::coordinator_protocol::{HostVersions, ManagedWsl};
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::wsl::record::WslProviderRecord;

use super::daemon::BinaryStamp;
use super::update::{Channel, Installation, service_source};

/// How old a reading may be before the next heartbeat asks for a new one.
const REFRESH: Duration = Duration::from_secs(60);

/// The service source as last read: `--version` runs a process, so it is
/// asked again only when the file changed.
struct Source {
    path: PathBuf,
    stamp: Option<BinaryStamp>,
    version: Option<String>,
    describe: &'static str,
    updatable: bool,
    missing: bool,
}

impl Source {
    /// Reads the service source at `path`, whose file is `stamp`.
    fn read(paths: &AppPaths, path: PathBuf, stamp: Option<BinaryStamp>) -> Self {
        let version = super::update::executable_version(&path);
        let installation = Installation::of_source(paths, path.clone(), version.as_deref());
        Self {
            describe: installation.channel.describe(),
            updatable: installation.refusal().is_none(),
            missing: installation.channel == Channel::Missing,
            path,
            stamp,
            version,
        }
    }

    /// Puts what the heartbeat says of this source into `versions`.
    fn report(&self, versions: &mut HostVersions) {
        versions.app.clone_from(&self.version);
        versions.app_source = Some(self.describe.to_owned());
        versions.updatable = self.updatable;
        versions.app_missing = self.missing.then(|| self.path.display().to_string());
    }
}

#[derive(Default)]
struct Reading {
    versions: Option<HostVersions>,
    at: Option<Instant>,
    source: Option<Source>,
}

static READING: Mutex<Reading> = Mutex::new(Reading {
    versions: None,
    at: None,
    source: None,
});
static REFRESHING: AtomicBool = AtomicBool::new(false);
/// Bumped by [`invalidate`]: a reading begun before it is not fresh.
static GENERATION: AtomicU64 = AtomicU64::new(0);

fn reading() -> std::sync::MutexGuard<'static, Reading> {
    READING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// This host's builds as last read, with the coordinator's update as it is
/// now; `None` until the first reading is done. Never blocks on the files.
#[must_use]
pub fn report(paths: &AppPaths) -> Option<HostVersions> {
    let (versions, stale) = {
        let reading = reading();
        (
            reading.versions.clone(),
            reading.at.is_none_or(|at| at.elapsed() >= REFRESH),
        )
    };
    if stale {
        refresh_in_background(paths.clone());
    }
    versions.map(|mut versions| {
        versions.update = super::remote::update_progress();
        let reboot = super::reboot::control();
        versions.rebootable = reboot.available();
        versions.starts_at_login = reboot.starts_at_login();
        versions.reboot = reboot.progress();
        versions.bounded()
    })
}

/// Reads again at the next heartbeat: an update just changed the binary.
pub fn invalidate() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
    reading().at = None;
}

/// Reads now, unless a reading exists: for the first heartbeat of a session,
/// which would otherwise say nothing. Blocks; call it off the runtime.
pub fn prime(paths: &AppPaths) {
    if reading().versions.is_none() {
        refresh(paths);
    }
}

fn refresh_in_background(paths: AppPaths) {
    if REFRESHING.swap(true, Ordering::AcqRel) {
        return;
    }
    std::thread::spawn(move || {
        refresh(&paths);
        REFRESHING.store(false, Ordering::Release);
    });
}

fn refresh(paths: &AppPaths) {
    let generation = GENERATION.load(Ordering::Acquire);
    let mut versions = HostVersions {
        service: env!("RUNNER_MANAGER_BUILD_VERSION").to_owned(),
        wsl: WslProviderRecord::all(paths)
            .unwrap_or_default()
            .into_iter()
            .map(|record| ManagedWsl {
                distribution: record.distribution,
                installed_version: record.installed_version,
            })
            .collect(),
        wsl_guest: super::reboot::is_wsl_guest(paths),
        ..HostVersions::default()
    };
    let previous = reading().source.take();
    let source = service_source(paths).ok().flatten().map(|path| {
        let stamp = BinaryStamp::of(&path);
        match previous {
            Some(source) if source.path == path && source.stamp == stamp => source,
            _ => Source::read(paths, path, stamp),
        }
    });
    if let Some(source) = &source {
        source.report(&mut versions);
    }
    let mut reading = reading();
    reading.versions = Some(versions);
    // Read before an update changed the binary: stale at once.
    reading.at = (GENERATION.load(Ordering::Acquire) == generation).then(Instant::now);
    reading.source = source;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A service source that is gone is reported missing, with its path, and
    /// not updatable: the dashboard offers no Update that would fail.
    #[test]
    fn a_missing_service_source_is_not_updatable_and_names_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted_at(dir.path());
        let gone = dir.path().join("gone/target/release/runner-manager");
        let mut versions = HostVersions::default();
        Source::read(&paths, gone.clone(), BinaryStamp::of(&gone)).report(&mut versions);
        assert!(!versions.updatable);
        assert_eq!(versions.app, None);
        assert_eq!(versions.app_source.as_deref(), Some("missing"));
        assert_eq!(
            versions.app_missing.as_deref(),
            Some(gone.display().to_string().as_str())
        );
    }

    /// A source that is there says nothing of being missing.
    #[test]
    fn a_present_service_source_is_not_called_missing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted_at(dir.path());
        let archive = dir.path().join("bin/runner-manager");
        std::fs::create_dir_all(archive.parent().unwrap()).unwrap();
        std::fs::write(&archive, b"not a program").unwrap();
        let mut versions = HostVersions::default();
        Source::read(&paths, archive.clone(), BinaryStamp::of(&archive)).report(&mut versions);
        assert!(versions.updatable);
        assert_eq!(versions.app_source.as_deref(), Some("release archive"));
        assert_eq!(versions.app_missing, None);
    }
}
