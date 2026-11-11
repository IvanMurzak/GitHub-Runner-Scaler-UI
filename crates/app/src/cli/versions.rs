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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use runner_manager_domain::coordinator_protocol::{HostVersions, ManagedWsl};
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::wsl::fence::GuestRecoveryConfig;
use runner_manager_platform::wsl::record::WslProviderRecord;

use super::daemon::BinaryStamp;
use super::update::{Installation, service_source};

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
        versions.bounded()
    })
}

/// Reads again at the next heartbeat: an update just changed the binary.
pub fn invalidate() {
    reading().at = None;
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
        wsl_guest: GuestRecoveryConfig::path(paths).exists(),
        ..HostVersions::default()
    };
    let previous = reading().source.take();
    let source = service_source(paths).ok().flatten().map(|path| {
        let stamp = BinaryStamp::of(&path);
        match previous {
            Some(source) if source.path == path && source.stamp == stamp => source,
            _ => {
                let version = super::update::executable_version(&path);
                let installation = Installation::of_source(paths, path.clone(), version.as_deref());
                Source {
                    describe: installation.channel.describe(),
                    updatable: installation.refusal().is_none(),
                    path,
                    stamp,
                    version,
                }
            }
        }
    });
    if let Some(source) = &source {
        versions.app.clone_from(&source.version);
        versions.app_source = Some(source.describe.to_owned());
        versions.updatable = source.updatable;
    }
    let mut reading = reading();
    reading.versions = Some(versions);
    reading.at = Some(Instant::now());
    reading.source = source;
}
