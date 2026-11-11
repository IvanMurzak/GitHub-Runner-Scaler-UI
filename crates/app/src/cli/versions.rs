//! The runner-manager builds on this host, as its heartbeat tells the
//! coordinator (0.4.64): the build the service runs, the installed binary it
//! was installed from (what `runner-manager` on this machine's command line
//! usually is), whether the coordinator can update it, and the WSL
//! distributions this machine manages.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use runner_manager_domain::coordinator_protocol::{HostVersions, ManagedWsl};
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::wsl::fence::GuestRecoveryConfig;
use runner_manager_platform::wsl::record::WslProviderRecord;

use super::update::{Installation, service_source};

/// The service source as last read: `--version` runs a process, so it is
/// asked again only when the file changed.
struct Source {
    path: PathBuf,
    stamp: Option<(u64, Option<SystemTime>)>,
    version: Option<String>,
    describe: &'static str,
    updatable: bool,
}

static SOURCE: Mutex<Option<Source>> = Mutex::new(None);

fn stamp(path: &std::path::Path) -> Option<(u64, Option<SystemTime>)> {
    std::fs::metadata(path)
        .ok()
        .map(|meta| (meta.len(), meta.modified().ok()))
}

/// This host's builds, now.
#[must_use]
pub fn report(paths: &AppPaths) -> HostVersions {
    let mut versions = HostVersions {
        service: env!("RUNNER_MANAGER_BUILD_VERSION").to_owned(),
        update: super::remote::update_progress(),
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
    if let Ok(Some(path)) = service_source(paths) {
        let mut cached = SOURCE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = stamp(&path);
        if !cached
            .as_ref()
            .is_some_and(|source| source.path == path && source.stamp == now)
        {
            let version = super::update::executable_version(&path);
            let installation = Installation::of_source(paths, path.clone(), version.as_deref());
            *cached = Some(Source {
                describe: installation.channel.describe(),
                updatable: installation.refusal().is_none(),
                path,
                stamp: now,
                version,
            });
        }
        if let Some(source) = cached.as_ref() {
            versions.app.clone_from(&source.version);
            versions.app_source = Some(source.describe.to_owned());
            versions.updatable = source.updatable && super::remote::changes_allowed(paths);
        }
    }
    versions.bounded()
}
