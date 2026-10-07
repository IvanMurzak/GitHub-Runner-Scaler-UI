//! The daemon's half of `runner_manager_platform::dependency_cache`: which
//! variables a native runner gets at launch, and the periodic prune.
//!
//! The settings (`caches.toml`) are read at every launch, like `runner.env`,
//! so `host cache` and `repo cache` reach the next runner without a restart.
//! A file that does not parse fails the launch in `prepare`, before the runner
//! is registered with GitHub: it may hold an operator's decision to turn a
//! repository's caches off, and starting runners without it would silently
//! reverse that. Anything that goes wrong after registration — the file broken
//! since, no root, a lock that cannot be taken, a directory that cannot be
//! created — starts the runner without caches and is logged: a cache makes a
//! job faster, never possible.
//!
//! Isolated runners (OCI, Hyper-V containers) get no caches. Their environment
//! is the image's and the providers mount no host directory by design, so a
//! cache would need a bind mount those providers deliberately refuse;
//! `host cache show` says so for each such policy.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use runner_manager_domain::attempt::FailureReason;
use runner_manager_domain::model::ScaleTarget;
use runner_manager_platform::dependency_cache::{
    self, CacheConfig, CacheUsage, ResolvedRoot, runtime_holds_runner,
};
use runner_manager_platform::runner_env::{RunnerEnv, RunnerPlatform};

/// Set while a prune pass walks the cache root. A daemon reload starts new
/// maintenance loops while a blocking walk of the old one may still run; two
/// walks of a pnpm store at once would only double the I/O.
static PRUNING: AtomicBool = AtomicBool::new(false);

/// The effective host runner root, read when needed: it lives in the journal
/// and `host set-runtime-root` may change it while the daemon runs.
pub type RunnerRootSource = Arc<dyn Fn() -> Option<PathBuf> + Send + Sync>;

/// Where the cache settings and the default root come from.
#[derive(Clone)]
pub struct DependencyCaches {
    config_file: PathBuf,
    runner_root: RunnerRootSource,
    fallback: Option<PathBuf>,
}

impl fmt::Debug for DependencyCaches {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DependencyCaches")
            .field("config_file", &self.config_file)
            .field("fallback", &self.fallback)
            .finish_non_exhaustive()
    }
}

impl DependencyCaches {
    /// `config_file` is `caches.toml`; `fallback` is
    /// [`dependency_cache::platform_fallback_root`].
    #[must_use]
    pub fn new(
        config_file: PathBuf,
        runner_root: RunnerRootSource,
        fallback: Option<PathBuf>,
    ) -> Self {
        Self {
            config_file,
            runner_root,
            fallback,
        }
    }

    /// The settings, read now.
    ///
    /// # Errors
    /// A file that cannot be read or parsed, as a launch failure that names
    /// the file and the command that fixes it.
    pub fn config(&self) -> Result<CacheConfig, FailureReason> {
        CacheConfig::load(&self.config_file).map_err(|error| {
            tracing::warn!(
                reason = "dependency_cache_config_invalid",
                "caches.toml could not be applied, so no runner starts until it is fixed: {error}"
            );
            FailureReason::Other(format!(
                "caches.toml cannot be applied ({error}); fix it with `runner-manager host cache` \
                 or delete the file"
            ))
        })
    }

    /// The cache root under `config`.
    ///
    /// # Errors
    /// Why no root resolves.
    pub fn root(&self, config: &CacheConfig) -> Result<ResolvedRoot, String> {
        dependency_cache::resolve_root(
            config,
            (self.runner_root)().as_deref(),
            self.fallback.clone(),
        )
    }

    /// The variables a native runner of `target` whose attempt is at `runtime`
    /// starts with, after leasing its slot and creating its directories.
    ///
    /// A tool any of whose variables `host_env` or the service's own
    /// environment already sets is left out entirely, so an operator's setting
    /// is never mixed with this one. Never fails: `prepare` already refused a
    /// broken file, and anything wrong now costs the job its caches, not its
    /// runner.
    #[must_use]
    pub fn for_launch(
        &self,
        target: &ScaleTarget,
        runtime: &Path,
        host_env: &RunnerEnv,
    ) -> Vec<(&'static str, OsString)> {
        let config = match CacheConfig::load(&self.config_file) {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(
                    reason = "dependency_cache_config_invalid",
                    "starting the runner without dependency caches: {error}"
                );
                return Vec::new();
            }
        };
        let platform = RunnerPlatform::current();
        let mut selection = dependency_cache::select(&config, target, platform);
        if selection.disabled.is_some() {
            return Vec::new();
        }
        selection.defer_to_operator(platform, |name| {
            dependency_cache::inherited(name)
                || host_env
                    .entries()
                    .any(|(set, _)| set.eq_ignore_ascii_case(name))
        });
        let root = match self.root(&config) {
            Ok(root) => root,
            Err(why) => {
                tracing::warn!(
                    reason = "dependency_cache_root_unresolved",
                    "starting the runner without dependency caches: {why}"
                );
                return Vec::new();
            }
        };
        match dependency_cache::prepare_launch(
            &root.path,
            &selection,
            runtime,
            platform,
            &runtime_holds_runner,
        ) {
            Ok(launch) => launch.variables,
            Err(error) => {
                tracing::warn!(
                    reason = "dependency_cache_unavailable",
                    "starting the runner without dependency caches: {error}"
                );
                Vec::new()
            }
        }
    }

    /// Measures the cache root and prunes it to the configured cap. `None`
    /// when caches are off, no root resolves or the root does not exist yet.
    #[must_use]
    pub fn prune_once(&self) -> Option<CacheUsage> {
        self.prune_guarded(true)
    }

    /// [`Self::prune_once`] for an operator's `host cache prune` that this
    /// service carries out on their behalf: it prunes whether or not caches
    /// are on, exactly as the command does when it can write the root itself.
    #[must_use]
    pub fn prune_on_request(&self) -> Option<CacheUsage> {
        self.prune_guarded(false)
    }

    fn prune_guarded(&self, only_when_enabled: bool) -> Option<CacheUsage> {
        if PRUNING.swap(true, Ordering::AcqRel) {
            return None;
        }
        let usage = self.prune_unguarded(only_when_enabled);
        PRUNING.store(false, Ordering::Release);
        usage
    }

    fn prune_unguarded(&self, only_when_enabled: bool) -> Option<CacheUsage> {
        let config = CacheConfig::load(&self.config_file).ok()?;
        if only_when_enabled && !config.host_enabled() {
            return None;
        }
        let root = self.root(&config).ok()?;
        if !root.path.is_dir() {
            return None;
        }
        match dependency_cache::prune(&root.path, config.max_bytes(), &runtime_holds_runner) {
            Ok(usage) => {
                if !usage.pruned.is_empty() {
                    tracing::info!(
                        reason = "dependency_cache_pruned",
                        "removed {} least-recently-used dependency cache namespace(s) to stay \
                         under the cap: {}",
                        usage.pruned.len(),
                        usage.pruned.join(", ")
                    );
                }
                if usage.max_bytes.is_some_and(|max| usage.total_bytes > max) {
                    tracing::warn!(
                        reason = "dependency_cache_over_cap",
                        "the dependency caches use {} against a cap of {}, and every remaining \
                         namespace is in use; raise it with `host cache set-max-size`",
                        dependency_cache::human_bytes(usage.total_bytes),
                        dependency_cache::human_bytes(usage.max_bytes.unwrap_or_default())
                    );
                }
                Some(usage)
            }
            Err(error) => {
                tracing::warn!(
                    reason = "dependency_cache_prune_failed",
                    "the dependency caches could not be pruned: {error}"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caches(dir: &Path, runner_root: Option<PathBuf>) -> DependencyCaches {
        DependencyCaches::new(
            dependency_cache::config_path_in(dir),
            Arc::new(move || runner_root.clone()),
            None,
        )
    }

    #[test]
    fn a_repository_launch_gets_variables_under_the_runner_roots_cache() {
        let dir = tempfile::tempdir().unwrap();
        let runner_root = dir.path().join("rman");
        let runtime = runner_root.join("a1b2c3d4");
        std::fs::create_dir_all(runtime.join("bin")).unwrap();
        let target = ScaleTarget::repository("Octo/Repo").unwrap();
        let variables = caches(dir.path(), Some(runner_root.clone())).for_launch(
            &target,
            &runtime,
            &RunnerEnv::default(),
        );
        let npm = variables
            .iter()
            .find(|(name, _)| *name == "npm_config_cache")
            .map(|(_, value)| PathBuf::from(value))
            .unwrap();
        assert_eq!(
            npm,
            runner_root
                .join("_cache")
                .join("octo")
                .join("repo")
                .join("npm")
        );
        assert!(npm.is_dir());
    }

    #[test]
    fn an_organization_a_disabled_host_or_a_broken_file_gets_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("a1");
        let none = RunnerEnv::default();
        let caches = caches(dir.path(), Some(dir.path().to_path_buf()));
        let org = ScaleTarget::organization("acme").unwrap();
        assert!(caches.for_launch(&org, &runtime, &none).is_empty());

        let path = dependency_cache::config_path_in(dir.path());
        std::fs::write(&path, "enabled = false\n").unwrap();
        let repo = ScaleTarget::repository("o/r").unwrap();
        assert!(caches.for_launch(&repo, &runtime, &none).is_empty());

        // `prepare` refuses a broken file before registration; one broken
        // after it costs the job its caches, not its runner.
        std::fs::write(&path, "[tools]\nnope = true\n").unwrap();
        assert!(caches.for_launch(&repo, &runtime, &none).is_empty());
        let failure = caches.config().unwrap_err().to_string();
        assert!(failure.contains("caches.toml"), "{failure}");
    }

    /// An operator's `runner.env` takes a whole tool, in any letter case.
    #[test]
    fn runner_env_takes_the_whole_tool_whatever_the_case() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("rman").join("a1");
        std::fs::create_dir_all(runtime.join("bin")).unwrap();
        let caches = caches(dir.path(), Some(dir.path().join("rman")));
        let repo = ScaleTarget::repository("o/r").unwrap();
        let host_env =
            RunnerEnv::parse("NPM_CONFIG_STORE_DIR=/operator/pnpm\nRUNNER_TOOL_CACHE=/tc\n")
                .unwrap();
        let names: Vec<&str> = caches
            .for_launch(&repo, &runtime, &host_env)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        for gone in [
            "npm_config_store_dir",
            "PNPM_CONFIG_STORE_DIR",
            "RUNNER_TOOL_CACHE",
            "AGENT_TOOLSDIRECTORY",
        ] {
            assert!(
                !names.contains(&gone),
                "{gone} was set beside the operator's"
            );
        }
        assert!(names.contains(&"npm_config_cache"));
    }

    #[test]
    fn no_root_means_no_caches_rather_than_no_runner() {
        let dir = tempfile::tempdir().unwrap();
        let caches = caches(dir.path(), Some(PathBuf::from("/has space/rman")));
        let repo = ScaleTarget::repository("o/r").unwrap();
        assert!(
            caches
                .for_launch(&repo, &dir.path().join("a"), &RunnerEnv::default())
                .is_empty()
        );
    }
}
