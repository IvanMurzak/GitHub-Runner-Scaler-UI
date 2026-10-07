//! Persistent dependency and tool caches for native runners.
//!
//! An ephemeral attempt starts in a fresh directory, and on Windows with a
//! fresh profile (`runner_env::platform_defaults`), so every tool cache a job
//! relies on starts empty: pnpm reinstalls its store, `setup-node` downloads
//! Node again into `_work/_tool`, NuGet restores every package from the
//! network. Worse, a cache under the attempt directory has a different absolute
//! path every job, and `actions/cache` hashes the paths into its key, so even an
//! explicit cache step never hits.
//!
//! This module gives each runner a set of environment variables that point
//! those tools at directories that outlive the attempt, without anything being
//! configured by hand on each machine.
//!
//! # Layout
//!
//! ```text
//! <cache root>/                  default <runner root>/_cache
//!   .lock                        LockKind::DependencyCache
//!   .usage.json                  the daemon's last measurement
//!   .trash/                      namespaces being deleted
//!   <owner>/<repo>/              a repository policy's namespace (lower case)
//!   _org/<org>/                  an organization policy's, when it opts in
//!   _shared/<name>/              a namespace policies share on purpose
//!     .last-used                 touched at every launch; the LRU clock
//!     npm/ pnpm-store/ nuget/ …  caches every runner of the namespace shares
//!     _slots/<n>.lease           which attempt holds slot n
//!     _slots/<n>/tool-cache/ …   caches one runner at a time may write
//! ```
//!
//! Owners and organizations on GitHub cannot start with `_`, so `_org` and
//! `_shared` never collide with a repository's namespace.
//!
//! # Trust model
//!
//! A cache is an input to the next job that reads it: a job that can write
//! `npm/` can plant a package the next job installs. So the default namespace
//! is one **repository**: every profile of `owner/repo` shares one, and no
//! other repository can read or write it. An organization policy accepts jobs
//! from every repository in the organization, so it gets no cache unless an
//! operator opts in, for the same reason it never gets a persistent workspace.
//! Two policies share a namespace only when an operator names the same
//! `_shared/<name>` for both. None of this is a defence against a hostile
//! workflow in the same repository; that is the model GitHub documents for
//! self-hosted runners.
//!
//! # Concurrency
//!
//! Concurrent runners of one policy share a namespace. Every cache marked
//! [`Sharing::Namespace`] in [`TOOLS`] is documented as safe for concurrent
//! processes (cacache, the pnpm store, NuGet with a shared scratch folder, the
//! Go caches, Yarn Berry, uv, Playwright's lock). The rest are
//! [`Sharing::Slot`]: each runner leases the lowest free slot of its namespace
//! and gets that slot's own directory. The `@actions/tool-cache` library is the
//! important one: `cacheDir` deletes a version's folder before copying into it,
//! with no lock, so two cold jobs filling the same Node version would delete
//! each other's toolchain.
//!
//! A lease is held while its attempt's runtime still holds the runner package
//! (`<runtime>/bin`), which is removed by the attempt's cleanup in both
//! workspace modes. A crashed daemon therefore keeps a lease for as long as the
//! attempt it belongs to is not cleaned, which is exactly as long as a runner
//! may still be using the slot.
//!
//! # Disk
//!
//! The daemon measures the root periodically and, over the cap, removes whole
//! namespaces in least-recently-used order, never one with a live lease. The
//! check is repeated under [`LockKind::DependencyCache`] immediately before
//! the namespace is renamed aside, and a launch takes its lease under the same
//! lock, so a prune cannot take a namespace a runner is about to use.
//!
//! # Precedence
//!
//! Platform defaults < these variables < `runner.env` < the per-attempt
//! `TMPDIR`/`TEMP`/`TMP`. A variable an operator sets in `runner.env` always
//! wins.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use runner_manager_domain::model::ScaleTarget;
use serde::{Deserialize, Serialize};

use crate::lock::{HostLock, LockKind};
use crate::paths::AppPaths;
use crate::runner_env::RunnerPlatform;

/// The configuration file's name inside the configuration directory.
pub const CONFIG_FILE: &str = "caches.toml";

/// The default cache root's name inside the host runner root.
pub const DEFAULT_ROOT_NAME: &str = "_cache";

/// The default cap on the whole cache root.
pub const DEFAULT_MAX_SIZE_GIB: u64 = 20;

/// How often the daemon measures and prunes.
pub const PRUNE_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// How long a launch or a prune waits for [`LockKind::DependencyCache`].
pub const LOCK_WAIT: Duration = Duration::from_secs(30);

/// The daemon's last measurement, inside the cache root.
pub const USAGE_FILE: &str = ".usage.json";

const TRASH_DIR: &str = ".trash";
const SLOTS_DIR: &str = "_slots";
const LEASE_EXTENSION: &str = "lease";
const LAST_USED_FILE: &str = ".last-used";
const ORG_PREFIX: &str = "_org";
const SHARED_PREFIX: &str = "_shared";
const GIB: u64 = 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

/// Which platforms a variable is set on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Platforms {
    pub windows: bool,
    pub macos: bool,
    pub linux: bool,
}

impl Platforms {
    pub const ALL: Self = Self {
        windows: true,
        macos: true,
        linux: true,
    };
    pub const UNIX: Self = Self {
        windows: false,
        macos: true,
        linux: true,
    };

    #[must_use]
    pub const fn includes(self, platform: RunnerPlatform) -> bool {
        match platform {
            RunnerPlatform::Windows => self.windows,
            RunnerPlatform::MacOs => self.macos,
            RunnerPlatform::Linux => self.linux,
        }
    }
}

/// Whether concurrent runners of one namespace share a cache directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sharing {
    /// One directory for every runner of the namespace: the tool is designed
    /// for concurrent processes.
    Namespace,
    /// One directory per leased slot: the tool is not, or is not known to be.
    Slot,
}

/// What a variable is set to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarValue {
    /// The tool's directory.
    Dir,
    /// A subdirectory of the tool's directory.
    Sub(&'static str),
    /// A fixed value.
    Literal(&'static str),
    /// A value with `{dir}` replaced by the tool's directory. The cache root
    /// never contains whitespace, so the result is one shell word.
    Template(&'static str),
}

/// One variable a tool reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheVariable {
    pub name: &'static str,
    pub value: VarValue,
    pub platforms: Platforms,
}

const fn all(name: &'static str, value: VarValue) -> CacheVariable {
    CacheVariable {
        name,
        value,
        platforms: Platforms::ALL,
    }
}

const fn unix(name: &'static str, value: VarValue) -> CacheVariable {
    CacheVariable {
        name,
        value,
        platforms: Platforms::UNIX,
    }
}

/// One tool, or one family of variables that is switched on and off together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTool {
    /// The name `host cache set-tool` and `caches.toml` use.
    pub id: &'static str,
    /// The directory under the namespace (or the slot) the variables point at.
    pub dir: &'static str,
    pub sharing: Sharing,
    /// Whether a host that says nothing about this tool gets it.
    pub default_enabled: bool,
    pub variables: &'static [CacheVariable],
    /// One line for `host cache show`: what it covers or why it is opt-in.
    pub note: &'static str,
}

impl CacheTool {
    /// The variables this tool sets on `platform`.
    pub fn variables_on(&self, platform: RunnerPlatform) -> impl Iterator<Item = &CacheVariable> {
        self.variables
            .iter()
            .filter(move |variable| variable.platforms.includes(platform))
    }

    /// Whether the tool sets anything on `platform`.
    #[must_use]
    pub fn applies_to(&self, platform: RunnerPlatform) -> bool {
        self.variables_on(platform).next().is_some()
    }
}

/// Every cache this module knows. Adding a tool is one entry.
///
/// Each variable name below was checked against the tool's own documentation
/// or source; `docs`-less choices are explained in `note`. The README carries
/// the same table with its sources.
pub const TOOLS: &[CacheTool] = &[
    CacheTool {
        id: "xdg",
        dir: "xdg",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[unix("XDG_CACHE_HOME", VarValue::Dir)],
        note: "catch-all for Unix tools that follow the XDG base directory specification; not set \
               on Windows, where pnpm, Bun and Deno would also move global state",
    },
    CacheTool {
        id: "tool-cache",
        dir: "tool-cache",
        sharing: Sharing::Slot,
        default_enabled: true,
        variables: &[
            all("RUNNER_TOOL_CACHE", VarValue::Dir),
            all("AGENT_TOOLSDIRECTORY", VarValue::Dir),
        ],
        note: "toolchains setup-node, setup-go and setup-java download; per slot because \
               @actions/tool-cache deletes a version's folder before filling it",
    },
    CacheTool {
        id: "dotnet",
        dir: "dotnet",
        sharing: Sharing::Slot,
        default_enabled: true,
        variables: &[all("DOTNET_INSTALL_DIR", VarValue::Dir)],
        note: "SDKs setup-dotnet installs; per slot because an install replaces the shared dotnet \
               host",
    },
    CacheTool {
        id: "npm",
        dir: "npm",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[all("npm_config_cache", VarValue::Dir)],
        note: "npm's cacache and npx",
    },
    CacheTool {
        id: "pnpm",
        dir: "pnpm-store",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[
            all("npm_config_store_dir", VarValue::Dir),
            all("PNPM_CONFIG_STORE_DIR", VarValue::Dir),
        ],
        note: "the content-addressed store: pnpm 9 and 10 read npm_config_store_dir, pnpm 11 and \
               later PNPM_CONFIG_STORE_DIR; npm 12 warns that store-dir is unknown",
    },
    CacheTool {
        id: "yarn",
        dir: "yarn",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[all("YARN_GLOBAL_FOLDER", VarValue::Dir)],
        note: "Yarn 2+ global cache; YARN_CACHE_FOLDER is left alone because it would override a \
               zero-install project's committed cache",
    },
    CacheTool {
        id: "bun",
        dir: "bun",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[all("BUN_INSTALL_CACHE_DIR", VarValue::Dir)],
        note: "Bun's package cache",
    },
    CacheTool {
        id: "deno",
        dir: "deno",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[all("DENO_DIR", VarValue::Dir)],
        note: "Deno's module and npm cache (it also keeps localStorage there)",
    },
    CacheTool {
        id: "node-gyp",
        dir: "node-gyp",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[
            all("npm_config_devdir", VarValue::Dir),
            all("npm_package_config_node_gyp_devdir", VarValue::Dir),
        ],
        note: "Node headers node-gyp downloads for native modules",
    },
    CacheTool {
        id: "electron",
        dir: "electron",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[
            // `electron`'s postinstall reads this exact lower-case name. On
            // Windows the name is case-insensitive and already covers
            // `ELECTRON_CACHE`, so that one is Unix-only.
            all("electron_config_cache", VarValue::Dir),
            unix("ELECTRON_CACHE", VarValue::Dir),
        ],
        note: "Electron release downloads",
    },
    CacheTool {
        id: "electron-builder",
        dir: "electron-builder",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[all("ELECTRON_BUILDER_CACHE", VarValue::Dir)],
        note: "NSIS, winCodeSign, AppImage and other packaging tools",
    },
    CacheTool {
        id: "playwright",
        dir: "ms-playwright",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[
            all("PLAYWRIGHT_BROWSERS_PATH", VarValue::Dir),
            // Install otherwise deletes every browser no live checkout links
            // to, and every earlier checkout is gone; pruning bounds the size.
            all("PLAYWRIGHT_SKIP_BROWSER_GC", VarValue::Literal("1")),
        ],
        note: "Playwright browsers",
    },
    CacheTool {
        id: "cypress",
        dir: "cypress",
        sharing: Sharing::Slot,
        default_enabled: true,
        variables: &[all("CYPRESS_CACHE_FOLDER", VarValue::Dir)],
        note: "Cypress binaries; per slot because cypress install takes no lock",
    },
    CacheTool {
        id: "nuget",
        dir: "nuget",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[
            all("NUGET_PACKAGES", VarValue::Sub("packages")),
            all("NUGET_HTTP_CACHE_PATH", VarValue::Sub("http-cache")),
            all("NUGET_PLUGINS_CACHE_PATH", VarValue::Sub("plugins-cache")),
            // NuGet's cross-process locks live in the scratch folder, which
            // defaults to the per-attempt temporary directory; processes must
            // share it to share the packages folder safely.
            all("NUGET_SCRATCH", VarValue::Sub("scratch")),
        ],
        note: "global packages and HTTP cache",
    },
    CacheTool {
        id: "pip",
        dir: "pip",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[all("PIP_CACHE_DIR", VarValue::Dir)],
        note: "pip's HTTP and wheel cache",
    },
    CacheTool {
        id: "uv",
        dir: "uv",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[all("UV_CACHE_DIR", VarValue::Dir)],
        note: "uv's cache",
    },
    CacheTool {
        id: "go",
        dir: "go",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[
            all("GOMODCACHE", VarValue::Sub("mod")),
            all("GOCACHE", VarValue::Sub("build")),
        ],
        note: "Go module and build caches",
    },
    CacheTool {
        id: "composer",
        dir: "composer",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[all("COMPOSER_CACHE_DIR", VarValue::Dir)],
        note: "Composer's download cache",
    },
    CacheTool {
        id: "cocoapods",
        dir: "cocoapods",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[unix("CP_CACHE_DIR", VarValue::Dir)],
        note: "CocoaPods download cache",
    },
    CacheTool {
        id: "ccache",
        dir: "ccache",
        sharing: Sharing::Namespace,
        default_enabled: true,
        variables: &[all("CCACHE_DIR", VarValue::Dir)],
        note: "ccache objects",
    },
    CacheTool {
        id: "poetry",
        dir: "poetry",
        sharing: Sharing::Slot,
        default_enabled: false,
        variables: &[all("POETRY_CACHE_DIR", VarValue::Dir)],
        note: "opt-in: Poetry also keeps virtualenvs in its cache directory, one per workspace path",
    },
    CacheTool {
        id: "cargo",
        dir: "cargo",
        sharing: Sharing::Namespace,
        default_enabled: false,
        variables: &[all("CARGO_HOME", VarValue::Dir)],
        note: "opt-in: CARGO_HOME also holds config, registry credentials and installed binaries",
    },
    CacheTool {
        id: "gradle",
        dir: "gradle",
        sharing: Sharing::Namespace,
        default_enabled: false,
        variables: &[all("GRADLE_USER_HOME", VarValue::Dir)],
        note: "opt-in: GRADLE_USER_HOME also holds gradle.properties, init scripts and daemons",
    },
    CacheTool {
        id: "maven",
        dir: "maven",
        sharing: Sharing::Slot,
        default_enabled: false,
        variables: &[all(
            "MAVEN_ARGS",
            VarValue::Template("-Dmaven.repo.local={dir}"),
        )],
        note: "opt-in: Maven 3.9+ local repository via MAVEN_ARGS, which a workflow's own \
               MAVEN_ARGS replaces",
    },
    CacheTool {
        id: "pub",
        dir: "pub",
        sharing: Sharing::Slot,
        default_enabled: false,
        variables: &[all("PUB_CACHE", VarValue::Dir)],
        note: "opt-in: PUB_CACHE also holds globally activated Dart tools",
    },
    CacheTool {
        id: "bundler",
        dir: "bundler",
        sharing: Sharing::Slot,
        default_enabled: false,
        variables: &[all("BUNDLE_USER_CACHE", VarValue::Dir)],
        note: "opt-in: Bundler's download cache",
    },
];

/// The tool named `id`.
#[must_use]
pub fn tool(id: &str) -> Option<&'static CacheTool> {
    TOOLS.iter().find(|tool| tool.id == id)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why the configuration could not be used, or a cache operation failed.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("{} is not valid TOML for caches: {message}", path.display())]
    Parse { path: PathBuf, message: String },
    #[error("`{0}` is not a cache this version knows; `host cache show` lists them")]
    UnknownTool(String),
    #[error(
        "`{0}` is not a valid shared namespace name; use 1 to 64 lower-case letters, digits, \
         `.`, `_` or `-`, not starting with `.`"
    )]
    InvalidNamespace(String),
    #[error("`{0}` is not a repository (OWNER/REPO) or an organization")]
    InvalidTarget(String),
    #[error("the cache root {0} must be an absolute path without spaces")]
    InvalidRoot(String),
    #[error("cannot {action} {}: {source}", path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{0}")]
    Lock(String),
}

fn io_error(action: &'static str, path: &Path) -> impl FnOnce(io::Error) -> CacheError + use<> {
    let path = path.to_path_buf();
    move |source| CacheError::Io {
        action,
        path,
        source,
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// `caches.toml`: what an operator changed from the defaults. Everything is
/// optional; an absent file is every default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// `false` turns caches off for every policy on this host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// The cache root, replacing `<runner root>/_cache`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// The cap on the whole root; `0` means no cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size_gib: Option<u64>,
    /// Tools switched on or off for every policy, by id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, bool>,
    /// Per-target settings, keyed by `owner/repo` or the organization, in
    /// lower case.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub targets: BTreeMap<String, TargetCacheConfig>,
}

/// One repository's or organization's settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCacheConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// A shared namespace name, instead of the target's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, bool>,
}

impl TargetCacheConfig {
    fn is_empty(&self) -> bool {
        self.enabled.is_none() && self.namespace.is_none() && self.tools.is_empty()
    }
}

/// The `caches.toml` path for a configuration directory.
#[must_use]
pub fn config_path_in(config_dir: &Path) -> PathBuf {
    config_dir.join(CONFIG_FILE)
}

/// The key a target's settings are stored under.
#[must_use]
pub fn target_key(target: &ScaleTarget) -> String {
    target.slug().to_ascii_lowercase()
}

impl CacheConfig {
    /// Parses and validates the file's text.
    ///
    /// # Errors
    /// Malformed TOML, an unknown key or tool, an invalid namespace, target or
    /// root.
    pub fn parse(text: &str, path: &Path) -> Result<Self, CacheError> {
        let config: Self = toml::from_str(text).map_err(|error| CacheError::Parse {
            path: path.to_path_buf(),
            message: error.message().to_owned(),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Reads `path`; a file that does not exist is every default.
    ///
    /// # Errors
    /// As [`Self::parse`], and [`CacheError::Io`] when it cannot be read.
    pub fn load(path: &Path) -> Result<Self, CacheError> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(CacheError::Io {
                action: "read",
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    fn validate(&self) -> Result<(), CacheError> {
        if let Some(root) = &self.root {
            validate_root_text(root)?;
        }
        let tool_ids = self
            .tools
            .keys()
            .chain(self.targets.values().flat_map(|target| target.tools.keys()));
        for id in tool_ids {
            if tool(id).is_none() {
                return Err(CacheError::UnknownTool(id.clone()));
            }
        }
        for (key, target) in &self.targets {
            ScaleTarget::repository(key)
                .or_else(|_| ScaleTarget::organization(key))
                .map_err(|_| CacheError::InvalidTarget(key.clone()))?;
            if let Some(name) = &target.namespace {
                validate_namespace_name(name)?;
            }
        }
        Ok(())
    }

    /// Writes the file atomically, after validating it, removing target
    /// sections that no longer say anything.
    ///
    /// # Errors
    /// [`CacheError::Io`], or a value that would not load back.
    pub fn save(&self, path: &Path) -> Result<(), CacheError> {
        let mut config = self.clone();
        config.targets.retain(|_, target| !target.is_empty());
        config.validate()?;
        let mut text = String::from(
            "# Dependency caches for native runners. Edited by `runner-manager host cache`,\n\
             # `repo cache` and `org cache`; see `host cache show`.\n",
        );
        text.push_str(
            &toml::to_string(&config).map_err(|error| CacheError::Parse {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?,
        );
        write_atomically(path, text.as_bytes())
    }

    /// The settings for `target`, if any.
    #[must_use]
    pub fn target(&self, target: &ScaleTarget) -> Option<&TargetCacheConfig> {
        self.targets.get(&target_key(target))
    }

    /// The settings for `target`, created empty if absent.
    pub fn target_mut(&mut self, target: &ScaleTarget) -> &mut TargetCacheConfig {
        self.targets.entry(target_key(target)).or_default()
    }

    /// The cap in bytes; `None` when there is none.
    #[must_use]
    pub fn max_bytes(&self) -> Option<u64> {
        match self.max_size_gib.unwrap_or(DEFAULT_MAX_SIZE_GIB) {
            0 => None,
            gib => Some(gib.saturating_mul(GIB)),
        }
    }

    /// Whether caches are on for this host at all.
    #[must_use]
    pub fn host_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(io_error("create the directory of", path))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(io_error("write", path))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(io_error("write", path))?;
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| CacheError::Io {
            action: "replace",
            path: path.to_path_buf(),
            source: error.error,
        })
}

/// A cache root an operator may configure: absolute and free of whitespace.
///
/// Whitespace is refused on every platform, not only where the default would
/// have one: a value such as `MAVEN_ARGS` is split on spaces, and unquoted
/// paths in tool installers break on them (actions/python-versions' setup
/// scripts are one).
///
/// # Errors
/// [`CacheError::InvalidRoot`].
pub fn validate_root_text(root: &str) -> Result<(), CacheError> {
    if root.chars().any(char::is_whitespace) || !Path::new(root).is_absolute() {
        return Err(CacheError::InvalidRoot(root.to_owned()));
    }
    Ok(())
}

/// A shared namespace name: a single, portable, lower-case path segment.
///
/// # Errors
/// [`CacheError::InvalidNamespace`].
pub fn validate_namespace_name(name: &str) -> Result<(), CacheError> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
        && !is_windows_device_name(name);
    if valid {
        Ok(())
    } else {
        Err(CacheError::InvalidNamespace(name.to_owned()))
    }
}

/// `CON`, `NUL`, `COM1` and the rest, which Windows will not create as a
/// directory whatever follows a dot.
fn is_windows_device_name(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
}

// ---------------------------------------------------------------------------
// Root resolution
// ---------------------------------------------------------------------------

/// Where the cache root came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootSource {
    /// `host cache set-root`.
    Configured,
    /// `<runner root>/_cache`.
    RunnerRoot,
    /// The runner root has whitespace in it, so a platform location stood in.
    PlatformFallback,
}

impl RootSource {
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::RunnerRoot => "runner-root",
            Self::PlatformFallback => "platform-fallback",
        }
    }
}

/// The resolved cache root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoot {
    pub path: PathBuf,
    pub source: RootSource,
}

/// The cache root for a host whose effective runner root is `runner_root`.
///
/// `fallback` is used when `<runner root>/_cache` would contain whitespace (the
/// macOS platform-default runner root does: `Application Support`); see
/// [`platform_fallback_root`]. `None` when nothing usable resolves, with the
/// reason.
///
/// # Errors
/// The sentence an operator reads about why there is no cache root.
pub fn resolve_root(
    config: &CacheConfig,
    runner_root: Option<&Path>,
    fallback: Option<PathBuf>,
) -> Result<ResolvedRoot, String> {
    if let Some(root) = &config.root {
        return Ok(ResolvedRoot {
            path: PathBuf::from(root),
            source: RootSource::Configured,
        });
    }
    let usable = |path: &Path| !path.to_string_lossy().chars().any(char::is_whitespace);
    if let Some(runner_root) = runner_root {
        let candidate = runner_root.join(DEFAULT_ROOT_NAME);
        if usable(&candidate) {
            return Ok(ResolvedRoot {
                path: candidate,
                source: RootSource::RunnerRoot,
            });
        }
    }
    match fallback.filter(|path| usable(path) && path.is_absolute()) {
        Some(path) => Ok(ResolvedRoot {
            path,
            source: RootSource::PlatformFallback,
        }),
        None => Err(
            "no cache root without spaces could be derived; set one with \
             `runner-manager host cache set-root --path <PATH>`"
                .to_owned(),
        ),
    }
}

/// The platform location used when the runner root has whitespace in it.
///
/// Windows: `<system drive>\rman\_cache`, short and inside the default runner
/// root, so one Defender exclusion covers both. macOS and Linux: this
/// account's cache directory (`~/Library/Caches`, `$XDG_CACHE_HOME`) plus
/// `runner-manager`, which is on the same volume as the default runner root.
#[must_use]
pub fn platform_fallback_root(app_paths: &AppPaths) -> Option<PathBuf> {
    if cfg!(windows) {
        crate::runner_root::default_runner_root(app_paths)
            .ok()
            .map(|root| root.as_path().join(DEFAULT_ROOT_NAME))
    } else {
        directories::BaseDirs::new().map(|dirs| dirs.cache_dir().join("runner-manager"))
    }
}

// ---------------------------------------------------------------------------
// Selection: what one target gets
// ---------------------------------------------------------------------------

/// Whose cache a runner uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Namespace {
    Repository { owner: String, repo: String },
    Organization(String),
    Shared(String),
}

impl Namespace {
    /// The target's own namespace.
    #[must_use]
    pub fn of(target: &ScaleTarget) -> Self {
        match target {
            ScaleTarget::Repository(repository) => Self::Repository {
                owner: repository.owner().to_ascii_lowercase(),
                repo: repository.repo().to_ascii_lowercase(),
            },
            ScaleTarget::Organization(org) => Self::Organization(org.as_str().to_ascii_lowercase()),
        }
    }

    /// The two path segments below the cache root.
    #[must_use]
    pub fn segments(&self) -> [String; 2] {
        match self {
            Self::Repository { owner, repo } => [segment(owner), segment(repo)],
            Self::Organization(org) => [ORG_PREFIX.to_owned(), segment(org)],
            Self::Shared(name) => [SHARED_PREFIX.to_owned(), segment(name)],
        }
    }

    /// The namespace's directory under `root`.
    #[must_use]
    pub fn dir(&self, root: &Path) -> PathBuf {
        let [first, second] = self.segments();
        root.join(first).join(second)
    }

    /// How an operator reads it: `owner/repo`, `_org/name`, `_shared/name`.
    #[must_use]
    pub fn label(&self) -> String {
        self.segments().join("/")
    }
}

/// One path segment, made safe for every platform. GitHub names already use
/// only letters, digits, `.`, `-` and `_`; a Windows device name gets a `_`.
fn segment(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = match cleaned.as_str() {
        "" | "." | ".." => format!("_{cleaned}"),
        _ => cleaned,
    };
    if is_windows_device_name(&cleaned) {
        format!("{cleaned}_")
    } else {
        cleaned
    }
}

/// Where one tool's on/off state came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSource {
    Default,
    Host,
    Target,
}

/// One tool's state for a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolState {
    pub tool: &'static CacheTool,
    pub enabled: bool,
    pub source: ToolSource,
}

/// What a target gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// `None` when caches are on; otherwise why not.
    pub disabled: Option<&'static str>,
    pub namespace: Namespace,
    /// Every tool that applies to the platform, on or off.
    pub tools: Vec<ToolState>,
}

impl Selection {
    /// The tools that are on.
    pub fn enabled_tools(&self) -> impl Iterator<Item = &'static CacheTool> + '_ {
        self.tools
            .iter()
            .filter(|state| state.enabled)
            .map(|state| state.tool)
    }
}

/// The reason an organization policy has no cache until an operator opts in.
pub const ORGANIZATION_OPT_IN: &str = "organization policies accept jobs from every repository \
     in the organization, so they get a cache only with `org cache set-enabled ORG --enabled \
     true`";

/// What `target` gets on `platform` under `config`. Host-wide tool settings
/// override the defaults and the target's override both.
#[must_use]
pub fn select(config: &CacheConfig, target: &ScaleTarget, platform: RunnerPlatform) -> Selection {
    let own = config.target(target);
    let namespace = own
        .and_then(|own| own.namespace.clone())
        .map_or_else(|| Namespace::of(target), Namespace::Shared);
    let disabled = if !config.host_enabled() {
        Some("caches are turned off on this host")
    } else {
        match (own.and_then(|own| own.enabled), target) {
            (Some(true), _) => None,
            (Some(false), _) => Some("caches are turned off for this target"),
            (None, ScaleTarget::Repository(_)) => None,
            (None, ScaleTarget::Organization(_)) => Some(ORGANIZATION_OPT_IN),
        }
    };
    let tools = TOOLS
        .iter()
        .filter(|tool| tool.applies_to(platform))
        .map(|tool| {
            let mut state = ToolState {
                tool,
                enabled: tool.default_enabled,
                source: ToolSource::Default,
            };
            if let Some(enabled) = config.tools.get(tool.id) {
                state.enabled = *enabled;
                state.source = ToolSource::Host;
            }
            if let Some(enabled) = own.and_then(|own| own.tools.get(tool.id)) {
                state.enabled = *enabled;
                state.source = ToolSource::Target;
            }
            state
        })
        .collect();
    Selection {
        disabled,
        namespace,
        tools,
    }
}

// ---------------------------------------------------------------------------
// The environment
// ---------------------------------------------------------------------------

/// The directory a tool uses: under the namespace, or under the slot.
#[must_use]
pub fn tool_dir(tool: &CacheTool, namespace_dir: &Path, slot_dir: &Path) -> PathBuf {
    match tool.sharing {
        Sharing::Namespace => namespace_dir.join(tool.dir),
        Sharing::Slot => slot_dir.join(tool.dir),
    }
}

/// One variable's value, and the directory it names if it names one.
fn render(variable: &CacheVariable, dir: &Path) -> (OsString, Option<PathBuf>) {
    match variable.value {
        VarValue::Dir => (dir.as_os_str().to_owned(), Some(dir.to_path_buf())),
        VarValue::Sub(sub) => {
            let path = dir.join(sub);
            (path.as_os_str().to_owned(), Some(path))
        }
        VarValue::Literal(value) => (OsString::from(value), None),
        VarValue::Template(template) => (
            OsString::from(template.replace("{dir}", &dir.to_string_lossy())),
            Some(dir.to_path_buf()),
        ),
    }
}

/// The variables `tools` set on `platform`, and the directories they name.
#[must_use]
pub fn environment<'a>(
    tools: impl IntoIterator<Item = &'a CacheTool>,
    namespace_dir: &Path,
    slot_dir: &Path,
    platform: RunnerPlatform,
) -> (Vec<(&'static str, OsString)>, Vec<PathBuf>) {
    let mut variables = Vec::new();
    let mut dirs = Vec::new();
    for tool in tools {
        let dir = tool_dir(tool, namespace_dir, slot_dir);
        for variable in tool.variables_on(platform) {
            let (value, named) = render(variable, &dir);
            variables.push((variable.name, value));
            dirs.extend(named);
        }
    }
    (variables, dirs)
}

// ---------------------------------------------------------------------------
// Launch: lease a slot, create the directories
// ---------------------------------------------------------------------------

/// Whether the attempt whose runtime is `runtime` may still be running a
/// runner: its runner package is still there. Cleanup removes it in both
/// workspace modes.
#[must_use]
pub fn runtime_holds_runner(runtime: &Path) -> bool {
    runtime.join("bin").is_dir()
}

/// What one launch gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchCaches {
    pub namespace_dir: PathBuf,
    pub slot: u32,
    pub variables: Vec<(&'static str, OsString)>,
}

fn lock_cache_root(root: &Path) -> Result<HostLock, CacheError> {
    HostLock::acquire_at(
        &root.join(LockKind::DependencyCache.file_name()),
        LockKind::DependencyCache,
        LOCK_WAIT,
    )
    .map_err(|error| CacheError::Lock(error.to_string()))
}

/// Leases a slot in `selection`'s namespace for the attempt at `runtime`,
/// creates every directory its variables name, and marks the namespace used.
///
/// `holds_runner` decides whether an existing lease is still held; production
/// passes [`runtime_holds_runner`].
///
/// # Errors
/// The lock could not be taken, or a directory or lease could not be written.
pub fn prepare_launch(
    root: &Path,
    selection: &Selection,
    runtime: &Path,
    platform: RunnerPlatform,
    holds_runner: &dyn Fn(&Path) -> bool,
) -> Result<LaunchCaches, CacheError> {
    fs::create_dir_all(root).map_err(io_error("create", root))?;
    let namespace_dir = selection.namespace.dir(root);
    let slots = namespace_dir.join(SLOTS_DIR);
    let slot = {
        let _lock = lock_cache_root(root)?;
        fs::create_dir_all(&slots).map_err(io_error("create", &slots))?;
        let slot = free_slot(&slots, runtime, holds_runner);
        let lease = slots.join(format!("{slot}.{LEASE_EXTENSION}"));
        fs::write(&lease, runtime.to_string_lossy().as_bytes())
            .map_err(io_error("write", &lease))?;
        let marker = namespace_dir.join(LAST_USED_FILE);
        fs::write(&marker, Utc::now().to_rfc3339().as_bytes())
            .map_err(io_error("write", &marker))?;
        slot
    };
    let slot_dir = slots.join(slot.to_string());
    let (variables, dirs) = environment(
        selection.enabled_tools(),
        &namespace_dir,
        &slot_dir,
        platform,
    );
    for dir in dirs {
        fs::create_dir_all(&dir).map_err(io_error("create", &dir))?;
    }
    Ok(LaunchCaches {
        namespace_dir,
        slot,
        variables,
    })
}

/// The lowest slot whose lease is absent, is this attempt's own, or belongs to
/// an attempt that no longer holds a runner.
fn free_slot(slots: &Path, runtime: &Path, holds_runner: &dyn Fn(&Path) -> bool) -> u32 {
    let own = runtime.to_string_lossy();
    (1..)
        .find(
            |slot| match fs::read_to_string(slots.join(format!("{slot}.{LEASE_EXTENSION}"))) {
                Err(_) => true,
                Ok(holder) => holder == own || !holds_runner(Path::new(&holder)),
            },
        )
        .expect("an unbounded range has a free slot")
}

/// Whether any lease in the namespace is still held.
fn namespace_in_use(namespace_dir: &Path, holds_runner: &dyn Fn(&Path) -> bool) -> bool {
    let Ok(entries) = fs::read_dir(namespace_dir.join(SLOTS_DIR)) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        path.extension().is_some_and(|ext| ext == LEASE_EXTENSION)
            && fs::read_to_string(&path).is_ok_and(|holder| holds_runner(Path::new(&holder)))
    })
}

// ---------------------------------------------------------------------------
// Measurement and pruning
// ---------------------------------------------------------------------------

/// One namespace's size and age.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceUsage {
    /// `owner/repo`, `_org/name` or `_shared/name`.
    pub name: String,
    pub bytes: u64,
    pub last_used: Option<DateTime<Utc>>,
    pub in_use: bool,
}

/// The whole root, as last measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheUsage {
    pub measured_at: DateTime<Utc>,
    pub total_bytes: u64,
    pub max_bytes: Option<u64>,
    pub namespaces: Vec<NamespaceUsage>,
    /// Namespaces this pass removed.
    pub pruned: Vec<String>,
}

impl CacheUsage {
    /// The daemon's last measurement of `root`, if it wrote one.
    #[must_use]
    pub fn read(root: &Path) -> Option<Self> {
        let bytes = fs::read(root.join(USAGE_FILE)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

/// The total size of the regular files under `path`, without following links.
fn tree_size(path: &Path) -> u64 {
    let mut total = 0_u64;
    let mut pending = vec![path.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    total
}

fn modified(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Every namespace directory under `root`: exactly two levels down, below a
/// first level that does not start with `.`.
fn namespace_dirs(root: &Path) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    let Ok(first) = fs::read_dir(root) else {
        return found;
    };
    for outer in first.flatten() {
        let outer_name = outer.file_name().to_string_lossy().into_owned();
        if outer_name.starts_with('.') || !outer.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(second) = fs::read_dir(outer.path()) else {
            continue;
        };
        for inner in second.flatten() {
            if inner.file_type().is_ok_and(|t| t.is_dir()) {
                let name = format!("{outer_name}/{}", inner.file_name().to_string_lossy());
                found.push((name, inner.path()));
            }
        }
    }
    found.sort();
    found
}

/// Measures every namespace under `root`.
#[must_use]
pub fn measure(root: &Path, holds_runner: &dyn Fn(&Path) -> bool) -> Vec<NamespaceUsage> {
    namespace_dirs(root)
        .into_iter()
        .map(|(name, dir)| NamespaceUsage {
            bytes: tree_size(&dir),
            last_used: modified(&dir.join(LAST_USED_FILE))
                .or_else(|| modified(&dir))
                .map(DateTime::<Utc>::from),
            in_use: namespace_in_use(&dir, holds_runner),
            name,
        })
        .collect()
}

/// Which namespaces to remove to bring the total within `max_bytes`: those
/// not in use, least recently used first, until the total fits. In-use
/// namespaces are never chosen, even if the total cannot fit without them.
#[must_use]
pub fn plan_prune(namespaces: &[NamespaceUsage], max_bytes: Option<u64>) -> Vec<String> {
    let Some(max) = max_bytes else {
        return Vec::new();
    };
    let mut total: u64 = namespaces.iter().map(|ns| ns.bytes).sum();
    let mut idle: Vec<&NamespaceUsage> = namespaces.iter().filter(|ns| !ns.in_use).collect();
    // Never-used (no marker, no mtime) sorts first: nothing can be relying on it.
    idle.sort_by(|a, b| a.last_used.cmp(&b.last_used).then(a.name.cmp(&b.name)));
    let mut chosen = Vec::new();
    for namespace in idle {
        if total <= max {
            break;
        }
        total = total.saturating_sub(namespace.bytes);
        chosen.push(namespace.name.clone());
    }
    chosen
}

/// Measures `root`, removes least-recently-used idle namespaces until it fits
/// under `max_bytes`, and records the result in [`USAGE_FILE`].
///
/// Each chosen namespace is re-checked under [`LockKind::DependencyCache`]
/// and renamed into `.trash` before anything is deleted, so a launch that
/// leased it after the measurement keeps it.
///
/// # Errors
/// The lock could not be taken or the usage file could not be written. A
/// namespace that cannot be moved or deleted is skipped, not an error.
pub fn prune(
    root: &Path,
    max_bytes: Option<u64>,
    holds_runner: &dyn Fn(&Path) -> bool,
) -> Result<CacheUsage, CacheError> {
    empty_trash(root);
    let mut namespaces = measure(root, holds_runner);
    let planned = plan_prune(&namespaces, max_bytes);
    let mut pruned = Vec::new();
    if !planned.is_empty() {
        let trash = root.join(TRASH_DIR);
        fs::create_dir_all(&trash).map_err(io_error("create", &trash))?;
        let _lock = lock_cache_root(root)?;
        for name in planned {
            let dir = root.join(&name);
            if namespace_in_use(&dir, holds_runner) {
                continue;
            }
            let aside = trash.join(uuid::Uuid::new_v4().simple().to_string());
            if fs::rename(&dir, &aside).is_ok() {
                pruned.push(name);
            }
        }
    }
    empty_trash(root);
    namespaces.retain(|ns| !pruned.contains(&ns.name));
    let usage = CacheUsage {
        measured_at: Utc::now(),
        total_bytes: namespaces.iter().map(|ns| ns.bytes).sum(),
        max_bytes,
        namespaces,
        pruned,
    };
    let json = serde_json::to_vec_pretty(&usage).map_err(|error| CacheError::Io {
        action: "encode",
        path: root.join(USAGE_FILE),
        source: io::Error::other(error),
    })?;
    write_atomically(&root.join(USAGE_FILE), &json)?;
    Ok(usage)
}

/// Deletes whatever is in `.trash`. Best effort: what cannot go now goes on a
/// later pass.
fn empty_trash(root: &Path) {
    let Ok(entries) = fs::read_dir(root.join(TRASH_DIR)) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        make_removable(&path);
        let _ = remove_dir_all::remove_dir_all(&path);
    }
}

/// Lets a tree be deleted by the account that owns it: Go makes its module
/// cache read-only, and a read-only directory keeps its entries on Unix, a
/// read-only file refuses deletion on Windows. Links are not followed.
fn make_removable(path: &Path) {
    let mut pending = vec![path.to_path_buf()];
    while let Some(current) = pending.pop() {
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        let mut permissions = metadata.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.is_dir() && permissions.mode() & 0o700 != 0o700 {
                permissions.set_mode(permissions.mode() | 0o700);
                let _ = fs::set_permissions(&current, permissions);
            }
        }
        #[cfg(not(unix))]
        if permissions.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            let _ = fs::set_permissions(&current, permissions);
        }
        if metadata.is_dir()
            && let Ok(entries) = fs::read_dir(&current)
        {
            pending.extend(entries.flatten().map(|entry| entry.path()));
        }
    }
}

/// Every tool id, for help text and errors.
#[must_use]
pub fn tool_ids() -> BTreeSet<&'static str> {
    TOOLS.iter().map(|tool| tool.id).collect()
}

/// A size for an operator: `1.5 GiB`, `320 MiB`.
#[must_use]
pub fn human_bytes(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let value = bytes as f64;
    if bytes >= GIB {
        format!("{:.1} GiB", value / GIB as f64)
    } else if bytes >= 1024 * 1024 {
        format!("{:.0} MiB", value / (1024.0 * 1024.0))
    } else {
        format!("{:.0} KiB", value / 1024.0)
    }
}

#[cfg(test)]
mod tests;
