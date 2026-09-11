// owner: b2-local-chain-runner
//
//! One case's isolated world, and the only road from a typed action to a
//! process.
//!
//! # What a scenario owns
//!
//! A temporary directory laid out as `03-coverage-model.md` and
//! [`crate::cli_chains::values::PathValue`] require:
//!
//! ```text
//! <scenario>/data   --data-dir; created by the binary on its first run
//! <scenario>/roots  scratch runner roots; holds only occupied.txt at the start
//! <scenario>/cwd    the child's working directory; must stay empty
//! ```
//!
//! plus a loopback [`FakeGithub`] answering for the case's installation
//! fixture, and a service fixture tag unique to the case. `<roots>` does not
//! contain `<data>` and neither is a filesystem root, which is the precondition
//! the model's path values are written against.
//!
//! # The allowlist is kept all the way to the process
//!
//! [`Scenario::run_action`] takes an [`Action`], never a string, and the
//! argument vector is [`Action::argv`] -- a `match` over the typed grammar --
//! prefixed with `--data-dir`. There is no other way into [`Scenario::invoke`]
//! from outside this module. Every invocation also goes through
//! [`support::runner_manager_against`], so the wrapper's removal of every
//! `RUNNER_MANAGER_*`, `RUST_LOG` and proxy variable is retained, and the child
//! gets `NO_PROXY` for the loopback fixture.
//!
//! # Seeds go through public interfaces
//!
//! A [`Seed`] is a state the daemon or another process would produce. It is
//! applied here, in-process, through the public [`Store`] trait and the rooted
//! [`PlatformSecretStore`] -- never through a command, and never by writing
//! SQL -- so the database the next process opens is one the product's own
//! types wrote.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use runner_manager_domain::attempt::{AttemptOutcome, AttemptState, FailureReason};
use runner_manager_domain::model::{AttemptId, ScaleTarget, StartMode};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::{SqliteStore, Store};
use runner_manager_platform::secrets::{PlatformSecretStore, SecretScope, SecretStore};
use runner_manager_testkit::fixtures;
use secrecy::SecretString;

use crate::cli_chains::action::{Action, AttemptKind, Seed, Target, TargetKey};
use crate::cli_chains::ids::CaseId;
use crate::cli_chains::model::Installation;
use crate::cli_chains::values::{Anchor, PathValue, Resolver, Scope};
use crate::support::{self, FakeGithub};

/// The variable `runner-manager` reads its service fixture tag from.
///
/// Restated rather than imported: the binary has no library target, and the
/// value is part of the published test seam `support::runner_manager` already
/// relies on.
pub const SERVICE_TAG_VARIABLE: &str = "RUNNER_MANAGER_SERVICE_NAME_TAG";

/// The database the binary keeps under `<data>/config/`.
pub const DATABASE: [&str; 2] = ["config", "runner-manager.sqlite3"];

/// How long one command may take before the runner gives up on it.
///
/// Generous on purpose: this is a hang detector, not a performance oracle.
/// `02-target-architecture.md` forbids using wall-clock time as a correctness
/// signal; a command that is merely slow still finishes and is judged on what
/// it did.
pub const INVOCATION_TIMEOUT: Duration = Duration::from_secs(120);

/// The contents `<roots>/occupied.txt` is created with, so a command that
/// overwrote the file is caught as surely as one that removed it.
pub const OCCUPIED_CONTENTS: &str = "an existing file, not a directory\n";

/// This machine's segments of the derived label `rm-<host>-<os>-<arch>`.
///
/// Stated from `std::env::consts` and the published token spellings rather
/// than asked of the product, for the reason `cli_chains/values.rs` gives: an
/// oracle that asks the code under test for the right answer cannot catch it
/// being wrong.
#[must_use]
pub fn platform_tokens() -> (&'static str, &'static str) {
    let os = match std::env::consts::OS {
        "windows" => "win",
        "macos" => "osx",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "arm" => "arm",
        other => other,
    };
    (os, arch)
}

/// Resolves the model's two platform-dependent values against one scenario.
#[derive(Debug, Clone)]
pub struct RealResolver {
    pub data: PathBuf,
    pub roots: PathBuf,
    pub os: &'static str,
    pub arch: &'static str,
}

impl RealResolver {
    /// The absolute path a path value names, or `None` for the relative one.
    #[must_use]
    pub fn absolute(&self, value: PathValue) -> Option<PathBuf> {
        let (anchor, parts) = value.location()?;
        let mut path = match anchor {
            Anchor::Roots => self.roots.clone(),
            Anchor::Data => self.data.clone(),
        };
        for part in parts {
            path.push(part);
        }
        Some(path)
    }

    /// Which path value a path the product reports names, if any.
    ///
    /// Compared lexically first and then through the filesystem, because the
    /// product stores a root as written and the temporary directory may be
    /// reached through a symlink or an 8.3 short name.
    #[must_use]
    pub fn identify(&self, reported: &str) -> Option<PathValue> {
        PathValue::ALL.into_iter().find(|value| {
            self.absolute(*value)
                .is_some_and(|expected| same_path(&expected, Path::new(reported)))
        })
    }

    /// Replaces this machine's real derived-label suffix with the model's
    /// placeholders, so an observed label compares with a symbolic one.
    #[must_use]
    pub fn symbolic_label(&self, label: &str) -> String {
        let suffix = format!("-{}-{}", self.os, self.arch);
        match label.strip_suffix(&suffix) {
            Some(stem) if stem.starts_with("rm-") => format!("{stem}-<os>-<arch>"),
            _ => label.to_string(),
        }
    }

    /// Resolves the placeholders a model fragment may carry.
    #[must_use]
    pub fn resolve_text(&self, text: &str) -> String {
        text.replace("<os>", self.os)
            .replace("<arch>", self.arch)
            .replace("<OS>", &self.os.to_ascii_uppercase())
            .replace("<ARCH>", &self.arch.to_ascii_uppercase())
            .replace("<roots>", &self.roots.to_string_lossy())
            .replace("<data>", &self.data.to_string_lossy())
    }
}

impl Resolver for RealResolver {
    fn path(&self, value: PathValue) -> String {
        self.absolute(value).map_or_else(
            || value.symbolic(),
            |path| path.to_string_lossy().into_owned(),
        )
    }

    fn derived_label(&self, host_label: &str) -> String {
        format!("rm-{host_label}-{}-{}", self.os, self.arch)
    }
}

/// Whether two paths name the same location: equal as written, or equal once
/// both are resolved through the filesystem.
#[must_use]
pub fn same_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// What one process did.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// The complete argument vector after the program name.
    pub argv: Vec<String>,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    /// The requests the fake GitHub answered while this process ran, in order.
    pub requests: Vec<String>,
    /// Measured for the suite summary only; never compared.
    pub elapsed: Duration,
}

/// One case's isolated world.
pub struct Scenario {
    /// Kept alive for the scenario's lifetime; removed on drop.
    _temporary: tempfile::TempDir,
    /// The scenario directory, resolved through any symlink on Unix.
    pub root: PathBuf,
    pub data: PathBuf,
    pub roots: PathBuf,
    pub cwd: PathBuf,
    pub github: FakeGithub,
    pub installation: Installation,
    /// The service fixture tag every process of this case carries.
    pub tag: String,
    pub resolver: RealResolver,
}

impl Scenario {
    /// Builds the directories and the fake GitHub for one case.
    ///
    /// # Panics
    /// If the temporary directory or the scratch file cannot be created, which
    /// makes the case meaningless rather than failing.
    #[must_use]
    pub fn new(case: CaseId, installation: Installation) -> Self {
        let temporary = tempfile::Builder::new()
            .prefix(&format!("clichains-{case}-"))
            .tempdir()
            .expect("a temporary scenario directory");
        // macOS hands out `/var/folders/...`, which is a symlink to
        // `/private/var/...`. Resolving it once here means the paths the
        // model's path values resolve to are the ones the product's canonical
        // comparisons see. Windows keeps the path as given: `canonicalize`
        // would add a `\\?\` prefix no operator would type.
        let root = if cfg!(windows) {
            temporary.path().to_path_buf()
        } else {
            std::fs::canonicalize(temporary.path()).expect("the scenario directory resolves")
        };
        let data = root.join("data");
        let roots = root.join("roots");
        let cwd = root.join("cwd");
        std::fs::create_dir(&roots).expect("the scratch roots directory");
        std::fs::write(roots.join("occupied.txt"), OCCUPIED_CONTENTS)
            .expect("the scratch occupied file");
        std::fs::create_dir(&cwd).expect("the child working directory");

        let github = FakeGithub::start();
        github.with_device_code().with_approval();
        let specs = installation.specs();
        if specs.is_empty() {
            github.with_no_installations();
        } else {
            let repositories: Vec<Vec<&str>> = specs
                .iter()
                .map(|spec| spec.repositories.iter().map(String::as_str).collect())
                .collect();
            let listed: Vec<support::Installation<'_>> = specs
                .iter()
                .zip(&repositories)
                .map(|(spec, repositories)| support::Installation {
                    id: spec.id,
                    account: spec.account,
                    account_type: "Organization",
                    selection: "selected",
                    repositories,
                })
                .collect();
            github.with_installations(&listed);
        }

        let tag = format!("clichains-{case}-{}", std::process::id());
        let (os, arch) = platform_tokens();
        Self {
            _temporary: temporary,
            resolver: RealResolver {
                data: data.clone(),
                roots: roots.clone(),
                os,
                arch,
            },
            root,
            data,
            roots,
            cwd,
            github,
            installation,
            tag,
        }
    }

    /// Runs one typed action as a fresh `runner-manager` process.
    pub fn run_action(&self, action: &Action) -> Invocation {
        self.invoke(&action.argv(&self.resolver))
    }

    /// Starts the binary. Private: the only caller is [`Self::run_action`], so
    /// no text that did not come from [`Action::argv`] can reach a process.
    fn invoke(&self, arguments: &[String]) -> Invocation {
        let mut command = support::runner_manager_against(&self.data, &self.github);
        // One tag per case, overriding the wrapper's per-invocation one: the
        // whole chain addresses one fixture registration, which is what makes
        // "no process of this case named the product's service" a single fact.
        command.env(SERVICE_TAG_VARIABLE, &self.tag);
        command.current_dir(&self.cwd);
        command.timeout(INVOCATION_TIMEOUT);
        command.args(arguments);
        let already_seen = self.github.seen().len();
        let started = Instant::now();
        let outcome = support::run(command);
        let elapsed = started.elapsed();
        let requests = self.github.seen().split_off(already_seen);
        let mut argv = vec![
            "--data-dir".to_string(),
            self.data.to_string_lossy().into_owned(),
        ];
        argv.extend(arguments.iter().cloned());
        Invocation {
            argv,
            code: outcome.code,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
            requests,
            elapsed,
        }
    }

    /// The database path.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        let mut path = self.data.clone();
        for part in DATABASE {
            path.push(part);
        }
        path
    }

    /// Opens the scenario's database, if a command has created it.
    ///
    /// # Errors
    /// When the file exists and cannot be opened.
    pub fn store(&self) -> Result<Option<SqliteStore>, String> {
        let path = self.database_path();
        if !path.exists() {
            return Ok(None);
        }
        SqliteStore::open(&path)
            .map(Some)
            .map_err(|error| format!("cannot open {}: {error}", path.display()))
    }

    /// The start mode recorded for this host, which decides the store scope.
    ///
    /// # Errors
    /// When the database cannot be read.
    pub fn recorded_start_mode(&self) -> Result<StartMode, String> {
        let Some(store) = self.store()? else {
            return Ok(StartMode::default());
        };
        let hosts = store
            .hosts()
            .map_err(|error| format!("cannot read hosts: {error}"))?;
        Ok(hosts
            .first()
            .map_or_else(StartMode::default, |host| host.service_start_mode))
    }

    /// The secret store the binary would open for this data root.
    ///
    /// # Errors
    /// When the start mode cannot be read or the store cannot be resolved.
    pub fn secret_store(&self) -> Result<PlatformSecretStore, String> {
        let scope = SecretScope::for_start_mode(self.recorded_start_mode()?);
        PlatformSecretStore::rooted_at(scope, &self.data)
            .map_err(|error| format!("cannot resolve the rooted secret store: {error}"))
    }

    /// Applies a seeded fact through public interfaces.
    ///
    /// # Errors
    /// When the store refuses, or the policy the seed addresses is missing.
    pub fn apply_seed(&self, seed: &Seed) -> Result<(), String> {
        match seed {
            Seed::Credential => {
                // The shape `auth login` writes: the credential document, not
                // a bare token, so the next process reads exactly what a
                // completed sign-in would have left.
                let document = format!(r#"{{"access_token":"{}"}}"#, support::fixture_token());
                self.secret_store()?
                    .store(&SecretString::from(document))
                    .map_err(|error| format!("cannot seed the credential: {error}"))
            }
            Seed::Attempt { target, kind } => {
                let store = self.require_store()?;
                let policy = policy_for(&store, *target)?;
                let state = match kind {
                    AttemptKind::Active => AttemptState::Busy,
                    AttemptKind::AwaitingCleanup => AttemptState::Failed,
                    AttemptKind::Cleaned => AttemptState::Cleaned,
                };
                let mut builder = fixtures::attempt()
                    .id(AttemptId::new_random())
                    .policy_id(policy.id)
                    .state(state);
                match kind {
                    AttemptKind::Active => {
                        builder = builder.github_runner_id(73).process_id(4242);
                    }
                    AttemptKind::AwaitingCleanup | AttemptKind::Cleaned => {
                        builder = builder
                            .outcome(AttemptOutcome::failed(FailureReason::ProcessStartFailed));
                    }
                }
                store
                    .record_attempt(&builder.build())
                    .map_err(|error| format!("cannot journal the seeded attempt: {error}"))
            }
            Seed::RepairRequired(target) => {
                let store = self.require_store()?;
                let mut policy = policy_for(&store, *target)?;
                let expected = policy.revision();
                policy
                    .repair_required()
                    .map_err(|error| format!("cannot mark repair_required: {error}"))?;
                store
                    .update_policy(&policy, expected)
                    .map_err(|error| format!("cannot store repair_required: {error}"))
            }
            Seed::Drain(target) => {
                let store = self.require_store()?;
                let mut policy = policy_for(&store, *target)?;
                let expected = policy.revision();
                policy
                    .request_disable()
                    .map_err(|error| format!("cannot start a drain: {error}"))?;
                store
                    .update_policy(&policy, expected)
                    .map_err(|error| format!("cannot store the drain: {error}"))
            }
            Seed::PackageCache => {
                let cache = self.data.join("state").join("packages");
                std::fs::create_dir_all(&cache)
                    .and_then(|()| std::fs::write(cache.join("seeded-package.marker"), "seed\n"))
                    .map_err(|error| format!("cannot seed the package cache: {error}"))
            }
        }
    }

    fn require_store(&self) -> Result<SqliteStore, String> {
        self.store()?
            .ok_or_else(|| "a seed needs a policy, but no database exists yet".to_string())
    }
}

/// The stored policy a target names.
///
/// # Errors
/// When the target is not a valid spelling or no policy for it is stored.
pub fn policy_for(store: &dyn Store, target: Target) -> Result<ScalePolicy, String> {
    let key = target
        .key()
        .ok_or_else(|| format!("{} is not a valid target", target.token()))?;
    let policies = store
        .policies()
        .map_err(|error| format!("cannot read policies: {error}"))?;
    policies
        .into_iter()
        .find(|policy| key_of(&policy.target) == key)
        .ok_or_else(|| format!("no stored policy for {key}"))
}

/// The model's identity for a stored target: scope plus case-folded slug.
#[must_use]
pub fn key_of(target: &ScaleTarget) -> TargetKey {
    let scope = match target {
        ScaleTarget::Repository(_) => Scope::Repository,
        ScaleTarget::Organization(_) => Scope::Organization,
    };
    TargetKey {
        scope,
        slug: target.slug().to_ascii_lowercase(),
    }
}
