// owner: f1-cli-auth-host-status
//
// f1 owns this module list and `dispatch`, plus `auth`, `host` and `status`;
// f2 owns `policy`; f3 owns `daemon` and `service`.

//! The command tree, the exit-code taxonomy, and the composition root.
//!
//! # The command surface is declared whole, here, once
//!
//! `02-target-architecture.md` lists the binary's commands and says *"This list
//! is exhaustive"*. All of it is declared in this file — including the `repo`,
//! `org`, `daemon` and `service` families that `f2` and `f3` implement — so that
//! those tasks attach handlers to a shape that already exists rather than
//! growing the surface one task at a time. A command that appears only when its
//! implementer arrives is a command nobody can write a script against, and
//! `--help` is the thing an operator reads before deciding whether this tool
//! does what they need.
//!
//! The unimplemented arms return [`Failure::NotImplemented`] and name the task
//! that owns them. That is deliberately a *distinct* exit code: a script that
//! runs `repo add` today must be able to tell "this build cannot do that yet"
//! from "your arguments were wrong".
//!
//! # Exit codes are a scripting contract
//!
//! `f1`, `f2` and `f3` all require *"distinct exit codes per failure class"*, so
//! the taxonomy lives here rather than in each command file. [`Failure`] is the
//! whole of it; `the_exit_codes_are_distinct_and_non_zero` in the tests below is
//! what keeps two classes from quietly collapsing onto one number.
//!
//! # What the composition root actually composes
//!
//! [`Context`] resolves — once, at the top — the four things every command below
//! needs and none of them may resolve for itself:
//!
//! | Thing | Where it comes from | Why it is here |
//! |---|---|---|
//! | [`AppPaths`] | `d1` | Two resolutions in one process must agree |
//! | the SQLite [`Store`] | `b2` | Its path is `config/`, which only `AppPaths` knows |
//! | the [`SecretStore`] | `d2` | Its *scope* follows the host's start mode (D13) |
//! | [`Endpoints`] + [`AppRegistration`] | `c2` | The published App is a product fact, not a per-command one |

pub mod auth;
pub mod daemon;
pub mod host;
pub mod policy;
pub mod service;
pub mod status;

use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use runner_manager_domain::model::{Clock, Host, StartMode, SystemClock};
use runner_manager_domain::store::{SqliteStore, Store};
use runner_manager_github::{AppRegistration, Endpoints};
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::secrets::{PlatformSecretStore, SecretScope};

// ---------------------------------------------------------------------------
// The published App
// ---------------------------------------------------------------------------

/// The published GitHub App's OAuth client id.
///
/// **Empty on purpose, and it must stay empty until the App is registered.**
/// Registering and publishing the App is Phase 0 of `06-migration-rollout.md`
/// and has not happened. `crates/github` declines to compile a placeholder in
/// for the same reason and hands the choice here:
///
/// > "Committing a placeholder that looked real would be worse than requiring
/// > the caller to pass one."
///
/// A plausible-looking constant would produce a device flow that fails against
/// GitHub with `incorrect_client_credentials` — a message that reads like a
/// GitHub outage rather than like an unfinished rollout. Empty produces
/// [`Failure::AppNotPublished`], which says exactly what is wrong.
pub const PUBLISHED_CLIENT_ID: &str = "";

/// The published App's slug, the `<slug>` in
/// `github.com/apps/<slug>/installations/new`. Empty for
/// [`PUBLISHED_CLIENT_ID`]'s reason.
pub const PUBLISHED_APP_SLUG: &str = "";

/// Overrides the client id, for a test that drives a fake GitHub.
pub const CLIENT_ID_VARIABLE: &str = "RUNNER_MANAGER_GITHUB_CLIENT_ID";
/// Overrides the App slug, for a test that drives a fake GitHub.
pub const APP_SLUG_VARIABLE: &str = "RUNNER_MANAGER_GITHUB_APP_SLUG";

/// Points every GitHub endpoint at another origin.
///
/// # This is a test seam and it is restricted to loopback
///
/// The device flow ends with a bearer token being handed to whatever answered
/// the access-token request, so an environment variable that could redirect
/// `github.com` to an arbitrary host would be a credential-harvesting primitive
/// aimed at whoever runs `auth login` next. [`Context::resolve_endpoints`]
/// therefore accepts **only** a loopback origin, and says loudly on stderr that
/// it is not talking to GitHub.
///
/// It exists because there is no other way to exercise `auth login` end to end:
/// `crates/app` has no HTTP mocking dev-dependency and may not acquire one
/// (`a1` owns every manifest), and `DeviceFlow` is a concrete type with no
/// gateway trait. The alternative was to leave the whole authentication path
/// untested against the real client.
pub const GITHUB_BASE_URL_VARIABLE: &str = "RUNNER_MANAGER_GITHUB_BASE_URL";

/// The file the local SQLite database lives in, under `config/`.
///
/// `05-infrastructure.md` puts *"non-secret TOML and SQLite"* in `config/`;
/// this is the SQLite half. Named rather than inlined because `f2`, `f3` and
/// `g1` all reach the same database through [`Context::store`] and a second
/// spelling would be a second database.
pub const DATABASE_FILE: &str = "runner-manager.sqlite3";

/// Where `--data-dir` can also be given.
pub const DATA_DIR_VARIABLE: &str = "RUNNER_MANAGER_DATA_DIR";

/// The default `host_capacity` for a host record this tool creates.
///
/// **One, chosen rather than inferred.** `f1`'s specification is explicit that
/// a capacity value *"comes from an observed workload measurement"* and must
/// never be derived from a runner count, so the only honest default is the most
/// conservative non-zero one: this host will start at most one runner attempt
/// until its operator says otherwise. `03-control-flows.md` step 2 assumes
/// exactly this shape — *"runs `host set-capacity 2` if the host default is not
/// acceptable"*.
pub const DEFAULT_HOST_CAPACITY: u16 = 1;

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// One number per failure class, for a script to branch on.
///
/// `2` is absent because clap owns it: a usage error exits `2` before any of
/// this runs, and re-using it for a runtime failure would make the two
/// indistinguishable to the caller. `1` is [`Failure::Unclassified`] and is the
/// bucket a failure lands in when it has not been classified — a value worth
/// having precisely so that "we forgot to classify this" is visible rather than
/// disguised as one of the named classes.
//
// ----------------------------------------------------------------------------
// THE TAXONOMY IS DECLARED ONCE AND EVERYTHING IS DERIVED FROM THAT DECLARATION.
// ----------------------------------------------------------------------------
// `Failure::ALL` used to be a hand-maintained array typed `[Failure; 19]`,
// parallel to the enum rather than derived from it. That is a real hole and not
// a stylistic one: adding a variant forces an edit to `as_str`'s exhaustive
// match — the compiler sees to that — but nothing forced an edit to `ALL`, so a
// new class was invisible to every test that iterates it.
//
// Worth being exact about which half rustc already covers, because the two are
// easy to conflate. A *duplicate* discriminant is a compile error either way:
// this is a `#[repr(u8)]` enum with an explicit value on every variant, so
// `RateLimited = 4` beside `AuthenticationFailed = 4` is E0081 and never
// reaches a test. What rustc does not catch is a class on a *fresh* value that
// is nonetheless wrong — `RateLimited = 2`, on the code clap already owns for a
// usage error. Under the old shape that compiled, `ALL` stayed at nineteen,
// `the_exit_codes_are_distinct_and_non_zero` never iterated the new class, and
// the whole suite passed: measured, 39 passed / 0 failed. Under this shape the
// same edit fails that test on `assert_ne!(class.code(), 2)`. The Definition of
// Done reads "every command returns a distinct non-zero exit code per failure
// class", and that is the gap it was leaving open.
//
// Rust cannot enumerate an enum's variants without a macro or a derive, and no
// derive crate is available here (`a1` owns every manifest). So the list below
// is the *only* place a class is written down: the enum, `ALL`, and `as_str`
// are all expanded from it. Adding a class to the enum without adding it to
// `ALL` is no longer something a person can do — there is one list, and it
// feeds all three.
//
// `dead_code` is allowed for the same reason the command tree above is declared
// whole: the taxonomy is a scripting contract, and the classes `f2` and `f3`
// will raise (`NotFound`, `Conflict`, `BudgetRefused`) have to hold their
// numbers before those tasks land, or the numbers move under a script that was
// already written against them. This crate is a `[[bin]]`, so an unused `pub`
// item is dead code rather than public API.
macro_rules! failure_taxonomy {
    (
        $(
            $(#[$documentation:meta])*
            $variant:ident = $code:literal => $name:literal,
        )+
    ) => {
        #[allow(dead_code)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum Failure {
            $(
                $(#[$documentation])*
                $variant = $code,
            )+
        }

        impl Failure {
            /// Every class, expanded from the same declaration as the enum, so
            /// it cannot fall behind it.
            #[allow(
                dead_code,
                reason = "read by the distinctness proof in this file's tests"
            )]
            pub const ALL: &'static [Failure] = &[$(Failure::$variant,)+];

            /// The stable name a `--json` document and a log field use.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }
        }
    };
}

failure_taxonomy! {
    /// Something went wrong that this taxonomy does not name yet.
    Unclassified = 1 => "unclassified",
    /// No credential is stored on this host. Remedy: `auth login`.
    NotAuthenticated = 3 => "not_authenticated",
    /// GitHub rejected the stored credential. Remedy: `auth login`.
    AuthenticationFailed = 4 => "authentication_failed",
    /// GitHub's temporary authentication lockout. Remedy: wait.
    AuthenticationLockout = 5 => "authentication_lockout",
    /// The user declined the login on GitHub. **Not** a case to retry: the same
    /// login presented again re-prompts somebody who has already said no.
    AuthenticationDeclined = 6 => "authentication_declined",
    /// GitHub could not be reached at all.
    GithubUnavailable = 7 => "github_unavailable",
    /// GitHub answered, refusing on rate-limit or permission grounds.
    GithubRefused = 8 => "github_refused",
    /// An argument was well-formed for clap and wrong for the domain.
    InvalidArgument = 9 => "invalid_argument",
    /// The thing named does not exist locally.
    NotFound = 10 => "not_found",
    /// A concurrent change, a duplicate, or a held lock.
    Conflict = 11 => "conflict",
    /// The projected REST budget will not admit this configuration.
    BudgetRefused = 12 => "budget_refused",
    /// The machine-scoped secret store could not be reached.
    SecretStore = 13 => "secret_store",
    /// Local configuration or the SQLite journal could not be read or written.
    LocalState = 14 => "local_state",
    /// This host's OS or architecture is outside GitHub's documented matrix.
    UnsupportedHost = 15 => "unsupported_host",
    /// This build carries no published GitHub App registration.
    AppNotPublished = 16 => "app_not_published",
    /// A declared command whose implementing task has not landed.
    NotImplemented = 17 => "not_implemented",
    /// The device code expired, or GitHub stopped recognising it. Unlike
    /// [`Failure::AuthenticationDeclined`], starting a fresh login is the right
    /// response and a script may do it unattended.
    AuthenticationExpired = 18 => "authentication_expired",
    /// GitHub says the published App itself is wrong — device flow not
    /// enabled, or a `client_id` it does not know. No operator action helps;
    /// a maintainer must fix the registration.
    AppMisconfigured = 19 => "app_misconfigured",
    /// GitHub's answer could not be used: it did not decode, it carried a value
    /// this client cannot accept, or — the security case — it pointed the login
    /// at a verification page that is not GitHub's own.
    UnusableResponse = 20 => "unusable_response",
}

impl Failure {
    /// The process exit code for this class.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A failure with the two things an operator needs: what happened, and the
/// command that fixes it.
///
/// `f1`: *"Every failure explains itself in one screenful, without exposing
/// credentials, and names the command that fixes it."* The `remedy` field is
/// that last clause made structural — a failure constructed without one is
/// visible in the source rather than only in the rendered output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    class: Failure,
    message: String,
    remedy: Option<String>,
}

impl CliError {
    /// A failure whose remedy is not a command this tool offers.
    #[must_use]
    pub fn new(class: Failure, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
            remedy: None,
        }
    }

    /// A failure and the command that clears it.
    #[must_use]
    pub fn with_remedy(
        class: Failure,
        message: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self {
            class,
            message: message.into(),
            remedy: Some(remedy.into()),
        }
    }

    #[must_use]
    pub const fn class(&self) -> Failure {
        self.class
    }

    #[must_use]
    #[allow(dead_code, reason = "read by the failure-copy tests in `auth`")]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    #[allow(dead_code, reason = "read by the failure-copy tests in `auth`")]
    pub fn remedy(&self) -> Option<&str> {
        self.remedy.as_deref()
    }

    /// Renders onto stderr in the shape every command uses.
    pub fn render(&self, err: &mut dyn Write) -> io::Result<()> {
        writeln!(err, "error: {}", self.message)?;
        if let Some(remedy) = &self.remedy {
            writeln!(err, "  try: {remedy}")?;
        }
        Ok(())
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// The phrase a failure uses when nothing the operator can type will help.
///
/// Stated as a constant because it is load-bearing rather than decorative.
/// `every_failure_says_what_to_do_next` treats "carries a remedy" and "says
/// plainly that no remedy exists" as the two allowed answers and checks them as
/// an exact bi-implication, so a phrase is what makes the second answer
/// recognisable. Without one that test degenerated into accepting any message
/// at all — it matched the substring `"Nothing was stored."`, which several
/// arms emit *alongside* a remedy.
///
/// It lives here rather than in [`auth`] because three different mappers owe
/// the same guarantee: `auth`'s two error mappers and
/// [`Context::app_registration`]. The first version of this constant was
/// `auth`-local, and the mapper one function away from it was left carrying
/// neither a remedy nor the phrase.
pub const NO_OPERATOR_REMEDY: &str = "there is no command here that fixes this";

/// The failure every command reaches when its output sink gives way.
///
/// One definition rather than one per command file. `auth`, `host` and `status`
/// each had a byte-identical copy of this, and `f2` and `f3` would have added a
/// fourth and a fifth — every one of them constructing the same
/// [`Failure::Unclassified`] from the same `io::Error`.
///
/// `what` names the thing that was being written, because "cannot write to this
/// terminal" is the same sentence whether a status document or a permission
/// disclosure was cut short, and the two are worth telling apart in a bug
/// report.
///
/// # Bind it once per command, do not spell it at each call site
///
/// The return type is `Fn + Copy` rather than `FnOnce` for one reason: so a
/// command can write `let failed = write_failed("this sign-out");` at the top
/// and pass `failed` to every `map_err` below it. Repeating the string at each
/// call site is how `auth status` and `auth logout` ended up reporting *"cannot
/// write this sign-in"* — a bulk edit gave one string to a file that holds
/// three commands, and nothing in the shape of the code objected. One binding
/// per command makes that particular mistake unwritable, and puts the string
/// next to the function whose name has to agree with it.
pub fn write_failed(what: &str) -> impl Fn(io::Error) -> CliError + Copy + '_ {
    move |source| {
        CliError::new(
            Failure::Unclassified,
            format!("cannot write {what}: {source}"),
        )
    }
}

// ---------------------------------------------------------------------------
// The command tree
// ---------------------------------------------------------------------------

/// Local-first autoscaling manager for ephemeral GitHub Actions runners.
#[derive(Debug, Parser)]
#[command(
    name = "runner-manager",
    version,
    about = "Local-first autoscaling manager for ephemeral GitHub Actions self-hosted runners.",
    long_about = None,
    propagate_version = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Root for this host's config, state, runtime and log directories.
    ///
    /// Also selects a secret store rooted under it. Without this, the
    /// platform-standard locations are used.
    #[arg(long, value_name = "DIR", global = true, env = DATA_DIR_VARIABLE)]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// The whole command surface of `02-target-architecture.md`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign in to GitHub, inspect the credential, or purge it.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// Read and change this machine's runner ceiling.
    #[command(subcommand)]
    Host(HostCommand),
    /// Repository-scoped scale policies.
    #[command(subcommand)]
    Repo(RepoCommand),
    /// Organization-scoped scale policies.
    #[command(subcommand)]
    Org(OrgCommand),
    /// Run the host agent in the foreground.
    #[command(subcommand)]
    Daemon(DaemonCommand),
    /// Install, remove, or inspect the OS service.
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Open the terminal UI.
    Tui,
    /// One snapshot of this host, for a human or for a script.
    Status(StatusArgs),
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Sign in with GitHub's device flow.
    Login,
    /// Report the credential's state and what it can reach.
    Status,
    /// Purge the local credential.
    Logout,
}

#[derive(Debug, Subcommand)]
pub enum HostCommand {
    /// Set the ceiling on concurrent runner attempts for this machine.
    SetCapacity(HostSetCapacityArgs),
    /// Show this machine's capacity, store, and projected REST budget.
    Show,
}

#[derive(Debug, Args)]
pub struct HostSetCapacityArgs {
    /// Concurrent runner attempts this machine may hold, across every policy.
    #[arg(value_name = "N")]
    pub capacity: u16,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Emit the versioned, schema-stable JSON document instead of text.
    #[arg(long)]
    pub json: bool,
}

// -- f2's surface, declared here so `f2` attaches to a shape that exists ------

#[derive(Debug, Subcommand)]
pub enum RepoCommand {
    /// Create a repository-scoped policy in `pending`. Never enables scaling.
    Add(RepoAddArgs),
    /// List repository-scoped policies.
    List,
    /// Set a policy's `max_capacity`, promoting monitor-only to autoscale.
    SetCapacity(RepoSetCapacityArgs),
    /// Arm or drain a policy.
    SetScale(RepoSetScaleArgs),
    /// Remove a policy, optionally with its cache and diagnostics.
    Remove(RepoRemoveArgs),
}

#[derive(Debug, Args)]
pub struct RepoAddArgs {
    /// `OWNER/REPO`.
    #[arg(value_name = "OWNER/REPO")]
    pub repository: String,
    /// The host identity the routing label is derived from.
    #[arg(long, value_name = "HOST")]
    pub host_label: String,
    /// Omit for a monitor-only policy that never starts a runner (D19).
    #[arg(long, value_name = "N")]
    pub max_capacity: Option<u16>,
}

#[derive(Debug, Args)]
pub struct RepoSetCapacityArgs {
    #[arg(value_name = "OWNER/REPO")]
    pub repository: String,
    #[arg(long, value_name = "N")]
    pub max_capacity: u16,
}

#[derive(Debug, Args)]
pub struct RepoSetScaleArgs {
    #[arg(value_name = "OWNER/REPO")]
    pub repository: String,
    #[arg(long, value_name = "BOOL", action = clap::ArgAction::Set)]
    pub enabled: bool,
}

#[derive(Debug, Args)]
pub struct RepoRemoveArgs {
    #[arg(value_name = "OWNER/REPO")]
    pub repository: String,
    /// Also delete the runner package cache and historical diagnostics.
    #[arg(long)]
    pub purge: bool,
}

#[derive(Debug, Subcommand)]
pub enum OrgCommand {
    /// Create an organization-scoped policy in `pending`.
    Add(OrgAddArgs),
    /// List organization-scoped policies.
    List,
    /// Set a policy's `max_capacity`, promoting monitor-only to autoscale.
    SetCapacity(OrgSetCapacityArgs),
    /// Arm or drain a policy.
    SetScale(OrgSetScaleArgs),
    /// Remove a policy, optionally with its cache and diagnostics.
    Remove(OrgRemoveArgs),
}

#[derive(Debug, Args)]
pub struct OrgAddArgs {
    #[arg(value_name = "ORG")]
    pub organization: String,
    #[arg(long, value_name = "HOST")]
    pub host_label: String,
    #[arg(long, value_name = "N")]
    pub max_capacity: Option<u16>,
}

#[derive(Debug, Args)]
pub struct OrgSetCapacityArgs {
    #[arg(value_name = "ORG")]
    pub organization: String,
    #[arg(long, value_name = "N")]
    pub max_capacity: u16,
}

#[derive(Debug, Args)]
pub struct OrgSetScaleArgs {
    #[arg(value_name = "ORG")]
    pub organization: String,
    #[arg(long, value_name = "BOOL", action = clap::ArgAction::Set)]
    pub enabled: bool,
}

#[derive(Debug, Args)]
pub struct OrgRemoveArgs {
    #[arg(value_name = "ORG")]
    pub organization: String,
    #[arg(long)]
    pub purge: bool,
}

// -- f3's surface ------------------------------------------------------------

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Run the reconciliation loop in the foreground.
    Run(DaemonRunArgs),
}

/// Arguments normally supplied by `service install`.
///
/// The four hidden leaves preserve the application-data layout selected by
/// the installing operator when the service manager later starts the daemon
/// under LocalSystem/root. They do not affect secret-store selection: the
/// secret remains in the platform-standard machine/user store for the recorded
/// start mode.
#[derive(Debug, Args, Default)]
pub struct DaemonRunArgs {
    #[arg(long, hide = true, requires_all = ["service_state_dir", "service_runtime_dir", "service_logs_dir"])]
    pub service_config_dir: Option<PathBuf>,
    #[arg(long, hide = true, requires_all = ["service_config_dir", "service_runtime_dir", "service_logs_dir"])]
    pub service_state_dir: Option<PathBuf>,
    #[arg(long, hide = true, requires_all = ["service_config_dir", "service_state_dir", "service_logs_dir"])]
    pub service_runtime_dir: Option<PathBuf>,
    #[arg(long, hide = true, requires_all = ["service_config_dir", "service_state_dir", "service_runtime_dir"])]
    pub service_logs_dir: Option<PathBuf>,
}

impl DaemonRunArgs {
    fn service_paths(&self) -> Option<AppPaths> {
        Some(AppPaths::from_directories(
            self.service_config_dir.as_ref()?,
            self.service_state_dir.as_ref()?,
            self.service_runtime_dir.as_ref()?,
            self.service_logs_dir.as_ref()?,
        ))
    }
}

#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Register `daemon run` with the operating system.
    Install(ServiceInstallArgs),
    /// Deregister without deleting configuration, secrets, or cache.
    Uninstall,
    /// Report the start mode, resolved binary path, and last GitHub contact.
    Status,
    /// Switch between boot and login start without reinstalling the product.
    SetStartMode(ServiceSetStartModeArgs),
}

#[derive(Debug, Args)]
pub struct ServiceInstallArgs {
    /// `boot` starts the agent with the machine; `login` waits for a session.
    #[arg(long, value_name = "WHEN", default_value = "boot")]
    pub start_at: StartAt,
}

#[derive(Debug, Args)]
pub struct ServiceSetStartModeArgs {
    /// `boot` starts the agent with the machine; `login` waits for a session.
    #[arg(value_name = "WHEN")]
    pub start_at: StartAt,
}

/// `--start-at boot|login`, mapped onto `b1`'s [`StartMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum StartAt {
    Boot,
    Login,
}

impl From<StartAt> for StartMode {
    fn from(value: StartAt) -> Self {
        match value {
            StartAt::Boot => StartMode::Boot,
            StartAt::Login => StartMode::Login,
        }
    }
}

// ---------------------------------------------------------------------------
// The composition root
// ---------------------------------------------------------------------------

/// Everything a command needs, resolved once.
#[derive(Debug)]
pub struct Context {
    paths: AppPaths,
    /// `Some` when `--data-dir` was given: the secret store is rooted there too.
    data_root: Option<PathBuf>,
    endpoints: Endpoints,
    clock: Arc<dyn Clock>,
}

impl Context {
    /// Resolves paths and endpoints, and creates the four directories.
    ///
    /// # Errors
    /// [`Failure::LocalState`] when the platform reports no home directory or
    /// the directories cannot be created, and [`Failure::InvalidArgument`] when
    /// [`GITHUB_BASE_URL_VARIABLE`] holds something this refuses to trust.
    pub fn resolve(data_dir: Option<&Path>, err: &mut dyn Write) -> Result<Self, CliError> {
        let paths = match data_dir {
            Some(root) => AppPaths::rooted_at(root),
            None => AppPaths::discover().map_err(|source| {
                CliError::with_remedy(
                    Failure::LocalState,
                    format!("cannot work out where this host's data directories live: {source}"),
                    "runner-manager --data-dir <DIR> <COMMAND>",
                )
            })?,
        };
        paths.create_all().map_err(|source| {
            CliError::with_remedy(
                Failure::LocalState,
                format!("cannot create this host's data directories: {source}"),
                "runner-manager --data-dir <DIR> <COMMAND>",
            )
        })?;

        Ok(Self {
            paths,
            data_root: data_dir.map(Path::to_path_buf),
            endpoints: Self::resolve_endpoints(err)?,
            clock: Arc::new(SystemClock),
        })
    }

    /// Resolves a daemon against the exact non-secret directories captured by
    /// `service install`, while leaving the secret store platform-standard.
    fn resolve_service(paths: AppPaths, err: &mut dyn Write) -> Result<Self, CliError> {
        paths.create_all().map_err(|source| {
            CliError::new(
                Failure::LocalState,
                format!("cannot create this service's application-data directories: {source}"),
            )
        })?;
        Ok(Self {
            paths,
            // This is the load-bearing difference from `--data-dir`: a service
            // path handoff must not re-root the machine secret into another
            // file underneath the data tree.
            data_root: None,
            endpoints: Self::resolve_endpoints(err)?,
            clock: Arc::new(SystemClock),
        })
    }

    /// Production GitHub, unless a loopback override says otherwise.
    ///
    /// See [`GITHUB_BASE_URL_VARIABLE`] for why the loopback restriction is the
    /// whole of this function's security value.
    ///
    /// The parse goes through [`Endpoints::for_test_server`] rather than
    /// through `url` directly: `url` is not a dependency of this crate and `a1`
    /// owns every manifest, so the URL type is reachable only through the
    /// values `crates/github` hands back. That is a constraint, not a
    /// preference, and it is why the loopback test below reads a host *string*
    /// rather than matching on `url::Host`.
    fn resolve_endpoints(err: &mut dyn Write) -> Result<Endpoints, CliError> {
        let Some(raw) = std::env::var_os(GITHUB_BASE_URL_VARIABLE) else {
            return Ok(Endpoints::production());
        };
        let raw = raw.to_string_lossy().into_owned();
        let endpoints = Endpoints::for_test_server(&raw).map_err(|source| {
            CliError::new(
                Failure::InvalidArgument,
                format!("{GITHUB_BASE_URL_VARIABLE} is not usable as an endpoint base: {source}"),
            )
        })?;
        refuse_unless_every_origin_is_loopback(&endpoints, &raw)?;
        let _ = writeln!(
            err,
            "warning: talking to {raw} instead of GitHub, because \
             {GITHUB_BASE_URL_VARIABLE} is set."
        );
        Ok(endpoints)
    }

    #[must_use]
    pub fn paths(&self) -> &AppPaths {
        &self.paths
    }

    #[must_use]
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    #[must_use]
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// The published App this binary authenticates as.
    ///
    /// # Errors
    /// [`Failure::AppNotPublished`] while [`PUBLISHED_CLIENT_ID`] is empty and
    /// no override is set. See that constant for why an empty default is the
    /// honest one.
    pub fn app_registration(&self) -> Result<AppRegistration, CliError> {
        let client_id =
            std::env::var(CLIENT_ID_VARIABLE).unwrap_or_else(|_| PUBLISHED_CLIENT_ID.to_string());
        let slug =
            std::env::var(APP_SLUG_VARIABLE).unwrap_or_else(|_| PUBLISHED_APP_SLUG.to_string());
        AppRegistration::new(client_id, slug).map_err(|_| {
            CliError::new(
                Failure::AppNotPublished,
                format!(
                    "this build carries no published GitHub App registration, so there is \
                     nothing to sign in to. Registering and publishing the App is Phase 0 of \
                     the rollout and has not happened yet, so {NO_OPERATOR_REMEDY}."
                ),
            )
        })
    }

    /// The local SQLite database, opened under `config/`.
    ///
    /// # Errors
    /// [`Failure::LocalState`], carrying what SQLite said.
    pub fn store(&self) -> Result<SqliteStore, CliError> {
        let path = self.paths.config_dir().join(DATABASE_FILE);
        SqliteStore::open(&path).map_err(|source| {
            CliError::new(
                Failure::LocalState,
                format!(
                    "cannot open the local database at {}: {source}",
                    path.display()
                ),
            )
        })
    }

    /// The secret store this host's start mode obliges (D13).
    ///
    /// The scope is **not** a preference: `SecretScope::for_start_mode` is a
    /// total function of the start mode recorded for this host, because a
    /// service starting at boot has no login session to read a user-scoped
    /// store from. A host that has never been configured has no recorded mode,
    /// and [`StartMode::default`] — `boot` — is what `service install` defaults
    /// to, so the two agree by construction.
    ///
    /// # Errors
    /// [`Failure::SecretStore`] when the platform cannot say where the store
    /// lives.
    pub fn secret_store(&self, start_mode: StartMode) -> Result<PlatformSecretStore, CliError> {
        let scope = SecretScope::for_start_mode(start_mode);
        let resolved = match &self.data_root {
            Some(root) => PlatformSecretStore::rooted_at(scope, root),
            None => PlatformSecretStore::standard(scope),
        };
        resolved.map_err(|source| {
            CliError::with_remedy(
                Failure::SecretStore,
                format!("cannot reach the {scope}-scoped secret store: {source}"),
                "runner-manager host show",
            )
        })
    }

    /// The start mode recorded for this host, or the default when none is.
    ///
    /// # Errors
    /// [`Failure::LocalState`] when the database cannot be read.
    pub fn recorded_start_mode(&self, store: &dyn Store) -> Result<StartMode, CliError> {
        Ok(host::local_host(store)?.map_or_else(StartMode::default, |h| h.service_start_mode))
    }
}

/// Refuses an override unless **every** origin it produced is loopback.
///
/// # Why both bases, and not the one this check used to read
///
/// [`Endpoints`] carries two: `api_base` for `api.github.com`, and `web_base`
/// for `github.com`. The bearer token is exchanged at
/// `Endpoints::access_token_url`, which joins **`web_base`** — and `web_base` is
/// also what `c2` compares the device-flow `verification_uri` against, so it is
/// the origin behind both of this variable's security properties.
///
/// This check used to read `api_base` alone. That was sound only because
/// `Endpoints::for_test_server` builds both bases from one root, which is an
/// invariant `c2` owns and could reasonably change — a loosening there would
/// silently unhook the one check whose whole purpose is to be unbypassable.
/// Reading both costs a line and removes the cross-crate dependence.
///
/// # Errors
/// [`Failure::InvalidArgument`], naming which base failed.
fn refuse_unless_every_origin_is_loopback(
    endpoints: &Endpoints,
    raw: &str,
) -> Result<(), CliError> {
    let bases = [
        ("the API base", endpoints.api_base()),
        (
            "the web base, which is where the device flow hands over the token",
            endpoints.web_base(),
        ),
    ];
    for (what, base) in bases {
        let host = base.host_str().unwrap_or_default();
        if !is_loopback_host(host) {
            return Err(CliError::new(
                Failure::InvalidArgument,
                format!(
                    "{GITHUB_BASE_URL_VARIABLE} may only point at a loopback address. \
                     {raw:?} put {what} on host {host:?}, which is not one. This variable \
                     redirects the device flow, and the device flow ends by handing a \
                     GitHub credential to whatever answered it."
                ),
            ));
        }
    }
    Ok(())
}

/// Whether a URL host component names this machine.
///
/// Three forms, and no more. A domain other than `localhost` is refused
/// outright rather than resolved: a name that resolves to `127.0.0.1` today can
/// resolve elsewhere on the next lookup, and the whole value of this check is
/// that it cannot be talked out of its answer.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(address) = host.parse::<std::net::Ipv4Addr>() {
        return address.is_loopback();
    }
    // `Url::host_str` renders an IPv6 literal in its bracketed authority form.
    let unbracketed = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    if let Some(inner) = unbracketed
        && let Ok(address) = inner.parse::<std::net::Ipv6Addr>()
    {
        return address.is_loopback();
    }
    false
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// The single entry point `main` calls.
///
/// Two properties of the original skeleton survive, and must keep surviving:
/// it returns an [`ExitCode`] so exit codes stay a CLI concern, and the `tui`
/// command calls [`crate::tui::run`] and nothing else reaches the terminal UI.
#[must_use]
pub fn dispatch() -> ExitCode {
    let cli = Cli::parse();

    // The terminal UI owns the terminal and owns its own exit code, so it is
    // routed here rather than through `run`: `ExitCode` cannot be inspected, so
    // a TUI that exited non-zero for its own reasons would otherwise be
    // re-reported as whichever class this file guessed. The data root still
    // crosses this seam: the TUI's production event source reads the same local
    // lifecycle journal as `status`, never a second database.
    if matches!(cli.command, Command::Tui) {
        return crate::tui::run(cli.data_dir.as_deref());
    }

    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();

    match run(&cli, &mut out, &mut err) {
        Ok(()) => {
            let _ = out.flush();
            ExitCode::SUCCESS
        }
        Err(failure) => {
            let _ = out.flush();
            let _ = failure.render(&mut err);
            let _ = err.flush();
            ExitCode::from(failure.class().code())
        }
    }
}

/// Everything `dispatch` does except owning the process's streams and turning
/// a failure into an exit code.
///
/// Separated so that routing is written against `&mut dyn Write` rather than
/// against `stdout()`, which is what lets every command below be a function of
/// its output sink instead of of the process.
///
/// # Errors
/// Whatever the routed command returns.
pub fn run(cli: &Cli, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), CliError> {
    let service_paths = match &cli.command {
        Command::Daemon(DaemonCommand::Run(args)) => args.service_paths(),
        _ => None,
    };
    if service_paths.is_some() && cli.data_dir.is_some() {
        return Err(CliError::new(
            Failure::InvalidArgument,
            "the service supplied its recorded application-data directories, so --data-dir cannot also select a different database",
        ));
    }
    let context = match service_paths {
        Some(paths) => Context::resolve_service(paths, err)?,
        None => Context::resolve(cli.data_dir.as_deref(), err)?,
    };

    // Diagnostics go to `logs/`, redacted by `d1`'s allowlist sink. A CLI that
    // could not install them is still a CLI that must run, so this is a warning
    // rather than a failure: the alternative is `host show` refusing to print a
    // capacity because a log file could not be opened.
    let _logging = match runner_manager_platform::logging::install(context.paths(), "warn") {
        Ok(guard) => Some(guard),
        Err(source) => {
            let _ = writeln!(err, "warning: diagnostics are not being recorded: {source}");
            None
        }
    };

    match &cli.command {
        Command::Auth(command) => auth::dispatch(&context, command, out),
        Command::Host(command) => host::dispatch(&context, command, out),
        Command::Status(args) => status::dispatch(&context, args, out),
        Command::Repo(command) => policy::dispatch_repo(&context, command, out),
        Command::Org(command) => policy::dispatch_org(&context, command, out),
        Command::Daemon(command) => daemon::dispatch(&context, command, out),
        Command::Service(command) => service::dispatch(&context, command, out),
        // `dispatch` returns the terminal UI's own exit code before reaching
        // here, so that `g1` owns what `tui` exits with.
        Command::Tui => Err(not_implemented("g1")),
    }
}

/// The arm a declared-but-unimplemented command takes.
///
/// It names the task rather than saying "not supported", because the command
/// *is* part of the surface `02-target-architecture.md` fixes — a script that
/// finds it missing is looking at an unfinished build, not at a typo.
fn not_implemented(task: &str) -> CliError {
    CliError::new(
        Failure::NotImplemented,
        format!(
            "this command is declared but not implemented in this build (task {task}). \
             It exits {} so a script can tell it apart from a usage error.",
            Failure::NotImplemented.code()
        ),
    )
}

/// Builds the current-thread Tokio runtime a command needs for GitHub I/O.
///
/// Current-thread rather than multi-thread: every CLI command issues a short
/// sequence of requests and then exits, so a worker pool buys nothing and costs
/// one thread per core on a home host.
///
/// # Errors
/// [`Failure::Unclassified`] when the runtime will not start.
pub fn runtime() -> Result<tokio::runtime::Runtime, CliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| {
            CliError::new(
                Failure::Unclassified,
                format!("cannot start the async runtime: {source}"),
            )
        })
}

/// The one place a host record is created, for [`host`] and for `f2`.
///
/// # Errors
/// [`Failure::UnsupportedHost`] when this OS/architecture pair is outside
/// GitHub's documented matrix, and [`Failure::LocalState`] on a write failure.
pub fn create_local_host(store: &dyn Store, clock: &dyn Clock) -> Result<Host, CliError> {
    let support = runner_manager_platform::os::detect().map_err(|source| {
        CliError::new(
            Failure::UnsupportedHost,
            format!("this machine cannot run GitHub's runner application: {source}"),
        )
    })?;
    let capacity = std::num::NonZeroU16::new(DEFAULT_HOST_CAPACITY)
        .expect("DEFAULT_HOST_CAPACITY is a non-zero constant");
    let host = Host::new(
        runner_manager_domain::model::HostId::new_random(),
        local_display_name(),
        support.os(),
        support.arch(),
        capacity,
        clock.now(),
    )
    .map_err(|source| {
        CliError::new(
            Failure::LocalState,
            format!("cannot describe this host: {source}"),
        )
    })?;
    store.put_host(&host).map_err(|source| {
        CliError::new(
            Failure::LocalState,
            format!("cannot record this host: {source}"),
        )
    })?;
    Ok(host)
}

/// A human-readable name for this machine.
///
/// `d1` exposes no hostname primitive — it deliberately covers only the
/// platform differences some task's Definition of Done depends on — and this is
/// a display string with no authority behind it: nothing routes, matches, or
/// authorises on it. So it is read from whichever environment variable the
/// platform sets, and falls back to a constant rather than failing a command
/// over a cosmetic field.
fn local_display_name() -> String {
    for variable in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(value) = std::env::var(variable) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "this host".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::CommandFactory as _;

    /// The whole point of the taxonomy: two classes must never share a number,
    /// and none may be zero, or a script cannot branch on the answer.
    #[test]
    fn the_exit_codes_are_distinct_and_non_zero() {
        let mut seen = std::collections::BTreeMap::new();
        for class in Failure::ALL.iter().copied() {
            assert_ne!(
                class.code(),
                0,
                "{class} would be indistinguishable from success"
            );
            assert_ne!(
                class.code(),
                2,
                "{class} would be indistinguishable from clap's usage error, which exits 2 \
                 before any of this code runs"
            );
            if let Some(previous) = seen.insert(class.code(), class) {
                panic!("{previous} and {class} both exit {}", class.code());
            }
        }
        assert_eq!(
            seen.len(),
            Failure::ALL.len(),
            "every class must occupy its own code"
        );
    }

    /// The distinctness proof above is only worth its name if `ALL` really is
    /// every class, so this pins the property that makes it so.
    ///
    /// `ALL` is expanded from the `failure_taxonomy!` declaration, alongside the
    /// enum itself and `as_str`, so a class that exists and is missing from
    /// `ALL` is not a thing that can be written. The previous version of this
    /// test asserted `!class.as_str().is_empty()` over an exhaustive match —
    /// which is true by construction, because every arm returns a string
    /// literal, and which left the actual hole open: `ALL` was a separate
    /// hand-maintained array, and a new variant compiled without being added
    /// to it.
    ///
    /// What is checked here is the one thing the macro does *not* guarantee:
    /// that two classes were not given the same name. The names reach
    /// `status --json` and the `tracing` fields, where a duplicate would make
    /// two different failures indistinguishable to a consumer for the same
    /// reason a shared exit code would.
    #[test]
    fn every_class_is_reachable_from_all_and_names_itself_uniquely() {
        assert!(
            Failure::ALL.len() >= 19,
            "the taxonomy has only ever grown; a shorter `ALL` means classes were \
             removed without the scripting contract being revisited"
        );

        let mut names = std::collections::BTreeMap::new();
        for class in Failure::ALL.iter().copied() {
            assert!(
                !class.as_str().is_empty(),
                "{class:?} has no stable name for a `--json` document to carry"
            );
            if let Some(previous) = names.insert(class.as_str(), class) {
                panic!(
                    "{previous:?} and {class:?} are both called {:?}",
                    class.as_str()
                );
            }
        }
        assert_eq!(names.len(), Failure::ALL.len());
    }

    /// A sink that fails on the first byte, so every command's write path can
    /// be driven to its error branch.
    #[derive(Debug)]
    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "the pipe closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "the pipe closed"))
        }
    }

    /// Every command reports the operation **it** was performing when its
    /// output sink gave way.
    ///
    /// This is the assertion that was missing. `write_failed` takes the noun as
    /// a parameter, and a bulk edit handed one noun to a file holding three
    /// commands: `auth status` and `auth logout` both reported *"cannot write
    /// this sign-in"*. Nothing objected, because a wrong string is still a
    /// string — and error copy that names the wrong operation is the same class
    /// of defect as error copy that names the wrong remedy, which this task's
    /// Definition of Done rules out explicitly.
    ///
    /// The table is checked in both directions: each command's message must
    /// carry its own noun **and** none of the others'. A one-directional check
    /// would have passed the very bug it is here to catch, because "this
    /// sign-in" really was present in the logout message.
    #[test]
    fn every_command_names_the_operation_whose_output_failed() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let mut discarded = Vec::new();
        let context = Context::resolve(Some(temporary.path()), &mut discarded)
            .expect("a context rooted at a temporary directory");

        // (what the command is, the noun it must use)
        let expected: [(&str, &str); 6] = [
            ("auth login", "this sign-in"),
            ("auth status", "this credential's status"),
            ("auth logout", "this sign-out"),
            ("host set-capacity", "this host's new capacity"),
            ("host show", "this host's settings"),
            ("status", "this host's status"),
        ];

        let run_one = |command: &str| -> CliError {
            let out: &mut dyn Write = &mut BrokenPipe;
            let outcome = match command {
                "auth login" => auth::login(&context, out),
                "auth status" => auth::status(&context, out),
                "auth logout" => auth::logout(&context, out),
                "host set-capacity" => {
                    host::set_capacity(&context, &HostSetCapacityArgs { capacity: 1 }, out)
                }
                "host show" => host::show(&context, out),
                "status" => status::dispatch(&context, &StatusArgs { json: false }, out),
                other => panic!("unknown command {other}"),
            };
            outcome.expect_err("a sink that fails on the first byte must fail the command")
        };

        for (command, noun) in expected {
            let error = run_one(command);
            assert_eq!(
                error.class(),
                Failure::Unclassified,
                "`{command}` must report a write failure as a write failure, not as \
                 something about GitHub or the local database: {error}"
            );
            assert!(
                error.message().contains(noun),
                "`{command}` must say it could not write {noun:?}; it said: {error}"
            );
            for (other_command, other_noun) in expected {
                if other_noun == noun {
                    continue;
                }
                assert!(
                    !error.message().contains(other_noun),
                    "`{command}` reported {other_noun:?}, which belongs to \
                     `{other_command}`: {error}"
                );
            }
        }
    }

    /// clap refuses to build a malformed command tree, and it does so at
    /// runtime rather than at compile time. Every other test in this crate that
    /// runs the binary would fail with the same panic and a worse message.
    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn repository_and_organization_set_scale_parse_explicit_true_and_false() {
        for (scope, target) in [("repo", "octo/repo"), ("org", "octo")] {
            for expected in [true, false] {
                let cli = Cli::try_parse_from([
                    "runner-manager",
                    scope,
                    "set-scale",
                    target,
                    "--enabled",
                    if expected { "true" } else { "false" },
                ])
                .unwrap();
                let actual = match cli.command {
                    Command::Repo(RepoCommand::SetScale(args)) => args.enabled,
                    Command::Org(OrgCommand::SetScale(args)) => args.enabled,
                    _ => panic!("wrong command parsed for {scope}"),
                };
                assert_eq!(actual, expected, "{scope} must retain explicit {expected}");
            }
        }
    }

    /// The override is the one environment variable that can send a credential
    /// somewhere other than GitHub, so the loopback rule is asserted from both
    /// sides.
    #[test]
    fn only_a_loopback_origin_may_replace_github() {
        for raw in [
            "http://127.0.0.1:8080/",
            "http://127.0.0.2/",
            "http://[::1]:8080/",
            "http://localhost:8080/",
            "http://LOCALHOST:8080/",
        ] {
            let endpoints = Endpoints::for_test_server(raw).expect("a valid URL");
            refuse_unless_every_origin_is_loopback(&endpoints, raw)
                .unwrap_or_else(|error| panic!("{raw} must be accepted: {error}"));
        }

        for raw in [
            "https://api.github.com/",
            "http://127.0.0.1.evil.example/",
            "http://localhost.evil.example/",
            "http://10.0.0.1/",
            "http://[2001:db8::1]/",
        ] {
            let endpoints = Endpoints::for_test_server(raw).expect("a valid URL");
            assert!(
                refuse_unless_every_origin_is_loopback(&endpoints, raw).is_err(),
                "{raw} must be refused: this variable redirects the device flow, and the \
                 device flow ends by handing a GitHub credential to whatever answered"
            );
        }

        // A URL with no host component at all must not be read as loopback by
        // the `unwrap_or_default()` that turns `None` into `""`.
        assert!(!is_loopback_host(""), "an absent host is not loopback");
    }

    /// The token is exchanged at `web_base`, so a guard that only inspected
    /// `api_base` would pass a pair whose web half is remote.
    ///
    /// `Endpoints::for_test_server` cannot build such a pair — it sets both from
    /// one root — which is precisely why the old single-base check was sound in
    /// practice and unsound in principle: it depended on an invariant owned by
    /// `crates/github`. `Endpoints::new` can build it, so the case is testable
    /// here without touching that crate, and this test fails if the guard is
    /// ever narrowed back to one base.
    #[test]
    fn a_pair_whose_web_base_is_remote_is_refused_even_when_the_api_base_is_loopback() {
        let loopback = Endpoints::for_test_server("http://127.0.0.1:8080/").expect("valid");
        let production = Endpoints::production();

        let split = Endpoints::new(loopback.api_base().clone(), production.web_base().clone());
        assert!(
            is_loopback_host(split.api_base().host_str().unwrap_or_default()),
            "the API half of this pair is loopback, which is what makes it the case the \
             old check would have waved through"
        );
        let refusal = refuse_unless_every_origin_is_loopback(&split, "http://127.0.0.1:8080/")
            .expect_err(
                "a pair whose web base is github.com must be refused: `access_token_url` \
                 joins `web_base`, so that is the origin the bearer token is handed to",
            );
        assert!(
            refusal.message().contains("hands over the token"),
            "the refusal must name which base failed: {refusal}"
        );

        // And the mirror image, so the loop is not simply refusing everything.
        let both_loopback =
            Endpoints::new(loopback.api_base().clone(), loopback.web_base().clone());
        refuse_unless_every_origin_is_loopback(&both_loopback, "http://127.0.0.1:8080/")
            .expect("a pair that is loopback on both bases must be accepted");
    }

    /// The empty default is load-bearing: it is what turns "the App has not
    /// been registered yet" into a named failure instead of a device flow that
    /// dies against GitHub with a message about client credentials.
    #[test]
    fn no_plausible_client_id_is_compiled_in() {
        assert!(
            PUBLISHED_CLIENT_ID.is_empty() && PUBLISHED_APP_SLUG.is_empty(),
            "Phase 0 of `06-migration-rollout.md` registers and publishes the App. Until it \
             has, a non-empty constant here is a value somebody invented. When Phase 0 does \
             land, this test is the place to record that it did."
        );
    }

    #[test]
    fn a_failure_renders_its_remedy() {
        let error = CliError::with_remedy(
            Failure::NotAuthenticated,
            "no credential is stored on this host",
            "runner-manager auth login",
        );
        let mut rendered = Vec::new();
        error.render(&mut rendered).expect("writing to a Vec");
        let rendered = String::from_utf8(rendered).expect("ASCII");
        assert!(rendered.contains("error: no credential is stored on this host"));
        assert!(rendered.contains("try: runner-manager auth login"));
    }
}
