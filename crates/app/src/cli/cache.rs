//! `host cache`, `repo cache` and `org cache`: the operator's half of
//! `runner_manager_platform::dependency_cache`.
//!
//! Every command here edits `caches.toml` in the configuration directory, and
//! the daemon reads that file at every launch, so a change reaches the next
//! runner without a restart. On a managed WSL host, `--host wsl:NAME` forwards
//! the command line to the Linux binary like every other command, so the file
//! it edits, the defaults it shows and the paths it validates are the Linux
//! host's own; nothing resolved on Windows is written there.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use runner_manager_agent::dependency_caches::DependencyCaches;
use runner_manager_domain::model::{Host, HostId, ScaleTarget, Timestamp};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::Store;
use runner_manager_platform::dependency_cache::{
    self, CacheConfig, CacheError, CacheUsage, ResolvedRoot, Selection, Sharing, TOOLS, VarValue,
};
use runner_manager_platform::runner_env::RunnerPlatform;
use runner_manager_platform::runner_root::RootOwner;
use runner_manager_platform::service_request::{self, AskError, Wait};
use serde::Serialize;

use super::workspace;
use super::{
    CacheNamespaceArgs, CacheToolArgs, CacheToolState, CliError, Context, Failure,
    HostCacheCommand, OrgCacheCommand, RepoCacheCommand, write_failed,
};

// ---------------------------------------------------------------------------
// Shared resolution
// ---------------------------------------------------------------------------

fn config_path(context: &Context) -> PathBuf {
    dependency_cache::config_path_in(context.paths().config_dir())
}

fn cache_failure(error: CacheError) -> CliError {
    match error {
        CacheError::Io { .. } | CacheError::Lock(_) => {
            CliError::new(Failure::LocalState, error.to_string())
        }
        _ => CliError::new(Failure::InvalidArgument, error.to_string()),
    }
}

/// The configuration, or a failure that says where the file is.
fn load(context: &Context) -> Result<CacheConfig, CliError> {
    let path = config_path(context);
    CacheConfig::load(&path).map_err(|error| match error {
        CacheError::Io { .. } => cache_failure(error),
        _ => CliError::with_remedy(
            Failure::InvalidArgument,
            format!("{error}; no runner starts until it is fixed"),
            format!("edit or delete {}", path.display()),
        ),
    })
}

fn save(context: &Context, config: &CacheConfig) -> Result<(), CliError> {
    config.save(&config_path(context)).map_err(cache_failure)
}

/// The cache root for this host's current runner root.
fn root(
    context: &Context,
    host: Option<&Host>,
    config: &CacheConfig,
) -> Result<ResolvedRoot, String> {
    let runner_root = workspace::host_root(context.paths(), host);
    dependency_cache::resolve_root(
        config,
        runner_root.effective.as_ref().map(|root| root.as_path()),
        dependency_cache::platform_fallback_root(context.paths()),
    )
}

/// What the daemon launches with: the settings file and a runner root read
/// from the journal at each launch.
#[must_use]
pub fn daemon_caches(
    context: &Context,
    store: Arc<dyn Store>,
    host_id: HostId,
) -> DependencyCaches {
    let paths = context.paths().clone();
    let runner_root = Arc::new(move || {
        let host = store.host(host_id).ok().flatten();
        workspace::host_root(&paths, host.as_ref())
            .effective
            .map(|root| root.as_path().to_path_buf())
    });
    DependencyCaches::new(
        config_path(context),
        runner_root,
        dependency_cache::platform_fallback_root(context.paths()),
    )
}

// ---------------------------------------------------------------------------
// The snapshot `status` and `host show` print
// ---------------------------------------------------------------------------

/// The caches in `status --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheSnapshot {
    pub enabled: bool,
    pub root: Option<String>,
    pub root_source: Option<&'static str>,
    /// Why no root resolves, or why `caches.toml` cannot be used.
    pub problem: Option<String>,
    pub max_bytes: Option<u64>,
    /// From the daemon's last measurement; `null` before the first.
    pub used_bytes: Option<u64>,
    pub namespaces: Option<usize>,
    pub measured_at: Option<Timestamp>,
}

impl CacheSnapshot {
    /// One line for `status` and `host show`.
    #[must_use]
    pub fn line(&self) -> String {
        if let Some(problem) = &self.problem {
            return format!("unusable: {problem}");
        }
        if !self.enabled {
            return "off (`host cache set-enabled --enabled true`)".to_owned();
        }
        let root = self.root.as_deref().unwrap_or("?");
        let cap = self
            .max_bytes
            .map_or_else(|| "no cap".to_owned(), dependency_cache::human_bytes);
        match self.used_bytes {
            Some(used) => format!("{} of {cap} at {root}", dependency_cache::human_bytes(used)),
            None => format!("{cap} cap at {root}, not measured yet"),
        }
    }
}

/// The caches as `status` reports them.
#[must_use]
pub fn snapshot(context: &Context, host: Option<&Host>) -> CacheSnapshot {
    let config = match CacheConfig::load(&config_path(context)) {
        Ok(config) => config,
        Err(error) => {
            return CacheSnapshot {
                enabled: false,
                root: None,
                root_source: None,
                problem: Some(error.to_string()),
                max_bytes: None,
                used_bytes: None,
                namespaces: None,
                measured_at: None,
            };
        }
    };
    let resolved = root(context, host, &config);
    let usage = resolved
        .as_ref()
        .ok()
        .and_then(|root| CacheUsage::read(&root.path));
    CacheSnapshot {
        enabled: config.host_enabled(),
        root: resolved
            .as_ref()
            .ok()
            .map(|root| root.path.display().to_string()),
        root_source: resolved.as_ref().ok().map(|root| root.source.as_token()),
        problem: resolved.as_ref().err().cloned(),
        max_bytes: config.max_bytes(),
        used_bytes: usage.as_ref().map(|usage| usage.total_bytes),
        namespaces: usage.as_ref().map(|usage| usage.namespaces.len()),
        measured_at: usage.map(|usage| usage.measured_at),
    }
}

/// The cache root, when caches are on and it resolves: `host doctor` checks
/// it like a runner root.
#[must_use]
pub fn active_root(context: &Context, host: Option<&Host>) -> Option<PathBuf> {
    let config = CacheConfig::load(&config_path(context)).ok()?;
    if !config.host_enabled() {
        return None;
    }
    root(context, host, &config).ok().map(|root| root.path)
}

// ---------------------------------------------------------------------------
// host cache
// ---------------------------------------------------------------------------

/// # Errors
/// [`Failure::InvalidArgument`] for a refused value or an unusable file, and
/// [`Failure::LocalState`] when it cannot be read or written.
pub fn dispatch_host(
    context: &Context,
    command: &HostCacheCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("the dependency caches");
    let mut config = load(context)?;
    match command {
        HostCacheCommand::Show => {
            let (host, policies) = host_and_policies(context)?;
            write_host_show(context, host.as_ref(), &policies, &config, out).map_err(failed)?;
        }
        HostCacheCommand::SetEnabled(args) => {
            config.enabled = (!args.enabled).then_some(false);
            save(context, &config)?;
            writeln!(
                out,
                "Dependency caches are {} for native runners started from now on.",
                if args.enabled { "on" } else { "off" }
            )
            .map_err(failed)?;
        }
        HostCacheCommand::SetRoot(args) => {
            dependency_cache::validate_root_text(&args.path).map_err(|error| {
                CliError::with_remedy(
                    Failure::InvalidArgument,
                    error.to_string(),
                    RootOwner::DependencyCache.remediation(),
                )
            })?;
            let store = context.store()?;
            // The checks every runner root passes: local, writable, outside
            // application data and not overlapping any runner root, so a
            // network share, a WSL `/mnt/<drive>` 9p mount or a path inside a
            // workspace that is removed recursively is refused.
            let root =
                workspace::check_root(context, &store, &RootOwner::DependencyCache, &args.path)?;
            config.root = Some(root.as_str().to_owned());
            save(context, &config)?;
            writeln!(
                out,
                "Dependency caches go under {} for runners started from now on. Nothing under \
                 the previous root was moved or deleted.",
                root.as_str()
            )
            .map_err(failed)?;
            if RunnerPlatform::current() == RunnerPlatform::Linux {
                // The unit's `ProtectSystem=strict` leaves only the service's
                // own directories writable, and runners inherit that sandbox.
                writeln!(
                    out,
                    "Note: a systemd service can write only its own directories. Add \
                     `ReadWritePaths={}` to the unit with a drop-in, or runners start without \
                     caches (`dependency_cache_unavailable` in the log).",
                    root.as_str()
                )
                .map_err(failed)?;
            }
        }
        HostCacheCommand::ResetRoot => {
            config.root = None;
            save(context, &config)?;
            let store = context.store()?;
            let host = super::host::local_host(&store)?;
            let resolved = root(context, host.as_ref(), &config);
            writeln!(
                out,
                "Dependency caches go under {} for runners started from now on.",
                resolved.map_or_else(|why| why, |root| root.path.display().to_string())
            )
            .map_err(failed)?;
        }
        HostCacheCommand::SetMaxSize(args) => {
            config.max_size_gib = Some(args.gib);
            save(context, &config)?;
            if args.gib == 0 {
                writeln!(out, "The dependency caches have no size cap.").map_err(failed)?;
            } else {
                writeln!(
                    out,
                    "The dependency caches are capped at {} GiB; the service removes the least \
                     recently used idle namespaces above it.",
                    args.gib
                )
                .map_err(failed)?;
            }
        }
        HostCacheCommand::SetTool(args) => {
            let id = known_tool(&args.tool)?;
            set_tool_state(&mut config.tools, id, args.state);
            save(context, &config)?;
            writeln!(
                out,
                "{id} is {} for every policy on this host unless a repository says otherwise.",
                state_word(args.state, id)
            )
            .map_err(failed)?;
        }
        HostCacheCommand::Prune => {
            let store = context.store()?;
            let host = super::host::local_host(&store)?;
            let resolved = root(context, host.as_ref(), &config)
                .map_err(|why| CliError::new(Failure::LocalState, why))?;
            if !resolved.path.is_dir() {
                writeln!(
                    out,
                    "{} does not exist yet; there is nothing to prune.",
                    resolved.path.display()
                )
                .map_err(failed)?;
                return Ok(());
            }
            let service_registered =
                runner_manager_platform::service::InstallRecord::read(context.paths())
                    .is_ok_and(|record| record.is_some());
            if let Some(usage) = prune_root(
                context.paths().state_dir(),
                service_registered,
                &resolved.path,
                config.max_bytes(),
                PRUNE_WAIT,
                out,
            )? {
                write_pruned(&usage, &resolved.path, out).map_err(failed)?;
            }
        }
    }
    Ok(())
}

/// Prunes `root` here, or -- when this account may not write it, as with the
/// cache root of a service running as LocalSystem or root -- has the service
/// registered for this account's directories do it. `None` when the service
/// is still working and that has been said.
fn prune_root(
    state_dir: &Path,
    service_registered: bool,
    root: &Path,
    max_bytes: Option<u64>,
    wait: Wait,
    out: &mut dyn Write,
) -> Result<Option<CacheUsage>, CliError> {
    match dependency_cache::prune(root, max_bytes, &dependency_cache::runtime_holds_runner) {
        Ok(usage) => Ok(Some(usage)),
        Err(error) if error.is_permission_denied() && service_registered => {
            prune_through_service(state_dir, root, &error, wait, out)
        }
        // No service reads this account's directories, so none would see a
        // request: the root is another account's, or a service's that this
        // account did not install.
        Err(error) if error.is_permission_denied() => Err(CliError::with_remedy(
            Failure::LocalState,
            format!(
                "this account cannot prune {} ({error}), and no service is installed from this \
                 account's directories to ask instead",
                root.display()
            ),
            elevated_remedy(),
        )),
        Err(error) => Err(cache_failure(error)),
    }
}

/// What to do when neither this account nor the service can prune.
fn elevated_remedy() -> &'static str {
    if cfg!(windows) {
        "run `runner-manager host cache prune` from an elevated prompt"
    } else {
        "run `runner-manager host cache prune` as the account the service runs as, with this \
         account's data directory (`--data-dir`)"
    }
}

fn write_pruned(usage: &CacheUsage, root: &Path, out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "{} in {} namespace(s) at {}; removed {}.",
        dependency_cache::human_bytes(usage.total_bytes),
        usage.namespaces.len(),
        root.display(),
        if usage.pruned.is_empty() {
            "nothing".to_owned()
        } else {
            usage.pruned.join(", ")
        }
    )
}

/// How long `host cache prune` waits on the service: several of its polls for
/// it to take the request, and a measuring and pruning pass for the answer.
const PRUNE_WAIT: Wait = Wait {
    taken: Duration::from_secs(4 * dependency_cache::PRUNE_REQUEST_POLL.as_secs()),
    finished: Duration::from_secs(10 * 60),
    poll: Duration::from_secs(1),
};

/// Asks the running service to prune a cache root this account cannot write,
/// and reports what it did. `None` when the service took the request and was
/// still working when the wait ran out; that has been said.
///
/// # Errors
/// [`Failure::LocalState`] naming the remedies when the request cannot be
/// left, no running service took it, or the service could not prune either.
fn prune_through_service(
    state_dir: &Path,
    root: &Path,
    denied: &CacheError,
    wait: Wait,
    out: &mut dyn Write,
) -> Result<Option<CacheUsage>, CliError> {
    let failed = write_failed("the dependency caches");
    let remedy = format!(
        "runner-manager service status   (the service prunes on request while it runs), or {}",
        elevated_remedy()
    );
    let mut announced = Ok(());
    let answer = service_request::CACHE_PRUNE.ask_with(state_dir, wait, || {
        announced = writeln!(
            out,
            "This account cannot write {}; asking the service to prune it.",
            root.display()
        )
        .and_then(|()| out.flush());
    });
    announced.map_err(failed)?;
    let refused = |why: String, remedy: String| {
        CliError::with_remedy(
            Failure::LocalState,
            format!(
                "this account cannot prune {} ({denied}), and {why}",
                root.display()
            ),
            remedy,
        )
    };
    match answer {
        Ok(usage) => Ok(Some(usage)),
        Err(AskError::NotSent(why)) => Err(refused(
            format!("cannot ask the service to either: {why}"),
            remedy,
        )),
        Err(error @ AskError::NotTaken(_)) => Err(refused(error.to_string(), remedy)),
        Err(AskError::Refused(why)) => Err(refused(
            format!("the service could not either: {why}"),
            elevated_remedy().to_owned(),
        )),
        Err(AskError::NoAnswer(_)) => {
            writeln!(
                out,
                "The service took the request and is still working; `runner-manager host cache \
                 show` reports the result once it finishes."
            )
            .map_err(failed)?;
            Ok(None)
        }
    }
}

/// This host's record and policies, for the `show` commands.
fn host_and_policies(context: &Context) -> Result<(Option<Host>, Vec<ScalePolicy>), CliError> {
    let store = context.store()?;
    let host = super::host::local_host(&store)?;
    let policies = store.policies().map_err(|source| {
        CliError::new(
            Failure::LocalState,
            format!("cannot read this host's policies: {source}"),
        )
    })?;
    Ok((host, policies))
}

fn known_tool(raw: &str) -> Result<&'static str, CliError> {
    dependency_cache::tool(raw)
        .map(|tool| tool.id)
        .ok_or_else(|| {
            CliError::with_remedy(
                Failure::InvalidArgument,
                format!(
                    "`{raw}` is not a cache this version knows; one of: {}",
                    dependency_cache::tool_ids().join(", ")
                ),
                "runner-manager host cache show",
            )
        })
}

fn set_tool_state(tools: &mut BTreeMap<String, bool>, id: &str, state: CacheToolState) {
    match state {
        CacheToolState::On => {
            tools.insert(id.to_owned(), true);
        }
        CacheToolState::Off => {
            tools.insert(id.to_owned(), false);
        }
        CacheToolState::Default => {
            tools.remove(id);
        }
    }
}

fn state_word(state: CacheToolState, id: &str) -> String {
    match state {
        CacheToolState::On => "on".to_owned(),
        CacheToolState::Off => "off".to_owned(),
        CacheToolState::Default => {
            let default = dependency_cache::tool(id).is_some_and(|tool| tool.default_enabled);
            format!(
                "back to its default ({})",
                if default { "on" } else { "off" }
            )
        }
    }
}

/// `<namespace>/npm` or `<namespace>/_slots/<n>/tool-cache`, for a table that
/// describes every target at once.
fn described_value(sharing: Sharing, dir: &str, value: VarValue) -> String {
    let base = match sharing {
        Sharing::Namespace => format!("<namespace>/{dir}"),
        Sharing::Slot => format!("<namespace>/_slots/<n>/{dir}"),
    };
    match value {
        VarValue::Dir => base,
        VarValue::Sub(sub) => format!("{base}/{sub}"),
        VarValue::Literal(literal) => literal.to_owned(),
        VarValue::Template(template) => template.replace("{dir}", &base),
    }
}

fn write_host_show(
    context: &Context,
    host: Option<&Host>,
    policies: &[ScalePolicy],
    config: &CacheConfig,
    out: &mut dyn Write,
) -> io::Result<()> {
    let platform = RunnerPlatform::current();
    let resolved = root(context, host, config);
    writeln!(
        out,
        "Dependency caches: {}",
        if config.host_enabled() { "on" } else { "off" }
    )?;
    match &resolved {
        Ok(root) => writeln!(
            out,
            "  root                      {} ({})",
            root.path.display(),
            root.source.as_token()
        )?,
        Err(why) => writeln!(out, "  root                      none: {why}")?,
    }
    writeln!(
        out,
        "  settings                  {}",
        config_path(context).display()
    )?;
    writeln!(
        out,
        "  size cap                  {}",
        config
            .max_bytes()
            .map_or_else(|| "none".to_owned(), dependency_cache::human_bytes)
    )?;
    let usage = resolved
        .as_ref()
        .ok()
        .and_then(|root| CacheUsage::read(&root.path));
    match &usage {
        Some(usage) => {
            writeln!(
                out,
                "  in use                    {} in {} namespace(s), measured {}",
                dependency_cache::human_bytes(usage.total_bytes),
                usage.namespaces.len(),
                usage.measured_at.format("%Y-%m-%d %H:%M UTC")
            )?;
            let mut largest: Vec<_> = usage.namespaces.iter().collect();
            largest.sort_by(|a, b| b.bytes.cmp(&a.bytes));
            for namespace in largest.iter().take(10) {
                writeln!(
                    out,
                    "    {:<40} {:>10}{}",
                    namespace.name,
                    dependency_cache::human_bytes(namespace.bytes),
                    if namespace.in_use { "  in use" } else { "" }
                )?;
            }
        }
        None => writeln!(
            out,
            "  in use                    not measured yet; the service measures every {} minutes, \
             `host cache prune` measures now",
            dependency_cache::PRUNE_INTERVAL.as_secs() / 60
        )?,
    }
    writeln!(out)?;
    writeln!(
        out,
        "Caches on this platform (`host cache set-tool TOOL --state on|off|default`):"
    )?;
    for tool in TOOLS.iter().filter(|tool| tool.applies_to(platform)) {
        let (enabled, source) = match config.tools.get(tool.id) {
            Some(enabled) => (*enabled, "host"),
            None => (tool.default_enabled, "default"),
        };
        writeln!(
            out,
            "  {:<17} {:<4} ({source}){}",
            tool.id,
            if enabled { "on" } else { "off" },
            if tool.sharing == Sharing::Slot {
                ", one per concurrent runner"
            } else {
                ""
            }
        )?;
        for variable in tool.variables_on(platform) {
            writeln!(
                out,
                "      {}={}",
                variable.name,
                described_value(tool.sharing, tool.dir, variable.value)
            )?;
        }
        writeln!(out, "      {}", tool.note)?;
    }
    writeln!(out)?;
    writeln!(out, "Policies:")?;
    if policies.is_empty() {
        writeln!(out, "  none yet")?;
    }
    let mut seen = std::collections::BTreeSet::new();
    for policy in policies {
        if !seen.insert((
            dependency_cache::target_key(&policy.target),
            policy.execution_policy().is_native(),
        )) {
            continue;
        }
        let selection = dependency_cache::select(config, &policy.target, platform);
        writeln!(
            out,
            "  {:<40} {}",
            policy.target.slug(),
            policy_line(policy, &selection)
        )?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "A variable set in runner.env (`host env set`) always wins over these. Isolated runners \
         get no caches: their providers mount no host directory."
    )?;
    if platform == RunnerPlatform::MacOs {
        writeln!(
            out,
            "setup-python on macOS ignores the tool cache and installs under \
             /Users/runner/hostedtoolcache; create that directory for the runner account once if \
             workflows use it."
        )?;
    }
    Ok(())
}

fn policy_line(policy: &ScalePolicy, selection: &Selection) -> String {
    if !policy.execution_policy().is_native() {
        return "no cache: isolated runners use the image's environment".to_owned();
    }
    match selection.disabled {
        Some(why) => format!("no cache: {why}"),
        None => format!("namespace {}", selection.namespace.label()),
    }
}

// ---------------------------------------------------------------------------
// repo cache / org cache
// ---------------------------------------------------------------------------

/// The parts of `repo cache` and `org cache` that differ only in the target.
enum TargetCommand<'a> {
    Show,
    SetEnabled(bool),
    SetNamespace(&'a CacheNamespaceArgs),
    SetTool(&'a CacheToolArgs),
}

fn parse_repository(raw: &str) -> Result<ScaleTarget, CliError> {
    ScaleTarget::repository(raw)
        .map_err(|source| CliError::new(Failure::InvalidArgument, source.to_string()))
}

fn parse_organization(raw: &str) -> Result<ScaleTarget, CliError> {
    ScaleTarget::organization(raw)
        .map_err(|source| CliError::new(Failure::InvalidArgument, source.to_string()))
}

/// # Errors
/// As [`dispatch_host`], and a malformed `OWNER/REPO`.
pub fn dispatch_repo(
    context: &Context,
    command: &RepoCacheCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let (target, command) = match command {
        RepoCacheCommand::Show(args) => (parse_repository(&args.repository)?, TargetCommand::Show),
        RepoCacheCommand::SetEnabled(args) => (
            parse_repository(&args.repository)?,
            TargetCommand::SetEnabled(args.enabled.enabled),
        ),
        RepoCacheCommand::SetNamespace(args) => (
            parse_repository(&args.repository)?,
            TargetCommand::SetNamespace(&args.namespace),
        ),
        RepoCacheCommand::SetTool(args) => (
            parse_repository(&args.repository)?,
            TargetCommand::SetTool(&args.tool),
        ),
    };
    target_command(context, &target, &command, out)
}

/// # Errors
/// As [`dispatch_host`], and a malformed organization.
pub fn dispatch_org(
    context: &Context,
    command: &OrgCacheCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let (target, command) = match command {
        OrgCacheCommand::Show(args) => {
            (parse_organization(&args.organization)?, TargetCommand::Show)
        }
        OrgCacheCommand::SetEnabled(args) => (
            parse_organization(&args.organization)?,
            TargetCommand::SetEnabled(args.enabled.enabled),
        ),
        OrgCacheCommand::SetNamespace(args) => (
            parse_organization(&args.organization)?,
            TargetCommand::SetNamespace(&args.namespace),
        ),
        OrgCacheCommand::SetTool(args) => (
            parse_organization(&args.organization)?,
            TargetCommand::SetTool(&args.tool),
        ),
    };
    target_command(context, &target, &command, out)
}

fn target_command(
    context: &Context,
    target: &ScaleTarget,
    command: &TargetCommand<'_>,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("the dependency caches");
    let mut config = load(context)?;
    let slug = target.slug();
    match command {
        TargetCommand::Show => {
            let (host, policies) = host_and_policies(context)?;
            write_target_show(context, host.as_ref(), &policies, &config, target, out)
                .map_err(failed)?;
            return Ok(());
        }
        TargetCommand::SetEnabled(enabled) => {
            config.target_mut(target).enabled = Some(*enabled);
            save(context, &config)?;
            writeln!(
                out,
                "Dependency caches are {} for {slug}'s native runners started from now on.",
                if *enabled { "on" } else { "off" }
            )
            .map_err(failed)?;
        }
        TargetCommand::SetNamespace(args) => {
            if let Some(name) = &args.shared {
                dependency_cache::validate_namespace_name(name).map_err(cache_failure)?;
                config.target_mut(target).namespace = Some(name.clone());
                save(context, &config)?;
                writeln!(
                    out,
                    "{slug} now uses the shared cache `{name}`. Every policy naming it reads and \
                     writes the same files, so share only between repositories you trust \
                     equally."
                )
                .map_err(failed)?;
            } else {
                config.target_mut(target).namespace = None;
                save(context, &config)?;
                writeln!(out, "{slug} uses its own cache again.").map_err(failed)?;
            }
        }
        TargetCommand::SetTool(args) => {
            let id = known_tool(&args.tool)?;
            set_tool_state(&mut config.target_mut(target).tools, id, args.state);
            save(context, &config)?;
            let word = match args.state {
                CacheToolState::Default => "back to the host's setting".to_owned(),
                state => state_word(state, id),
            };
            writeln!(out, "{id} is {word} for {slug}.").map_err(failed)?;
        }
    }
    warn_without_policy(context, target, out)
}

/// A setting for a target this host has no policy for is kept, and said so:
/// it is most likely a typo.
fn warn_without_policy(
    context: &Context,
    target: &ScaleTarget,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let store = context.store()?;
    let known = store
        .policies()
        .map(|policies| {
            policies.iter().any(|policy| {
                dependency_cache::target_key(&policy.target) == dependency_cache::target_key(target)
            })
        })
        .unwrap_or(true);
    if !known {
        writeln!(
            out,
            "Note: this host has no policy for {}; the setting applies once one is added.",
            target.slug()
        )
        .map_err(write_failed("the dependency caches"))?;
    }
    Ok(())
}

fn write_target_show(
    context: &Context,
    host: Option<&Host>,
    policies: &[ScalePolicy],
    config: &CacheConfig,
    target: &ScaleTarget,
    out: &mut dyn Write,
) -> io::Result<()> {
    let platform = RunnerPlatform::current();
    let mut selection = dependency_cache::select(config, target, platform);
    // What the daemon defers to `runner.env`. The service's own environment
    // is not this process's, so only the file can be asked here.
    let runner_env = runner_manager_platform::runner_env::RunnerEnv::load(
        &runner_manager_platform::runner_env::path_in(context.paths().config_dir()),
    )
    .unwrap_or_default();
    selection.defer_to_operator(platform, |name| {
        runner_env
            .entries()
            .any(|(set, _)| set.eq_ignore_ascii_case(name))
    });
    writeln!(out, "Dependency caches for {}", target.slug())?;
    match selection.disabled {
        Some(why) => writeln!(out, "  state                     off: {why}")?,
        None => writeln!(out, "  state                     on")?,
    }
    let resolved = root(context, host, config);
    match &resolved {
        Ok(root) => writeln!(
            out,
            "  namespace                 {}",
            selection.namespace.dir(&root.path).display()
        )?,
        Err(why) => writeln!(
            out,
            "  namespace                 {} (no root: {why})",
            selection.namespace.label()
        )?,
    }
    let usage = resolved
        .as_ref()
        .ok()
        .and_then(|root| CacheUsage::read(&root.path))
        .and_then(|usage| {
            let label = selection.namespace.label();
            usage.namespaces.into_iter().find(|ns| ns.name == label)
        });
    if let Some(usage) = usage {
        writeln!(
            out,
            "  size                      {}{}",
            dependency_cache::human_bytes(usage.bytes),
            if usage.in_use { ", in use" } else { "" }
        )?;
    }
    let isolated = policies
        .iter()
        .filter(|policy| {
            dependency_cache::target_key(&policy.target) == dependency_cache::target_key(target)
        })
        .any(|policy| !policy.execution_policy().is_native());
    if isolated {
        writeln!(
            out,
            "  isolated profiles         get no caches; their providers mount no host directory"
        )?;
    }
    writeln!(out, "  caches:")?;
    for state in &selection.tools {
        let source = state.source.as_token();
        let names: Vec<&str> = state
            .tool
            .variables_on(platform)
            .map(|variable| variable.name)
            .collect();
        writeln!(
            out,
            "    {:<17} {:<4} ({source})  {}",
            state.tool.id,
            if state.enabled { "on" } else { "off" },
            names.join(", ")
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cache root this account may not write, as the cache root of a
    /// service running as another account is. `None` where the environment
    /// cannot express that (a test run as root ignores Unix permissions).
    fn unwritable_root() -> Option<(tempfile::TempDir, PathBuf, PathBuf)> {
        let base = tempfile::tempdir().unwrap();
        let state = base.path().join("state");
        let root = base.path().join("_cache");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(root.join("some-namespace")).unwrap();
        set_writable(&root, false);
        let refused = std::fs::write(root.join(dependency_cache::USAGE_FILE), b"{}").is_err();
        if !refused {
            set_writable(&root, true);
            eprintln!("this account can write anything, so a refusal cannot be staged here");
            return None;
        }
        Some((base, state, root))
    }

    /// Windows: a read-only usage file, which the atomic rename cannot
    /// replace. Unix: a read-only directory.
    fn set_writable(root: &Path, writable: bool) {
        #[cfg(windows)]
        {
            let usage = root.join(dependency_cache::USAGE_FILE);
            if !usage.exists() {
                std::fs::write(&usage, b"{}").unwrap();
            }
            let mut permissions = std::fs::metadata(&usage).unwrap().permissions();
            #[allow(
                clippy::permissions_set_readonly_false,
                reason = "the test undoes its own lock"
            )]
            permissions.set_readonly(!writable);
            std::fs::set_permissions(&usage, permissions).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = if writable { 0o755 } else { 0o555 };
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    /// Long enough for a stand-in service on a loaded machine to take the
    /// request: at 400 ms a full test run's load let it miss.
    const QUICK: Wait = Wait {
        taken: Duration::from_secs(2),
        finished: Duration::from_secs(20),
        poll: Duration::from_millis(20),
    };

    /// A stand-in service: it takes the request as the daemon does, and
    /// answers it with what `answer` returns, given the rights the asking
    /// account does not have.
    fn service_answering(
        state: &Path,
        root: &Path,
        answer: fn(&Path) -> Result<CacheUsage, String>,
    ) -> std::thread::JoinHandle<()> {
        let (state, root) = (state.to_path_buf(), root.to_path_buf());
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            let request = loop {
                if let Some(request) = dependency_cache::take_prune_request(&state) {
                    break request;
                }
                assert!(std::time::Instant::now() < deadline, "no request arrived");
                std::thread::sleep(Duration::from_millis(10));
            };
            set_writable(&root, true);
            dependency_cache::PruneResult {
                request,
                outcome: answer(&root),
            }
            .write(&state)
            .unwrap();
        })
    }

    #[test]
    fn a_root_this_account_cannot_write_is_pruned_by_the_running_service() {
        let Some((_base, state, root)) = unwritable_root() else {
            return;
        };
        let service = service_answering(&state, &root, |root| {
            dependency_cache::prune(root, None, &|_| false).map_err(|error| error.to_string())
        });

        let mut out = Vec::new();
        let usage = prune_root(&state, true, &root, None, QUICK, &mut out)
            .expect("the service pruned it")
            .expect("and reported back in time");
        service.join().unwrap();

        assert_eq!(
            Some(usage),
            CacheUsage::read(&root),
            "what is reported is the measurement the service just recorded"
        );
        let said = String::from_utf8(out).unwrap();
        assert!(said.contains("asking the service to prune it"), "{said}");
        assert!(!dependency_cache::prune_request_path(&state).exists());
    }

    #[test]
    fn a_service_that_cannot_prune_either_says_why_at_once() {
        let Some((_base, state, root)) = unwritable_root() else {
            return;
        };
        let service =
            service_answering(&state, &root, |_| Err("the root belongs to nobody".into()));
        let refusal = prune_root(&state, true, &root, None, QUICK, &mut Vec::new())
            .expect_err("the service could not either");
        service.join().unwrap();

        assert_eq!(refusal.class(), Failure::LocalState);
        assert!(
            refusal
                .to_string()
                .contains("the service could not either: the root belongs to nobody"),
            "{refusal}"
        );
        assert_eq!(refusal.remedy(), Some(elevated_remedy()));
    }

    #[test]
    fn a_root_this_account_cannot_write_with_no_service_running_names_both_remedies() {
        let Some((_base, state, root)) = unwritable_root() else {
            return;
        };
        let mut out = Vec::new();
        let refusal = prune_root(&state, true, &root, None, QUICK, &mut out)
            .expect_err("nobody took the request");
        set_writable(&root, true);

        assert_eq!(refusal.class(), Failure::LocalState);
        assert!(
            refusal
                .to_string()
                .contains("no running service took the request"),
            "{refusal}"
        );
        let remedy = refusal.remedy().expect("a remedy").to_string();
        assert!(remedy.contains("runner-manager service status"), "{remedy}");
        assert!(remedy.contains(elevated_remedy()), "{remedy}");
        assert!(
            !remedy.contains("service start"),
            "there is no `service start` command: {remedy}"
        );
        assert!(
            !dependency_cache::prune_request_path(&state).exists(),
            "a request nobody waits for is withdrawn"
        );
    }

    #[test]
    fn without_a_service_installed_from_these_directories_nothing_is_asked() {
        let Some((_base, state, root)) = unwritable_root() else {
            return;
        };
        let refusal = prune_root(&state, false, &root, None, QUICK, &mut Vec::new())
            .expect_err("nobody would see a request");
        set_writable(&root, true);

        assert!(
            refusal.to_string().contains("no service is installed"),
            "{refusal}"
        );
        assert_eq!(refusal.remedy(), Some(elevated_remedy()));
        assert!(!dependency_cache::prune_request_path(&state).exists());
    }

    #[test]
    fn the_table_describes_shared_and_per_runner_directories_distinctly() {
        assert_eq!(
            described_value(Sharing::Namespace, "nuget", VarValue::Sub("packages")),
            "<namespace>/nuget/packages"
        );
        assert_eq!(
            described_value(Sharing::Slot, "tool-cache", VarValue::Dir),
            "<namespace>/_slots/<n>/tool-cache"
        );
        assert_eq!(
            described_value(
                Sharing::Slot,
                "maven",
                VarValue::Template("-Dmaven.repo.local={dir}")
            ),
            "-Dmaven.repo.local=<namespace>/_slots/<n>/maven"
        );
    }

    #[test]
    fn the_status_line_names_usage_the_cap_and_the_root() {
        let mut snapshot = CacheSnapshot {
            enabled: true,
            root: Some("/rman/_cache".into()),
            root_source: Some("runner-root"),
            problem: None,
            max_bytes: Some(20 * 1024 * 1024 * 1024),
            used_bytes: None,
            namespaces: None,
            measured_at: None,
        };
        assert_eq!(
            snapshot.line(),
            "20.0 GiB cap at /rman/_cache, not measured yet"
        );
        snapshot.used_bytes = Some(3 * 1024 * 1024 * 1024 / 2);
        assert_eq!(snapshot.line(), "1.5 GiB of 20.0 GiB at /rman/_cache");
        snapshot.enabled = false;
        assert!(snapshot.line().starts_with("off"));
        snapshot.problem = Some("bad".into());
        assert_eq!(snapshot.line(), "unusable: bad");
    }
}
