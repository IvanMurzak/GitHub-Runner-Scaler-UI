//! Attempt-scoped Docker accounting for native Linux runners.
//!
//! The journal is outside the disposable workspace. Only creations passing
//! through the private proxy are attributed; absence of a container reference
//! or an old creation date is never evidence that a volume is ours.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use runner_manager_domain::model::{AttemptId, HostId};
use runner_manager_platform::process::ProcessIdentity;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod http;
#[cfg(target_os = "linux")]
mod proxy;
#[cfg(test)]
mod tests;

pub const HOST_LABEL: &str = "runner-manager.host";
pub const ATTEMPT_LABEL: &str = "runner-manager.attempt";
pub const OPERATION_LABEL: &str = "runner-manager.operation";
pub const RETAIN_LABEL: &str = "runner-manager.retain";
const SCHEMA: u32 = 1;
const PENDING_ENGINE: &str = "runner-manager-pending-engine";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Off,
    #[default]
    Report,
    Apply,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
}

impl Config {
    pub fn load(path: &Path) -> io::Result<Self> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(invalid),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DockerCleanup {
    pub host: HostId,
    pub root: PathBuf,
    pub config: PathBuf,
    /// Embedders may supply the manager binary that implements companion mode.
    pub companion: Option<PathBuf>,
}

impl DockerCleanup {
    pub fn new(host: HostId, config_dir: &Path, state_dir: &Path) -> Self {
        Self {
            host,
            root: state_dir.join("docker-cleanup"),
            config: config_dir.join("docker-cleanup.json"),
            companion: None,
        }
    }

    pub fn supported() -> bool {
        cfg!(target_os = "linux")
    }

    /// A remote endpoint or explicitly selected context stays under operator
    /// control. Dependency-cache environment variables are never changed.
    pub fn launch_environment(
        &self,
        attempt: AttemptId,
        repository: &str,
        host_env: &runner_manager_platform::runner_env::RunnerEnv,
    ) -> io::Result<Option<std::ffi::OsString>> {
        if !Self::supported() || Config::load(&self.config)?.mode == Mode::Off {
            return Ok(None);
        }
        let inherited = |name: &str| {
            host_env
                .entries()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.to_owned())
                .or_else(|| std::env::var(name).ok())
        };
        if inherited("DOCKER_CONTEXT").is_some_and(|value| !value.is_empty()) {
            tracing::info!(event="docker_accounting_bypassed",attempt_id=%attempt,reason="explicit_context");
            return Ok(None);
        }
        let selected_host = inherited("DOCKER_HOST");
        if selected_host.is_none() {
            let docker_config = inherited("DOCKER_CONFIG")
                .map(PathBuf::from)
                .or_else(|| inherited("HOME").map(|home| PathBuf::from(home).join(".docker")));
            if let Some(path) = docker_config.map(|directory| directory.join("config.json")) {
                match fs::read(path) {
                    Ok(bytes) => {
                        let value: Value = serde_json::from_slice(&bytes).map_err(invalid)?;
                        if value
                            .get("currentContext")
                            .and_then(Value::as_str)
                            .is_some_and(|context| !context.is_empty() && context != "default")
                        {
                            tracing::info!(event="docker_accounting_bypassed",attempt_id=%attempt,reason="stored_context");
                            return Ok(None);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        }
        let upstream = selected_host.unwrap_or_else(|| "unix:///var/run/docker.sock".into());
        let Some(socket) = upstream.strip_prefix("unix://") else {
            tracing::info!(event="docker_accounting_bypassed",attempt_id=%attempt,reason="remote_endpoint");
            return Ok(None);
        };
        let socket = PathBuf::from(socket);
        if !socket.is_absolute() {
            return Err(invalid("Docker Unix endpoint must be absolute"));
        }
        #[cfg(target_os = "linux")]
        {
            proxy::launch(self, attempt, repository, &socket)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (attempt, repository, socket);
            Ok(None)
        }
    }

    /// Authoritative attempt states are supplied by Store, never inferred from
    /// an absent workspace or a stale timestamp. Unknown attempts are retained.
    pub fn sweep(
        &self,
        attempts: &[runner_manager_domain::attempt::RunnerAttempt],
        dry_run: bool,
    ) -> io::Result<SweepReport> {
        self.sweep_with_lookup(
            &|id| Ok(attempts.iter().find(|attempt| attempt.id == id).cloned()),
            dry_run,
        )
    }

    /// Query only journalled attempt IDs rather than loading years of host history.
    pub fn sweep_with_lookup(
        &self,
        lookup: &dyn Fn(
            AttemptId,
        )
            -> io::Result<Option<runner_manager_domain::attempt::RunnerAttempt>>,
        dry_run: bool,
    ) -> io::Result<SweepReport> {
        #[cfg(target_os = "linux")]
        {
            proxy::sweep(self, lookup, dry_run)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (lookup, dry_run);
            Ok(SweepReport::default())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Container,
    Volume,
    Network,
}

impl Kind {
    fn collection(self) -> &'static str {
        match self {
            Self::Container => "containers",
            Self::Volume => "volumes",
            Self::Network => "networks",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub id: String,
    pub kind: Kind,
    /// Digests, not raw workflow paths: destinations can contain credentials.
    pub explicit_volume_destinations: BTreeSet<String>,
    pub inherits_volumes: bool,
    /// True only after Docker acknowledged creation and every association was
    /// durably captured. An ambiguous request must retain its recovery intent.
    pub settled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub kind: Kind,
    pub id: String,
    pub created: String,
    pub operation: String,
    /// Implicit image volumes do not inherit container labels. Their exact
    /// name + creation fingerprint are recorded before create returns.
    pub implicit_volume: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub schema: u32,
    pub host: HostId,
    pub attempt: AttemptId,
    pub repository: String,
    pub upstream: PathBuf,
    pub engine: String,
    pub proxy: Option<ProcessIdentity>,
    pub intents: Vec<Intent>,
    pub resources: Vec<Resource>,
    #[serde(default)]
    pub last_reported_secs: Option<u64>,
}

impl Journal {
    pub fn new(
        host: HostId,
        attempt: AttemptId,
        repository: String,
        upstream: PathBuf,
        engine: String,
    ) -> Self {
        Self {
            schema: SCHEMA,
            host,
            attempt,
            repository,
            upstream,
            engine,
            proxy: None,
            intents: Vec::new(),
            resources: Vec::new(),
            last_reported_secs: None,
        }
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.len() > 8 * 1024 * 1024 {
            return Err(invalid("invalid Docker journal file"));
        }
        let value: Self = serde_json::from_slice(&fs::read(path)?).map_err(invalid)?;
        if value.schema != SCHEMA
            || !value.upstream.is_absolute()
            || value.engine.is_empty()
            || (value.engine == PENDING_ENGINE
                && (!value.intents.is_empty()
                    || !value.resources.is_empty()
                    || value.proxy.is_some()))
            || value
                .intents
                .iter()
                .any(|intent| !valid_operation(&intent.id))
            || value
                .resources
                .iter()
                .any(|resource| !valid_id(&resource.id) || !valid_operation(&resource.operation))
        {
            return Err(invalid("invalid Docker journal identity"));
        }
        let operations: BTreeSet<_> = value
            .intents
            .iter()
            .map(|intent| intent.id.as_str())
            .collect();
        let resources: BTreeSet<_> = value
            .resources
            .iter()
            .map(|resource| (resource.kind.collection(), resource.id.as_str()))
            .collect();
        if operations.len() != value.intents.len()
            || resources.len() != value.resources.len()
            || (!value.intents.is_empty() && value.proxy.is_none())
            || value.intents.iter().any(|intent| {
                intent
                    .explicit_volume_destinations
                    .iter()
                    .any(|digest| !valid_id(digest))
                    || (intent.kind != Kind::Container
                        && (!intent.explicit_volume_destinations.is_empty()
                            || intent.inherits_volumes))
            })
            || value.resources.iter().any(|resource| {
                value
                    .intents
                    .iter()
                    .find(|intent| intent.id == resource.operation)
                    .is_none_or(|intent| {
                        if resource.implicit_volume {
                            resource.kind != Kind::Volume
                                || intent.kind != Kind::Container
                                || intent.inherits_volumes
                        } else {
                            resource.kind != intent.kind
                        }
                    })
            })
        {
            return Err(invalid("invalid Docker journal resource associations"));
        }
        Ok(value)
    }

    fn labels(&self, operation: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            (HOST_LABEL.into(), self.host.to_string()),
            (ATTEMPT_LABEL.into(), self.attempt.to_string()),
            (OPERATION_LABEL.into(), operation.into()),
        ])
    }
}

pub fn write_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("missing journal parent"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(temporary.as_file_mut(), value).map_err(invalid)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_operation(value: &str) -> bool {
    uuid::Uuid::try_parse(value).is_ok_and(|id| id.to_string() == value)
}

fn labels_of(value: &Value, kind: Kind) -> Value {
    match kind {
        Kind::Container => value.pointer("/Config/Labels"),
        _ => value.get("Labels"),
    }
    .cloned()
    .unwrap_or(Value::Null)
}

fn retained(labels: &Value) -> bool {
    labels.get(RETAIN_LABEL).and_then(Value::as_str) == Some("true")
}

/// Return an intent only for disposable creations. Explicit named volumes and
/// builder state are persistent by default, even if no container uses them now.
pub fn creation_intent(
    journal: &Journal,
    path: &str,
    body: &mut Value,
) -> io::Result<Option<Intent>> {
    let endpoint = path.split('?').next().unwrap_or(path);
    let kind = if endpoint.ends_with("/containers/create") {
        Kind::Container
    } else if endpoint.ends_with("/volumes/create") {
        Kind::Volume
    } else if endpoint.ends_with("/networks/create") {
        Kind::Network
    } else {
        return Ok(None);
    };
    let object = body
        .as_object_mut()
        .ok_or_else(|| invalid("expected Docker creation object"))?;
    let labels = object.get("Labels").cloned().unwrap_or(Value::Null);
    if retained(&labels) {
        return Ok(None);
    }
    if kind == Kind::Volume
        && object
            .get("Name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty())
    {
        return Ok(None);
    }
    let host_config = object.get("HostConfig").cloned().unwrap_or(Value::Null);
    let mounts = host_config.get("Mounts").and_then(Value::as_array);
    let name = path
        .split_once('?')
        .into_iter()
        .flat_map(|(_, query)| query.split('&'))
        .find_map(|field| field.strip_prefix("name="));
    // Buildx's docker-container driver uses a named state volume mounted here.
    // Preserve custom BuildKit images too, not only moby/buildkit tags.
    if kind == Kind::Container
        && (name.is_some_and(|name| name.starts_with("buildx_buildkit_"))
            || mounts.is_some_and(|mounts| {
                mounts.iter().any(|mount| {
                    mount.get("Target").and_then(Value::as_str) == Some("/var/lib/buildkit")
                })
            }))
    {
        return Ok(None);
    }
    let id = uuid::Uuid::new_v4().to_string();
    let mut owned = labels.as_object().cloned().unwrap_or_default();
    if !labels.is_null() && !labels.is_object() {
        return Err(invalid("invalid Docker labels"));
    }
    for (key, value) in journal.labels(&id) {
        if owned.contains_key(&key) {
            return Err(invalid("Docker ownership labels already supplied"));
        }
        owned.insert(key, Value::String(value));
    }
    object.insert("Labels".into(), Value::Object(owned));
    let mut explicit_volume_destinations = BTreeSet::new();
    if let Some(binds) = host_config.get("Binds").and_then(Value::as_array) {
        for bind in binds {
            let bind = bind
                .as_str()
                .ok_or_else(|| invalid("invalid Docker bind"))?;
            let parts: Vec<_> = bind.split(':').collect();
            if parts.len() >= 2 {
                explicit_volume_destinations.insert(destination_key(parts[1]));
            }
        }
    }
    if let Some(mounts) = mounts {
        for mount in mounts {
            if mount
                .get("Source")
                .and_then(Value::as_str)
                .is_some_and(|source| !source.is_empty())
            {
                let target = mount
                    .get("Target")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("missing mount target"))?;
                explicit_volume_destinations.insert(destination_key(target));
            }
        }
    }
    let inherits_volumes = host_config
        .get("VolumesFrom")
        .and_then(Value::as_array)
        .is_some_and(|from| !from.is_empty());
    Ok(Some(Intent {
        id,
        kind,
        explicit_volume_destinations,
        inherits_volumes,
        settled: false,
    }))
}

#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
}

/// Narrow Docker API port; cleanup never invokes global prune endpoints.
pub trait Engine {
    fn request(&self, method: &str, path: &str, body: Option<&Value>) -> io::Result<Reply>;
}

fn inspected(engine: &dyn Engine, kind: Kind, id: &str) -> io::Result<Option<Value>> {
    if !valid_id(id) {
        return Err(invalid("invalid Docker resource ID"));
    }
    let suffix = if kind == Kind::Container { "/json" } else { "" };
    let reply = engine.request("GET", &format!("/{}/{id}{suffix}", kind.collection()), None)?;
    match reply.status {
        404 => Ok(None),
        200 => Ok(Some(reply.body)),
        _ => Err(invalid("Docker inspection failed")),
    }
}

fn created(value: &Value) -> io::Result<String> {
    value
        .get("Created")
        .or_else(|| value.get("CreatedAt"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid("missing Docker creation fingerprint"))
}

fn matches_labels(journal: &Journal, intent: &Intent, labels: &Value) -> bool {
    !retained(labels)
        && journal
            .labels(&intent.id)
            .into_iter()
            .all(|(key, expected)| {
                labels.get(key).and_then(Value::as_str) == Some(expected.as_str())
            })
}

/// Record only exact owned IDs and implicit anonymous mounts not supplied by
/// the workflow. Called before releasing a successful create response.
pub fn capture_created(
    journal: &mut Journal,
    intent: &Intent,
    id: &str,
    engine: &dyn Engine,
) -> io::Result<()> {
    let Some(value) = inspected(engine, intent.kind, id)? else {
        return Ok(());
    };
    if !matches_labels(journal, intent, &labels_of(&value, intent.kind)) {
        return Err(invalid("Docker creation ownership mismatch"));
    }
    let resource = Resource {
        kind: intent.kind,
        id: id.into(),
        created: created(&value)?,
        operation: intent.id.clone(),
        implicit_volume: false,
    };
    add_resource(journal, resource);
    if intent.kind != Kind::Container || intent.inherits_volumes {
        return Ok(());
    }
    for mount in value
        .get("Mounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if mount.get("Type").and_then(Value::as_str) != Some("volume") {
            continue;
        }
        let destination = mount
            .get("Destination")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing volume destination"))?;
        if intent
            .explicit_volume_destinations
            .contains(&destination_key(destination))
        {
            continue;
        }
        let name = mount
            .get("Name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing volume name"))?;
        // Named volumes are never inferred as disposable from a mount.
        if !valid_id(name) {
            continue;
        }
        let Some(volume) = inspected(engine, Kind::Volume, name)? else {
            continue;
        };
        let labels = labels_of(&volume, Kind::Volume);
        if retained(&labels) || labels.get("com.docker.volume.anonymous").is_none() {
            continue;
        }
        add_resource(
            journal,
            Resource {
                kind: Kind::Volume,
                id: name.into(),
                created: created(&volume)?,
                operation: intent.id.clone(),
                implicit_volume: true,
            },
        );
    }
    Ok(())
}

fn add_resource(journal: &mut Journal, resource: Resource) {
    if !journal
        .resources
        .iter()
        .any(|known| known.kind == resource.kind && known.id == resource.id)
    {
        journal.resources.push(resource);
    }
}

fn destination_key(value: &str) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(value.as_bytes()))
}

#[derive(Debug, Default, Serialize)]
pub struct SweepReport {
    pub candidates: usize,
    pub removed: usize,
    pub pending: usize,
    pub protected: usize,
    pub details: Vec<ResourceDetail>,
    pub details_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceDetail {
    pub attempt: AttemptId,
    pub kind: Kind,
    pub id: String,
    pub outcome: &'static str,
}

impl SweepReport {
    fn detail(&mut self, journal: &Journal, resource: &Resource, outcome: &'static str) {
        self.append_details([ResourceDetail {
            attempt: journal.attempt,
            kind: resource.kind,
            id: resource.id.clone(),
            outcome,
        }]);
    }

    fn append_details(&mut self, details: impl IntoIterator<Item = ResourceDetail>) {
        for detail in details {
            if self.details.len() >= 1_000 {
                self.details_truncated = true;
                break;
            }
            self.details.push(detail);
        }
    }
}

/// Caller must prove the authoritative attempt is cleaned and the proxy gone.
/// Docker's unforced volume/network delete is the final atomic in-use check.
pub fn clean_resources(
    journal: &mut Journal,
    engine: &dyn Engine,
    mode: Mode,
) -> io::Result<SweepReport> {
    let mut report = SweepReport::default();
    if mode == Mode::Off {
        return Ok(report);
    }
    let info = engine.request("GET", "/info", None)?;
    if info.status != 200
        || info.body.get("ID").and_then(Value::as_str) != Some(journal.engine.as_str())
    {
        return Err(invalid("Docker engine identity changed; cleanup refused"));
    }
    let mut kept = Vec::new();
    // Containers precede volumes and networks, irrespective of creation order.
    journal
        .resources
        .sort_by_key(|resource| match resource.kind {
            Kind::Container => 0,
            Kind::Volume => 1,
            Kind::Network => 2,
        });
    for resource in &journal.resources {
        let Some(value) = inspected(engine, resource.kind, &resource.id)? else {
            continue;
        };
        let labels = labels_of(&value, resource.kind);
        let intent = journal
            .intents
            .iter()
            .find(|intent| intent.id == resource.operation)
            .ok_or_else(|| invalid("resource without creation intent"))?;
        let ownership = if resource.implicit_volume {
            resource.kind == Kind::Volume
                && !intent.inherits_volumes
                && labels.get("com.docker.volume.anonymous").is_some()
                && !retained(&labels)
        } else {
            matches_labels(journal, intent, &labels)
        };
        if !ownership || created(&value)? != resource.created {
            report.protected += 1;
            report.detail(journal, resource, "protected");
            kept.push(resource.clone());
            continue;
        }
        report.candidates += 1;
        if mode == Mode::Report {
            report.detail(journal, resource, "would_remove");
            kept.push(resource.clone());
            continue;
        }
        let suffix = if resource.kind == Kind::Container {
            "?force=true"
        } else {
            ""
        };
        let reply = engine.request(
            "DELETE",
            &format!("/{}/{}{suffix}", resource.kind.collection(), resource.id),
            None,
        )?;
        if matches!(reply.status, 200 | 204 | 404) {
            report.removed += 1;
            report.detail(journal, resource, "removed");
        } else {
            report.pending += 1;
            report.detail(journal, resource, "pending");
            kept.push(resource.clone());
        }
    }
    journal.resources = kept;
    Ok(report)
}

/// Handle the private companion invocation before the ordinary CLI. The only
/// argument is a local journal path, never a request body or credential.
pub fn internal_proxy_entry() -> Option<std::process::ExitCode> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--runner-manager-docker-proxy")) {
        return None;
    }
    let path = args.next().map(PathBuf::from);
    if args.next().is_some() || path.is_none() {
        return Some(std::process::ExitCode::FAILURE);
    }
    #[cfg(target_os = "linux")]
    let result = proxy::serve(path.as_deref().expect("checked"));
    #[cfg(not(target_os = "linux"))]
    let result: io::Result<()> = Err(invalid("Docker proxy requires native Linux"));
    Some(if result.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    })
}
