//! What a job may ask of the Docker engine through its proxy.
//!
//! Access to a Docker engine is access to `root`: a container can mount any
//! host directory, join the host's network or process namespaces, or run
//! privileged. Every native Linux job reaches the engine through its own
//! proxy, so the proxy is where those requests are seen. In [`Mode::Audit`]
//! each one is recorded and still forwarded; in [`Mode::Enforce`] it is
//! refused with the rule it broke.
//!
//! The rules are about the host and about other jobs, never about what a job
//! does inside its own containers:
//!
//! - a container may bind-mount only the job's own attempt directory, its
//!   dependency caches, and paths the operator allowed, each judged after the
//!   host resolves its links;
//! - no privileged container or exec, no added capability or device, no
//!   weakened security profile, and no host network, process, IPC, UTS, user
//!   or cgroup namespace;
//! - no volume bound to a host path and no network attached to the host's LAN;
//! - no request about a container another job, or the host, started;
//! - no host-wide prune, swarm, plugin or secret API.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The label the proxy puts on every container a job creates, naming the job's
/// attempt, so a later request can tell the job's containers from others.
pub const JOB_LABEL: &str = "runner-manager.job";

/// The policy's settings, in the configuration directory.
pub const CONFIG_FILE: &str = "docker-policy.json";

/// Where violations are recorded, under the state directory.
pub const LOG_DIR: &str = "docker-policy";
/// The violation log in [`LOG_DIR`], one JSON object per line.
pub const LOG_FILE: &str = "violations.jsonl";
/// The size at which the log is moved to `violations.jsonl.1`.
const LOG_ROTATE_BYTES: u64 = 1024 * 1024;

/// What the proxy does with a request that breaks a rule.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// No rule is checked.
    Off,
    /// Each violation is recorded, and the request still goes to the engine.
    #[default]
    Audit,
    /// A request with a violation is refused, and the violation recorded.
    Enforce,
}

impl Mode {
    /// The mode as `host docker-policy set-mode` spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Audit => "audit",
            Self::Enforce => "enforce",
        }
    }
}

/// The operator's settings.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,
    /// Host directories every job may bind-mount besides its own.
    #[serde(default)]
    pub allow: Vec<PathBuf>,
}

impl Config {
    /// The settings at `path`, or the defaults when there is no file.
    ///
    /// # Errors
    ///
    /// When the file cannot be read or does not parse.
    pub fn load(path: &Path) -> io::Result<Self> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(super::invalid),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error),
        }
    }

    /// Writes the settings to `path`.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        super::write_json(path, self)
    }
}

/// What one attempt's proxy enforces, fixed when the attempt launches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub mode: Mode,
    /// The directories a container may bind-mount from, already resolved.
    pub allowed: Vec<PathBuf>,
    /// Host paths the operator protected (`host protect-path`), already
    /// resolved: never mountable, even inside an allowed directory. The
    /// service's own sandbox hides them, but the engine runs outside it.
    #[serde(default)]
    pub protected: Vec<PathBuf>,
    /// The violation log.
    pub log: PathBuf,
}

/// Whether a container may bind-mount a host path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Allowed,
    /// Outside the job's own directories and the operator's allowed ones.
    Outside,
    /// A protected path, or one inside or above it.
    Protected,
}

impl Context {
    /// Whether a container may bind-mount `source`.
    #[must_use]
    pub fn access(&self, source: &Path) -> Access {
        let Some(resolved) = (source.is_absolute()
            && !source
                .components()
                .any(|component| matches!(component, Component::ParentDir)))
        .then(|| resolve(source))
        .flatten() else {
            return Access::Outside;
        };
        if self
            .protected
            .iter()
            .any(|protected| resolved.starts_with(protected) || protected.starts_with(&resolved))
        {
            Access::Protected
        } else if self.allowed.iter().any(|root| resolved.starts_with(root)) {
            Access::Allowed
        } else {
            Access::Outside
        }
    }
}

/// A rule a request broke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub rule: String,
    pub detail: String,
}

impl Violation {
    fn new(rule: &str, detail: impl Into<String>) -> Self {
        let mut detail = detail.into();
        if detail.len() > 300 {
            let mut end = 300;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        Self {
            rule: rule.to_owned(),
            detail,
        }
    }
}

/// One recorded violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub at: String,
    pub attempt: String,
    pub repository: String,
    pub rule: String,
    pub detail: String,
    /// Whether the request was refused.
    pub refused: bool,
}

/// Appends `records` to the log at `path`, moving a full log aside first.
///
/// # Errors
///
/// When the log cannot be written.
pub fn record(path: &Path, records: &[Record]) -> io::Result<()> {
    use std::io::Write as _;
    if records.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::metadata(path).is_ok_and(|metadata| metadata.len() > LOG_ROTATE_BYTES) {
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        fs::rename(path, rotated)?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    for record in records {
        let mut line = serde_json::to_vec(record).map_err(super::invalid)?;
        line.push(b'\n');
        file.write_all(&line)?;
    }
    Ok(())
}

/// Every record in the log at `path` and its rotated predecessor, oldest
/// first. A line that does not parse is skipped.
#[must_use]
pub fn read_records(path: &Path) -> Vec<Record> {
    let mut rotated = path.as_os_str().to_owned();
    rotated.push(".1");
    [PathBuf::from(rotated), path.to_path_buf()]
        .iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .flat_map(|text| {
            text.lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The API path without its version prefix: `/v1.47/containers/x/json`
/// becomes `/containers/x/json`.
#[must_use]
pub fn unversioned(endpoint: &str) -> &str {
    let rest = endpoint.strip_prefix('/').unwrap_or(endpoint);
    match rest.split_once('/') {
        Some((version, tail))
            if version.len() > 1
                && version.starts_with('v')
                && version[1..].chars().all(|c| c.is_ascii_digit() || c == '.') =>
        {
            &endpoint[endpoint.len() - tail.len() - 1..]
        }
        _ => endpoint,
    }
}

/// What a request acts on, when it is one container or exec instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    Container(&'a str),
    Exec(&'a str),
    None,
}

/// The container or exec instance an unversioned `endpoint` names.
#[must_use]
pub fn target(endpoint: &str) -> Target<'_> {
    let mut parts = endpoint.trim_start_matches('/').split('/');
    match (parts.next(), parts.next()) {
        (Some("containers"), Some(id)) if !matches!(id, "" | "create" | "json" | "prune") => {
            Target::Container(id)
        }
        (Some("exec"), Some(id)) if !id.is_empty() => Target::Exec(id),
        _ => Target::None,
    }
}

/// Rules an unversioned `endpoint` breaks by what it is, whatever its body.
#[must_use]
pub fn check_endpoint(method: &str, endpoint: &str, query: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let first = endpoint
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("");
    if matches!(
        first,
        "plugins" | "swarm" | "services" | "secrets" | "configs" | "nodes" | "tasks"
    ) {
        violations.push(Violation::new(
            "host_wide_api",
            format!("{method} {endpoint} acts on the engine itself"),
        ));
    }
    if method == "POST"
        && matches!(
            endpoint,
            "/containers/prune" | "/volumes/prune" | "/networks/prune"
        )
    {
        violations.push(Violation::new(
            "host_wide_prune",
            format!("{endpoint} removes what other jobs and the host created"),
        ));
    }
    if method == "POST"
        && endpoint == "/build"
        && query
            .split('&')
            .any(|field| field.eq_ignore_ascii_case("networkmode=host"))
    {
        violations.push(Violation::new(
            "host_network",
            "a build on the host's network",
        ));
    }
    violations
}

/// Rules a container-create `body` breaks. `allowed` says whether a host path
/// may be bind-mounted.
#[must_use]
pub fn check_container_create(body: &Value, allowed: &dyn Fn(&Path) -> Access) -> Vec<Violation> {
    let mut violations = Vec::new();
    let host = body.get("HostConfig").unwrap_or(&Value::Null);
    if host.get("Privileged").and_then(Value::as_bool) == Some(true) {
        violations.push(Violation::new("privileged", "a privileged container"));
    }
    for (key, rule) in [
        ("NetworkMode", "host_network"),
        ("PidMode", "host_pid"),
        ("IpcMode", "host_ipc"),
        ("UTSMode", "host_uts"),
        ("UsernsMode", "host_userns"),
        ("CgroupnsMode", "host_cgroupns"),
    ] {
        if host.get(key).and_then(Value::as_str) == Some("host") {
            violations.push(Violation::new(rule, format!("{key}=host")));
        }
    }
    if let Some(added) = host.get("CapAdd").and_then(Value::as_array)
        && !added.is_empty()
    {
        let names = added
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(",");
        violations.push(Violation::new(
            "added_capability",
            format!("CapAdd={names}"),
        ));
    }
    for key in ["Devices", "DeviceCgroupRules", "DeviceRequests"] {
        if host
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|devices| !devices.is_empty())
        {
            violations.push(Violation::new("host_device", format!("{key} is set")));
        }
    }
    if let Some(options) = host.get("SecurityOpt").and_then(Value::as_array) {
        for option in options.iter().filter_map(Value::as_str) {
            let lowered = option.to_ascii_lowercase();
            if lowered.contains("unconfined")
                || lowered == "label=disable"
                || lowered == "label:disable"
                || lowered.starts_with("no-new-privileges=false")
                || lowered.starts_with("no-new-privileges:false")
            {
                violations.push(Violation::new(
                    "weakened_security",
                    format!("SecurityOpt={option}"),
                ));
            }
        }
    }
    if let Some(binds) = host.get("Binds").and_then(Value::as_array) {
        for bind in binds.iter().filter_map(Value::as_str) {
            let source = bind.split(':').next().unwrap_or("");
            if source.starts_with('/') {
                check_host_path(Path::new(source), allowed, &mut violations);
            }
        }
    }
    if let Some(mounts) = host.get("Mounts").and_then(Value::as_array) {
        for mount in mounts {
            match mount.get("Type").and_then(Value::as_str) {
                Some("bind") => {
                    if let Some(source) = mount.get("Source").and_then(Value::as_str) {
                        check_host_path(Path::new(source), allowed, &mut violations);
                    }
                }
                Some("volume") => {
                    if let Some(device) = bound_device(
                        mount
                            .pointer("/VolumeOptions/DriverConfig/Options")
                            .unwrap_or(&Value::Null),
                    ) {
                        check_host_path(Path::new(device), allowed, &mut violations);
                    }
                }
                _ => {}
            }
        }
    }
    violations
}

/// The other containers a container-create `body` joins or borrows from:
/// `container:<id>` namespaces and `VolumesFrom`. Whether each is the job's
/// own is for the proxy to ask the engine.
#[must_use]
pub fn referenced_containers(body: &Value) -> Vec<String> {
    let host = body.get("HostConfig").unwrap_or(&Value::Null);
    let mut referenced = Vec::new();
    for key in ["NetworkMode", "PidMode", "IpcMode"] {
        if let Some(other) = host
            .get(key)
            .and_then(Value::as_str)
            .and_then(|mode| mode.strip_prefix("container:"))
        {
            referenced.push(other.to_owned());
        }
    }
    if let Some(sources) = host.get("VolumesFrom").and_then(Value::as_array) {
        referenced.extend(
            sources
                .iter()
                .filter_map(Value::as_str)
                .map(|source| source.split(':').next().unwrap_or(source).to_owned()),
        );
    }
    referenced
}

/// Rules an exec-create `body` breaks.
#[must_use]
pub fn check_exec_create(body: &Value) -> Vec<Violation> {
    if body.get("Privileged").and_then(Value::as_bool) == Some(true) {
        vec![Violation::new("privileged", "a privileged exec")]
    } else {
        Vec::new()
    }
}

/// Rules a volume-create `body` breaks.
#[must_use]
pub fn check_volume_create(body: &Value, allowed: &dyn Fn(&Path) -> Access) -> Vec<Violation> {
    let mut violations = Vec::new();
    if let Some(device) = bound_device(body.get("DriverOpts").unwrap_or(&Value::Null)) {
        check_host_path(Path::new(device), allowed, &mut violations);
    }
    violations
}

/// Rules a network-create `body` breaks.
#[must_use]
pub fn check_network_create(body: &Value) -> Vec<Violation> {
    match body.get("Driver").and_then(Value::as_str) {
        Some(driver @ ("macvlan" | "ipvlan")) => vec![Violation::new(
            "host_network",
            format!("a {driver} network on the host's LAN"),
        )],
        _ => Vec::new(),
    }
}

/// The host path a `local` volume's options bind, if they bind one.
fn bound_device(options: &Value) -> Option<&str> {
    let bind = options.get("o").and_then(Value::as_str).is_some_and(|o| {
        o.split(',')
            .any(|option| option == "bind" || option == "rbind")
    });
    options
        .get("device")
        .and_then(Value::as_str)
        .filter(|device| bind && device.starts_with('/'))
}

/// The engine sockets a container must never be handed: either one is the
/// whole engine, with none of these rules.
const ENGINE_SOCKETS: [&str; 2] = ["/var/run/docker.sock", "/run/docker.sock"];

fn check_host_path(
    source: &Path,
    allowed: &dyn Fn(&Path) -> Access,
    violations: &mut Vec<Violation>,
) {
    if ENGINE_SOCKETS
        .iter()
        .any(|socket| source == Path::new(socket))
    {
        violations.push(Violation::new(
            "engine_socket",
            format!("{} is the Docker engine itself", source.display()),
        ));
    } else if allowed(source) == Access::Protected {
        violations.push(Violation::new(
            "protected_path",
            format!("{} is a protected host path", source.display()),
        ));
    } else if allowed(source) == Access::Outside {
        violations.push(Violation::new(
            "host_path",
            format!("{} is outside the job's own directories", source.display()),
        ));
    }
}

/// Whether `source` lies inside one of `roots`, as the host will resolve it.
///
/// A path with `..` is refused outright. Otherwise the longest existing prefix
/// is resolved through every link on the host, so that a link the job left in
/// its own directory cannot point a mount anywhere else, and the rest is
/// appended as written: Docker creates a missing bind source as a directory.
#[must_use]
pub fn inside(source: &Path, roots: &[PathBuf]) -> bool {
    if !source.is_absolute()
        || source
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return false;
    }
    let Some(resolved) = resolve(source) else {
        return false;
    };
    roots.iter().any(|root| resolved.starts_with(root))
}

/// `path` with its longest existing prefix resolved through links.
#[must_use]
pub fn resolve(path: &Path) -> Option<PathBuf> {
    let mut existing = path.to_path_buf();
    let mut rest = Vec::new();
    loop {
        match fs::canonicalize(&existing) {
            Ok(mut resolved) => {
                for component in rest.iter().rev() {
                    resolved.push(component);
                }
                return Some(resolved);
            }
            Err(_) => {
                rest.push(existing.file_name()?.to_owned());
                existing = existing.parent()?.to_path_buf();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rules(violations: &[Violation]) -> Vec<&str> {
        violations
            .iter()
            .map(|violation| violation.rule.as_str())
            .collect()
    }

    #[test]
    fn the_version_prefix_is_dropped_and_targets_are_found() {
        assert_eq!(
            unversioned("/v1.47/containers/abc/json"),
            "/containers/abc/json"
        );
        assert_eq!(unversioned("/containers/abc/json"), "/containers/abc/json");
        assert_eq!(unversioned("/version"), "/version");
        assert_eq!(target("/containers/abc/exec"), Target::Container("abc"));
        assert_eq!(target("/containers/create"), Target::None);
        assert_eq!(target("/containers/json"), Target::None);
        assert_eq!(target("/exec/e1/start"), Target::Exec("e1"));
        assert_eq!(target("/images/json"), Target::None);
    }

    #[test]
    fn host_wide_endpoints_are_violations_and_ordinary_ones_are_not() {
        assert_eq!(
            rules(&check_endpoint("POST", "/swarm/init", "")),
            ["host_wide_api"]
        );
        assert_eq!(
            rules(&check_endpoint("POST", "/plugins/pull", "")),
            ["host_wide_api"]
        );
        assert_eq!(
            rules(&check_endpoint("POST", "/containers/prune", "")),
            ["host_wide_prune"]
        );
        assert_eq!(
            rules(&check_endpoint("POST", "/build", "t=x&networkmode=host")),
            ["host_network"]
        );
        assert!(check_endpoint("POST", "/build", "t=x").is_empty());
        assert!(check_endpoint("GET", "/containers/json", "").is_empty());
        assert!(check_endpoint("POST", "/images/create", "fromImage=x").is_empty());
    }

    #[test]
    fn a_container_that_reaches_for_the_host_breaks_each_rule_it_touches() {
        let body = json!({
            "HostConfig": {
                "Privileged": true,
                "NetworkMode": "host",
                "PidMode": "host",
                "CapAdd": ["SYS_ADMIN"],
                "Devices": [{"PathOnHost": "/dev/sda"}],
                "SecurityOpt": ["seccomp=unconfined"],
                "Binds": ["/etc:/host-etc:ro", "/var/run/docker.sock:/var/run/docker.sock", "named:/data"],
                "Mounts": [{"Type": "bind", "Source": "/root", "Target": "/r"}]
            }
        });
        let found = check_container_create(&body, &|_| Access::Outside);
        assert_eq!(
            rules(&found),
            [
                "privileged",
                "host_network",
                "host_pid",
                "added_capability",
                "host_device",
                "weakened_security",
                "host_path",
                "engine_socket",
                "host_path"
            ]
        );
    }

    #[test]
    fn an_ordinary_job_container_breaks_nothing() {
        let body = json!({
            "Image": "node:22",
            "HostConfig": {
                "NetworkMode": "bridge",
                "Binds": ["/attempt/_work:/__w", "/attempt/externals:/__e:ro", "cache:/cache"],
                "Mounts": [{"Type": "tmpfs", "Target": "/tmp"}]
            }
        });
        let found = check_container_create(&body, &|path| {
            if path.starts_with("/attempt") {
                Access::Allowed
            } else {
                Access::Outside
            }
        });
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn containers_a_new_one_joins_or_borrows_from_are_named() {
        let body = json!({"HostConfig": {
            "NetworkMode": "container:db",
            "PidMode": "host",
            "VolumesFrom": ["data:ro", "cache"]
        }});
        assert_eq!(referenced_containers(&body), ["db", "data", "cache"]);
    }

    #[test]
    fn volumes_and_networks_that_bind_the_host_are_violations() {
        let bound = json!({"Driver": "local", "DriverOpts": {"type": "none", "o": "bind", "device": "/srv/secret"}});
        assert_eq!(
            rules(&check_volume_create(&bound, &|_| Access::Outside)),
            ["host_path"]
        );
        assert!(check_volume_create(&json!({"Driver": "local"}), &|_| Access::Outside).is_empty());
        assert_eq!(
            rules(&check_network_create(&json!({"Driver": "macvlan"}))),
            ["host_network"]
        );
        assert!(check_network_create(&json!({"Driver": "bridge"})).is_empty());
        assert_eq!(
            rules(&check_exec_create(&json!({"Privileged": true}))),
            ["privileged"]
        );
        assert!(check_exec_create(&json!({"Cmd": ["sh"]})).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_inside_an_allowed_directory_does_not_carry_a_mount_outside_it() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let attempt = root.path().join("attempt");
        fs::create_dir_all(attempt.join("_work")).unwrap();
        std::os::unix::fs::symlink(outside.path(), attempt.join("escape")).unwrap();
        let roots = [fs::canonicalize(&attempt).unwrap()];
        assert!(inside(&attempt.join("_work"), &roots));
        assert!(inside(&attempt.join("_work/not/yet/created"), &roots));
        assert!(!inside(&attempt.join("escape"), &roots));
        assert!(!inside(&attempt.join("escape/inner"), &roots));
        assert!(!inside(&attempt.join("_work/../../etc"), &roots));
        assert!(!inside(Path::new("relative"), &roots));
    }

    #[cfg(unix)]
    #[test]
    fn a_protected_path_is_refused_even_inside_an_allowed_directory() {
        let root = tempfile::tempdir().unwrap();
        let shared = root.path().join("shared");
        fs::create_dir_all(shared.join("keys")).unwrap();
        fs::create_dir_all(shared.join("data")).unwrap();
        let context = Context {
            mode: Mode::Enforce,
            allowed: vec![fs::canonicalize(&shared).unwrap()],
            protected: vec![fs::canonicalize(shared.join("keys")).unwrap()],
            log: root.path().join("log"),
        };
        assert_eq!(context.access(&shared.join("data")), Access::Allowed);
        assert_eq!(context.access(&shared.join("keys/id")), Access::Protected);
        assert_eq!(
            context.access(&shared),
            Access::Protected,
            "a parent exposes it too"
        );
        assert_eq!(context.access(Path::new("/etc")), Access::Outside);
        let body =
            json!({"HostConfig": {"Binds": [format!("{}:/k", shared.join("keys").display())]}});
        assert_eq!(
            rules(&check_container_create(&body, &|path| context.access(path))),
            ["protected_path"]
        );
    }

    #[test]
    fn records_round_trip_through_a_rotating_log() {
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join(LOG_DIR).join(LOG_FILE);
        let entry = Record {
            at: "2026-11-10T00:00:00Z".into(),
            attempt: "a".into(),
            repository: "o/r".into(),
            rule: "privileged".into(),
            detail: "a privileged container".into(),
            refused: false,
        };
        record(&log, std::slice::from_ref(&entry)).unwrap();
        record(&log, std::slice::from_ref(&entry)).unwrap();
        assert_eq!(read_records(&log), [entry.clone(), entry]);
    }
}
