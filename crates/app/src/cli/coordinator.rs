// owner: coordinator-stage1

//! `coordinator join | status | leave`, and the daemon's link to a joined
//! coordinator (`.taskflow/2026-11-07-coordinator-server`, stage 1).
//!
//! # What the link may and may not do
//!
//! The coordinator only ever says "poll this target now". The daemon then
//! polls it exactly as it would have at its next interval — same demand
//! computation, same allocator, same ceilings — just sooner. Three limits keep
//! a wake from becoming a way around the poll schedule:
//!
//! * a woken target is polled no sooner than [`WAKE_MIN_GAP`] after its last
//!   poll began;
//! * a wake is not honoured while the target's pace is a slowdown (rate
//!   limited, stretched, offline, locked out, blocked) — the schedule GitHub
//!   asked for stands;
//! * the shared demand gateway's host-wide rate-limit quiet period still
//!   withholds every request inside it.
//!
//! Without a joined coordinator, or while the link is down, nothing here
//! changes how the daemon polls (D1: standalone and fallback are today's
//! behaviour).
//!
//! # Secrets
//!
//! The host's Ed25519 private key is generated at `join` and goes straight
//! into the secret store the GitHub credential uses
//! ([`SecretItem::CoordinatorKey`]); it never touches disk in the clear, a
//! log, an argument, or command output. The one-time invite code is spent at
//! `join` and not kept. Logs carry fixed words, counts and this host's own
//! configuration — never text that came off the wire.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::{SinkExt as _, StreamExt as _};
use runner_manager_coordinator_protocol::{
    CLOSE_UNAUTHORIZED, CLOSE_UNSUPPORTED_VERSION, CoordinatorUrl, EnrollRequest, EnrollResponse,
    Heartbeat, Hello, HostMessage, HostSigningKey, PROTOCOL_VERSION, Profile, ServerMessage,
    Target, TargetRef, TargetScope, Wake, decode_nonce, decode_signing_key, encode_public_key,
    encode_signing_key, sign_challenge, signing_key_from_seed,
};
use runner_manager_domain::attempt::active_count;
use runner_manager_domain::model::{OwnerRepo, ScaleTarget, StartMode};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::Store;
use runner_manager_github::demand::RestDemand;
use runner_manager_platform::coordinator::{self as records, CoordinatorConfig, LinkRecord};
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::secrets::{SecretItem, SecretStore};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite;

use super::{CliError, Context, CoordinatorCommand, Failure, write_failed};

/// The shortest gap between the start of a target's last poll and a
/// wake-triggered one.
pub const WAKE_MIN_GAP: Duration = Duration::from_secs(5);

/// The daemon's link record older than this is not believed: a running daemon
/// rewrites it at least every heartbeat or reconnect attempt.
const LINK_STALE_AFTER: Duration = Duration::from_secs(3 * 60);

/// How long `join` waits for the coordinator.
const ENROLL_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the link waits for each step of the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// The heartbeat interval until the coordinator names one.
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(15);

/// Reconnect back-off: first wait, cap, and the cap after a refusal.
const RECONNECT_FIRST: Duration = Duration::from_secs(1);
const RECONNECT_CAP: Duration = Duration::from_secs(60);
const REJECTED_CAP: Duration = Duration::from_secs(5 * 60);
/// A session that lasted this long resets the back-off.
const STABLE_SESSION: Duration = Duration::from_secs(60);
/// How often an unconfigured daemon looks for a `coordinator join`.
const CONFIG_RECHECK: Duration = Duration::from_secs(15);

/// Version of `coordinator status --json`.
const STATUS_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub fn dispatch(
    context: &Context,
    command: &CoordinatorCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        CoordinatorCommand::Join(args) => join(context, &args.url, &args.code, out),
        CoordinatorCommand::Status(args) => status(context, args.json, out),
        CoordinatorCommand::Leave => leave(context, out),
    }
}

fn local_state(source: impl std::fmt::Display) -> CliError {
    CliError::new(
        Failure::LocalState,
        format!("cannot read or write the coordinator setting: {source}"),
    )
}

fn unavailable(detail: impl Into<String>) -> CliError {
    CliError::with_remedy(
        Failure::CoordinatorUnavailable,
        detail,
        "check the URL and this machine's network, then run the same `coordinator join` again",
    )
}

fn key_store(context: &Context, mode: StartMode) -> Result<Arc<dyn SecretStore>, CliError> {
    context.secret_store_for(mode, SecretItem::CoordinatorKey)
}

fn join(context: &Context, url: &str, code: &str, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("the join report");
    let url = CoordinatorUrl::parse(url).map_err(|error| {
        CliError::new(
            Failure::InvalidArgument,
            format!("`coordinator join` needs the coordinator's https URL: {error}"),
        )
    })?;
    if let Some(existing) = records::configured(context.paths()).map_err(local_state)? {
        return Err(CliError::with_remedy(
            Failure::Conflict,
            format!(
                "this host already joined {} as {}",
                existing.url, existing.name
            ),
            "runner-manager coordinator leave, then join again",
        ));
    }
    let store = context.store()?;
    let mode = context.recorded_start_mode(&store)?;
    let hostname = super::host::local_host(&store)?
        .map_or_else(|| String::from("unknown"), |host| host.display_name);
    let secrets = key_store(context, mode)?;
    // Before the code is spent: a code burned on a host that cannot keep the
    // key is a code the operator has to issue again.
    secrets.ensure_writable().map_err(|source| {
        CliError::with_remedy(
            Failure::SecretStore,
            format!("this account cannot write the {mode}-mode secret store: {source}"),
            "run the same command with administrator rights (sudo, or an elevated terminal)",
        )
    })?;

    let key = signing_key_from_seed(&rand::random::<[u8; 32]>());
    let request = EnrollRequest {
        protocol_version: PROTOCOL_VERSION,
        code: code.trim().to_string(),
        hostname,
        public_key: encode_public_key(&key.verifying_key()),
    };
    let enrolled = super::runtime()?.block_on(enroll(&url, &request))?;

    secrets
        .store(&SecretString::from(encode_signing_key(&key)))
        .map_err(|source| {
            CliError::new(
                Failure::SecretStore,
                format!(
                    "the coordinator enrolled this host, but its key could not be stored: \
                     {source}; ask the coordinator's operator to revoke host {} and issue a new \
                     invite",
                    enrolled.host_id
                ),
            )
        })?;
    let config = CoordinatorConfig::new(
        url.origin(),
        enrolled.host_id.clone(),
        enrolled.name.clone(),
        context.clock().now(),
    );
    records::save(context.paths(), &config).map_err(local_state)?;
    writeln!(
        out,
        "joined {} as {} (host id {}); the service connects within {} seconds",
        config.url,
        config.name,
        config.host_id,
        CONFIG_RECHECK.as_secs()
    )
    .map_err(failed)?;
    writeln!(
        out,
        "the private key is in {}; nothing else changed",
        secrets.location()
    )
    .map_err(failed)?;
    Ok(())
}

async fn enroll(url: &CoordinatorUrl, request: &EnrollRequest) -> Result<EnrollResponse, CliError> {
    let client = reqwest::Client::builder()
        .timeout(ENROLL_TIMEOUT)
        .build()
        .map_err(|_| unavailable("cannot prepare an HTTPS client"))?;
    let response = client
        .post(url.enroll_url())
        .json(request)
        .send()
        .await
        .map_err(|_| unavailable(format!("{url} could not be reached")))?;
    match response.status().as_u16() {
        200 => response.json::<EnrollResponse>().await.map_err(|_| {
            unavailable(format!(
                "{url} answered with something that is not an enrollment"
            ))
        }),
        401 => Err(CliError::with_remedy(
            Failure::InvalidArgument,
            "the coordinator refused the code: it is unknown, already used, or expired",
            "ask for a new one: runner-manager-coordinator invite --name NAME",
        )),
        426 => Err(CliError::with_remedy(
            Failure::UnsupportedHost,
            "the coordinator speaks a different protocol version",
            "update runner-manager, or the coordinator, so both are current",
        )),
        429 => Err(unavailable(
            "the coordinator is limiting attempts from this address; wait a minute",
        )),
        status => Err(unavailable(format!("{url} answered HTTP {status}"))),
    }
}

fn leave(context: &Context, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("the leave report");
    let Some(config) = records::configured(context.paths()).map_err(local_state)? else {
        writeln!(out, "this host has not joined a coordinator").map_err(failed)?;
        return Ok(());
    };
    let store = context.store()?;
    let mode = context.recorded_start_mode(&store)?;
    // The key first: a setting left behind with no key is retried by `leave`;
    // a key left behind with no setting would be found by nothing.
    key_store(context, mode)?.delete().map_err(|source| {
        CliError::with_remedy(
            Failure::SecretStore,
            format!("the coordinator key could not be removed: {source}"),
            "run the same command with administrator rights (sudo, or an elevated terminal)",
        )
    })?;
    records::forget(context.paths()).map_err(local_state)?;
    writeln!(
        out,
        "left {}; the service disconnects within {} seconds and polls on its own as before",
        config.url,
        DEFAULT_HEARTBEAT.as_secs()
    )
    .map_err(failed)?;
    writeln!(
        out,
        "on the coordinator, revoke it with: runner-manager-coordinator hosts revoke {}",
        config.host_id
    )
    .map_err(failed)?;
    Ok(())
}

fn status(context: &Context, json: bool, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("the coordinator status");
    let snapshot = CoordinatorSnapshot::read(context.paths(), context.clock().now());
    if json {
        #[derive(Serialize)]
        struct Document<'a> {
            schema_version: u32,
            #[serde(flatten)]
            coordinator: &'a CoordinatorSnapshot,
        }
        serde_json::to_writer_pretty(
            &mut *out,
            &Document {
                schema_version: STATUS_SCHEMA_VERSION,
                coordinator: &snapshot,
            },
        )
        .map_err(|error| CliError::new(Failure::LocalState, error.to_string()))?;
        writeln!(out).map_err(failed)?;
        return Ok(());
    }
    writeln!(out, "Coordinator: {}", snapshot.describe()).map_err(failed)?;
    if let (Some(name), Some(id)) = (&snapshot.name, &snapshot.host_id) {
        writeln!(out, "  this host     {name} (id {id})").map_err(failed)?;
    }
    if snapshot.configured {
        let wake = snapshot
            .last_wake_at
            .map_or_else(|| "none yet".to_string(), |at| at.to_rfc3339());
        writeln!(
            out,
            "  wakes         {} since the service started; last {wake}",
            snapshot.wakes_received
        )
        .map_err(failed)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The snapshot `status`, `host doctor` and the TUI show
// ---------------------------------------------------------------------------

/// The link's state, as one word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    NotConfigured,
    Connected,
    Disconnected,
    /// Joined, but no running daemon has reported the link recently.
    Unknown,
}

/// What this host knows about its coordinator, read from disk only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorSnapshot {
    pub configured: bool,
    pub url: Option<String>,
    pub host_id: Option<String>,
    pub name: Option<String>,
    pub link: LinkState,
    /// Since when the link has been in `link`'s state.
    pub since: Option<DateTime<Utc>>,
    /// Why it is down, as a fixed word.
    pub reason: Option<String>,
    pub last_wake_at: Option<DateTime<Utc>>,
    pub wakes_received: u64,
    /// The setting exists and could not be read.
    pub unreadable: Option<String>,
}

impl CoordinatorSnapshot {
    /// A host that has not joined a coordinator.
    #[must_use]
    pub const fn not_configured() -> Self {
        Self {
            configured: false,
            url: None,
            host_id: None,
            name: None,
            link: LinkState::NotConfigured,
            since: None,
            reason: None,
            last_wake_at: None,
            wakes_received: 0,
            unreadable: None,
        }
    }

    #[must_use]
    pub fn read(paths: &AppPaths, now: DateTime<Utc>) -> Self {
        let mut snapshot = Self::not_configured();
        let config = match records::configured(paths) {
            Ok(Some(config)) => config,
            Ok(None) => return snapshot,
            Err(error) => {
                snapshot.unreadable = Some(error.to_string());
                snapshot.link = LinkState::Unknown;
                return snapshot;
            }
        };
        snapshot.configured = true;
        snapshot.url = Some(config.url);
        snapshot.host_id = Some(config.host_id);
        snapshot.name = Some(config.name);
        snapshot.link = LinkState::Unknown;
        let link = records::last_link(paths).ok().flatten();
        if let Some(link) = link {
            snapshot.last_wake_at = link.last_wake_at;
            snapshot.wakes_received = link.wakes_received;
            let fresh = now
                .signed_duration_since(link.written_at)
                .to_std()
                .is_ok_and(|age| age < LINK_STALE_AFTER);
            if fresh {
                snapshot.link = if link.connected {
                    LinkState::Connected
                } else {
                    LinkState::Disconnected
                };
                snapshot.since = link.since;
                snapshot.reason = link.reason;
            }
        }
        snapshot
    }

    /// One line for a person.
    #[must_use]
    pub fn describe(&self) -> String {
        let url = self.url.as_deref().unwrap_or("the coordinator");
        let since = |prefix: &str| {
            self.since
                .map_or_else(String::new, |at| format!(" {prefix} {}", at.to_rfc3339()))
        };
        match (self.link, &self.unreadable) {
            (_, Some(error)) => format!("the setting could not be read: {error}"),
            (LinkState::NotConfigured, _) => {
                "not configured; this host polls GitHub on its own".to_string()
            }
            (LinkState::Connected, _) => format!("connected to {url}{}", since("since")),
            (LinkState::Disconnected, _) => format!(
                "disconnected from {url}{}{}; polling on its own meanwhile",
                since("since"),
                self.reason
                    .as_deref()
                    .map_or_else(String::new, |reason| format!(
                        " ({})",
                        reason.replace('_', " ")
                    ))
            ),
            (LinkState::Unknown, _) => {
                format!("joined {url}; the service has not reported its link recently")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Wake routing and throttling
// ---------------------------------------------------------------------------

/// The moment a wake may move a target's next poll to: no later than it was
/// already scheduled, and no sooner than [`WAKE_MIN_GAP`] after the last poll
/// began.
#[must_use]
pub fn woken_deadline(
    scheduled: tokio::time::Instant,
    last_poll: tokio::time::Instant,
    now: tokio::time::Instant,
) -> tokio::time::Instant {
    scheduled.min((last_poll + WAKE_MIN_GAP).max(now))
}

/// One target's wake signal, shared between the link and its loop.
#[derive(Debug)]
pub struct WakeRoute {
    pub target: ScaleTarget,
    pub notify: Arc<Notify>,
}

/// Every target loop's wake signal, and the gateway whose shared readings a
/// wake invalidates.
#[derive(Debug, Default)]
pub struct WakeRoutes {
    routes: Vec<WakeRoute>,
    demand: Option<Arc<RestDemand>>,
}

impl WakeRoutes {
    #[must_use]
    pub fn new(demand: Option<Arc<RestDemand>>) -> Self {
        Self {
            routes: Vec::new(),
            demand,
        }
    }

    /// Registers `target` and returns its signal.
    pub fn add(&mut self, target: ScaleTarget) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        self.routes.push(WakeRoute {
            target,
            notify: Arc::clone(&notify),
        });
        notify
    }

    /// Delivers `wake`; `true` when a local target took it.
    pub fn deliver(&self, wake: &Wake) -> bool {
        let Some(route) = self
            .routes
            .iter()
            .find(|route| same_target(&route.target, &wake.target))
        else {
            return false;
        };
        if let (Some(demand), Ok(repository)) = (&self.demand, OwnerRepo::parse(&wake.repository))
            && wake.target.covers(&wake.repository)
        {
            demand.forget_shared_reading(&repository);
        }
        route.notify.notify_one();
        tracing::info!(target = %route.target, "the coordinator woke a target; polling it now");
        true
    }
}

fn same_target(local: &ScaleTarget, remote: &TargetRef) -> bool {
    match (local, remote.scope) {
        (ScaleTarget::Repository(repository), TargetScope::Repo) => {
            repository.to_string().eq_ignore_ascii_case(&remote.name)
        }
        (ScaleTarget::Organization(org), TargetScope::Org) => {
            org.to_string().eq_ignore_ascii_case(&remote.name)
        }
        _ => false,
    }
}

fn target_ref(target: &ScaleTarget) -> (TargetScope, String) {
    match target {
        ScaleTarget::Repository(repository) => (TargetScope::Repo, repository.to_string()),
        ScaleTarget::Organization(org) => (TargetScope::Org, org.to_string()),
    }
}

/// The targets and profiles this host advertises: its autoscale policies.
#[must_use]
pub fn advertised_targets(policies: &[ScalePolicy]) -> Vec<Target> {
    let mut targets: Vec<Target> = Vec::new();
    for policy in policies {
        let Some(labels) = policy.routing_labels() else {
            continue;
        };
        let (scope, name) = target_ref(&policy.target);
        let profile = Profile {
            name: policy.profile_name().to_string(),
            labels: labels.as_registration_labels(),
            enabled: policy.may_start_runners(),
        };
        match targets
            .iter_mut()
            .find(|target| target.scope == scope && target.name == name)
        {
            Some(target) => target.profiles.push(profile),
            None => targets.push(Target {
                scope,
                name,
                profiles: vec![profile],
            }),
        }
    }
    targets
}

// ---------------------------------------------------------------------------
// The daemon's link
// ---------------------------------------------------------------------------

/// What the link reads about this host to describe it.
pub struct LinkPorts {
    pub paths: AppPaths,
    pub key_store: Arc<dyn SecretStore>,
    pub store: Arc<dyn Store>,
    pub routes: Arc<WakeRoutes>,
    pub unfit: Arc<AtomicBool>,
    pub draining: Arc<AtomicBool>,
    pub host: runner_manager_domain::model::Host,
    /// Where runners work, for the free-disk figure.
    pub runner_root: std::path::PathBuf,
}

/// Why one session ended, as fixed words for the link record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionEnd {
    /// The setting changed or was removed; reconnect at once.
    Reconfigured,
    Unreachable,
    Rejected,
    UnsupportedVersion,
    Closed,
    NoKey,
}

impl SessionEnd {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reconfigured => "reconfigured",
            Self::Unreachable => "unreachable",
            Self::Rejected => "rejected",
            Self::UnsupportedVersion => "unsupported_version",
            Self::Closed => "closed",
            Self::NoKey => "no_key",
        }
    }
}

/// The link's record on disk, kept in step with the session.
struct Recorder {
    paths: AppPaths,
    record: LinkRecord,
}

impl Recorder {
    fn write(&mut self) {
        self.record.written_at = Utc::now();
        if let Err(error) = records::record_link(&self.paths, &self.record) {
            tracing::warn!(%error, "cannot record the coordinator link state");
        }
    }

    fn connected(&mut self) {
        self.record.connected = true;
        self.record.since = Some(Utc::now());
        self.record.reason = None;
        self.write();
    }

    fn disconnected(&mut self, end: SessionEnd) {
        if self.record.connected || self.record.since.is_none() {
            self.record.since = Some(Utc::now());
        }
        self.record.connected = false;
        self.record.reason = Some(end.as_str().to_string());
        self.write();
    }

    fn woke(&mut self) {
        self.record.wakes_received = self.record.wakes_received.saturating_add(1);
        self.record.last_wake_at = Some(Utc::now());
        self.write();
    }
}

/// Keeps the link up while this host has joined a coordinator. Never returns.
pub async fn maintain_link(ports: LinkPorts) {
    let tls = tls_config();
    let mut recorder = Recorder {
        paths: ports.paths.clone(),
        record: LinkRecord::new(Utc::now()),
    };
    let mut backoff = RECONNECT_FIRST;
    loop {
        let config = match records::configured(&ports.paths) {
            Ok(Some(config)) => config,
            Ok(None) => {
                tokio::time::sleep(CONFIG_RECHECK).await;
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, "the coordinator setting could not be read");
                tokio::time::sleep(CONFIG_RECHECK).await;
                continue;
            }
        };
        let started = tokio::time::Instant::now();
        let end = session(&ports, &config, tls.clone(), &mut recorder).await;
        recorder.disconnected(end);
        tracing::info!(reason = end.as_str(), "the coordinator link ended");
        if end == SessionEnd::Reconfigured {
            backoff = RECONNECT_FIRST;
            continue;
        }
        if started.elapsed() >= STABLE_SESSION {
            backoff = RECONNECT_FIRST;
        }
        let cap = match end {
            SessionEnd::Rejected | SessionEnd::UnsupportedVersion | SessionEnd::NoKey => {
                REJECTED_CAP
            }
            _ => RECONNECT_CAP,
        };
        backoff = backoff.min(cap);
        tokio::time::sleep(jittered(backoff)).await;
        backoff = backoff.saturating_mul(2).min(cap);
    }
}

/// `delay` plus up to half of it again, so a fleet does not reconnect in step.
fn jittered(delay: Duration) -> Duration {
    delay.saturating_add(delay.mul_f64(rand::random::<f64>() * 0.5))
}

fn tls_config() -> Option<Arc<rustls::ClientConfig>> {
    use rustls_platform_verifier::ConfigVerifierExt as _;
    match rustls::ClientConfig::with_platform_verifier() {
        Ok(config) => Some(Arc::new(config)),
        Err(error) => {
            tracing::warn!(%error, "the platform certificate verifier is unavailable");
            None
        }
    }
}

fn load_key(store: &dyn SecretStore) -> Option<HostSigningKey> {
    let secret = store.load().ok().flatten()?;
    decode_signing_key(secret.expose_secret()).ok()
}

fn hello(ports: &LinkPorts, host_id: &str) -> Hello {
    let policies: Vec<ScalePolicy> = ports
        .store
        .policies()
        .unwrap_or_default()
        .into_iter()
        .filter(|policy| policy.routing_labels().is_some())
        .collect();
    Hello {
        protocol_version: PROTOCOL_VERSION,
        host_id: host_id.to_string(),
        os: ports.host.os.to_string(),
        arch: ports.host.architecture.to_string(),
        cores: std::thread::available_parallelism()
            .ok()
            .and_then(|cores| u32::try_from(cores.get()).ok())
            .unwrap_or(1),
        ram_bytes: runner_manager_platform::host_fitness::physical_memory_bytes(),
        disk_free_bytes: runner_manager_platform::host_fitness::free_disk_bytes(&ports.runner_root),
        targets: advertised_targets(&policies),
    }
}

fn heartbeat(ports: &LinkPorts) -> Heartbeat {
    let busy = ports
        .store
        .attempts()
        .map_or(0, |attempts| active_count(attempts.iter()));
    Heartbeat {
        free_slots: u32::from(ports.host.host_capacity.get().saturating_sub(busy)),
        busy_slots: u32::from(busy),
        cpu_load_percent: runner_manager_platform::host_fitness::cpu_load_percent(),
        free_ram_bytes: runner_manager_platform::host_fitness::available_memory_bytes(),
        unfit: ports.unfit.load(Ordering::Relaxed),
        draining: ports.draining.load(Ordering::Relaxed),
    }
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The next text frame, or how the socket ended.
async fn next_text(socket: &mut Socket) -> Result<String, SessionEnd> {
    loop {
        match socket.next().await {
            Some(Ok(tungstenite::Message::Text(text))) => return Ok(text.to_string()),
            Some(Ok(tungstenite::Message::Close(frame))) => {
                return Err(match frame.map(|frame| u16::from(frame.code)) {
                    Some(CLOSE_UNAUTHORIZED) => SessionEnd::Rejected,
                    Some(CLOSE_UNSUPPORTED_VERSION) => SessionEnd::UnsupportedVersion,
                    _ => SessionEnd::Closed,
                });
            }
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return Err(SessionEnd::Closed),
        }
    }
}

/// [`next_text`], bounded by [`HANDSHAKE_TIMEOUT`].
async fn next_text_within(socket: &mut Socket) -> Result<String, SessionEnd> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, next_text(socket))
        .await
        .map_err(|_| SessionEnd::Closed)?
}

async fn send(socket: &mut Socket, message: &HostMessage) -> Result<(), SessionEnd> {
    socket
        .send(tungstenite::Message::Text(message.encode().into()))
        .await
        .map_err(|_| SessionEnd::Closed)
}

/// One connection, from handshake to whatever ends it.
async fn session(
    ports: &LinkPorts,
    config: &CoordinatorConfig,
    tls: Option<Arc<rustls::ClientConfig>>,
    recorder: &mut Recorder,
) -> SessionEnd {
    let Ok(url) = CoordinatorUrl::parse(&config.url) else {
        return SessionEnd::Unreachable;
    };
    let Some(key) = load_key(ports.key_store.as_ref()) else {
        return SessionEnd::NoKey;
    };
    let socket_config = tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(runner_manager_coordinator_protocol::MAX_MESSAGE_BYTES))
        .max_frame_size(Some(runner_manager_coordinator_protocol::MAX_MESSAGE_BYTES));
    let connector = tls.map(tokio_tungstenite::Connector::Rustls);
    let connected = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::connect_async_tls_with_config(
            url.connect_url(),
            Some(socket_config),
            true,
            connector,
        ),
    )
    .await;
    let Ok(Ok((mut socket, _))) = connected else {
        return SessionEnd::Unreachable;
    };
    match handshake(&mut socket, &url, &config.host_id, &key).await {
        Ok(interval) => {
            drop(key);
            recorder.connected();
            tracing::info!(coordinator = %url, "connected to the coordinator");
            serve(&mut socket, ports, config, interval, recorder).await
        }
        Err(end) => end,
    }
}

/// Challenge, signature, welcome. Returns the heartbeat interval.
async fn handshake(
    socket: &mut Socket,
    url: &CoordinatorUrl,
    host_id: &str,
    key: &HostSigningKey,
) -> Result<Duration, SessionEnd> {
    let challenge = next_text_within(socket).await?;
    let Ok(ServerMessage::Challenge {
        protocol_version,
        nonce,
    }) = ServerMessage::decode(&challenge)
    else {
        return Err(SessionEnd::Closed);
    };
    if protocol_version != PROTOCOL_VERSION {
        return Err(SessionEnd::UnsupportedVersion);
    }
    let nonce = decode_nonce(&nonce).map_err(|_| SessionEnd::Closed)?;
    send(
        socket,
        &HostMessage::Auth {
            protocol_version: PROTOCOL_VERSION,
            host_id: host_id.to_string(),
            signature: sign_challenge(key, &nonce, &url.origin()),
        },
    )
    .await?;
    let welcome = next_text_within(socket).await?;
    match ServerMessage::decode(&welcome) {
        Ok(ServerMessage::Welcome {
            heartbeat_interval_secs,
            ..
        }) => Ok(Duration::from_secs(u64::from(
            heartbeat_interval_secs.clamp(5, 300),
        ))),
        _ => Err(SessionEnd::Closed),
    }
}

async fn serve(
    socket: &mut Socket,
    ports: &LinkPorts,
    config: &CoordinatorConfig,
    interval: Duration,
    recorder: &mut Recorder,
) -> SessionEnd {
    let mut described = hello(ports, &config.host_id);
    if let Err(end) = send(socket, &HostMessage::Hello(described.clone())).await {
        return end;
    }
    let mut ticks = tokio::time::interval(interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            frame = next_text(socket) => {
                let text = match frame {
                    Ok(text) => text,
                    Err(end) => return end,
                };
                if let Ok(ServerMessage::Wake(wake)) = ServerMessage::decode(&text)
                    && ports.routes.deliver(&wake)
                {
                    recorder.woke();
                }
            }
            _ = ticks.tick() => {
                if records::configured(&ports.paths).ok().flatten().as_ref() != Some(config) {
                    let _ = socket.close(None).await;
                    return SessionEnd::Reconfigured;
                }
                let current = hello(ports, &config.host_id);
                if current != described {
                    described = current;
                    if let Err(end) = send(socket, &HostMessage::Hello(described.clone())).await {
                        return end;
                    }
                }
                if let Err(end) = send(socket, &HostMessage::Heartbeat(heartbeat(ports))).await {
                    return end;
                }
                recorder.write();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wake_never_moves_a_poll_sooner_than_the_gap_or_later_than_scheduled() {
        let start = tokio::time::Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        // Polled at 0, next at 60, woken at 1: polled at 5.
        assert_eq!(woken_deadline(at(60), at(0), at(1)), at(5));
        // Woken at 7: polled at once.
        assert_eq!(woken_deadline(at(60), at(0), at(7)), at(7));
        // Already due at 3: a wake does not delay it.
        assert_eq!(woken_deadline(at(3), at(0), at(1)), at(3));
    }

    #[test]
    fn a_wake_reaches_only_the_target_it_names() {
        let mut routes = WakeRoutes::new(None);
        let repo = routes.add(ScaleTarget::repository("Octo/App").expect("target"));
        let org = routes.add(ScaleTarget::organization("acme").expect("target"));
        let wake = |scope, name: &str| Wake {
            target: TargetRef {
                scope,
                name: name.into(),
            },
            repository: "octo/app".into(),
            reason: runner_manager_coordinator_protocol::WakeReason::JobQueued,
            delivery_id: "d".into(),
        };
        assert!(routes.deliver(&wake(TargetScope::Repo, "octo/app")));
        assert!(!routes.deliver(&wake(TargetScope::Org, "octo")));
        assert!(!routes.deliver(&wake(TargetScope::Repo, "acme")));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(100), repo.notified())
                .await
                .expect("the repository target was woken");
            assert!(
                tokio::time::timeout(Duration::from_millis(50), org.notified())
                    .await
                    .is_err(),
                "the organization target was not"
            );
        });
    }

    #[test]
    fn a_link_record_older_than_the_daemon_would_let_it_get_is_not_believed() {
        let dir = tempfile::tempdir().expect("dir");
        let paths = AppPaths::rooted_at(dir.path());
        let now = Utc::now();
        assert_eq!(
            CoordinatorSnapshot::read(&paths, now).link,
            LinkState::NotConfigured
        );
        records::save(
            &paths,
            &CoordinatorConfig::new("https://c.example".into(), "h".into(), "n".into(), now),
        )
        .expect("saved");
        assert_eq!(
            CoordinatorSnapshot::read(&paths, now).link,
            LinkState::Unknown
        );

        let mut link = LinkRecord::new(now);
        link.connected = true;
        link.since = Some(now);
        records::record_link(&paths, &link).expect("written");
        let fresh = CoordinatorSnapshot::read(&paths, now);
        assert_eq!(fresh.link, LinkState::Connected);
        assert!(
            fresh
                .describe()
                .starts_with("connected to https://c.example")
        );

        let later = now + chrono::TimeDelta::minutes(10);
        assert_eq!(
            CoordinatorSnapshot::read(&paths, later).link,
            LinkState::Unknown
        );

        link.connected = false;
        link.reason = Some("unreachable".into());
        records::record_link(&paths, &link).expect("written");
        let down = CoordinatorSnapshot::read(&paths, now);
        assert_eq!(down.link, LinkState::Disconnected);
        assert!(
            down.describe().contains("(unreachable)"),
            "{}",
            down.describe()
        );
    }

    /// The real link against the real coordinator, in-process: enroll, sign
    /// the challenge, advertise the policy, receive a wake for a queued job,
    /// and let go when the host leaves.
    #[tokio::test]
    async fn the_link_authenticates_advertises_and_delivers_a_wake() {
        use hmac::{Hmac, KeyInit as _, Mac as _};
        use runner_manager_coordinator::server::{AppState, Config, serve};
        use runner_manager_domain::store::SqliteStore;
        use runner_manager_platform::secrets::{PlatformSecretStore, SecretScope};
        use runner_manager_testkit::fixtures;

        const SECRET: &str = "a-webhook-secret-for-tests";

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let state = AppState::new(
            Config::new(base.clone(), SecretString::from(SECRET)),
            runner_manager_coordinator::store::Store::open_in_memory().expect("store"),
        );
        tokio::spawn(serve(listener, Arc::clone(&state), std::future::pending()));

        let code = state
            .store
            .lock()
            .expect("store")
            .create_invite("box", Duration::from_secs(900), Utc::now())
            .expect("invite")
            .code;
        let url = CoordinatorUrl::parse(&base).expect("url");
        let key = signing_key_from_seed(&[5; 32]);
        let enrolled = enroll(
            &url,
            &EnrollRequest {
                protocol_version: PROTOCOL_VERSION,
                code: code.expose_secret().to_string(),
                hostname: "box".into(),
                public_key: encode_public_key(&key.verifying_key()),
            },
        )
        .await
        .expect("enrolled");

        let dir = tempfile::tempdir().expect("dir");
        let paths = AppPaths::rooted_at(dir.path());
        let config = CoordinatorConfig::new(
            url.origin(),
            enrolled.host_id.clone(),
            enrolled.name,
            Utc::now(),
        );
        records::save(&paths, &config).expect("config");
        let key_store: Arc<dyn SecretStore> = Arc::new(
            PlatformSecretStore::rooted_at(SecretScope::User, dir.path().join("secrets"))
                .expect("store")
                .for_item(SecretItem::CoordinatorKey),
        );
        key_store
            .store(&SecretString::from(encode_signing_key(&key)))
            .expect("key stored");

        let host = fixtures::host().build();
        let policy = fixtures::policy()
            .repository("octo/app")
            .host(host.id)
            .autoscale("home", 1)
            .active()
            .build();
        let labels = policy
            .routing_labels()
            .expect("autoscale")
            .as_registration_labels();
        let store = SqliteStore::open_in_memory().expect("store");
        store.put_host(&host).expect("host");
        store.insert_policy(&policy).expect("policy");
        let mut routes = WakeRoutes::new(None);
        let woken = routes.add(policy.target.clone());

        let link = tokio::spawn(maintain_link(LinkPorts {
            paths: paths.clone(),
            key_store,
            store: Arc::new(store),
            routes: Arc::new(routes),
            unfit: Arc::new(AtomicBool::new(false)),
            draining: Arc::new(AtomicBool::new(false)),
            host,
            runner_root: dir.path().to_path_buf(),
        }));

        // Connected and described.
        let mut described = false;
        for _ in 0..200 {
            described = state.registry.connected().iter().any(|connected| {
                connected
                    .hello
                    .as_ref()
                    .is_some_and(|hello| hello.targets.len() == 1)
            });
            if described {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(described, "the host connected and advertised its target");
        assert_eq!(
            CoordinatorSnapshot::read(&paths, Utc::now()).link,
            LinkState::Connected
        );

        // GitHub queues a job the policy's labels cover.
        let body = serde_json::json!({
            "action": "queued",
            "workflow_job": {"id": 1, "run_id": 2, "labels": labels},
            "repository": {"full_name": "octo/app"},
        })
        .to_string();
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).expect("key");
        mac.update(body.as_bytes());
        let status = reqwest::Client::new()
            .post(format!("{base}/webhook"))
            .header("x-github-event", "workflow_job")
            .header("x-github-delivery", "e2e-1")
            .header(
                "x-hub-signature-256",
                format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
            )
            .body(body)
            .send()
            .await
            .expect("delivered")
            .status();
        assert_eq!(status, 200);
        tokio::time::timeout(Duration::from_secs(5), woken.notified())
            .await
            .expect("the target loop was woken");
        let snapshot = CoordinatorSnapshot::read(&paths, Utc::now());
        assert_eq!(snapshot.wakes_received, 1);

        link.abort();
    }

    #[test]
    fn jitter_only_ever_lengthens_the_wait() {
        for _ in 0..100 {
            let wait = jittered(Duration::from_secs(10));
            assert!(wait >= Duration::from_secs(10) && wait <= Duration::from_secs(15));
        }
    }
}
