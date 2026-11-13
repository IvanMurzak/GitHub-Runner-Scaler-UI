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
//! # Poll modes (stage 2)
//!
//! Each target is in one of three [`PollMode`]s:
//!
//! * `standalone` — no coordinator joined: today's polling.
//! * `coordinated` — the link is up (or down for less than
//!   [`FALLBACK_AFTER`]) and the coordinator's last `hello_ack` says its
//!   reconciliation sweep covers this target. The coordinator then reads the
//!   target's queue and wakes this host for any queued job, so the target's
//!   own poll stretches to the long coordinated interval
//!   (`host set-poll-interval --coordinated`, 300 s by default) -- except
//!   while this host runs a runner for it, when freed capacity must be
//!   reused promptly and the normal intervals apply. Wakes still bring a
//!   poll forward.
//! * `fallback` — joined, but the link has been down for
//!   [`FALLBACK_AFTER`], or the coordinator does not cover the target (no
//!   GitHub App, an installation that does not reach it, or a version-1
//!   coordinator). Today's polling, at once: a loop asleep on the long
//!   interval is re-scheduled the moment its target leaves `coordinated`.
//!
//! # Placement (stage 3)
//!
//! On a version-3 link, a pool profile (one carrying this host's
//! `rm-pool-<os>` label) of a `coordinated` target starts runners only for
//! the coordinator's `launch`es this host accepted; see [`super::launches`].
//! The link answers each `launch` with a `launch_ack`, honours
//! `cancel_launch`, and reports its attempts (`attempt_started` when a runner
//! takes a job, `attempt_finished` when it ends).
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
use runner_manager_agent::reconcile::{Jitter, RandomJitter};
use runner_manager_domain::attempt::active_count;
use runner_manager_domain::coordinator_protocol::{
    CLOSE_UNAUTHORIZED, CLOSE_UNSUPPORTED_VERSION, COMMAND_VERSION, CommandResult, CoordinatorUrl,
    EnrollRequest, EnrollResponse, HELLO_ACK_VERSION, Heartbeat, Hello, HelloAck, HostMessage,
    HostSigningKey, LAUNCH_VERSION, MAX_MESSAGE_BYTES, MIN_PROTOCOL_VERSION, Profile,
    STATS_VERSION, ServerMessage, SessionPurpose, StatsReport, Target, TargetRef, TargetScope,
    Wake, decode_nonce, decode_signing_key, encode_public_key, encode_signing_key, negotiate,
    sign_challenge, signing_key_from_seed,
};
use runner_manager_domain::model::{OwnerRepo, ScaleTarget, StartMode};
use runner_manager_domain::policy::{HostTraits, ScalePolicy};
use runner_manager_domain::store::Store;
use runner_manager_github::demand::RestDemand;
use runner_manager_platform::coordinator::{self as records, CoordinatorConfig, LinkRecord};
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::secrets::{SecretItem, SecretStore};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, watch};
use tokio_tungstenite::tungstenite;

use super::launches::{AttemptReport, AttemptReports, Launches};
use super::memory::HostMemory;
use super::meters::{AttemptMeters, sample_attempts};
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

/// Reconnect back-off: the first wait, and the longest wait, jitter
/// included, in general and after a refusal.
const RECONNECT_FIRST: Duration = Duration::from_secs(1);
const RECONNECT_CAP: Duration = Duration::from_secs(30);
const REJECTED_CAP: Duration = Duration::from_secs(5 * 60);
/// A connection that stayed up longer than this resets the back-off.
const STABLE_SESSION: Duration = Duration::from_secs(60);
/// How often an unconfigured daemon looks for a `coordinator join`.
const CONFIG_RECHECK: Duration = Duration::from_secs(15);

/// Version of `coordinator status --json`.
const STATUS_SCHEMA_VERSION: u32 = 1;

/// How often the link looks at this host's attempts for its reports.
const ATTEMPT_WATCH: Duration = Duration::from_secs(2);

/// How long a lost link keeps covered targets on the coordinated interval:
/// a reconnect inside it changes nothing, and past it every target polls on
/// its own again.
pub const FALLBACK_AFTER: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub fn dispatch(
    context: &Context,
    command: &CoordinatorCommand,
    styling: super::Styling,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        CoordinatorCommand::Join(args) => join(context, &args.url, &args.code, out),
        CoordinatorCommand::Status(args) => status(context, args.json, out),
        CoordinatorCommand::Leave => leave(context, out),
        CoordinatorCommand::Stats(args) => stats(context, args.json, out),
        CoordinatorCommand::RemoteChanges(args) => {
            super::remote::remote_changes(context, args, out)
        }
        CoordinatorCommand::Login(args) => {
            super::coordinator_session::login(context, args, styling, out)
        }
        CoordinatorCommand::Logout => super::coordinator_session::logout(context, out),
        CoordinatorCommand::Hosts(args) => super::coordinator_session::hosts(context, args, out),
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
    // Enrollment has not changed since version 1, and every coordinator
    // accepts 1; a stage-1 coordinator accepts nothing else.
    let request = EnrollRequest {
        protocol_version: MIN_PROTOCOL_VERSION,
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
        409 => Err(CliError::with_remedy(
            Failure::Conflict,
            "the coordinator could not enroll this host: an active host already holds the \
             invite's name",
            "ask the coordinator's operator to revoke that host or issue an invite with another \
             name",
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
        return write_document(out, STATUS_SCHEMA_VERSION, &snapshot);
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
        writeln!(out, "  sweep         {}", snapshot.describe_sweep()).map_err(failed)?;
    }
    Ok(())
}

/// `body` as the versioned JSON document `status --json` and `stats --json`
/// print: its fields beside `schema_version`.
fn write_document(
    out: &mut dyn Write,
    schema_version: u32,
    body: &impl Serialize,
) -> Result<(), CliError> {
    #[derive(Serialize)]
    struct Document<'a, T: Serialize> {
        schema_version: u32,
        #[serde(flatten)]
        body: &'a T,
    }
    serde_json::to_writer_pretty(
        &mut *out,
        &Document {
            schema_version,
            body,
        },
    )
    .map_err(|error| CliError::new(Failure::LocalState, error.to_string()))?;
    writeln!(out).map_err(write_failed("the JSON document"))
}

/// `coordinator stats`: asks the coordinator for its statistics on a query
/// session of its own, signed with this host's key like the daemon's link,
/// which stays connected meanwhile.
fn stats(context: &Context, json: bool, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("the coordinator statistics");
    let Some(config) = records::configured(context.paths()).map_err(local_state)? else {
        return Err(CliError::with_remedy(
            Failure::NotFound,
            "this host has not joined a coordinator",
            "runner-manager coordinator join URL --code CODE",
        ));
    };
    let url = CoordinatorUrl::parse(&config.url).map_err(|_| {
        local_state("the recorded coordinator URL is not a URL; leave and join again")
    })?;
    let store = context.store()?;
    let mode = context.recorded_start_mode(&store)?;
    let key = load_key(key_store(context, mode)?.as_ref()).ok_or_else(|| {
        CliError::with_remedy(
            Failure::SecretStore,
            format!("this account cannot read the coordinator key in the {mode}-mode secret store"),
            "run the same command with administrator rights (sudo, or an elevated terminal)",
        )
    })?;
    let report = super::runtime()?
        .block_on(fetch_stats(&url, &config.host_id, &key, tls_config()))
        .map_err(|end| match end {
            SessionEnd::UnsupportedVersion => CliError::with_remedy(
                Failure::UnsupportedHost,
                "the coordinator is older than statistics (protocol version 4)",
                "update the coordinator",
            ),
            SessionEnd::Rejected => CliError::with_remedy(
                Failure::CoordinatorUnavailable,
                "the coordinator refused this host's key",
                "ask its operator whether this host was revoked; then leave and join again",
            ),
            other => unavailable(format!(
                "the statistics could not be fetched from {url} ({})",
                other.as_str()
            )),
        })?;
    if json {
        return write_document(
            out,
            runner_manager_domain::coordinator_protocol::STATS_JSON_SCHEMA_VERSION,
            &report,
        );
    }
    let mut text = String::new();
    report
        .render(&mut text)
        .map_err(|_| CliError::new(Failure::LocalState, "the statistics could not be printed"))?;
    write!(out, "{text}").map_err(failed)?;
    Ok(())
}

/// One query session: handshake for [`SessionPurpose::Query`], one request,
/// one answer.
async fn fetch_stats(
    url: &CoordinatorUrl,
    host_id: &str,
    key: &HostSigningKey,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<StatsReport, SessionEnd> {
    let mut socket = open_socket(url, tls).await?;
    handshake(&mut socket, url, host_id, key, Some(SessionPurpose::Query)).await?;
    send(&mut socket, &HostMessage::StatsRequest).await?;
    loop {
        let text = next_text_within(&mut socket).await?;
        if let Ok(ServerMessage::Stats(report)) = ServerMessage::decode(&text) {
            let _ = socket.close(None).await;
            return Ok(report);
        }
    }
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

/// How one target is polled. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PollMode {
    Standalone,
    Coordinated,
    Fallback,
}

impl PollMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Coordinated => "coordinated",
            Self::Fallback => "fallback",
        }
    }

    /// The one rule every reader applies: the daemon's loops, `status`,
    /// `host doctor` and the TUI.
    #[must_use]
    pub fn of(
        configured: bool,
        connected: bool,
        down_for: Option<Duration>,
        covered: bool,
    ) -> Self {
        if !configured {
            Self::Standalone
        } else if covered && (connected || down_for.is_some_and(|down| down < FALLBACK_AFTER)) {
            Self::Coordinated
        } else {
            Self::Fallback
        }
    }
}

/// One target and how it is polled, for `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetPollMode {
    /// `owner/repo`, or an organization's login.
    pub target: String,
    pub mode: PollMode,
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
    /// How often the coordinator's reconciliation sweep runs, as its last
    /// `hello_ack` said; `null` when it runs none, or never said.
    pub reconcile_interval_secs: Option<u32>,
    /// The targets that sweep covers, as `repo:owner/name` or `org:login`.
    pub covered: Vec<String>,
    /// Each of this host's targets and its poll mode. Empty where the
    /// reader did not ask about targets.
    pub targets: Vec<TargetPollMode>,
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
            reconcile_interval_secs: None,
            covered: Vec::new(),
            targets: Vec::new(),
        }
    }

    /// [`Self::read`], with each of `targets`' poll mode.
    #[must_use]
    pub fn read_for(paths: &AppPaths, now: DateTime<Utc>, targets: &[ScaleTarget]) -> Self {
        let mut snapshot = Self::read(paths, now);
        let mut seen: Vec<&ScaleTarget> = Vec::new();
        for target in targets {
            if seen.contains(&target) {
                continue;
            }
            seen.push(target);
            snapshot.targets.push(TargetPollMode {
                target: target.slug(),
                mode: snapshot.mode_for(target, now),
            });
        }
        snapshot
    }

    /// How `target` is polled, as far as the daemon's record says.
    #[must_use]
    pub fn mode_for(&self, target: &ScaleTarget, now: DateTime<Utc>) -> PollMode {
        // The same rule as `HelloAck::covers`: scope and name, case-blind.
        let reference = target_ref(target).to_string();
        let covered = self.reconcile_interval_secs.is_some()
            && self
                .covered
                .iter()
                .any(|covered| covered.eq_ignore_ascii_case(&reference));
        let down_for = (self.link == LinkState::Disconnected)
            .then(|| {
                self.since
                    .and_then(|since| now.signed_duration_since(since).to_std().ok())
            })
            .flatten();
        PollMode::of(
            self.configured,
            self.link == LinkState::Connected,
            down_for,
            covered,
        )
    }

    /// How many of [`Self::targets`] are in `mode`.
    #[must_use]
    pub fn count(&self, mode: PollMode) -> usize {
        self.targets
            .iter()
            .filter(|target| target.mode == mode)
            .count()
    }

    /// One phrase on the coordinator's sweep and what it covers here.
    #[must_use]
    pub fn describe_sweep(&self) -> String {
        match self.reconcile_interval_secs {
            None => "none reported: every target polls GitHub on its own (fallback)".to_string(),
            Some(secs) if self.targets.is_empty() => {
                format!("every {secs}s, covering {} target(s)", self.covered.len())
            }
            Some(secs) => format!(
                "every {secs}s; {} of {} target(s) coordinated, {} in fallback",
                self.count(PollMode::Coordinated),
                self.targets.len(),
                self.count(PollMode::Fallback)
            ),
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
            snapshot.reconcile_interval_secs = link.reconcile_interval_secs;
            snapshot.covered = link.covered;
            if !runner_manager_platform::wsl::fence::elapsed_at_least(
                link.written_at,
                now,
                LINK_STALE_AFTER,
            ) {
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

/// One target loop's signals, shared between the link and that loop.
#[derive(Debug, Clone)]
pub struct RouteSignals {
    /// Poll now (no sooner than [`WAKE_MIN_GAP`] after the last poll).
    pub wake: Arc<Notify>,
    /// Start the runners of the launches accepted for this target, now: no
    /// poll is needed for that, so no gap applies.
    pub launch: Arc<Notify>,
}

#[derive(Debug)]
struct WakeRoute {
    target: ScaleTarget,
    signals: RouteSignals,
}

/// Every target loop's signals, and the gateway whose shared readings a wake
/// invalidates. Loops come and go while the daemon runs (a repository added
/// or removed), so the set is behind a lock.
#[derive(Debug, Default)]
pub struct WakeRoutes {
    routes: std::sync::Mutex<Vec<WakeRoute>>,
    demand: Option<Arc<RestDemand>>,
}

impl WakeRoutes {
    #[must_use]
    pub fn new(demand: Option<Arc<RestDemand>>) -> Self {
        Self {
            routes: std::sync::Mutex::new(Vec::new()),
            demand,
        }
    }

    fn routes(&self) -> std::sync::MutexGuard<'_, Vec<WakeRoute>> {
        self.routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn signals(&self, target: &TargetRef) -> Option<(ScaleTarget, RouteSignals)> {
        self.routes()
            .iter()
            .find(|route| same_target(&route.target, target))
            .map(|route| (route.target.clone(), route.signals.clone()))
    }

    /// Registers `target`'s loop and returns its signals.
    pub fn add(&self, target: ScaleTarget) -> RouteSignals {
        let signals = RouteSignals {
            wake: Arc::new(Notify::new()),
            launch: Arc::new(Notify::new()),
        };
        let mut routes = self.routes();
        routes.retain(|route| route.target != target);
        routes.push(WakeRoute {
            target,
            signals: signals.clone(),
        });
        signals
    }

    /// Forgets `target`'s loop: it is draining away.
    pub fn remove(&self, target: &ScaleTarget) {
        self.routes().retain(|route| &route.target != target);
    }

    /// Delivers `wake`; `true` when a local target took it.
    pub fn deliver(&self, wake: &Wake) -> bool {
        let Some((target, signals)) = self.signals(&wake.target) else {
            return false;
        };
        if let (Some(demand), Ok(repository)) = (&self.demand, OwnerRepo::parse(&wake.repository))
            && wake.target.covers(&wake.repository)
        {
            demand.forget_shared_reading(&repository);
            // GitHub's run listing can leave the run out: read it by its id.
            if let Some(run_id) = wake.run_id {
                demand.expect_run(&repository, run_id);
            }
        }
        signals.wake.notify_one();
        tracing::info!(target = %target, "the coordinator woke a target; polling it now");
        true
    }

    /// Starts `target`'s accepted launches now. Several accepted in a row
    /// are served together: the signal holds one permit.
    pub fn launch_now(&self, target: &TargetRef) {
        if let Some((_, signals)) = self.signals(target) {
            signals.launch.notify_one();
        }
    }

    /// Runs `target`'s next pass as soon as a wake may: one of its runners
    /// exited and the pass concludes it. The shared reading is kept.
    pub fn pass_soon(&self, target: &TargetRef) {
        if let Some((_, signals)) = self.signals(target) {
            signals.wake.notify_one();
        }
    }
}

pub(super) fn same_target(local: &ScaleTarget, remote: &TargetRef) -> bool {
    target_ref(local).same_as(remote)
}

pub(super) fn target_ref(target: &ScaleTarget) -> TargetRef {
    TargetRef {
        scope: match target {
            ScaleTarget::Repository(_) => TargetScope::Repo,
            ScaleTarget::Organization(_) => TargetScope::Org,
        },
        name: target.slug(),
    }
}

// ---------------------------------------------------------------------------
// The link's view, shared with the target loops
// ---------------------------------------------------------------------------

/// What the link knows right now, for the target loops' poll mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkView {
    /// This host has joined a coordinator.
    pub configured: bool,
    pub connected: bool,
    /// When the link went down, while it is down after having been up.
    pub down_since: Option<tokio::time::Instant>,
    /// The coordinator's last `hello_ack`; `None` before one, and from a
    /// version-1 coordinator.
    pub ack: Option<HelloAck>,
    /// The protocol version of the last connection, kept while it is down.
    pub version: Option<u32>,
}

impl LinkView {
    /// `target`'s poll mode at `now`.
    #[must_use]
    pub fn mode(&self, target: &ScaleTarget, now: tokio::time::Instant) -> PollMode {
        let covered = self
            .ack
            .as_ref()
            .is_some_and(|ack| ack.covers(&target_ref(target)));
        PollMode::of(
            self.configured,
            self.connected,
            self.down_since
                .map(|since| now.saturating_duration_since(since)),
            covered,
        )
    }

    /// Whether `target`'s pool profiles start runners only on the
    /// coordinator's launches: coordinated, on a version-3 link.
    #[must_use]
    pub fn launch_mode(&self, target: &ScaleTarget, now: tokio::time::Instant) -> bool {
        self.version
            .is_some_and(|version| version >= LAUNCH_VERSION)
            && self.mode(target, now) == PollMode::Coordinated
    }

    /// When a coordinated target falls back on its own, if the link is down
    /// and that is still ahead.
    #[must_use]
    pub fn fallback_at(&self) -> Option<tokio::time::Instant> {
        self.down_since
            .filter(|_| !self.connected)
            .map(|since| since + FALLBACK_AFTER)
    }
}

/// The link's side of [`LinkView`]; every target loop holds a receiver.
pub type Coordination = watch::Sender<LinkView>;

/// A sender for a daemon that has just started: not joined, not connected.
#[must_use]
pub fn coordination() -> Arc<Coordination> {
    Arc::new(watch::Sender::new(LinkView::default()))
}

/// What this host is, as labels every profile carries: `wsl` or `not-wsl`.
#[must_use]
pub fn host_traits() -> HostTraits {
    HostTraits::wsl(runner_manager_platform::wsl::running_inside_wsl())
}

/// The targets and profiles this host advertises: its autoscale policies,
/// each with the labels its runners register with, [`host_traits`]
/// included.
#[must_use]
pub fn advertised_targets(policies: &[ScalePolicy], traits: HostTraits) -> Vec<Target> {
    let mut targets: Vec<Target> = Vec::new();
    for policy in policies {
        let Some(labels) = policy.routing_labels() else {
            continue;
        };
        let TargetRef { scope, name } = target_ref(&policy.target);
        let profile = Profile {
            name: policy.profile_name().to_string(),
            labels: labels.with_labels(traits.labels()).as_registration_labels(),
            enabled: policy.may_start_runners(),
            warm: policy.workspace_policy().is_persistent(),
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
    /// Where the link tells the target loops what it knows.
    pub coordination: Arc<Coordination>,
    /// The coordinator's launches on this host (stage 3).
    pub launches: Arc<Launches>,
    /// The host's memory admission: its meters, and where the coordinator's
    /// memory estimates go (0.4.53).
    pub memory: Arc<HostMemory>,
    /// The service's own context, for commands the coordinator relays
    /// (0.4.61); `None` answers each with a refusal.
    pub commands: Option<super::Context>,
}

/// The most relayed commands this host runs at once.
const COMMANDS_AT_ONCE: usize = 4;

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
    /// The platform certificate verifier could not be built, so no `wss://`
    /// connection can be verified.
    NoTls,
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
            Self::NoTls => "no_tls_verifier",
        }
    }
}

/// The link's record on disk, kept in step with the session.
struct Recorder {
    paths: AppPaths,
    record: LinkRecord,
    written: Option<tokio::time::Instant>,
    /// When the current session connected, for the reconnect back-off.
    connected_at: Option<tokio::time::Instant>,
}

/// How often an unchanged link record is rewritten, well inside
/// [`LINK_STALE_AFTER`].
const LINK_KEEPALIVE: Duration = Duration::from_secs(60);

impl Recorder {
    /// Rewrites the record only when it is about to look stale.
    fn keep_alive(&mut self) {
        if self.written.is_none_or(|at| at.elapsed() >= LINK_KEEPALIVE) {
            self.write();
        }
    }

    fn write(&mut self) {
        self.written = Some(tokio::time::Instant::now());
        self.record.written_at = Utc::now();
        if let Err(error) = records::record_link(&self.paths, &self.record) {
            tracing::warn!(%error, "cannot record the coordinator link state");
        }
    }

    /// Connected at protocol `version`; a version-1 coordinator sends no
    /// `hello_ack`, so it covers nothing.
    fn connected(&mut self, version: u32) {
        self.connected_at = Some(tokio::time::Instant::now());
        self.record.connected = true;
        self.record.since = Some(Utc::now());
        self.record.reason = None;
        if version < HELLO_ACK_VERSION {
            self.record.reconcile_interval_secs = None;
            self.record.covered.clear();
        }
        self.write();
    }

    fn acknowledged(&mut self, ack: &HelloAck) {
        let covered: Vec<String> = ack.covered.iter().map(ToString::to_string).collect();
        if self.record.reconcile_interval_secs == ack.reconcile_interval_secs
            && self.record.covered == covered
        {
            return;
        }
        self.record.reconcile_interval_secs = ack.reconcile_interval_secs;
        self.record.covered = covered;
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
    let meters = ports.memory.meters();
    link(ports, &meters).await;
}

/// Samples what this host's attempts use while it has joined a coordinator
/// (for the job statistics) or memory admission is on (for admission and its
/// own estimates). Never returns.
pub async fn sample_for(
    memory: Arc<HostMemory>,
    store: Arc<dyn runner_manager_domain::store::Store>,
    host: runner_manager_domain::model::HostId,
    coordination: Arc<Coordination>,
    routes: Arc<WakeRoutes>,
) {
    sample_attempts(
        memory.meters(),
        store,
        host,
        move || coordination.borrow().configured || memory.settings().enabled,
        // A runner that exited holds its slot, and its memory, until a pass
        // concludes it.
        move |target| routes.pass_soon(&target_ref(target)),
    )
    .await;
}

async fn link(ports: LinkPorts, meters: &AttemptMeters) {
    let tls = tls_config();
    let mut recorder = Recorder {
        paths: ports.paths.clone(),
        record: LinkRecord::new(Utc::now()),
        written: None,
        connected_at: None,
    };
    let mut backoff = Backoff::default();
    loop {
        let config = match records::configured(&ports.paths) {
            Ok(Some(config)) => config,
            Ok(None) => {
                ports.coordination.send_if_modified(|view| {
                    let left = LinkView::default();
                    let changed = *view != left;
                    *view = left;
                    changed
                });
                tokio::time::sleep(CONFIG_RECHECK).await;
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, "the coordinator setting could not be read");
                tokio::time::sleep(CONFIG_RECHECK).await;
                continue;
            }
        };
        ports.coordination.send_if_modified(|view| {
            let changed = !view.configured;
            view.configured = true;
            changed
        });
        recorder.connected_at = None;
        let end = session(&ports, meters, &config, tls.clone(), &mut recorder).await;
        // The coordinator forgets a disconnected host's launches and places
        // their jobs elsewhere; starting them here as well would double up.
        ports.launches.clear();
        // Its memory estimates speak for a link that is gone (and maybe for a
        // coordinator this host left): its own measurements stand in until
        // the next session sends them again.
        ports.memory.set_coordinator_estimates(
            runner_manager_domain::coordinator_protocol::MemoryEstimates::default(),
        );
        // Only the first failure after a session changes anything; repeated
        // failed reconnects must not wake every target loop.
        ports.coordination.send_if_modified(|view| {
            let changed = view.connected || view.down_since.is_none();
            if changed {
                view.down_since = Some(tokio::time::Instant::now());
                view.connected = false;
            }
            changed
        });
        tracing::info!(reason = end.as_str(), "the coordinator link ended");
        if end == SessionEnd::Reconfigured {
            // After `leave` the setting is gone and `leave` already removed
            // the link record; writing it again would leave it behind.
            if matches!(records::configured(&ports.paths), Ok(Some(_))) {
                recorder.disconnected(end);
            }
            backoff.reset();
            continue;
        }
        recorder.disconnected(end);
        let connected_for = recorder.connected_at.map(|at| at.elapsed());
        // In steps, so a back-off longer than `LINK_STALE_AFTER` (a refusal
        // waits up to 5 minutes) does not make `status` call a running
        // service silent.
        let resume = tokio::time::Instant::now() + backoff.after(end, connected_for, &RandomJitter);
        while tokio::time::Instant::now() < resume {
            tokio::time::sleep_until(resume.min(tokio::time::Instant::now() + LINK_KEEPALIVE))
                .await;
            if !matches!(records::configured(&ports.paths), Ok(Some(_))) {
                // `leave` ran meanwhile: nothing to report, nothing to wait for.
                break;
            }
            recorder.keep_alive();
        }
    }
}

/// The link's reconnect back-off: doubles from [`RECONNECT_FIRST`] on every
/// failed attempt, starts over after a connection that stayed up longer than
/// [`STABLE_SESSION`], and never waits longer than its cap, jitter included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            next: RECONNECT_FIRST,
        }
    }
}

impl Backoff {
    fn reset(&mut self) {
        self.next = RECONNECT_FIRST;
    }

    /// The wait after a session that ended `end`, connected for
    /// `connected_for` (`None`: never). Jitter adds up to half the delay, and
    /// the delay stops at two thirds of the cap, so even the plateau is spread
    /// out and within the cap.
    fn after(
        &mut self,
        end: SessionEnd,
        connected_for: Option<Duration>,
        jitter: &dyn Jitter,
    ) -> Duration {
        if connected_for.is_some_and(|connected| connected > STABLE_SESSION) {
            self.reset();
        }
        let cap = match end {
            SessionEnd::Rejected
            | SessionEnd::UnsupportedVersion
            | SessionEnd::NoKey
            | SessionEnd::NoTls => REJECTED_CAP,
            _ => RECONNECT_CAP,
        };
        let delay = self.next.min(cap.mul_f64(2.0 / 3.0));
        self.next = self.next.saturating_mul(2);
        delay
            .saturating_add(delay.mul_f64(jitter.fraction().clamp(0.0, 1.0) * 0.5))
            .min(cap)
    }
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

fn hello(ports: &LinkPorts, host_id: &str, version: u32, policies: &[ScalePolicy]) -> Hello {
    Hello {
        protocol_version: version,
        host_id: host_id.to_string(),
        os: ports.host.os.to_string(),
        arch: ports.host.architecture.to_string(),
        cores: std::thread::available_parallelism()
            .ok()
            .and_then(|cores| u32::try_from(cores.get()).ok())
            .unwrap_or(1),
        ram_bytes: runner_manager_platform::host_fitness::physical_memory_bytes(),
        disk_free_bytes: runner_manager_platform::host_fitness::free_disk_bytes(&ports.runner_root),
        targets: advertised_targets(policies, host_traits()),
        remote_changes: super::remote::changes_allowed(&ports.paths),
        label_exclusions: true,
        plain_placement: true,
    }
}

/// This host's live runners, counted over its whole attempt journal as the
/// allocator counts them: a repository removed while its runners finish has
/// no policy any more, and its runners still hold their slots.
fn heartbeat(ports: &LinkPorts, open_leases: Option<Vec<String>>) -> Heartbeat {
    let attempts = ports.store.uncleaned_attempts().ok();
    let busy = attempts
        .as_ref()
        .map_or(0, |attempts| active_count(attempts.iter()));
    // Unknown when the store could not be read: an empty list would tell the
    // coordinator that every job running here has ended.
    let runners = attempts.map(|attempts| {
        attempts
            .iter()
            .map(|attempt| runner_manager_agent::lifecycle::runner_name(attempt.id))
            .collect()
    });
    // A launch with no runner yet has a slot spoken for: said here, the
    // coordinator offers what this host can really start.
    let spoken_for = ports.launches.unstarted();
    let disk = runner_manager_platform::host_fitness::disk_space(&ports.runner_root);
    Heartbeat {
        free_slots: u32::from(
            ports
                .launches
                .current_host()
                .host_capacity
                .get()
                .saturating_sub(busy)
                .saturating_sub(spoken_for),
        ),
        busy_slots: u32::from(busy),
        cpu_load_percent: runner_manager_platform::host_fitness::cpu_load_percent(),
        free_ram_bytes: runner_manager_platform::host_fitness::available_memory_bytes(),
        unfit: ports.unfit.load(Ordering::Relaxed),
        draining: ports.draining.load(Ordering::Relaxed),
        open_leases,
        disk_free_bytes: disk.map(|(free, _)| free),
        versions: super::versions::report(&ports.paths),
        disk_total_bytes: disk.map(|(_, total)| total),
        runners,
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

/// A WebSocket to `url`'s `/connect`, its certificate checked by the
/// platform verifier.
async fn open_socket(
    url: &CoordinatorUrl,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<Socket, SessionEnd> {
    let socket_config = tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    // Never let tungstenite fall back to a root-less default for `wss://`.
    let connector = match tls {
        Some(config) => Some(tokio_tungstenite::Connector::Rustls(config)),
        None if url.connect_url().starts_with("wss://") => return Err(SessionEnd::NoTls),
        None => None,
    };
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
    match connected {
        Ok(Ok((socket, _))) => Ok(socket),
        _ => Err(SessionEnd::Unreachable),
    }
}

/// One connection, from handshake to whatever ends it.
async fn session(
    ports: &LinkPorts,
    meters: &AttemptMeters,
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
    let mut socket = match open_socket(&url, tls).await {
        Ok(socket) => socket,
        Err(end) => return end,
    };
    match handshake(&mut socket, &url, &config.host_id, &key, None).await {
        Ok(handshake) => {
            let version = handshake.version;
            drop(key);
            recorder.connected(version);
            ports.coordination.send_modify(|view| {
                view.connected = true;
                view.down_since = None;
                view.version = Some(version);
                // A version-1 coordinator never sends a `hello_ack`; a
                // version-2 one sends a fresh one right after `hello`, and
                // until it does the last one stands, so a reconnect does not
                // flip every target to fallback for a moment.
                if version < HELLO_ACK_VERSION {
                    view.ack = None;
                }
            });
            tracing::info!(coordinator = %url, version, "connected to the coordinator");
            serve(&mut socket, ports, meters, config, handshake, recorder).await
        }
        Err(end) => end,
    }
}

/// What the handshake settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Handshake {
    heartbeat: Duration,
    /// The negotiated protocol version.
    version: u32,
}

/// The version to speak, from the coordinator's challenge: the highest both
/// sides speak. A version-1 coordinator names only `protocol_version`.
fn negotiated(protocol_version: u32, max_protocol_version: Option<u32>) -> Option<u32> {
    negotiate(
        protocol_version,
        max_protocol_version.unwrap_or(protocol_version),
    )
}

/// Challenge, signature, welcome. A query session (`purpose`) needs a
/// version-4 coordinator: against an older one it ends before signing.
async fn handshake(
    socket: &mut Socket,
    url: &CoordinatorUrl,
    host_id: &str,
    key: &HostSigningKey,
    purpose: Option<SessionPurpose>,
) -> Result<Handshake, SessionEnd> {
    let challenge = next_text_within(socket).await?;
    let Ok(ServerMessage::Challenge {
        protocol_version,
        nonce,
        max_protocol_version,
    }) = ServerMessage::decode(&challenge)
    else {
        return Err(SessionEnd::Closed);
    };
    let version =
        negotiated(protocol_version, max_protocol_version).ok_or(SessionEnd::UnsupportedVersion)?;
    if purpose.is_some() && version < STATS_VERSION {
        return Err(SessionEnd::UnsupportedVersion);
    }
    let nonce = decode_nonce(&nonce).map_err(|_| SessionEnd::Closed)?;
    send(
        socket,
        &HostMessage::Auth {
            protocol_version: version,
            host_id: host_id.to_string(),
            signature: sign_challenge(key, &nonce, &url.origin()),
            purpose,
        },
    )
    .await?;
    let welcome = next_text_within(socket).await?;
    match ServerMessage::decode(&welcome) {
        Ok(ServerMessage::Welcome {
            heartbeat_interval_secs,
            ..
        }) => Ok(Handshake {
            heartbeat: Duration::from_secs(u64::from(heartbeat_interval_secs.clamp(5, 300))),
            version,
        }),
        _ => Err(SessionEnd::Closed),
    }
}

async fn serve(
    socket: &mut Socket,
    ports: &LinkPorts,
    meters: &AttemptMeters,
    config: &CoordinatorConfig,
    Handshake {
        heartbeat: interval,
        version,
    }: Handshake,
    recorder: &mut Recorder,
) -> SessionEnd {
    let policies = ports.store.policies().unwrap_or_default();
    let mut described = advertised_targets(&policies, host_traits());
    let mut described_changes = super::remote::changes_allowed(&ports.paths);
    // Commands the coordinator relays run on threads of their own: one may
    // ask GitHub, and some start a runtime of their own, which a task on this
    // one cannot. Their results come back here.
    let (results, mut finished) = tokio::sync::mpsc::channel::<CommandResult>(COMMANDS_AT_ONCE);
    let running = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // The first heartbeat goes out at once: let it name this host's builds.
    let paths = ports.paths.clone();
    let _ = tokio::task::spawn_blocking(move || super::versions::prime(&paths)).await;
    if let Err(end) = send(
        socket,
        &HostMessage::Hello(hello(ports, &config.host_id, version, &policies)),
    )
    .await
    {
        return end;
    }
    let mut ticks = tokio::time::interval(interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut watch = tokio::time::interval(ATTEMPT_WATCH);
    watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut reports = AttemptReports::default();
    loop {
        tokio::select! {
            frame = next_text(socket) => {
                let text = match frame {
                    Ok(text) => text,
                    Err(end) => return end,
                };
                match ServerMessage::decode(&text) {
                    Ok(ServerMessage::Wake(wake)) => {
                        if ports.routes.deliver(&wake) {
                            recorder.woke();
                        }
                    }
                    Ok(ServerMessage::Launch(launch)) if version >= LAUNCH_VERSION => {
                        let ack = ports.launches.decide(
                            &launch,
                            ports.unfit.load(Ordering::Relaxed),
                            ports.draining.load(Ordering::Relaxed),
                        );
                        tracing::info!(
                            lease = %launch.lease_id,
                            accepted = ack.accepted,
                            reason = ack.reason.map_or("", |reason| reason.as_str()),
                            "the coordinator placed a launch here"
                        );
                        let accepted = ack.accepted;
                        if let Err(end) = send(socket, &HostMessage::LaunchAck(ack)).await {
                            return end;
                        }
                        if accepted {
                            ports.routes.launch_now(&launch.target);
                        }
                    }
                    Ok(ServerMessage::CancelLaunch(cancel)) if version >= LAUNCH_VERSION => {
                        if ports.launches.cancel(&cancel.lease_id) {
                            tracing::info!(lease = %cancel.lease_id, "the coordinator cancelled a launch");
                        }
                    }
                    Ok(ServerMessage::MemoryEstimates(estimates)) => {
                        tracing::info!(
                            count = estimates.estimates.len(),
                            "the coordinator sent memory estimates for this host's targets"
                        );
                        ports.memory.set_coordinator_estimates(estimates);
                    }
                    Ok(ServerMessage::RunCommand(command)) if version >= COMMAND_VERSION => {
                        let context = match &ports.commands {
                            None => Err("this host does not take commands from the coordinator"),
                            Some(_) if running.load(Ordering::Relaxed) >= COMMANDS_AT_ONCE => Err(
                                "this host is already running as many commands as it takes at once; try again",
                            ),
                            Some(context) => Ok(context.clone()),
                        };
                        let context = match context {
                            Ok(context) => context,
                            Err(message) => {
                                let refused = CommandResult::refused(
                                    &command.request_id,
                                    super::Failure::Conflict.code(),
                                    message,
                                );
                                if let Err(end) = send(socket, &HostMessage::CommandResult(refused)).await {
                                    return end;
                                }
                                continue;
                            }
                        };
                        running.fetch_add(1, Ordering::Relaxed);
                        let results = results.clone();
                        let running = Arc::clone(&running);
                        std::thread::spawn(move || {
                            let result = super::remote::execute(&context, &command);
                            running.fetch_sub(1, Ordering::Relaxed);
                            let _ = results.blocking_send(result);
                        });
                    }
                    Ok(ServerMessage::HelloAck(ack)) => {
                        tracing::info!(
                            covered = ack.covered.len(),
                            sweep_secs = ack.reconcile_interval_secs.unwrap_or_default(),
                            "the coordinator said which targets its sweep covers"
                        );
                        recorder.acknowledged(&ack);
                        ports.coordination.send_if_modified(|view| {
                            let changed = view.ack.as_ref() != Some(&ack);
                            view.ack = Some(ack);
                            changed
                        });
                    }
                    _ => {}
                }
            }
            Some(result) = finished.recv() => {
                if let Err(end) = send(socket, &HostMessage::CommandResult(result)).await {
                    return end;
                }
            }
            _ = ticks.tick() => {
                if records::configured(&ports.paths).ok().flatten().as_ref() != Some(config) {
                    let _ = socket.close(None).await;
                    return SessionEnd::Reconfigured;
                }
                // Described again only when what it serves changed; the
                // hardware figures that drift belong to the heartbeat.
                let policies = ports.store.policies().unwrap_or_default();
                let current = advertised_targets(&policies, host_traits());
                let changes = super::remote::changes_allowed(&ports.paths);
                if current != described || changes != described_changes {
                    described = current;
                    described_changes = changes;
                    let message =
                        HostMessage::Hello(hello(ports, &config.host_id, version, &policies));
                    if let Err(end) = send(socket, &message).await {
                        return end;
                    }
                }
                if let Err(end) = report_attempts(socket, ports, meters, &mut reports, version, true).await {
                    return end;
                }
                recorder.keep_alive();
            }
            _ = watch.tick(), if version >= LAUNCH_VERSION => {
                if let Err(end) = report_attempts(socket, ports, meters, &mut reports, version, false).await {
                    return end;
                }
            }
        }
    }
}

/// Sends what changed in this host's attempts, then a heartbeat when `beat`
/// says so or a slot may just have freed (an attempt ended, or an isolated
/// one was cleaned): the coordinator places by the last heartbeat.
///
/// The open launches the heartbeat lists are read *before* the attempt
/// reports: a launch missing from the list was closed because its runner
/// took a job or ended, and the report saying so then reaches the
/// coordinator ahead of the heartbeat, so the lease is claimed (or closed)
/// there, never dropped as one this host no longer holds.
async fn report_attempts(
    socket: &mut Socket,
    ports: &LinkPorts,
    meters: &AttemptMeters,
    reports: &mut AttemptReports,
    version: u32,
    beat: bool,
) -> Result<(), SessionEnd> {
    let directed = version >= LAUNCH_VERSION;
    let open = directed.then(|| ports.launches.open_leases());
    // A launch dropped is said at once: its job waits on the lease meanwhile.
    let dropped = ports.launches.take_dropped();
    let policies = ports.store.policies().unwrap_or_default();
    if directed {
        let own: Vec<ScalePolicy> = policies
            .iter()
            .filter(|policy| policy.is_owned_by(ports.host.id))
            .cloned()
            .collect();
        for report in reports.poll(ports.store.as_ref(), &own, &ports.launches, meters) {
            let message = match report {
                AttemptReport::Started(started) => HostMessage::AttemptStarted(started),
                AttemptReport::Finished(finished) => HostMessage::AttemptFinished(finished),
            };
            send(socket, &message).await?;
        }
    }
    if beat || dropped || reports.take_released() {
        send(socket, &HostMessage::Heartbeat(heartbeat(ports, open))).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runner_manager_agent::reconcile::{FixedJitter, NoJitter};
    use runner_manager_domain::coordinator_protocol::{PROTOCOL_VERSION, WakeReason};

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
        let routes = WakeRoutes::new(None);
        let repo = routes
            .add(ScaleTarget::repository("Octo/App").expect("target"))
            .wake;
        let org = routes
            .add(ScaleTarget::organization("acme").expect("target"))
            .wake;
        let wake = |scope, name: &str| Wake {
            target: TargetRef {
                scope,
                name: name.into(),
            },
            repository: "octo/app".into(),
            reason: WakeReason::JobQueued,
            delivery_id: "d".into(),
            run_id: None,
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
                protocol_version: MIN_PROTOCOL_VERSION,
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
        let routes = WakeRoutes::new(None);
        let woken = routes.add(policy.target.clone()).wake;

        let coordination = coordination();
        let mut view = coordination.subscribe();
        let store: Arc<dyn Store> = Arc::new(store);
        let launches = Arc::new(Launches::new(
            Arc::clone(&store),
            host.clone(),
            coordination.subscribe(),
        ));
        let memory = Arc::new(HostMemory::new(paths.clone(), Arc::clone(&store)));
        let link = tokio::spawn(maintain_link(LinkPorts {
            paths: paths.clone(),
            key_store,
            store,
            routes: Arc::new(routes),
            unfit: Arc::new(AtomicBool::new(false)),
            draining: Arc::new(AtomicBool::new(false)),
            host,
            runner_root: dir.path().to_path_buf(),
            coordination: Arc::clone(&coordination),
            launches,
            memory,
            commands: None,
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

        // This coordinator runs no sweep: connected, and still fallback.
        let mode = |view: &watch::Receiver<LinkView>| {
            view.borrow()
                .mode(&policy.target, tokio::time::Instant::now())
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            view.wait_for(|view| view.connected && view.ack.is_some()),
        )
        .await
        .expect("acknowledged in time")
        .expect("the link is alive");
        assert_eq!(mode(&view), PollMode::Fallback);

        // Its sweep starts and covers the target: coordinated, recorded for
        // `status`.
        state
            .registry
            .set_coverage(runner_manager_coordinator::registry::Coverage {
                interval: Some(Duration::from_secs(120)),
                repositories: ["octo/app".to_string()].into(),
                accounts: std::collections::BTreeSet::new(),
            });
        tokio::time::timeout(
            Duration::from_secs(5),
            view.wait_for(|view| view.ack.as_ref().is_some_and(|ack| !ack.covered.is_empty())),
        )
        .await
        .expect("the coverage arrived")
        .expect("the link is alive");
        assert_eq!(mode(&view), PollMode::Coordinated);
        let snapshot =
            CoordinatorSnapshot::read_for(&paths, Utc::now(), std::slice::from_ref(&policy.target));
        assert_eq!(snapshot.reconcile_interval_secs, Some(120));
        assert_eq!(snapshot.targets[0].mode, PollMode::Coordinated);

        link.abort();
    }

    /// Stage 3 end to end, in-process: a queued pool job reaches exactly this
    /// host as a `launch`, which it accepts through its allocator and turns
    /// into directed demand; a launch past `max_capacity`, a replayed lease
    /// and one while draining are refused; and once the link has been down
    /// past the fallback delay the profile serves its own demand again.
    #[tokio::test]
    async fn a_pool_launch_is_accepted_within_the_ceilings_and_fallback_restores_own_demand() {
        use hmac::{Hmac, KeyInit as _, Mac as _};
        use runner_manager_agent::reconcile::DemandDirector as _;
        use runner_manager_coordinator::server::{AppState, Config, serve};
        use runner_manager_domain::attempt::{AttemptOutcome, AttemptState};
        use runner_manager_domain::coordinator_protocol::{Launch, RefusalReason};
        use runner_manager_domain::model::AttemptId;
        use runner_manager_domain::policy::pool_label;
        use runner_manager_domain::store::SqliteStore;
        use runner_manager_platform::secrets::{PlatformSecretStore, SecretScope};
        use runner_manager_testkit::fixtures;

        const SECRET: &str = "a-webhook-secret-for-tests";

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let mut config = Config::new(base.clone(), SecretString::from(SECRET));
        // One heartbeat when the link comes up, then none for minutes: any
        // other one the coordinator sees was sent for a reason.
        config.heartbeat_interval = Duration::from_secs(300);
        let state = AppState::new(
            config,
            runner_manager_coordinator::store::Store::open_in_memory().expect("store"),
        );
        state
            .registry
            .set_coverage(runner_manager_coordinator::registry::Coverage {
                interval: Some(Duration::from_secs(120)),
                repositories: ["octo/app".to_string()].into(),
                accounts: std::collections::BTreeSet::new(),
            });
        tokio::spawn(serve(listener, Arc::clone(&state), std::future::pending()));
        let code = state
            .store
            .lock()
            .expect("store")
            .create_invite("pool-box", Duration::from_secs(900), Utc::now())
            .expect("invite")
            .code;
        let url = CoordinatorUrl::parse(&base).expect("url");
        let key = signing_key_from_seed(&[6; 32]);
        let enrolled = enroll(
            &url,
            &EnrollRequest {
                protocol_version: MIN_PROTOCOL_VERSION,
                code: code.expose_secret().to_string(),
                hostname: "pool-box".into(),
                public_key: encode_public_key(&key.verifying_key()),
            },
        )
        .await
        .expect("enrolled");

        let dir = tempfile::tempdir().expect("dir");
        let paths = AppPaths::rooted_at(dir.path());
        records::save(
            &paths,
            &CoordinatorConfig::new(
                url.origin(),
                enrolled.host_id.clone(),
                enrolled.name,
                Utc::now(),
            ),
        )
        .expect("config");
        let key_store: Arc<dyn SecretStore> = Arc::new(
            PlatformSecretStore::rooted_at(SecretScope::User, dir.path().join("secrets"))
                .expect("store")
                .for_item(SecretItem::CoordinatorKey),
        );
        key_store
            .store(&SecretString::from(encode_signing_key(&key)))
            .expect("key stored");

        let host = fixtures::host().build();
        let mut policy = fixtures::policy()
            .repository("octo/app")
            .host(host.id)
            .autoscale("home", 1)
            .active()
            .build();
        let pool = pool_label(host.os);
        policy.add_routing_label(pool.clone()).expect("pool label");
        let sqlite = Arc::new(SqliteStore::open_in_memory().expect("store"));
        sqlite.put_host(&host).expect("host");
        sqlite.insert_policy(&policy).expect("policy");
        let store: Arc<dyn Store> = Arc::clone(&sqlite) as Arc<dyn Store>;
        let routes = WakeRoutes::new(None);
        let nudged = routes.add(policy.target.clone()).launch;
        let coordination = coordination();
        let launches = Arc::new(Launches::new(
            Arc::clone(&store),
            host.clone(),
            coordination.subscribe(),
        ));
        let draining = Arc::new(AtomicBool::new(false));
        let memory = Arc::new(HostMemory::new(paths.clone(), Arc::clone(&store)));
        let link = tokio::spawn(maintain_link(LinkPorts {
            paths,
            key_store,
            store,
            routes: Arc::new(routes),
            unfit: Arc::new(AtomicBool::new(false)),
            draining: Arc::clone(&draining),
            host,
            runner_root: dir.path().to_path_buf(),
            coordination: Arc::clone(&coordination),
            launches: Arc::clone(&launches),
            memory,
            commands: None,
        }));

        // Connected at version 3, covered, and its heartbeat in.
        let mut view = coordination.subscribe();
        tokio::time::timeout(
            Duration::from_secs(5),
            view.wait_for(|view| view.ack.as_ref().is_some_and(|ack| !ack.covered.is_empty())),
        )
        .await
        .expect("covered in time")
        .expect("the link is alive");
        assert!(launches.is_directed(&policy));
        assert_eq!(launches.directed_demand(&policy), Some(0));
        for _ in 0..200 {
            if state
                .registry
                .connected()
                .iter()
                .all(|host| host.heartbeat.is_some())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let body = serde_json::json!({
            "action": "queued",
            "workflow_job": {"id": 41, "run_id": 2, "labels": [pool.as_str()]},
            "repository": {"full_name": "octo/app"},
        })
        .to_string();
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).expect("key");
        mac.update(body.as_bytes());
        let status = reqwest::Client::new()
            .post(format!("{base}/webhook"))
            .header("x-github-event", "workflow_job")
            .header("x-github-delivery", "pool-1")
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
        tokio::time::timeout(Duration::from_secs(5), nudged.notified())
            .await
            .expect("the accepted launch nudged the target loop");
        assert_eq!(launches.open_for(policy.id), 1);
        assert_eq!(launches.directed_demand(&policy), Some(1));

        // max_capacity is 1 and one launch is open: a second is refused.
        let launch = |lease: &str| Launch {
            target: target_ref(&policy.target),
            profile: policy.profile_name().to_string(),
            job_key: "octo/app#42".into(),
            lease_id: lease.into(),
            expires_at: 0,
            ttl_secs: 300,
            exclusions: Vec::new(),
        };
        let refused = launches.decide(&launch("second"), false, false);
        assert_eq!(refused.reason, Some(RefusalReason::MaxCapacity));
        assert_eq!(
            launches.decide(&launch("second"), false, false).reason,
            Some(RefusalReason::Stale),
            "a lease id is used once"
        );
        assert_eq!(
            launches.decide(&launch("third"), false, true).reason,
            Some(RefusalReason::Draining)
        );
        assert!(
            !launches.cancel("second"),
            "a refused launch was never opened"
        );

        // Two runners take jobs; when one ends, its freed slot reaches the
        // coordinator with the attempt report, not at the next heartbeat
        // (five minutes away here).
        let (first, second) = (AttemptId::new_random(), AttemptId::new_random());
        let attempt = |id, state| {
            fixtures::attempt()
                .id(id)
                .policy_id(policy.id)
                .state(state)
                .build()
        };
        for id in [first, second] {
            sqlite
                .record_attempt(&attempt(id, AttemptState::Busy))
                .expect("busy");
        }
        let finished = fixtures::attempt()
            .id(first)
            .policy_id(policy.id)
            .state(AttemptState::Finished)
            .outcome(AttemptOutcome::CompletedJob)
            .build();
        // The accepted launch's runner: its end is reported even if the link
        // never saw it busy, however slow this machine is.
        launches.launched(&policy, first);
        sqlite.record_attempt(&finished).expect("finished");
        let busy = || {
            state
                .registry
                .connected()
                .first()
                .and_then(|host| host.heartbeat.as_ref().map(|beat| beat.busy_slots))
        };
        assert_eq!(busy(), Some(0), "only the first heartbeat so far");
        tokio::time::timeout(Duration::from_secs(5), async {
            while busy() != Some(1) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the freed slot was reported with the finished attempt");

        // The link goes down and stays down past the fallback delay: the
        // profile is no longer directed and serves its own demand.
        link.abort();
        coordination.send_modify(|view| {
            view.connected = false;
            view.down_since =
                tokio::time::Instant::now().checked_sub(FALLBACK_AFTER + Duration::from_secs(1));
        });
        assert!(!launches.is_directed(&policy));
        assert_eq!(launches.directed_demand(&policy), None);
    }

    /// `coordinator stats` over a real socket: the enrolled key reads the
    /// statistics on a query session; another key reads nothing.
    #[tokio::test]
    async fn statistics_are_read_with_this_hosts_key_and_refused_to_any_other() {
        use runner_manager_coordinator::server::{AppState, Config, serve};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let state = AppState::new(
            Config::new(
                base.clone(),
                SecretString::from("a-webhook-secret-for-tests"),
            ),
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
        let key = signing_key_from_seed(&[6; 32]);
        let enrolled = enroll(
            &url,
            &EnrollRequest {
                protocol_version: MIN_PROTOCOL_VERSION,
                code: code.expose_secret().to_string(),
                hostname: "box".into(),
                public_key: encode_public_key(&key.verifying_key()),
            },
        )
        .await
        .expect("enrolled");

        let report = fetch_stats(&url, &enrolled.host_id, &key, None)
            .await
            .expect("the statistics");
        assert_eq!(report.samples_per_job, 30);
        assert!(report.jobs.is_empty());
        let mut text = String::new();
        report.render(&mut text).expect("renders");
        assert!(text.contains("No job has been measured yet."), "{text}");

        let other = signing_key_from_seed(&[7; 32]);
        assert_eq!(
            fetch_stats(&url, &enrolled.host_id, &other, None).await,
            Err(SessionEnd::Rejected)
        );
        assert!(
            state.registry.host_ids().is_empty(),
            "a query session is never the host's link"
        );
    }

    #[test]
    fn the_host_negotiates_down_to_an_older_coordinator() {
        // A stage-1 coordinator: version 1 only.
        assert_eq!(negotiated(1, None), Some(1));
        // This coordinator.
        assert_eq!(
            negotiated(1, Some(PROTOCOL_VERSION)),
            Some(PROTOCOL_VERSION)
        );
        // A future one that dropped everything this build speaks.
        assert_eq!(negotiated(7, Some(9)), None);
    }

    #[test]
    fn a_target_is_coordinated_only_while_covered_and_linked() {
        let short = Some(FALLBACK_AFTER - Duration::from_secs(1));
        assert_eq!(PollMode::of(false, true, None, true), PollMode::Standalone);
        assert_eq!(PollMode::of(true, true, None, true), PollMode::Coordinated);
        assert_eq!(
            PollMode::of(true, false, short, true),
            PollMode::Coordinated
        );
        assert_eq!(
            PollMode::of(true, false, Some(FALLBACK_AFTER), true),
            PollMode::Fallback
        );
        assert_eq!(PollMode::of(true, false, None, true), PollMode::Fallback);
        assert_eq!(PollMode::of(true, true, None, false), PollMode::Fallback);

        // `status` reads the same rule off the daemon's record.
        let now = Utc::now();
        let mut snapshot = CoordinatorSnapshot::not_configured();
        let target = ScaleTarget::repository("Octo/App").expect("target");
        assert_eq!(snapshot.mode_for(&target, now), PollMode::Standalone);
        snapshot.configured = true;
        snapshot.link = LinkState::Connected;
        snapshot.covered = vec!["repo:octo/app".into()];
        assert_eq!(
            snapshot.mode_for(&target, now),
            PollMode::Fallback,
            "no sweep"
        );
        snapshot.reconcile_interval_secs = Some(120);
        assert_eq!(snapshot.mode_for(&target, now), PollMode::Coordinated);
        snapshot.link = LinkState::Disconnected;
        snapshot.since = Some(now - chrono::TimeDelta::seconds(10));
        assert_eq!(snapshot.mode_for(&target, now), PollMode::Coordinated);
        snapshot.since = Some(now - chrono::TimeDelta::seconds(31));
        assert_eq!(snapshot.mode_for(&target, now), PollMode::Fallback);
        snapshot.link = LinkState::Unknown;
        assert_eq!(snapshot.mode_for(&target, now), PollMode::Fallback);
    }

    #[test]
    fn jitter_only_ever_lengthens_the_wait() {
        for fraction in [0.0, 0.3, 0.999] {
            let wait = Backoff {
                next: Duration::from_secs(10),
            }
            .after(SessionEnd::Unreachable, None, &FixedJitter(fraction));
            assert!(wait >= Duration::from_secs(10) && wait <= Duration::from_secs(15));
        }
    }

    #[test]
    fn the_reconnect_wait_doubles_up_to_thirty_seconds_jitter_included() {
        let mut backoff = Backoff::default();
        let waits: Vec<u64> = (0..8)
            .map(|_| {
                backoff
                    .after(SessionEnd::Unreachable, None, &NoJitter)
                    .as_secs()
            })
            .collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 20, 20, 20]);
        // The most jitter there is still stays within the cap, and spreads
        // the fleet out below it.
        assert_eq!(
            backoff.after(SessionEnd::Closed, None, &FixedJitter(1.0)),
            RECONNECT_CAP
        );
        assert!(backoff.after(SessionEnd::Closed, None, &FixedJitter(0.5)) < RECONNECT_CAP);
        // A refusal keeps its own, longer cap.
        assert!(backoff.after(SessionEnd::Rejected, None, &FixedJitter(1.0)) <= REJECTED_CAP);
        assert!(backoff.after(SessionEnd::Rejected, None, &NoJitter) > RECONNECT_CAP);
    }

    #[test]
    fn only_a_connection_that_stayed_up_resets_the_reconnect_wait() {
        let grown = || {
            let mut backoff = Backoff::default();
            for _ in 0..6 {
                backoff.after(SessionEnd::Unreachable, None, &NoJitter);
            }
            backoff
        };
        // Never connected, or connected only briefly: still backing off.
        for connected_for in [None, Some(Duration::from_secs(5)), Some(STABLE_SESSION)] {
            assert_eq!(
                grown().after(SessionEnd::Closed, connected_for, &NoJitter),
                Duration::from_secs(20),
                "{connected_for:?}"
            );
        }
        // A connection that lasted over a minute starts over at once.
        let mut backoff = grown();
        assert_eq!(
            backoff.after(
                SessionEnd::Closed,
                Some(STABLE_SESSION + Duration::from_secs(1)),
                &NoJitter
            ),
            RECONNECT_FIRST
        );
        assert_eq!(
            backoff.after(SessionEnd::Unreachable, None, &NoJitter),
            Duration::from_secs(2)
        );
    }
}
