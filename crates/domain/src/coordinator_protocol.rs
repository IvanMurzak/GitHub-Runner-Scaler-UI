//! The wire contract between `runner-manager` and its optional coordinator.
//!
//! Stage 1 of `.taskflow/2026-11-07-coordinator-server`: hosts connect out to
//! the coordinator over a WebSocket, prove who they are with an Ed25519
//! signature over a server nonce, describe themselves (`hello`), report their
//! load (`heartbeat`), and are told to poll a target now (`wake`) when GitHub
//! delivers a queued `workflow_job`. The coordinator advises; the host decides.
//!
//! Stage 2 adds the coordinator's own reconciliation sweep: a host that
//! speaks version 2 is told, in a `hello_ack`, which of its targets the sweep
//! covers, and polls those rarely while the link is up.
//!
//! Stage 3 (version 3) adds placement for the shared pool labels
//! (`rm-pool-linux`, ...): the coordinator picks exactly one host for a queued
//! pool job and sends it a `launch`; the host checks it against its own
//! policy and ceilings, answers `launch_ack`, and reports its attempts
//! (`attempt_started`, `attempt_finished`) so the coordinator knows when a
//! launched runner took a job.
//!
//! Stage 4 (version 4) adds job weight statistics: `attempt_finished` carries
//! what the attempt used ([`AttemptUsage`]: peak memory and CPU of the
//! runner's process tree), and a **query session** (`auth` with
//! [`SessionPurpose::Query`]) lets an enrolled host ask for the
//! coordinator's statistics ([`HostMessage::StatsRequest`] answered by
//! [`ServerMessage::Stats`]) without taking over its daemon's link.
//!
//! # Versioning
//!
//! Every message is one JSON object tagged by `type`. Fields may be **added**
//! but never removed or retyped: unknown fields are ignored on decode, and an
//! unknown message type decodes as [`HostMessage::Unknown`] /
//! [`ServerMessage::Unknown`] so that an older peer skips it instead of
//! dropping the connection.
//!
//! A connection runs at one negotiated version, the highest both sides speak
//! (see [`negotiate`]). The server's `challenge` names
//! [`MIN_PROTOCOL_VERSION`] in `protocol_version`, the field a version-1 host
//! checks for equality, and the newest version it speaks in the additive
//! `max_protocol_version`. The host answers `auth` and `hello` with the
//! negotiated version, and the `welcome` repeats it. So a version-1 host and a
//! version-2 coordinator, or the other way round, settle on version 1 and work
//! exactly as stage 1 did; only a version-2 pair exchanges `hello_ack`.
//! Enrollment did not change and is still sent as version 1, which every
//! coordinator accepts.
//!
//! # What never crosses this wire
//!
//! GitHub tokens, JIT configurations, job logs, the host's private key, and
//! the webhook secret. A `wake` carries a target, a repository name, a reason
//! and GitHub's delivery id — nothing a host must trust beyond "poll now".

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The newest protocol this build speaks.
pub const PROTOCOL_VERSION: u32 = 4;

/// The oldest protocol this build still speaks: stage 1's.
pub const MIN_PROTOCOL_VERSION: u32 = 1;

/// The first version with [`ServerMessage::HelloAck`].
pub const HELLO_ACK_VERSION: u32 = 2;

/// The first version with coordinated placement: [`ServerMessage::Launch`],
/// [`ServerMessage::CancelLaunch`], [`HostMessage::LaunchAck`] and the
/// attempt reports. A version-2 peer never sees or sends them.
pub const LAUNCH_VERSION: u32 = 3;

/// The first version with [`AttemptUsage`] in `attempt_finished` and with
/// query sessions ([`SessionPurpose::Query`], [`HostMessage::StatsRequest`],
/// [`ServerMessage::Stats`]). A version-3 peer ignores the usage field and
/// never opens or is offered a query session.
pub const STATS_VERSION: u32 = 4;

/// The version a connection runs at, given the newest version the peer
/// speaks and the oldest it still accepts: the highest both sides speak, or
/// `None` when the ranges do not overlap.
#[must_use]
pub fn negotiate(peer_min: u32, peer_max: u32) -> Option<u32> {
    let version = peer_max.min(PROTOCOL_VERSION);
    (version >= peer_min.max(MIN_PROTOCOL_VERSION)).then_some(version)
}

/// Whether this build accepts `version` from a peer.
#[must_use]
pub const fn supported(version: u32) -> bool {
    version >= MIN_PROTOCOL_VERSION && version <= PROTOCOL_VERSION
}

/// Domain separation for the connection signature. A signature made for this
/// purpose can never be replayed as anything else, and vice versa.
pub const AUTH_CONTEXT: &[u8] = b"runner-manager-coordinator/v1/host-auth";

/// Bytes of server randomness in every challenge.
pub const NONCE_LEN: usize = 32;

/// The largest single WebSocket message either side accepts.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// WebSocket close code: authentication failed (unknown, revoked or wrong key).
pub const CLOSE_UNAUTHORIZED: u16 = 4401;
/// WebSocket close code: the peer speaks a protocol version this one does not.
pub const CLOSE_UNSUPPORTED_VERSION: u16 = 4400;
/// WebSocket close code: a newer connection for the same host replaced this one.
pub const CLOSE_REPLACED: u16 = 4409;

/// The coordinator's paths, relative to its public origin.
pub const CONNECT_PATH: &str = "/connect";
pub const ENROLL_PATH: &str = "/enroll";
pub const WEBHOOK_PATH: &str = "/webhook";
pub const HEALTH_PATH: &str = "/healthz";

/// Why a message or a URL was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("the coordinator URL is not a URL")]
    InvalidUrl,
    #[error("the coordinator URL must use https (http is allowed for loopback only)")]
    InsecureUrl,
    #[error("the message is not valid protocol JSON")]
    Malformed,
    #[error("the key is not a valid Ed25519 key")]
    InvalidKey,
    #[error("the signature is not a valid Ed25519 signature")]
    InvalidSignature,
}

// ---------------------------------------------------------------------------
// Targets, hello and heartbeat
// ---------------------------------------------------------------------------

/// Whether a target is one repository or a whole organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    Repo,
    Org,
}

/// A target as both sides name it: `owner/name` for a repository, the login
/// for an organization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetRef {
    pub scope: TargetScope,
    pub name: String,
}

impl TargetRef {
    /// Whether `other` names the same target: same scope, and the name
    /// compared the way GitHub compares names, case-insensitively.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        self.scope == other.scope && self.name.eq_ignore_ascii_case(&other.name)
    }

    /// Whether this target covers `repository` (`owner/name`), compared the
    /// way GitHub compares names: case-insensitively.
    #[must_use]
    pub fn covers(&self, repository: &str) -> bool {
        match self.scope {
            TargetScope::Repo => self.name.eq_ignore_ascii_case(repository),
            TargetScope::Org => repository
                .split_once('/')
                .is_some_and(|(owner, _)| owner.eq_ignore_ascii_case(&self.name)),
        }
    }
}

impl fmt::Display for TargetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scope {
            TargetScope::Repo => write!(f, "repo:{}", self.name),
            TargetScope::Org => write!(f, "org:{}", self.name),
        }
    }
}

/// One runner profile a host serves a target with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    /// The labels the profile's runners register with.
    pub labels: Vec<String>,
    /// Whether the profile may start runners now.
    pub enabled: bool,
    /// Version 3: the profile keeps a persistent workspace for the target, so
    /// a runner it starts finds a warm checkout. A placement hint only.
    #[serde(default)]
    pub warm: bool,
}

/// A target and the profiles that serve it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub scope: TargetScope,
    pub name: String,
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

impl Target {
    #[must_use]
    pub fn reference(&self) -> TargetRef {
        TargetRef {
            scope: self.scope,
            name: self.name.clone(),
        }
    }
}

/// What a host says about itself once authenticated (D8: hardware is
/// reported, never configured on the coordinator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u32,
    pub host_id: String,
    /// `windows`, `macos`, `linux`.
    pub os: String,
    /// `x64`, `arm64`.
    pub arch: String,
    pub cores: u32,
    #[serde(default)]
    pub ram_bytes: Option<u64>,
    #[serde(default)]
    pub disk_free_bytes: Option<u64>,
    #[serde(default)]
    pub targets: Vec<Target>,
}

/// A host's periodic load report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Heartbeat {
    pub free_slots: u32,
    pub busy_slots: u32,
    pub cpu_load_percent: Option<u32>,
    pub free_ram_bytes: Option<u64>,
    /// A required `host doctor` check fails; the host starts no runner.
    pub unfit: bool,
    /// The daemon is draining for a shutdown, upgrade or reload.
    pub draining: bool,
}

// ---------------------------------------------------------------------------
// Wake
// ---------------------------------------------------------------------------

/// Why the coordinator woke a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeReason {
    /// GitHub queued a job the host advertised a matching profile for.
    JobQueued,
    /// The coordinator's reconciliation sweep found a queued job that no wake
    /// was sent for recently (a lost webhook, or a job still waiting).
    Reconcile,
    /// A reason this build does not know. Still a wake.
    #[serde(other)]
    Other,
}

/// "Poll this target now." Nothing more: the host computes demand itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wake {
    pub target: TargetRef,
    /// The repository the event came from, `owner/name`.
    pub repository: String,
    pub reason: WakeReason,
    /// GitHub's `X-GitHub-Delivery`, for correlating logs on both sides.
    pub delivery_id: String,
}

// ---------------------------------------------------------------------------
// Hello acknowledgement (version 2)
// ---------------------------------------------------------------------------

/// The coordinator's answer to a `hello`: whether it runs a reconciliation
/// sweep, and which of the host's targets that sweep covers.
///
/// Sent after every `hello` from a version-2 host, and again whenever the
/// coverage changes (an App installation added or removed). A covered target
/// may be polled rarely while the link is up, because the coordinator polls
/// it for the host and wakes it for any queued job it finds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HelloAck {
    /// How often the sweep runs, or `None` when the coordinator runs none
    /// (no GitHub App configured): then nothing is covered.
    pub reconcile_interval_secs: Option<u32>,
    /// The host's targets the sweep reads, as the host named them.
    pub covered: Vec<TargetRef>,
}

impl HelloAck {
    /// Whether the sweep covers `target`.
    #[must_use]
    pub fn covers(&self, target: &TargetRef) -> bool {
        self.reconcile_interval_secs.is_some()
            && self.covered.iter().any(|covered| covered.same_as(target))
    }
}

// ---------------------------------------------------------------------------
// Placement (version 3)
// ---------------------------------------------------------------------------

/// "Start one runner of this pool profile for this target." The host decides:
/// it starts it through its own allocator and every ceiling it always
/// applies, or refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Launch {
    pub target: TargetRef,
    /// The profile's name, as the host advertised it.
    pub profile: String,
    /// What the coordinator placed the runner for (`owner/repo#job-id`, or
    /// `owner/repo` for a job only the sweep saw). For logs; a runner takes
    /// whatever matching job GitHub hands it.
    pub job_key: String,
    /// Unique per launch; the host refuses a repeat.
    pub lease_id: String,
    /// When the coordinator stops counting on this runner, in Unix seconds.
    pub expires_at: i64,
    /// The same deadline as a duration from now, which the host uses so a
    /// skewed clock cannot expire a lease early or keep it late.
    pub ttl_secs: u32,
}

/// The job a launch was for is no longer queued: a launch whose runner has
/// not started yet is dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelLaunch {
    pub lease_id: String,
}

/// Why a host refused a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// No profile of that name serves that target here, or it is not a pool
    /// profile.
    UnknownProfile,
    /// The profile is disabled, draining, or not an autoscale profile.
    Disabled,
    /// The target is not in coordinated mode here (fallback or standalone):
    /// the host serves it from its own demand.
    NotCoordinated,
    /// The profile's `max_capacity` is reached.
    MaxCapacity,
    /// The host's capacity is reached.
    HostCapacity,
    /// A required `host doctor` check fails.
    Unfit,
    /// The daemon is draining for a shutdown, upgrade or reload.
    Draining,
    /// The lease was already seen, or expired before it arrived.
    Stale,
    /// A reason this build does not know.
    #[serde(other)]
    Other,
}

impl RefusalReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownProfile => "unknown_profile",
            Self::Disabled => "disabled",
            Self::NotCoordinated => "not_coordinated",
            Self::MaxCapacity => "max_capacity",
            Self::HostCapacity => "host_capacity",
            Self::Unfit => "unfit",
            Self::Draining => "draining",
            Self::Stale => "stale",
            Self::Other => "other",
        }
    }
}

/// The host's answer to a [`Launch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchAck {
    pub lease_id: String,
    pub accepted: bool,
    /// Why, when refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<RefusalReason>,
}

impl LaunchAck {
    #[must_use]
    pub fn accepted(lease_id: impl Into<String>) -> Self {
        Self {
            lease_id: lease_id.into(),
            accepted: true,
            reason: None,
        }
    }

    #[must_use]
    pub fn refused(lease_id: impl Into<String>, reason: RefusalReason) -> Self {
        Self {
            lease_id: lease_id.into(),
            accepted: false,
            reason: Some(reason),
        }
    }
}

/// One of the host's runners took a job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptStarted {
    /// The launch the runner was started for; `None` for one the host started
    /// from its own demand.
    #[serde(default)]
    pub lease_id: Option<String>,
    /// The name the runner registered with GitHub, which a `workflow_job`
    /// webhook's `runner_name` repeats.
    pub runner_name: String,
    pub target: TargetRef,
    pub profile: String,
}

/// How a runner attempt ended, as fixed words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcomeKind {
    CompletedJob,
    /// No job arrived and the runner exited on its idle timeout.
    IdleExit,
    Failed,
    Orphaned,
    #[serde(other)]
    Other,
}

/// One of the host's runner attempts ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptFinished {
    #[serde(default)]
    pub lease_id: Option<String>,
    pub runner_name: String,
    pub outcome: AttemptOutcomeKind,
    /// From the attempt's creation to its end.
    #[serde(default)]
    pub duration_secs: Option<u64>,
    /// Version 4: what the runner's process tree used, when this host could
    /// measure it (a native runner it sampled at least once). Absent from a
    /// version-3 host, and from an isolated attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<AttemptUsage>,
}

/// What one attempt's runner process tree used, sampled every few seconds.
///
/// CPU is in millicores: 1000 is one logical CPU busy for the whole interval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AttemptUsage {
    /// The largest resident memory of the whole tree in one sample.
    pub peak_rss_bytes: u64,
    /// CPU time over wall time between the first and the last sample.
    pub cpu_avg_millicores: u32,
    /// The busiest interval between two consecutive samples.
    pub cpu_peak_millicores: u32,
    /// How many samples were taken.
    pub samples: u32,
}

// ---------------------------------------------------------------------------
// Statistics (version 4)
// ---------------------------------------------------------------------------

impl StatsReport {
    /// The report as an operator reads it, for `stats` on either side.
    ///
    /// # Errors
    /// The writer's.
    pub fn render(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        writeln!(
            out,
            "Job statistics: the last {} samples per job, kept {} days",
            self.samples_per_job, self.retention_days
        )?;
        writeln!(
            out,
            "  launches accepted {}, wakes sent {}, samples recorded {}",
            self.launches, self.wakes, self.samples
        )?;
        if self.p50_queue_wait_secs.is_some() {
            writeln!(
                out,
                "  queue wait (queued to started): p50 {}, p90 {}",
                duration(self.p50_queue_wait_secs),
                duration(self.p90_queue_wait_secs)
            )?;
        }
        if self.jobs.is_empty() {
            writeln!(out, "\nNo job has been measured yet.")?;
        } else {
            writeln!(
                out,
                "\nHeaviest jobs (p90 peak memory, p90 CPU, p50 run time, p50/p90 queue wait, samples):"
            )?;
            for job in &self.jobs {
                writeln!(
                    out,
                    "  {}\n      {}  {}  {}  wait {}/{}  ({})",
                    printable(&job.job_key),
                    bytes(job.p90_peak_rss_bytes),
                    cores(job.p90_cpu_millicores),
                    duration(job.p50_duration_secs),
                    duration(job.p50_queue_wait_secs),
                    duration(job.p90_queue_wait_secs),
                    job.samples
                )?;
                for host in &job.hosts {
                    writeln!(
                        out,
                        "      on {:<24} {:>3} samples  p50 {}  {}",
                        host_label(&host.host_id, host.host_name.as_deref()),
                        host.samples,
                        duration(host.p50_duration_secs),
                        host.duration_ratio_permille.map_or_else(
                            || "-".to_string(),
                            |ratio| format!(
                                "{}.{:02}x the usual time",
                                ratio / 1000,
                                ratio % 1000 / 10
                            )
                        )
                    )?;
                }
            }
        }
        if !self.hosts.is_empty() {
            writeln!(out, "\nSamples per host:")?;
            for host in &self.hosts {
                writeln!(
                    out,
                    "  {:<28} {:>4} samples over {} jobs, p90 peak memory {}",
                    host_label(&host.host_id, host.host_name.as_deref()),
                    host.samples,
                    host.job_keys,
                    bytes(host.p90_peak_rss_bytes)
                )?;
            }
        }
        if !self.decisions.is_empty() {
            writeln!(out, "\nLast placements, newest first (scores in points):")?;
            for decision in &self.decisions {
                writeln!(
                    out,
                    "  {} ago  {} [{}] needs {} ({}), {}: {}",
                    duration(u64::try_from(self.generated_at.saturating_sub(decision.at)).ok()),
                    printable(&decision.repository),
                    printable(&decision.labels),
                    bytes(Some(decision.estimate_bytes)),
                    decision.estimate_source,
                    decision.method,
                    decision
                        .chosen
                        .as_deref()
                        .map_or_else(|| "no host fits".to_string(), printable)
                )?;
                for score in &decision.scores {
                    writeln!(
                        out,
                        "      {:<24} {:<8} free after {:<10} cache {} headroom {} speed {} bigfit -{} = {}",
                        printable(&score.host_id),
                        if score.fits { "fits" } else { "too full" },
                        bytes(score.free_after_bytes),
                        points(score.cache),
                        points(score.headroom),
                        points(score.speed),
                        points(score.bigfit),
                        points(score.total)
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn host_label(id: &str, name: Option<&str>) -> String {
    let id = printable(id);
    name.map_or_else(|| id.clone(), |name| format!("{} ({id})", printable(name)))
}

fn bytes(value: Option<u64>) -> String {
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    match value {
        None => "-".into(),
        Some(value) if value >= GIB => {
            format!("{}.{} GiB", value / GIB, value % GIB * 10 / GIB)
        }
        Some(value) => format!("{} MiB", value / MIB),
    }
}

fn cores(millicores: Option<u32>) -> String {
    millicores.map_or_else(
        || "-".into(),
        |value| format!("{}.{:02} cores", value / 1000, value % 1000 / 10),
    )
}

fn duration(secs: Option<u64>) -> String {
    secs.map_or_else(
        || "-".into(),
        |secs| {
            if secs >= 60 {
                format!("{}m {:02}s", secs / 60, secs % 60)
            } else {
                format!("{secs}s")
            }
        },
    )
}

fn points(thousandths: i64) -> String {
    let sign = if thousandths < 0 { "-" } else { "" };
    let value = thousandths.unsigned_abs();
    format!("{sign}{}.{:02}", value / 1000, value % 1000 / 10)
}

/// The prefix of every runner name `runner-manager` registers
/// (`runner-manager-<attempt id>`): what the coordinator correlates webhooks
/// with, and the only runner names it remembers.
pub const RUNNER_NAME_PREFIX: &str = "runner-manager-";

/// The longest runner name the coordinator correlates.
pub const MAX_RUNNER_NAME: usize = 128;

/// Whether `name` is one `runner-manager` could have registered.
#[must_use]
pub fn is_managed_runner_name(name: &str) -> bool {
    name.len() <= MAX_RUNNER_NAME
        && name
            .get(..RUNNER_NAME_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(RUNNER_NAME_PREFIX))
}

/// `text` without the characters that could rewrite a terminal: control
/// characters (ESC, C1), bidirectional overrides and isolates, zero-width
/// characters and line or paragraph separators. Names in `stats` come from
/// webhooks, and a workflow or job name is whatever a pull request wrote.
#[must_use]
pub fn printable(text: &str) -> String {
    text.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    c,
                    '\u{200B}'..='\u{200F}'
                        | '\u{2028}'..='\u{202E}'
                        | '\u{2060}'..='\u{206F}'
                        | '\u{FEFF}'
                )
        })
        .collect()
}

/// What a connection is for, named in `auth` (version 4). Always a plain
/// string on the wire: a later purpose that needs parameters carries them in
/// new `auth` fields, so an older coordinator reads it as [`Self::Other`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPurpose {
    /// The daemon's link: `hello`, heartbeats, wakes and launches. What a
    /// connection without a purpose is.
    #[default]
    Link,
    /// One question from the operator's terminal: the connection is not
    /// registered as the host's link (the daemon's link stays up), answers
    /// one [`HostMessage::StatsRequest`], and closes.
    Query,
    #[serde(other)]
    Other,
}

/// The coordinator's job weight statistics, as `stats` prints them.
///
/// Repository, workflow and job names come from GitHub's webhooks for the
/// owner's own repositories and are shown only to the owner's enrolled
/// hosts and on the coordinator's machine (D3, D5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StatsReport {
    /// Unix seconds.
    pub generated_at: i64,
    /// Samples kept per job key.
    pub samples_per_job: u32,
    /// Samples older than this are dropped.
    pub retention_days: u32,
    /// Launches hosts accepted, wakes sent, samples recorded, all time.
    pub launches: u64,
    pub wakes: u64,
    pub samples: u64,
    /// How long jobs waited from being queued to starting on a runner, over
    /// every kept sample (GitHub's `created_at` to `started_at`): what
    /// placement exists to keep short. Absent from a coordinator older than
    /// 0.4.47.
    pub p50_queue_wait_secs: Option<u64>,
    pub p90_queue_wait_secs: Option<u64>,
    /// The heaviest job keys by p90 peak memory, heaviest first.
    pub jobs: Vec<JobStats>,
    /// How the samples spread over the hosts.
    pub hosts: Vec<HostStats>,
    /// The last placement decisions, newest first.
    pub decisions: Vec<PlacementDecision>,
}

/// One job key (`owner/repo/workflow/job`) and its aggregates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobStats {
    pub job_key: String,
    pub samples: u32,
    /// The job's own run time, by GitHub's webhooks (`started_at` to
    /// `completed_at`); a sample without them counts its host's attempt.
    pub p50_duration_secs: Option<u64>,
    /// Queued to started, by GitHub's webhooks.
    pub p50_queue_wait_secs: Option<u64>,
    pub p90_queue_wait_secs: Option<u64>,
    pub p90_peak_rss_bytes: Option<u64>,
    pub p90_cpu_millicores: Option<u32>,
    /// Per host: its samples, its median duration and that median over the
    /// usual duration (the mean of every host's median), in thousandths
    /// (1000: as fast as usual, 2000: twice as slow).
    pub hosts: Vec<HostJobStats>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostJobStats {
    pub host_id: String,
    pub host_name: Option<String>,
    pub samples: u32,
    pub p50_duration_secs: Option<u64>,
    pub duration_ratio_permille: Option<u32>,
}

/// One host's share of the samples.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostStats {
    pub host_id: String,
    pub host_name: Option<String>,
    pub samples: u32,
    pub job_keys: u32,
    pub p90_peak_rss_bytes: Option<u64>,
}

/// Why one host was chosen for a pool queue (design 4.5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlacementDecision {
    /// Unix seconds.
    pub at: i64,
    pub repository: String,
    /// The queue's required labels, comma-separated.
    pub labels: String,
    /// The memory the queue's heaviest job is expected to need.
    pub estimate_bytes: u64,
    /// Where the estimate came from: `job` (that job key's p90), `repository`
    /// (the repository's p90, for a job never measured) or `default`.
    pub estimate_source: String,
    /// `weighted`, or `stage3` when no statistics were there to weigh.
    pub method: String,
    pub chosen: Option<String>,
    /// Every candidate, best first.
    pub scores: Vec<HostScore>,
}

/// One candidate's score parts, in thousandths of a point.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostScore {
    pub host_id: String,
    /// The estimate fits its free memory (less its open leases' estimates)
    /// with the safety margin. A host that does not fit is not placed on.
    pub fits: bool,
    pub free_after_bytes: Option<u64>,
    pub cache: i64,
    pub headroom: i64,
    pub speed: i64,
    pub bigfit: i64,
    pub total: i64,
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

/// Everything a host sends over the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    /// The answer to [`ServerMessage::Challenge`].
    Auth {
        protocol_version: u32,
        host_id: String,
        /// Base64 Ed25519 signature over [`auth_message`].
        signature: String,
        /// Version 4: what the connection is for; absent means the link.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<SessionPurpose>,
    },
    Hello(Hello),
    Heartbeat(Heartbeat),
    /// Version 3: the answer to a [`ServerMessage::Launch`].
    LaunchAck(LaunchAck),
    /// Version 3.
    AttemptStarted(AttemptStarted),
    /// Version 3.
    AttemptFinished(AttemptFinished),
    /// Version 4, on a query session only: send the statistics.
    StatsRequest,
    #[serde(other)]
    Unknown,
}

/// Everything the coordinator sends over the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// The first message on every connection.
    Challenge {
        /// The oldest version the coordinator accepts. A version-1 host
        /// requires this to be 1.
        protocol_version: u32,
        /// Base64 of [`NONCE_LEN`] random bytes.
        nonce: String,
        /// The newest version the coordinator speaks; absent from a
        /// version-1 coordinator, which speaks only `protocol_version`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_protocol_version: Option<u32>,
    },
    /// Authentication succeeded, at the negotiated version.
    Welcome {
        protocol_version: u32,
        heartbeat_interval_secs: u32,
    },
    Wake(Wake),
    /// Version 2: the answer to a `hello`.
    HelloAck(HelloAck),
    /// Version 3: start one runner for a queued pool job.
    Launch(Launch),
    /// Version 3: drop a launch whose runner has not started.
    CancelLaunch(CancelLaunch),
    /// Version 4: the answer to a [`HostMessage::StatsRequest`].
    Stats(StatsReport),
    #[serde(other)]
    Unknown,
}

macro_rules! json_codec {
    ($ty:ty) => {
        impl $ty {
            /// The message as one JSON text frame.
            #[must_use]
            pub fn encode(&self) -> String {
                serde_json::to_string(self).expect("protocol messages always serialize")
            }

            /// Parses one frame.
            ///
            /// # Errors
            /// [`ProtocolError::Malformed`]: the error deliberately carries
            /// nothing from the frame, so it can be logged.
            pub fn decode(text: &str) -> Result<Self, ProtocolError> {
                if text.len() > MAX_MESSAGE_BYTES {
                    return Err(ProtocolError::Malformed);
                }
                serde_json::from_str(text).map_err(|_| ProtocolError::Malformed)
            }
        }
    };
}

json_codec!(HostMessage);
json_codec!(ServerMessage);

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

/// `POST /enroll`: spend a one-time code to register this host's public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub protocol_version: u32,
    pub code: String,
    /// The machine's own name, as the host reports it.
    pub hostname: String,
    /// Base64 of the 32-byte Ed25519 public key.
    pub public_key: String,
}

/// The coordinator's answer to a successful enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub protocol_version: u32,
    pub host_id: String,
    /// The name the coordinator's operator gave this host at `invite`.
    pub name: String,
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

/// A coordinator's address, normalised to its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorUrl {
    origin: url::Url,
}

impl CoordinatorUrl {
    /// Parses what an operator typed. Only the origin is kept: a path,
    /// query or fragment is dropped.
    ///
    /// # Errors
    /// Not a URL, not `https`, or `http` to anything but loopback.
    pub fn parse(raw: &str) -> Result<Self, ProtocolError> {
        let parsed = url::Url::parse(raw.trim()).map_err(|_| ProtocolError::InvalidUrl)?;
        let host = parsed.host().ok_or(ProtocolError::InvalidUrl)?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ProtocolError::InvalidUrl);
        }
        match parsed.scheme() {
            "https" => {}
            "http" if is_loopback(&host) => {}
            "http" => return Err(ProtocolError::InsecureUrl),
            _ => return Err(ProtocolError::InvalidUrl),
        }
        let origin = url::Url::parse(&parsed.origin().ascii_serialization())
            .map_err(|_| ProtocolError::InvalidUrl)?;
        Ok(Self { origin })
    }

    /// `scheme://host[:port]`, what the connection signature binds to.
    #[must_use]
    pub fn origin(&self) -> String {
        self.origin.origin().ascii_serialization()
    }

    /// The WebSocket endpoint: `wss://…/connect` (or `ws://` for loopback).
    #[must_use]
    pub fn connect_url(&self) -> String {
        let scheme = if self.origin.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        let rest = self
            .origin()
            .split_once("://")
            .map_or(String::new(), |(_, rest)| rest.to_string());
        format!("{scheme}://{rest}{CONNECT_PATH}")
    }

    /// The enrollment endpoint.
    #[must_use]
    pub fn enroll_url(&self) -> String {
        format!("{}{ENROLL_PATH}", self.origin())
    }
}

impl fmt::Display for CoordinatorUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.origin())
    }
}

fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

// ---------------------------------------------------------------------------
// Host authentication
// ---------------------------------------------------------------------------

/// The bytes a host signs: `nonce || AUTH_CONTEXT || origin`.
///
/// The nonce is fixed-length, so the concatenation is unambiguous. Binding the
/// origin means a signature a malicious server collects cannot be relayed to
/// a different coordinator.
#[must_use]
pub fn auth_message(nonce: &[u8; NONCE_LEN], origin: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(NONCE_LEN + AUTH_CONTEXT.len() + origin.len());
    message.extend_from_slice(nonce);
    message.extend_from_slice(AUTH_CONTEXT);
    message.extend_from_slice(origin.as_bytes());
    message
}

/// Encodes a nonce for the `challenge` message.
#[must_use]
pub fn encode_nonce(nonce: &[u8; NONCE_LEN]) -> String {
    BASE64.encode(nonce)
}

/// Decodes a `challenge` nonce.
///
/// # Errors
/// [`ProtocolError::Malformed`] when it is not base64 of [`NONCE_LEN`] bytes.
pub fn decode_nonce(text: &str) -> Result<[u8; NONCE_LEN], ProtocolError> {
    BASE64
        .decode(text)
        .ok()
        .and_then(|bytes| <[u8; NONCE_LEN]>::try_from(bytes).ok())
        .ok_or(ProtocolError::Malformed)
}

/// Signs a challenge; the result goes in [`HostMessage::Auth`].
#[must_use]
pub fn sign_challenge(key: &SigningKey, nonce: &[u8; NONCE_LEN], origin: &str) -> String {
    BASE64.encode(key.sign(&auth_message(nonce, origin)).to_bytes())
}

/// Whether `signature` is `public_key`'s signature over this challenge.
///
/// Strict verification: rejects weak keys and malleable signatures.
#[must_use]
pub fn verify_challenge(
    public_key: &VerifyingKey,
    nonce: &[u8; NONCE_LEN],
    origin: &str,
    signature: &str,
) -> bool {
    let Ok(bytes) = BASE64.decode(signature) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    public_key
        .verify_strict(&auth_message(nonce, origin), &signature)
        .is_ok()
}

/// A public key as it travels and is stored: base64 of 32 bytes.
#[must_use]
pub fn encode_public_key(key: &VerifyingKey) -> String {
    BASE64.encode(key.as_bytes())
}

/// Parses [`encode_public_key`]'s output, refusing weak keys.
///
/// # Errors
/// [`ProtocolError::InvalidKey`].
pub fn decode_public_key(text: &str) -> Result<VerifyingKey, ProtocolError> {
    let bytes = BASE64.decode(text).map_err(|_| ProtocolError::InvalidKey)?;
    let bytes = <[u8; 32]>::try_from(bytes).map_err(|_| ProtocolError::InvalidKey)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| ProtocolError::InvalidKey)?;
    if key.is_weak() {
        return Err(ProtocolError::InvalidKey);
    }
    Ok(key)
}

/// A private key as the host's secret store holds it: base64 of the 32-byte
/// seed. The caller keeps the result inside a secret type.
#[must_use]
pub fn encode_signing_key(key: &SigningKey) -> String {
    BASE64.encode(key.to_bytes())
}

/// Parses [`encode_signing_key`]'s output.
///
/// # Errors
/// [`ProtocolError::InvalidKey`]; the error carries nothing of the input.
pub fn decode_signing_key(text: &str) -> Result<SigningKey, ProtocolError> {
    let bytes = BASE64
        .decode(text.trim())
        .map_err(|_| ProtocolError::InvalidKey)?;
    let seed = <[u8; 32]>::try_from(bytes).map_err(|_| ProtocolError::InvalidKey)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// A new signing key from 32 bytes of the caller's randomness.
#[must_use]
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub use ed25519_dalek::SigningKey as HostSigningKey;

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        signing_key_from_seed(&[byte; 32])
    }

    fn hello() -> Hello {
        Hello {
            protocol_version: PROTOCOL_VERSION,
            host_id: "h1".into(),
            os: "linux".into(),
            arch: "x64".into(),
            cores: 16,
            ram_bytes: Some(64 << 30),
            disk_free_bytes: None,
            targets: vec![Target {
                scope: TargetScope::Repo,
                name: "octo/app".into(),
                profiles: vec![Profile {
                    name: "default".into(),
                    labels: vec!["self-hosted".into(), "linux".into()],
                    enabled: true,
                    warm: false,
                }],
            }],
        }
    }

    #[test]
    fn every_message_round_trips_with_its_type_tag() {
        let messages = [
            HostMessage::Auth {
                protocol_version: PROTOCOL_VERSION,
                host_id: "h1".into(),
                signature: "c2ln".into(),
                purpose: None,
            },
            HostMessage::Auth {
                protocol_version: PROTOCOL_VERSION,
                host_id: "h1".into(),
                signature: "c2ln".into(),
                purpose: Some(SessionPurpose::Query),
            },
            HostMessage::StatsRequest,
            HostMessage::Hello(hello()),
            HostMessage::Heartbeat(Heartbeat {
                free_slots: 2,
                busy_slots: 1,
                cpu_load_percent: Some(40),
                free_ram_bytes: None,
                unfit: false,
                draining: true,
            }),
        ];
        let attempts = [
            HostMessage::LaunchAck(LaunchAck::accepted("l1")),
            HostMessage::LaunchAck(LaunchAck::refused("l2", RefusalReason::HostCapacity)),
            HostMessage::AttemptStarted(AttemptStarted {
                lease_id: Some("l1".into()),
                runner_name: "runner-manager-1".into(),
                target: TargetRef {
                    scope: TargetScope::Repo,
                    name: "octo/app".into(),
                },
                profile: "default".into(),
            }),
            HostMessage::AttemptFinished(AttemptFinished {
                lease_id: None,
                runner_name: "runner-manager-1".into(),
                outcome: AttemptOutcomeKind::IdleExit,
                duration_secs: Some(42),
                usage: None,
            }),
            HostMessage::AttemptFinished(AttemptFinished {
                lease_id: Some("l1".into()),
                runner_name: "runner-manager-1".into(),
                outcome: AttemptOutcomeKind::CompletedJob,
                duration_secs: Some(600),
                usage: Some(AttemptUsage {
                    peak_rss_bytes: 3 << 30,
                    cpu_avg_millicores: 1500,
                    cpu_peak_millicores: 7900,
                    samples: 300,
                }),
            }),
        ];
        for message in messages.into_iter().chain(attempts) {
            let text = message.encode();
            assert!(text.contains("\"type\":"), "{text}");
            assert_eq!(HostMessage::decode(&text).expect("decodes"), message);
        }
        let server = [
            ServerMessage::Challenge {
                protocol_version: MIN_PROTOCOL_VERSION,
                nonce: encode_nonce(&[7; NONCE_LEN]),
                max_protocol_version: Some(PROTOCOL_VERSION),
            },
            ServerMessage::HelloAck(HelloAck {
                reconcile_interval_secs: Some(120),
                covered: vec![TargetRef {
                    scope: TargetScope::Repo,
                    name: "octo/app".into(),
                }],
            }),
            ServerMessage::Welcome {
                protocol_version: PROTOCOL_VERSION,
                heartbeat_interval_secs: 15,
            },
            ServerMessage::Wake(Wake {
                target: TargetRef {
                    scope: TargetScope::Org,
                    name: "octo".into(),
                },
                repository: "octo/app".into(),
                reason: WakeReason::JobQueued,
                delivery_id: "d-1".into(),
            }),
            ServerMessage::Launch(Launch {
                target: TargetRef {
                    scope: TargetScope::Repo,
                    name: "octo/app".into(),
                },
                profile: "default".into(),
                job_key: "octo/app#7".into(),
                lease_id: "l1".into(),
                expires_at: 1_800_000_000,
                ttl_secs: 300,
            }),
            ServerMessage::CancelLaunch(CancelLaunch {
                lease_id: "l1".into(),
            }),
            ServerMessage::Stats(StatsReport {
                generated_at: 1_800_000_000,
                samples_per_job: 30,
                retention_days: 90,
                launches: 4,
                wakes: 9,
                samples: 2,
                p50_queue_wait_secs: Some(3),
                p90_queue_wait_secs: Some(12),
                jobs: vec![JobStats {
                    job_key: "octo/app/ci/build (linux)".into(),
                    samples: 2,
                    p50_duration_secs: Some(60),
                    p50_queue_wait_secs: Some(3),
                    p90_queue_wait_secs: Some(12),
                    p90_peak_rss_bytes: Some(1 << 30),
                    p90_cpu_millicores: Some(2000),
                    hosts: vec![HostJobStats {
                        host_id: "h1".into(),
                        host_name: Some("linux".into()),
                        samples: 2,
                        p50_duration_secs: Some(60),
                        duration_ratio_permille: Some(1000),
                    }],
                }],
                hosts: vec![HostStats {
                    host_id: "h1".into(),
                    host_name: None,
                    samples: 2,
                    job_keys: 1,
                    p90_peak_rss_bytes: Some(1 << 30),
                }],
                decisions: vec![PlacementDecision {
                    at: 1_800_000_000,
                    repository: "octo/app".into(),
                    labels: "rm-pool-linux".into(),
                    estimate_bytes: 1 << 30,
                    estimate_source: "job".into(),
                    method: "weighted".into(),
                    chosen: Some("h1".into()),
                    scores: vec![HostScore {
                        host_id: "h1".into(),
                        fits: true,
                        free_after_bytes: Some(7 << 30),
                        cache: 0,
                        headroom: 1750,
                        speed: 0,
                        bigfit: 0,
                        total: 1750,
                    }],
                }],
            }),
        ];
        for message in server {
            assert_eq!(
                ServerMessage::decode(&message.encode()).expect("decodes"),
                message
            );
        }
    }

    #[test]
    fn the_wire_names_are_stable() {
        let text = HostMessage::Heartbeat(Heartbeat::default()).encode();
        assert_eq!(
            text,
            r#"{"type":"heartbeat","free_slots":0,"busy_slots":0,"cpu_load_percent":null,"free_ram_bytes":null,"unfit":false,"draining":false}"#
        );
    }

    #[test]
    fn a_newer_peer_is_tolerated_and_garbage_is_refused() {
        // An added field, and a message type this build has never heard of.
        let with_field = r#"{"type":"heartbeat","free_slots":1,"gpu":"x"}"#;
        assert!(matches!(
            HostMessage::decode(with_field),
            Ok(HostMessage::Heartbeat(Heartbeat { free_slots: 1, .. }))
        ));
        assert_eq!(
            ServerMessage::decode(r#"{"type":"rebalance","lease_id":"l"}"#),
            Ok(ServerMessage::Unknown)
        );
        let wake = r#"{"type":"wake","target":{"scope":"repo","name":"a/b"},"repository":"a/b","reason":"rebalance","delivery_id":"d"}"#;
        assert!(matches!(
            ServerMessage::decode(wake),
            Ok(ServerMessage::Wake(Wake {
                reason: WakeReason::Other,
                ..
            }))
        ));
        assert_eq!(
            HostMessage::decode("not json"),
            Err(ProtocolError::Malformed)
        );
        let huge = format!(
            r#"{{"type":"heartbeat","x":"{}"}}"#,
            "a".repeat(MAX_MESSAGE_BYTES)
        );
        assert_eq!(HostMessage::decode(&huge), Err(ProtocolError::Malformed));
    }

    #[test]
    fn a_version_one_peer_and_this_one_settle_on_version_one() {
        // A version-1 coordinator's challenge: no `max_protocol_version`.
        let old = r#"{"type":"challenge","protocol_version":1,"nonce":"AAAA"}"#;
        let Ok(ServerMessage::Challenge {
            protocol_version,
            max_protocol_version,
            ..
        }) = ServerMessage::decode(old)
        else {
            panic!("a version-1 challenge decodes");
        };
        assert_eq!(
            negotiate(
                protocol_version,
                max_protocol_version.unwrap_or(protocol_version)
            ),
            Some(1)
        );
        // This coordinator's challenge still says 1 where a version-1 host
        // looks, so that host proceeds at 1; this host proceeds at 2.
        let new = ServerMessage::Challenge {
            protocol_version: MIN_PROTOCOL_VERSION,
            nonce: "AAAA".into(),
            max_protocol_version: Some(PROTOCOL_VERSION),
        }
        .encode();
        assert!(new.contains(r#""protocol_version":1"#), "{new}");
        assert_eq!(negotiate(1, 2), Some(2));
        // A version-1 host's `auth` is accepted by this coordinator.
        assert!(supported(1) && supported(2) && supported(3));
        assert!(!supported(0) && !supported(PROTOCOL_VERSION + 1));
        // A future peer that dropped every version this one speaks does not
        // overlap.
        assert_eq!(negotiate(PROTOCOL_VERSION + 1, PROTOCOL_VERSION + 2), None);
        assert_eq!(negotiate(1, 9), Some(PROTOCOL_VERSION));
        // A `hello_ack` is an unknown type to a version-1 host's decoder,
        // which skips it; here it decodes, and its coverage is case-blind.
        let ack = r#"{"type":"hello_ack","reconcile_interval_secs":120,"covered":[{"scope":"org","name":"Octo"}],"later":1}"#;
        let Ok(ServerMessage::HelloAck(ack)) = ServerMessage::decode(ack) else {
            panic!("decodes");
        };
        assert!(ack.covers(&TargetRef {
            scope: TargetScope::Org,
            name: "octo".into()
        }));
        assert!(!ack.covers(&TargetRef {
            scope: TargetScope::Repo,
            name: "octo".into()
        }));
        let no_sweep = HelloAck {
            reconcile_interval_secs: None,
            ..ack
        };
        assert!(!no_sweep.covers(&TargetRef {
            scope: TargetScope::Org,
            name: "octo".into()
        }));
        // The sweep's own wake reason reaches a version-1 host as `Other`:
        // still a wake.
        let wake = ServerMessage::Wake(Wake {
            target: TargetRef {
                scope: TargetScope::Repo,
                name: "a/b".into(),
            },
            repository: "a/b".into(),
            reason: WakeReason::Reconcile,
            delivery_id: "reconcile".into(),
        })
        .encode();
        assert!(wake.contains(r#""reason":"reconcile""#), "{wake}");
    }

    #[test]
    fn a_version_two_peer_and_this_one_keep_working() {
        // A version-2 hello: no `warm` on its profiles.
        let profile = r#"{"name":"default","labels":["linux"],"enabled":true}"#;
        let decoded: Profile = serde_json::from_str(profile).expect("decodes");
        assert!(!decoded.warm);
        // Both sides settle on 2 with a version-2 peer.
        assert_eq!(negotiate(1, 2), Some(2));
        assert!(LAUNCH_VERSION > HELLO_ACK_VERSION && supported(LAUNCH_VERSION));
        // A refusal reason from a newer host is still a refusal here.
        let ack = r#"{"type":"launch_ack","lease_id":"l","accepted":false,"reason":"gpu_busy"}"#;
        assert_eq!(
            HostMessage::decode(ack),
            Ok(HostMessage::LaunchAck(LaunchAck::refused(
                "l",
                RefusalReason::Other
            )))
        );
        let finished = r#"{"type":"attempt_finished","runner_name":"r","outcome":"preempted"}"#;
        assert!(matches!(
            HostMessage::decode(finished),
            Ok(HostMessage::AttemptFinished(AttemptFinished {
                outcome: AttemptOutcomeKind::Other,
                lease_id: None,
                ..
            }))
        ));
    }

    #[test]
    fn a_report_renders_every_section_an_operator_reads() {
        let report = StatsReport {
            samples_per_job: 30,
            retention_days: 90,
            launches: 3,
            p50_queue_wait_secs: Some(4),
            p90_queue_wait_secs: Some(75),
            jobs: vec![JobStats {
                job_key: "octo/app/ci/build".into(),
                samples: 4,
                p50_duration_secs: Some(372),
                p50_queue_wait_secs: Some(3),
                p90_queue_wait_secs: Some(61),
                p90_peak_rss_bytes: Some(3 << 30),
                p90_cpu_millicores: Some(2150),
                hosts: vec![HostJobStats {
                    host_id: "h1".into(),
                    host_name: Some("linux".into()),
                    samples: 4,
                    p50_duration_secs: Some(372),
                    duration_ratio_permille: Some(910),
                }],
            }],
            decisions: vec![PlacementDecision {
                repository: "octo/app".into(),
                labels: "rm-pool-linux".into(),
                estimate_bytes: 3 << 30,
                estimate_source: "job".into(),
                method: "weighted".into(),
                chosen: Some("h1".into()),
                scores: vec![HostScore {
                    host_id: "h1".into(),
                    fits: true,
                    total: -1250,
                    ..HostScore::default()
                }],
                ..PlacementDecision::default()
            }],
            ..StatsReport::default()
        };
        let mut text = String::new();
        report.render(&mut text).expect("renders");
        for expected in [
            "launches accepted 3",
            "octo/app/ci/build",
            "queue wait (queued to started): p50 4s, p90 1m 15s",
            "3.0 GiB  2.15 cores  6m 12s  wait 3s/1m 01s  (4)",
            "linux (h1)",
            "0.91x the usual time",
            "needs 3.0 GiB (job), weighted: h1",
            "= -1.25",
        ] {
            assert!(text.contains(expected), "missing `{expected}`:\n{text}");
        }
        let hostile = StatsReport {
            jobs: vec![JobStats {
                job_key: "a\u{1b}[2Jb\u{202E}c\u{200B}d".into(),
                ..JobStats::default()
            }],
            ..StatsReport::default()
        };
        let mut text = String::new();
        hostile.render(&mut text).expect("renders");
        assert!(
            text.contains("a[2Jbcd") && !text.contains('\u{1b}'),
            "{text:?}"
        );
        assert!(is_managed_runner_name("Runner-Manager-0a1b"));
        assert!(!is_managed_runner_name("GitHub Actions 2"));
        assert!(!is_managed_runner_name(&format!(
            "runner-manager-{}",
            "x".repeat(200)
        )));
        let mut empty = String::new();
        StatsReport::default().render(&mut empty).expect("renders");
        assert!(empty.contains("No job has been measured yet."));
        assert!(!empty.contains("queue wait"), "nothing measured: no line");
        // A 0.4.46 coordinator's report has no queue wait: it still decodes.
        let older: StatsReport =
            serde_json::from_str(r#"{"jobs":[{"job_key":"k","p50_duration_secs":63}]}"#)
                .expect("decodes");
        assert_eq!(older.jobs[0].p50_queue_wait_secs, None);
        assert_eq!(older.p90_queue_wait_secs, None);
    }

    #[test]
    fn a_version_three_peer_and_this_one_keep_working() {
        assert_eq!(negotiate(1, 3), Some(3));
        assert!(STATS_VERSION > LAUNCH_VERSION && supported(STATS_VERSION));
        // A version-3 host's `attempt_finished` and `auth`: no usage, no
        // purpose, which means the link.
        let finished = r#"{"type":"attempt_finished","runner_name":"r","outcome":"completed_job","duration_secs":5}"#;
        assert!(matches!(
            HostMessage::decode(finished),
            Ok(HostMessage::AttemptFinished(AttemptFinished {
                usage: None,
                ..
            }))
        ));
        let auth = r#"{"type":"auth","protocol_version":3,"host_id":"h","signature":"s"}"#;
        assert!(matches!(
            HostMessage::decode(auth),
            Ok(HostMessage::Auth { purpose: None, .. })
        ));
        // What this build sends without usage or purpose is byte-for-byte
        // what a version-3 build sent.
        let plain = HostMessage::AttemptFinished(AttemptFinished {
            lease_id: None,
            runner_name: "r".into(),
            outcome: AttemptOutcomeKind::CompletedJob,
            duration_secs: Some(5),
            usage: None,
        })
        .encode();
        assert!(!plain.contains("usage"), "{plain}");
        let auth = HostMessage::Auth {
            protocol_version: 3,
            host_id: "h".into(),
            signature: "s".into(),
            purpose: None,
        }
        .encode();
        assert!(!auth.contains("purpose"), "{auth}");
        // The new messages are unknown types to a version-3 decoder, which
        // skips them; a newer purpose is not mistaken for the link.
        assert_eq!(
            ServerMessage::decode(r#"{"type":"stats","later":1}"#)
                .map(|m| matches!(m, ServerMessage::Stats(_))),
            Ok(true)
        );
        let future = r#"{"type":"auth","protocol_version":4,"host_id":"h","signature":"s","purpose":"watch"}"#;
        assert!(matches!(
            HostMessage::decode(future),
            Ok(HostMessage::Auth {
                purpose: Some(SessionPurpose::Other),
                ..
            })
        ));
        let usage = r#"{"type":"attempt_finished","runner_name":"r","outcome":"completed_job","usage":{"peak_rss_bytes":7,"gpu":1}}"#;
        assert!(matches!(
            HostMessage::decode(usage),
            Ok(HostMessage::AttemptFinished(AttemptFinished {
                usage: Some(AttemptUsage {
                    peak_rss_bytes: 7,
                    samples: 0,
                    ..
                }),
                ..
            }))
        ));
    }

    #[test]
    fn a_signature_verifies_only_for_its_key_nonce_and_origin() {
        let signer = key(1);
        let nonce = [9; NONCE_LEN];
        let origin = "https://runners.example.com";
        let signature = sign_challenge(&signer, &nonce, origin);
        let public = signer.verifying_key();
        assert!(verify_challenge(&public, &nonce, origin, &signature));
        assert!(!verify_challenge(
            &key(2).verifying_key(),
            &nonce,
            origin,
            &signature
        ));
        assert!(!verify_challenge(
            &public,
            &[8; NONCE_LEN],
            origin,
            &signature
        ));
        assert!(!verify_challenge(
            &public,
            &nonce,
            "https://evil.example.com",
            &signature
        ));
        assert!(!verify_challenge(&public, &nonce, origin, "not base64!"));
    }

    #[test]
    fn keys_round_trip_and_bad_ones_are_refused() {
        let signer = key(3);
        let decoded = decode_signing_key(&encode_signing_key(&signer)).expect("decodes");
        assert_eq!(decoded.to_bytes(), signer.to_bytes());
        let public = decode_public_key(&encode_public_key(&signer.verifying_key())).expect("ok");
        assert_eq!(public, signer.verifying_key());
        assert_eq!(decode_public_key("AAAA"), Err(ProtocolError::InvalidKey));
        // The identity point is a weak key.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            decode_public_key(&BASE64.encode(identity)),
            Err(ProtocolError::InvalidKey)
        );
        assert!(decode_nonce(&encode_nonce(&[1; NONCE_LEN])).is_ok());
        assert!(decode_nonce("AAAA").is_err());
    }

    #[test]
    fn urls_are_normalised_to_their_origin_and_must_be_secure() {
        let url = CoordinatorUrl::parse("https://Runners.Example.com/some/path?x=1").expect("ok");
        assert_eq!(url.origin(), "https://runners.example.com");
        assert_eq!(url.connect_url(), "wss://runners.example.com/connect");
        assert_eq!(url.enroll_url(), "https://runners.example.com/enroll");
        let local = CoordinatorUrl::parse("http://127.0.0.1:8080").expect("loopback");
        assert_eq!(local.connect_url(), "ws://127.0.0.1:8080/connect");
        assert_eq!(
            CoordinatorUrl::parse("http://runners.example.com"),
            Err(ProtocolError::InsecureUrl)
        );
        assert_eq!(
            CoordinatorUrl::parse("ftp://x"),
            Err(ProtocolError::InvalidUrl)
        );
        assert!(CoordinatorUrl::parse("https://user:pw@x.example").is_err());
    }

    #[test]
    fn a_target_covers_its_repository_or_its_organizations_repositories() {
        let repo = TargetRef {
            scope: TargetScope::Repo,
            name: "Octo/App".into(),
        };
        assert!(repo.covers("octo/app"));
        assert!(!repo.covers("octo/other"));
        let org = TargetRef {
            scope: TargetScope::Org,
            name: "OCTO".into(),
        };
        assert!(org.covers("octo/anything"));
        assert!(!org.covers("octopus/app"));
        assert!(!org.covers("octo"));
    }
}
