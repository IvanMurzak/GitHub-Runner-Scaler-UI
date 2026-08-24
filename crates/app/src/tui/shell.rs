// owner: g1-tui-shell-input

//! Terminal ownership, merged input, focus, and the TUI reducer.
//! Rendering accepts only immutable [`PresentationState`], so a frame has no
//! filesystem, store, or network capability.

use std::collections::{HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{
    DisableBracketedPaste, DisableFocusChange, DisableMouseCapture, EnableBracketedPaste,
    EnableFocusChange, EnableMouseCapture, Event, EventStream, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{Command, execute};
use futures::{Stream, StreamExt};
use ratatui::Frame;
use ratatui::backend::Backend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use tokio::sync::mpsc;

use runner_manager_domain::attempt::{AttemptOutcome, AttemptState, FailureReason, RunnerAttempt};
use runner_manager_domain::model::{Org, OwnerRepo, ScaleTarget, StartMode};
use runner_manager_domain::store::Store as _;
use runner_manager_github::rest::{
    ActivityScope, CancelToken, InventoryError, InventoryGateway, RefreshState, RestInventory,
};
use runner_manager_github::{AuthenticatedClient, UserAccessToken};
use runner_manager_platform::secrets::SecretStore as _;

use super::screens::{
    self, AgentHealth, Availability, DashboardMetrics, PolicyMode, ReadOnlyScreen, RepositoryRow,
    RunnerOwnership, RunnerRow, ScreenAction, ScreenModel, Snapshot,
};

#[cfg(test)]
pub const FRAME_BUDGET: Duration = Duration::from_millis(16);
pub const TICK_RATE: Duration = Duration::from_millis(250);
const LOCAL_AGENT_POLL_RATE: Duration = Duration::from_secs(60);
const MAX_ACTIVITY_HISTORY: usize = 256;
const REDACTED: &str = "[REDACTED]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Screen {
    Dashboard,
    Repositories,
    Runners,
    RepositorySettings,
    HostSettings,
    Activity,
}

impl Screen {
    pub const ALL: [Self; 6] = [
        Self::Dashboard,
        Self::Repositories,
        Self::Runners,
        Self::RepositorySettings,
        Self::HostSettings,
        Self::Activity,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Repositories => "Repositories",
            Self::Runners => "Runners",
            Self::RepositorySettings => "Repository settings",
            Self::HostSettings => "Host settings",
            Self::Activity => "Activity & errors",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Navigation,
    Content,
    Status,
}

impl Focus {
    fn next(self, backwards: bool) -> Self {
        match (self, backwards) {
            (Self::Navigation, false) | (Self::Status, true) => Self::Content,
            (Self::Content, false) | (Self::Navigation, true) => Self::Status,
            (Self::Status, false) | (Self::Content, true) => Self::Navigation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "g2 presentation states construct every health value"
)]
pub enum Health {
    Ready,
    Busy,
    Offline,
    Error,
}

impl Health {
    fn presentation(self) -> (&'static str, &'static str, Color) {
        match self {
            Self::Ready => ("OK", "Ready", Color::Green),
            Self::Busy => ("*", "Busy", Color::Yellow),
            Self::Offline => ("!", "Offline - no new runners will start", Color::Gray),
            Self::Error => ("X", "Error - open Activity for remediation", Color::Red),
        }
    }
}

/// Immutable, already-collected values a frame may display. The two sensitive
/// fields are never rendered; they drive unconditional boundary redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationState {
    pub heading: String,
    pub body: Vec<String>,
    pub diagnostics: Vec<String>,
    pub health: Health,
    pub access_token: Option<String>,
    pub jit_configuration: Option<String>,
}

impl Default for PresentationState {
    fn default() -> Self {
        Self {
            heading: "Local runner manager".to_owned(),
            body: vec!["Waiting for the first local status snapshot...".to_owned()],
            diagnostics: vec!["No activity recorded.".to_owned()],
            health: Health::Ready,
            access_token: None,
            jit_configuration: None,
        }
    }
}

impl PresentationState {
    fn redact(&self, value: &str) -> String {
        let mut safe = value.to_owned();
        for secret in [
            self.access_token.as_deref(),
            self.jit_configuration.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter(|secret| !secret.is_empty())
        {
            safe = safe.replace(secret, REDACTED);
        }
        safe
    }

    fn copy_text(&self) -> String {
        self.diagnostics
            .iter()
            .map(|line| self.redact(line))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEvent {
    pub summary: String,
    pub health: Health,
    /// A fully collected GitHub inventory snapshot when the embedding agent
    /// has one. The standalone local journal reader supplies `None`; it never
    /// invents GitHub workload counts from local attempt counts.
    pub snapshot: Option<Snapshot>,
}

/// Polls the durable lifecycle/status view written by the already-running
/// daemon. This is deliberately a local journal reader, not an IPC listener:
/// the product exposes no inbound control surface and `q` owns only this
/// reader thread.
struct LocalAgentEventSource {
    control: Arc<(Mutex<SourceState>, Condvar)>,
    worker: Option<thread::JoinHandle<()>>,
}

struct SourceState {
    stopped: bool,
    requested_generation: u64,
    active: Option<(u64, CancelToken)>,
}

impl LocalAgentEventSource {
    fn start(
        context: Arc<crate::cli::Context>,
        poll_rate: Duration,
    ) -> io::Result<(Self, mpsc::UnboundedReceiver<AgentEvent>)> {
        Self::start_with(move |cancel| local_agent_event(&context, cancel), poll_rate)
    }

    fn start_with(
        produce: impl Fn(&CancelToken) -> AgentEvent + Send + 'static,
        poll_rate: Duration,
    ) -> io::Result<(Self, mpsc::UnboundedReceiver<AgentEvent>)> {
        let (events, receiver) = mpsc::unbounded_channel();
        let control = Arc::new((
            Mutex::new(SourceState {
                stopped: false,
                requested_generation: 1,
                active: None,
            }),
            Condvar::new(),
        ));
        let worker_control = Arc::clone(&control);
        let worker = thread::Builder::new()
            .name("runner-manager-tui-events".to_owned())
            .spawn(move || {
                let mut completed_generation = 0_u64;
                loop {
                    let (state_lock, wake) = &*worker_control;
                    let mut state = state_lock.lock().unwrap();
                    while !state.stopped && state.requested_generation <= completed_generation {
                        let (next, timeout) = wake.wait_timeout(state, poll_rate).unwrap();
                        state = next;
                        if timeout.timed_out() && state.requested_generation <= completed_generation
                        {
                            state.requested_generation = completed_generation.saturating_add(1);
                        }
                    }
                    if state.stopped {
                        break;
                    }
                    let generation = state.requested_generation;
                    let cancel = CancelToken::new();
                    // Publication happens while holding the same lock used by
                    // refresh and stop, so neither can slip through before an
                    // active token exists to cancel.
                    state.active = Some((generation, cancel.clone()));
                    drop(state);

                    let event = produce(&cancel);
                    let mut state = state_lock.lock().unwrap();
                    let publish = !state.stopped
                        && state.requested_generation == generation
                        && !cancel.is_cancelled();
                    if state
                        .active
                        .as_ref()
                        .is_some_and(|(active_generation, _)| *active_generation == generation)
                    {
                        state.active = None;
                    }
                    completed_generation = generation;
                    if state.stopped {
                        break;
                    }
                    // Keep the control lock through the non-blocking publish.
                    // This linearizes a refresh request either before publish
                    // (and suppresses this result) or after it; there is no
                    // unlocked stale-send window between the generation check
                    // and delivery.
                    if publish && events.send(event).is_err() {
                        break;
                    }
                }
            })?;
        Ok((
            Self {
                control,
                worker: Some(worker),
            },
            receiver,
        ))
    }

    fn request_refresh(&self) -> io::Result<()> {
        let (state_lock, wake) = &*self.control;
        let mut state = state_lock.lock().unwrap();
        if state.stopped {
            return Err(io::Error::other("the TUI snapshot source stopped"));
        }
        state.requested_generation = state.requested_generation.saturating_add(1);
        if let Some((_, cancel)) = &state.active {
            cancel.cancel();
        }
        wake.notify_one();
        Ok(())
    }
}

impl Drop for LocalAgentEventSource {
    fn drop(&mut self) {
        let (state_lock, wake) = &*self.control;
        {
            let mut state = state_lock.lock().unwrap();
            state.stopped = true;
            if let Some((_, cancel)) = &state.active {
                cancel.cancel();
            }
            wake.notify_one();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub trait RefreshRequester {
    fn request_refresh(&self) -> io::Result<()>;
}

impl RefreshRequester for LocalAgentEventSource {
    fn request_refresh(&self) -> io::Result<()> {
        LocalAgentEventSource::request_refresh(self)
    }
}

#[allow(dead_code, reason = "used by the injected-agent embedding seam")]
struct NoopRefreshRequester;
impl RefreshRequester for NoopRefreshRequester {
    fn request_refresh(&self) -> io::Result<()> {
        Ok(())
    }
}

fn local_agent_event(context: &crate::cli::Context, cancel: &CancelToken) -> AgentEvent {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return AgentEvent {
                summary: format!("GitHub inventory runtime could not start: {error}"),
                health: Health::Error,
                snapshot: None,
            };
        }
    };
    runtime.block_on(production_agent_event(context, cancel))
}

async fn production_agent_event(context: &crate::cli::Context, cancel: &CancelToken) -> AgentEvent {
    match crate::cli::status::snapshot(context) {
        Ok(local) => {
            let summary = format!(
                "Local agent journal: {} active runner attempt(s), {} configured policy/policies.",
                local.host.in_use,
                local.policies.len()
            );
            match production_screen_snapshot(context, &local, cancel).await {
                Ok(snapshot) => AgentEvent {
                    health: if snapshot.metrics.busy_runners > 0 {
                        Health::Busy
                    } else {
                        Health::Ready
                    },
                    summary,
                    snapshot: Some(snapshot),
                },
                Err((availability, detail)) => AgentEvent {
                    summary: format!("{summary} GitHub inventory refresh failed: {detail}"),
                    health: Health::Error,
                    snapshot: Some(Snapshot {
                        activity: production_activity(context)
                            .unwrap_or_default()
                            .into_iter()
                            .chain(std::iter::once(refresh_activity(
                                &availability,
                                &detail,
                                context.clock().now(),
                            )))
                            .collect(),
                        availability,
                        ..Snapshot::default()
                    }),
                },
            }
        }
        Err(error) => AgentEvent {
            summary: format!("Local agent journal could not be read: {error}"),
            health: Health::Error,
            snapshot: None,
        },
    }
}

async fn production_screen_snapshot(
    context: &crate::cli::Context,
    local: &crate::cli::status::StatusDocument,
    cancel: &CancelToken,
) -> Result<Snapshot, (Availability, String)> {
    let activity =
        production_activity(context).map_err(|detail| offline_failure(context, detail))?;
    let start_mode = StartMode::from_str(&local.host.service_start_mode).map_err(|error| {
        offline_failure(context, format!("invalid service start mode: {error}"))
    })?;
    let secrets = context
        .secret_store(start_mode)
        .map_err(|error| offline_failure(context, error.to_string()))?;
    let Some(secret) = secrets
        .load()
        .map_err(|error| offline_failure(context, error.to_string()))?
    else {
        return Err((
            Availability::Unauthorized,
            "no GitHub credential is stored; run `runner-manager auth login`".into(),
        ));
    };
    if local.policies.is_empty() {
        return Ok(Snapshot {
            availability: Availability::Ready,
            activity,
            ..Snapshot::default()
        });
    }

    let clock = context.clock();
    let client = Arc::new(
        AuthenticatedClient::new(
            context.endpoints().clone(),
            UserAccessToken::from_stored(secret),
            Arc::clone(&clock),
        )
        .map_err(|error| offline_failure(context, error.to_string()))?,
    );
    let inventory = RestInventory::new(Arc::clone(&client), Arc::clone(&clock));
    let reachable = if local
        .policies
        .iter()
        .any(|policy| policy.scope == "organization")
    {
        let app = context
            .app_registration()
            .map_err(|error| (Availability::Unauthorized, error.to_string()))?;
        Some(
            client
                .discover_installations(&app)
                .await
                .map_err(|error| inventory_failure(context, &clock, InventoryError::from(error)))?,
        )
    } else {
        None
    };
    let reachable_repositories = reachable
        .as_ref()
        .and_then(|discovery| discovery.targets())
        .map_or_else(Vec::new, |targets| targets.repositories());

    let mut repositories = Vec::with_capacity(local.policies.len());
    let mut runners = Vec::new();
    let mut seen_runners = HashSet::new();
    let mut in_progress_workflows = 0_u32;
    let mut busy_runners = 0_u32;
    let mut assigned_jobs = 0_u32;
    let mut online_runners = 0_u32;

    for policy in &local.policies {
        let (target, scope) = if policy.scope == "repository" {
            let repository = OwnerRepo::from_str(&policy.target)
                .map_err(|error| offline_failure(context, error.to_string()))?;
            (
                ScaleTarget::Repository(repository.clone()),
                ActivityScope::repository(repository),
            )
        } else {
            let org = Org::from_str(&policy.target)
                .map_err(|error| offline_failure(context, error.to_string()))?;
            let repositories: Vec<_> = reachable_repositories
                .iter()
                .filter(|repository| repository.owner().eq_ignore_ascii_case(org.as_str()))
                .cloned()
                .collect();
            (
                ScaleTarget::Organization(org.clone()),
                ActivityScope::organization(org, repositories),
            )
        };
        let refreshed = inventory
            .snapshot(&scope, cancel)
            .await
            .map_err(|error| inventory_failure(context, &clock, error))?;
        let workflow_count = refreshed.activity.total();
        in_progress_workflows = in_progress_workflows.saturating_add(workflow_count);
        repositories.push(RepositoryRow {
            id: policy.id.clone(),
            target: policy.target.clone(),
            in_progress_workflows: workflow_count,
            mode: if policy.mode == "monitor_only" {
                PolicyMode::MonitorOnly
            } else {
                PolicyMode::Autoscale
            },
            max_capacity: policy.max_capacity,
            health: if policy.enabled && policy.state == "active" {
                AgentHealth::Healthy
            } else {
                AgentHealth::Degraded
            },
        });
        for runner in refreshed.runners.runners() {
            if !seen_runners.insert(runner.id) {
                continue;
            }
            let locally_owned = policy.mode != "monitor_only"
                && !policy.routing_labels.is_empty()
                && policy
                    .routing_labels
                    .iter()
                    .all(|label| runner.has_label(label));
            busy_runners = busy_runners.saturating_add(u32::from(runner.busy));
            assigned_jobs = assigned_jobs.saturating_add(u32::from(runner.busy && locally_owned));
            online_runners = online_runners.saturating_add(u32::from(runner.status.is_online()));
            runners.push(RunnerRow {
                id: runner.id.to_string(),
                name: runner.name.clone(),
                owner: target.slug(),
                os: runner.os.clone(),
                labels: runner.labels.clone(),
                online: runner.status.is_online(),
                busy: runner.busy,
                ephemeral: runner.ephemeral.unwrap_or(false),
                ownership: if locally_owned {
                    RunnerOwnership::Local
                } else {
                    RunnerOwnership::External
                },
            });
        }
    }

    Ok(Snapshot {
        availability: Availability::Ready,
        metrics: DashboardMetrics {
            in_progress_workflows,
            assigned_jobs,
            busy_runners,
            online_runners,
            host_capacity_used: local.host.in_use,
            host_capacity_total: local.host.capacity,
        },
        repositories,
        runners,
        activity,
    })
}

fn production_activity(context: &crate::cli::Context) -> Result<Vec<screens::ActivityRow>, String> {
    let store = context.store().map_err(|error| error.to_string())?;
    let attempts = store.attempts().map_err(|error| error.to_string())?;
    let policies = store.policies().map_err(|error| error.to_string())?;
    let targets = policies
        .into_iter()
        .map(|policy| (policy.id, policy.target.slug()))
        .collect::<HashMap<_, _>>();
    Ok(activity_rows(&attempts, &targets))
}

fn activity_rows(
    attempts: &[RunnerAttempt],
    targets: &HashMap<runner_manager_domain::model::PolicyId, String>,
) -> Vec<screens::ActivityRow> {
    let mut rows = Vec::new();
    for attempt in attempts {
        let target = targets
            .get(&attempt.policy_id)
            .map_or("removed policy", String::as_str);
        let attempt_id = attempt.id.to_string();
        let occurred_at = attempt
            .terminal_at()
            .unwrap_or_else(|| attempt.last_state_change_at())
            .to_rfc3339();
        match attempt.outcome() {
            Some(AttemptOutcome::CompletedJob) => rows.push(screens::ActivityRow {
                id: format!("{attempt_id}:outcome"),
                occurred_at: occurred_at.clone(),
                outcome: screens::ActivityOutcome::Info,
                summary: format!("Runner attempt {attempt_id} for {target} ran one job."),
                remediation: "No remediation required.".into(),
            }),
            Some(AttemptOutcome::ExitedIdleWithoutWork) => rows.push(screens::ActivityRow {
                id: format!("{attempt_id}:outcome"),
                occurred_at: occurred_at.clone(),
                outcome: screens::ActivityOutcome::ExitedIdleWithoutWork,
                summary: format!(
                    "Runner attempt {attempt_id} for {target} exited idle without accepting work."
                ),
                remediation: "No remediation required; this is a normal surplus-runner exit."
                    .into(),
            }),
            Some(AttemptOutcome::Failed { reason }) => {
                rows.push(screens::ActivityRow {
                    id: format!("{attempt_id}:outcome"),
                    occurred_at: occurred_at.clone(),
                    outcome: screens::ActivityOutcome::Failed,
                    summary: format!("Runner attempt {attempt_id} for {target} failed: {reason}."),
                    remediation: failure_remediation(reason).into(),
                });
                rows.push(screens::ActivityRow {
                    id: format!("{attempt_id}:retry"),
                    occurred_at: occurred_at.clone(),
                    outcome: screens::ActivityOutcome::Retry,
                    summary: format!(
                        "Attempt {attempt_id} is terminal; a new attempt is retried only while demand remains."
                    ),
                    remediation: "Wait for the bounded automatic retry or address the failure above."
                        .into(),
                });
            }
            Some(AttemptOutcome::Orphaned) => rows.push(screens::ActivityRow {
                id: format!("{attempt_id}:outcome"),
                occurred_at: occurred_at.clone(),
                outcome: screens::ActivityOutcome::Failed,
                summary: format!("Runner attempt {attempt_id} for {target} became orphaned."),
                remediation:
                    "Inspect the local runner process and logs, then restart the service if safe."
                        .into(),
            }),
            None => rows.push(screens::ActivityRow {
                id: format!("{attempt_id}:state"),
                occurred_at: occurred_at.clone(),
                outcome: screens::ActivityOutcome::Info,
                summary: format!(
                    "Runner attempt {attempt_id} for {target} is {}.",
                    attempt.state()
                ),
                remediation: "No action required while the lifecycle continues.".into(),
            }),
        }
        if attempt.state() == AttemptState::Cleaned {
            rows.push(screens::ActivityRow {
                id: format!("{attempt_id}:cleanup"),
                occurred_at: attempt.last_state_change_at().to_rfc3339(),
                outcome: screens::ActivityOutcome::CleanupComplete,
                summary: format!("Runtime cleanup completed for attempt {attempt_id} ({target})."),
                remediation: "No remediation required; local resources were released.".into(),
            });
        }
    }
    rows
}

fn failure_remediation(reason: &FailureReason) -> &'static str {
    match reason {
        FailureReason::JitRequestFailed | FailureReason::JitExpired => {
            "Verify GitHub connectivity and authorization; retry occurs only while demand remains."
        }
        FailureReason::RunnerPackageUnverified => {
            "Purge the runner package cache and verify the published checksum before retrying."
        }
        FailureReason::RunnerVersionRejected => {
            "Install a supported runner version; retrying the rejected version will not help."
        }
        FailureReason::ProcessStartFailed | FailureReason::ProcessExitedUnexpectedly => {
            "Inspect the local runner log, executable permissions, and process exit details."
        }
        FailureReason::RegistrationTimedOut | FailureReason::TerminatedAfterRegistrationTimeout => {
            "Check this host's network, DNS, proxy, firewall, and GitHub authorization."
        }
        FailureReason::Other(_) => "Inspect the local runner log and the copy-safe diagnostic.",
    }
}

fn refresh_activity(
    availability: &Availability,
    detail: &str,
    occurred_at: runner_manager_domain::model::Timestamp,
) -> screens::ActivityRow {
    let (outcome, remediation) = match availability {
        Availability::RateLimited { .. } => (
            screens::ActivityOutcome::RateLimit,
            "Wait for the displayed retry delay; F5 requests are coalesced.",
        ),
        Availability::Cancelled => (
            screens::ActivityOutcome::Info,
            "No action is required when a newer refresh superseded this one.",
        ),
        Availability::Unauthorized => (
            screens::ActivityOutcome::Failed,
            "Run `runner-manager auth login`.",
        ),
        Availability::Forbidden { .. } => (
            screens::ActivityOutcome::Failed,
            "Verify repository access and GitHub App/user permissions.",
        ),
        Availability::Offline { .. } => (
            screens::ActivityOutcome::Retry,
            "Check network, DNS, proxy, and system clock; retry is automatic.",
        ),
        Availability::Failed { .. } | Availability::Loading | Availability::Ready => (
            screens::ActivityOutcome::Failed,
            "Inspect the copy-safe diagnostic and retry with F5.",
        ),
    };
    screens::ActivityRow {
        id: format!(
            "github-inventory-refresh:{}",
            occurred_at.timestamp_nanos_opt().unwrap_or_default()
        ),
        occurred_at: occurred_at.to_rfc3339(),
        outcome,
        summary: screens::copy_safe(detail),
        remediation: remediation.into(),
    }
}

fn inventory_failure(
    context: &crate::cli::Context,
    clock: &Arc<dyn runner_manager_domain::model::Clock>,
    error: InventoryError,
) -> (Availability, String) {
    let state = RefreshState::from_error(&error);
    let availability = availability_from_refresh_state(context, clock, &state);
    (availability, error.to_string())
}

fn availability_from_refresh_state(
    context: &crate::cli::Context,
    clock: &Arc<dyn runner_manager_domain::model::Clock>,
    state: &RefreshState,
) -> Availability {
    match state {
        RefreshState::Unauthorized => Availability::Unauthorized,
        RefreshState::RateLimited(_) | RefreshState::LockedOut { .. } => {
            Availability::RateLimited {
                retry_after_seconds: state
                    .retry_delay(clock.now())
                    .unwrap_or(LOCAL_AGENT_POLL_RATE)
                    .as_secs(),
            }
        }
        RefreshState::Offline => offline_availability(context),
        RefreshState::Forbidden { message } => Availability::Forbidden {
            message: message.clone(),
        },
        RefreshState::Failed { message, .. } => Availability::Failed {
            detail: message.clone(),
        },
        RefreshState::Cancelled => Availability::Cancelled,
        RefreshState::Ready(_) => Availability::Failed {
            detail: "inventory failure unexpectedly mapped to a ready state".into(),
        },
    }
}

fn offline_failure(context: &crate::cli::Context, detail: String) -> (Availability, String) {
    (offline_availability(context), detail)
}

fn offline_availability(context: &crate::cli::Context) -> Availability {
    let last = runner_manager_platform::service::last_github_contact(context.paths())
        .ok()
        .flatten()
        .map_or_else(|| "none recorded".into(), |at| at.to_rfc3339());
    Availability::Offline {
        last_successful_contact: last,
        retry_after_seconds: LOCAL_AGENT_POLL_RATE.as_secs(),
    }
}

/// All terminal, timer, and agent events feed the same reducer through here.
#[derive(Debug)]
pub enum AppEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
    Paste(String),
    FocusGained,
    FocusLost,
    Timer(Instant),
    Agent(AgentEvent),
    InputFailed(String),
}

impl From<Event> for AppEvent {
    fn from(event: Event) -> Self {
        match event {
            Event::Key(event) => Self::Key(event),
            Event::Mouse(event) => Self::Mouse(event),
            Event::Resize(width, height) => Self::Resize(width, height),
            Event::Paste(text) => Self::Paste(text),
            Event::FocusGained => Self::FocusGained,
            Event::FocusLost => Self::FocusLost,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Refresh,
    Copy(String),
    SetMouseCapture(bool),
    ActivateFocusedControl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NavigationItem {
    screen: Screen,
    label: String,
    area: Rect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NavigationLayout {
    items: Vec<NavigationItem>,
}

impl NavigationLayout {
    fn for_area(area: Rect) -> Self {
        let labels: Vec<String> = Screen::ALL
            .into_iter()
            .map(|screen| navigation_label(screen, area.width))
            .collect();
        let gaps = labels.len().saturating_sub(1) as u16;
        let labels_width = labels
            .iter()
            .map(|label| u16::try_from(label.chars().count()).unwrap_or(u16::MAX))
            .sum::<u16>();
        let leading = area.width.saturating_sub(labels_width.saturating_add(gaps)) / 2;
        let mut x = area.x.saturating_add(leading);
        let mut items = Vec::with_capacity(labels.len());
        for (screen, label) in Screen::ALL.into_iter().zip(labels) {
            let width = u16::try_from(label.chars().count())
                .unwrap_or(u16::MAX)
                .min(area.right().saturating_sub(x));
            if width == 0 {
                break;
            }
            items.push(NavigationItem {
                screen,
                label,
                area: Rect::new(x, area.y, width, 1),
            });
            x = x.saturating_add(width).saturating_add(1);
        }
        Self { items }
    }

    fn hit(&self, column: u16, row: u16) -> Option<Screen> {
        self.items
            .iter()
            .find(|item| {
                column >= item.area.x
                    && column < item.area.right()
                    && row >= item.area.y
                    && row < item.area.bottom()
            })
            .map(|item| item.screen)
    }
}

fn navigation_label(screen: Screen, width: u16) -> String {
    let key = screen_key(screen);
    if width < 60 {
        format!("[{key}]")
    } else if width < 110 {
        let short = match screen {
            Screen::Dashboard => "Dash",
            Screen::Repositories => "Repos",
            Screen::Runners => "Run",
            Screen::RepositorySettings => "RepoCfg",
            Screen::HostSettings => "HostCfg",
            Screen::Activity => "Activity",
        };
        format!("[{key}]{short}")
    } else {
        format!("[{key}] {}", screen.title())
    }
}

fn navigation_area(size: Rect) -> Rect {
    Rect::new(size.x, size.y.saturating_add(1), size.width, 1)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppState {
    pub screen: Screen,
    pub focus: Focus,
    pub presentation: PresentationState,
    pub screen_model: ScreenModel,
    pub size: Rect,
    pub help_open: bool,
    pub filtering: bool,
    pub filter: String,
    pub mouse_capture: bool,
    pub terminal_focused: bool,
    pub should_exit: bool,
    pub ticks: u64,
    pub last_tick: Option<Instant>,
    navigation: NavigationLayout,
}

impl AppState {
    pub fn new(presentation: PresentationState, width: u16, height: u16) -> Self {
        Self {
            screen: Screen::Dashboard,
            focus: Focus::Content,
            presentation,
            screen_model: ScreenModel::new(Snapshot::default()),
            size: Rect::new(0, 0, width, height),
            help_open: false,
            filtering: false,
            filter: String::new(),
            mouse_capture: true,
            terminal_focused: true,
            should_exit: false,
            ticks: 0,
            last_tick: None,
            navigation: NavigationLayout::for_area(navigation_area(Rect::new(0, 0, width, height))),
        }
    }

    fn relayout(&mut self) {
        self.navigation = NavigationLayout::for_area(navigation_area(self.size));
    }

    fn open_screen(&mut self, screen: Screen) {
        self.screen = screen;
        if let Some(read_only) = read_only_screen(screen) {
            self.screen_model.apply(ScreenAction::Open(read_only));
        }
    }
}

const fn read_only_screen(screen: Screen) -> Option<ReadOnlyScreen> {
    match screen {
        Screen::Dashboard => Some(ReadOnlyScreen::Dashboard),
        Screen::Repositories => Some(ReadOnlyScreen::Repositories),
        Screen::Runners => Some(ReadOnlyScreen::Runners),
        Screen::Activity => Some(ReadOnlyScreen::Activity),
        Screen::RepositorySettings | Screen::HostSettings => None,
    }
}

/// Pure state transition. Effects are performed by the shell, never render.
pub fn reduce(state: &mut AppState, event: AppEvent) -> Vec<Effect> {
    match event {
        AppEvent::Key(key) if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
            reduce_key(state, key)
        }
        AppEvent::Mouse(mouse) => reduce_mouse(state, mouse),
        AppEvent::Resize(width, height) => {
            state.size = Rect::new(0, 0, width, height);
            state.relayout();
            Vec::new()
        }
        AppEvent::Paste(text) => {
            if state.filtering {
                state.filter.push_str(&state.presentation.redact(&text));
                state
                    .screen_model
                    .apply(ScreenAction::Filter(state.filter.clone()));
            }
            Vec::new()
        }
        AppEvent::FocusGained => {
            state.terminal_focused = true;
            Vec::new()
        }
        AppEvent::FocusLost => {
            state.terminal_focused = false;
            Vec::new()
        }
        AppEvent::Timer(instant) => {
            state.ticks = state.ticks.saturating_add(1);
            state.last_tick = Some(instant);
            Vec::new()
        }
        AppEvent::Agent(agent) => {
            state.presentation.health = agent.health;
            let summary = state.presentation.redact(&agent.summary);
            state.presentation.diagnostics.push(summary);
            if let Some(mut snapshot) = agent.snapshot {
                snapshot.activity = merge_activity_history(
                    &state.screen_model.snapshot.activity,
                    snapshot.activity,
                );
                state.screen_model.apply(ScreenAction::Refresh(snapshot));
            }
            Vec::new()
        }
        AppEvent::InputFailed(message) => {
            state.presentation.health = Health::Error;
            state
                .presentation
                .diagnostics
                .push(format!("terminal input failed: {message}"));
            Vec::new()
        }
        AppEvent::Key(_) => Vec::new(),
    }
}

fn merge_activity_history(
    previous: &[screens::ActivityRow],
    mut current: Vec<screens::ActivityRow>,
) -> Vec<screens::ActivityRow> {
    let mut ids = current
        .iter()
        .map(|row| row.id.clone())
        .collect::<HashSet<_>>();
    current.extend(
        previous
            .iter()
            .filter(|row| ids.insert(row.id.clone()))
            .cloned(),
    );
    current.sort_by(|left, right| right.occurred_at.cmp(&left.occurred_at));
    current.truncate(MAX_ACTIVITY_HISTORY);
    current
}

fn reduce_key(state: &mut AppState, key: KeyEvent) -> Vec<Effect> {
    if state.filtering {
        match key.code {
            KeyCode::Esc => {
                state.filtering = false;
                state.filter.clear();
                state
                    .screen_model
                    .apply(ScreenAction::Filter(String::new()));
                return Vec::new();
            }
            KeyCode::Enter => {
                state.filtering = false;
                return Vec::new();
            }
            KeyCode::Backspace => {
                state.filter.pop();
                state
                    .screen_model
                    .apply(ScreenAction::Filter(state.filter.clone()));
                return Vec::new();
            }
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                state.filter.push(character);
                state
                    .screen_model
                    .apply(ScreenAction::Filter(state.filter.clone()));
                return Vec::new();
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Char('d') => state.open_screen(Screen::Dashboard),
        KeyCode::Char('r') => state.open_screen(Screen::Repositories),
        KeyCode::Char('n') => state.open_screen(Screen::Runners),
        KeyCode::Char('s') => state.open_screen(Screen::RepositorySettings),
        KeyCode::Char('h') => state.open_screen(Screen::HostSettings),
        KeyCode::Char('a') => state.open_screen(Screen::Activity),
        KeyCode::Char('o') => {
            let current = match state.screen_model.screen {
                ReadOnlyScreen::Repositories => state.screen_model.repositories.sort_order,
                ReadOnlyScreen::Runners => state.screen_model.runners.sort_order,
                ReadOnlyScreen::Activity => state.screen_model.activity.sort_order,
                ReadOnlyScreen::Dashboard => screens::SortOrder::NameAscending,
            };
            let next = match (state.screen_model.screen, current) {
                (ReadOnlyScreen::Repositories, screens::SortOrder::NameAscending) => {
                    screens::SortOrder::NameDescending
                }
                (ReadOnlyScreen::Repositories, screens::SortOrder::NameDescending) => {
                    screens::SortOrder::WorkloadDescending
                }
                (_, screens::SortOrder::NameAscending) => screens::SortOrder::NameDescending,
                _ => screens::SortOrder::NameAscending,
            };
            state.screen_model.apply(ScreenAction::SetSort(next));
        }
        KeyCode::Char('/') => state.filtering = true,
        KeyCode::F(5) => return vec![Effect::Refresh],
        KeyCode::Char('?') => state.help_open = !state.help_open,
        KeyCode::Char('q') => state.should_exit = true,
        KeyCode::Char('c') => {
            let copy = if read_only_screen(state.screen) == Some(ReadOnlyScreen::Activity) {
                screens::render_text(&state.screen_model)
            } else {
                state.presentation.copy_text()
            };
            return vec![Effect::Copy(copy)];
        }
        KeyCode::Char('m') => {
            state.mouse_capture = !state.mouse_capture;
            return vec![Effect::SetMouseCapture(state.mouse_capture)];
        }
        KeyCode::Esc => {
            if state.help_open {
                state.help_open = false;
            } else if state.screen_model.repository_detail.is_some()
                || state.screen_model.runner_detail.is_some()
            {
                state
                    .screen_model
                    .apply(ScreenAction::CloseRepositoryDetail);
            } else if state.filtering || !state.filter.is_empty() {
                state.filtering = false;
                state.filter.clear();
                state
                    .screen_model
                    .apply(ScreenAction::Filter(String::new()));
            } else if state.screen != Screen::Dashboard {
                state.open_screen(Screen::Dashboard);
            }
        }
        KeyCode::Tab => {
            state.focus = state
                .focus
                .next(key.modifiers.contains(KeyModifiers::SHIFT))
        }
        KeyCode::Up
            if state.focus == Focus::Content && read_only_screen(state.screen).is_some() =>
        {
            state.screen_model.apply(ScreenAction::MoveSelection(-1));
        }
        KeyCode::Down
            if state.focus == Focus::Content && read_only_screen(state.screen).is_some() =>
        {
            state.screen_model.apply(ScreenAction::MoveSelection(1));
        }
        KeyCode::BackTab | KeyCode::Up | KeyCode::Left => state.focus = state.focus.next(true),
        KeyCode::Down | KeyCode::Right => state.focus = state.focus.next(false),
        KeyCode::Enter => {
            if state.focus == Focus::Content && read_only_screen(state.screen).is_some() {
                state.screen_model.apply(ScreenAction::Activate);
            }
            return vec![Effect::ActivateFocusedControl];
        }
        _ => {}
    }
    Vec::new()
}

fn reduce_mouse(state: &mut AppState, mouse: MouseEvent) -> Vec<Effect> {
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(screen) = state.navigation.hit(mouse.column, mouse.row) {
                state.open_screen(screen);
                state.focus = Focus::Navigation;
            } else {
                state.focus = Focus::Content;
                if state.screen == Screen::Repositories {
                    let content_first_row = 6;
                    if mouse.row >= content_first_row
                        && let Some(id) =
                            state
                                .screen_model
                                .repository_id_at_viewport_offset(usize::from(
                                    mouse.row - content_first_row,
                                ))
                    {
                        state
                            .screen_model
                            .apply(ScreenAction::OpenRepositoryByMouse(id));
                    }
                }
            }
        }
        MouseEventKind::ScrollUp => state.focus = state.focus.next(true),
        MouseEventKind::ScrollDown => state.focus = state.focus.next(false),
        _ => {}
    }
    Vec::new()
}

/// Draw one frame from memory only.
pub fn render(frame: &mut Frame<'_>, state: &AppState) {
    let area = frame.area();
    if area.width < 12 || area.height < 5 {
        frame.render_widget(
            Paragraph::new("runner-manager\n? help").wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let compact = area.width < 60 || area.height < 18;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);
    let (icon, health, colour) = state.presentation.health.presentation();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " runner-manager ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{icon} {health}"), Style::default().fg(colour)),
        ])),
        rows[0],
    );

    let navigation = NavigationLayout::for_area(rows[1]);
    for item in &navigation.items {
        let style = if item.screen == state.screen {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        frame.render_widget(Paragraph::new(item.label.as_str()).style(style), item.area);
    }

    if let Some(read_only) = read_only_screen(state.screen) {
        let mut model = state.screen_model.clone();
        model.apply(ScreenAction::Open(read_only));
        screens::render(frame, rows[2], &model);
    } else {
        let content = if compact {
            let filter = if state.filtering {
                format!("\nFilter: {}", state.presentation.redact(&state.filter))
            } else {
                String::new()
            };
            format!(
                "{}\n{}{}\n\nCompact layout active. Press ? for every control.",
                state.screen.title(),
                state.presentation.redact(&state.presentation.heading),
                filter
            )
        } else {
            let source = if state.screen == Screen::Activity {
                &state.presentation.diagnostics
            } else {
                &state.presentation.body
            };
            let mut lines = vec![Line::from(Span::styled(
                state.presentation.redact(&state.presentation.heading),
                Style::default().add_modifier(Modifier::BOLD),
            ))];
            lines.extend(
                source
                    .iter()
                    .map(|line| Line::from(state.presentation.redact(line))),
            );
            Text::from(lines).to_string()
        };
        frame.render_widget(
            Paragraph::new(content)
                .block(
                    Block::default()
                        .title(state.screen.title())
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false }),
            rows[2],
        );
    }
    let capture = if state.mouse_capture {
        "mouse:on"
    } else {
        "mouse:released"
    };
    let terminal_focus = if state.terminal_focused {
        "focused"
    } else {
        "unfocused"
    };
    let footer = if compact {
        format!("? help | q quit | {capture}")
    } else {
        format!(
            "Tab/arrows focus | Enter activate | / filter | o sort | F5 refresh | c copy | m release mouse | Esc back | q quit | {capture} | {terminal_focus}"
        )
    };
    frame.render_widget(Paragraph::new(footer).alignment(Alignment::Center), rows[3]);
    if state.help_open || compact {
        render_help(frame, area, compact);
    }
}

fn render_help(frame: &mut Frame<'_>, area: Rect, compact: bool) {
    let width = area
        .width
        .saturating_sub(2)
        .min(if compact { 48 } else { 72 });
    let height = area
        .height
        .saturating_sub(2)
        .min(if compact { 10 } else { 14 });
    if width < 8 || height < 3 {
        return;
    }
    let popup_y = if compact {
        area.y.saturating_add(3)
    } else {
        area.y + area.height.saturating_sub(height) / 2
    };
    let height = height.min(area.bottom().saturating_sub(popup_y).saturating_sub(1));
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        popup_y,
        width,
        height,
    );
    let help = if compact {
        "d Dashboard  r Repositories  n Runners\ns Repo settings  h Host settings  a Activity\n/ Filter F5 Refresh ? Help Esc Back q Quit\nTab Shift-Tab Arrows Focus  Enter Activate\nc Copy diagnostics  m Mouse capture  o Sort\nKeys mirror every mouse action"
    } else {
        "d Dashboard   r Repositories   n Runners\ns Repository settings   h Host settings   a Activity\n/ filter   o sort   F5 refresh   ? help   Esc close/back   q quit\nTab / Shift-Tab / arrows focus   Enter activate\nc copy diagnostics   m release/re-enable mouse capture\nMouse actions always have the keyboard equivalents above."
    };
    frame.render_widget(Clear, popup);
    let title = if compact {
        "Key help - compact layout"
    } else {
        "Key help"
    };
    frame.render_widget(
        Paragraph::new(help)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        popup,
    );
}

const fn screen_key(screen: Screen) -> char {
    match screen {
        Screen::Dashboard => 'd',
        Screen::Repositories => 'r',
        Screen::Runners => 'n',
        Screen::RepositorySettings => 's',
        Screen::HostSettings => 'h',
        Screen::Activity => 'a',
    }
}

trait TerminalActions {
    fn enable_raw(&mut self) -> io::Result<()>;
    fn disable_raw(&mut self) -> io::Result<()>;
    fn enter_alternate_screen(&mut self) -> io::Result<()>;
    fn leave_alternate_screen(&mut self) -> io::Result<()>;
    fn enable_mouse_capture(&mut self) -> io::Result<()>;
    fn disable_mouse_capture(&mut self) -> io::Result<()>;
    fn enable_focus_change(&mut self) -> io::Result<()>;
    fn disable_focus_change(&mut self) -> io::Result<()>;
    fn enable_bracketed_paste(&mut self) -> io::Result<()>;
    fn disable_bracketed_paste(&mut self) -> io::Result<()>;
}

trait RawModeActions {
    fn enable(&mut self) -> io::Result<()>;
    fn disable(&mut self) -> io::Result<()>;
}

struct SystemRawMode;
impl RawModeActions for SystemRawMode {
    fn enable(&mut self) -> io::Result<()> {
        enable_raw_mode()
    }
    fn disable(&mut self) -> io::Result<()> {
        disable_raw_mode()
    }
}

trait MouseCaptureActions<W: Write> {
    fn enable(&mut self, writer: &mut W) -> io::Result<()>;
    fn disable(&mut self, writer: &mut W) -> io::Result<()>;
}

struct CrosstermMouseCapture;

impl<W: Write> MouseCaptureActions<W> for CrosstermMouseCapture {
    fn enable(&mut self, writer: &mut W) -> io::Result<()> {
        execute!(writer, EnableMouseCapture).map(|_| ())
    }

    fn disable(&mut self, writer: &mut W) -> io::Result<()> {
        execute!(writer, DisableMouseCapture).map(|_| ())
    }
}

struct CrosstermActions<W: Write, R: RawModeActions, M: MouseCaptureActions<W>> {
    writer: W,
    raw_mode: R,
    mouse_capture: M,
}

impl<W: Write, R: RawModeActions> CrosstermActions<W, R, CrosstermMouseCapture> {
    fn new(writer: W, raw_mode: R) -> Self {
        Self {
            writer,
            raw_mode,
            mouse_capture: CrosstermMouseCapture,
        }
    }
}

impl<W: Write, R: RawModeActions, M: MouseCaptureActions<W>> CrosstermActions<W, R, M> {
    #[cfg(test)]
    fn with_mouse_capture(writer: W, raw_mode: R, mouse_capture: M) -> Self {
        Self {
            writer,
            raw_mode,
            mouse_capture,
        }
    }

    fn emit(&mut self, command: impl Command) -> io::Result<()> {
        execute!(self.writer, command).map(|_| ())
    }
}

impl<W: Write, R: RawModeActions, M: MouseCaptureActions<W>> TerminalActions
    for CrosstermActions<W, R, M>
{
    fn enable_raw(&mut self) -> io::Result<()> {
        self.raw_mode.enable()
    }
    fn disable_raw(&mut self) -> io::Result<()> {
        self.raw_mode.disable()
    }
    fn enter_alternate_screen(&mut self) -> io::Result<()> {
        self.emit(EnterAlternateScreen)
    }
    fn leave_alternate_screen(&mut self) -> io::Result<()> {
        self.emit(LeaveAlternateScreen)
    }
    fn enable_mouse_capture(&mut self) -> io::Result<()> {
        self.mouse_capture.enable(&mut self.writer)
    }
    fn disable_mouse_capture(&mut self) -> io::Result<()> {
        self.mouse_capture.disable(&mut self.writer)
    }
    fn enable_focus_change(&mut self) -> io::Result<()> {
        self.emit(EnableFocusChange)
    }
    fn disable_focus_change(&mut self) -> io::Result<()> {
        self.emit(DisableFocusChange)
    }
    fn enable_bracketed_paste(&mut self) -> io::Result<()> {
        self.emit(EnableBracketedPaste)
    }
    fn disable_bracketed_paste(&mut self) -> io::Result<()> {
        self.emit(DisableBracketedPaste)
    }
}

/// Owns all terminal modes. `Drop` is also the panic restoration path.
struct TerminalSession<A: TerminalActions> {
    actions: A,
    raw: bool,
    alternate: bool,
    mouse: bool,
    focus_change: bool,
    paste: bool,
}

impl<A: TerminalActions> TerminalSession<A> {
    fn start(actions: A) -> io::Result<Self> {
        let mut session = Self {
            actions,
            raw: false,
            alternate: false,
            mouse: false,
            focus_change: false,
            paste: false,
        };
        session.actions.enable_raw()?;
        session.raw = true;
        session.actions.enter_alternate_screen()?;
        session.alternate = true;
        session.actions.enable_mouse_capture()?;
        session.mouse = true;
        session.actions.enable_focus_change()?;
        session.focus_change = true;
        session.actions.enable_bracketed_paste()?;
        session.paste = true;
        Ok(session)
    }

    fn set_mouse_capture(&mut self, enabled: bool) -> io::Result<()> {
        if enabled == self.mouse {
            return Ok(());
        }
        if enabled {
            self.actions.enable_mouse_capture()?;
        } else {
            self.actions.disable_mouse_capture()?;
        }
        self.mouse = enabled;
        Ok(())
    }

    fn restore(&mut self) {
        if self.paste {
            let _ = self.actions.disable_bracketed_paste();
            self.paste = false;
        }
        if self.focus_change {
            let _ = self.actions.disable_focus_change();
            self.focus_change = false;
        }
        if self.mouse {
            let _ = self.actions.disable_mouse_capture();
            self.mouse = false;
        }
        if self.alternate {
            let _ = self.actions.leave_alternate_screen();
            self.alternate = false;
        }
        if self.raw {
            let _ = self.actions.disable_raw();
            self.raw = false;
        }
    }
}

impl<A: TerminalActions> Drop for TerminalSession<A> {
    fn drop(&mut self) {
        self.restore();
    }
}

pub fn copy_to_terminal_clipboard(writer: &mut dyn Write, text: &str) -> io::Result<()> {
    write!(writer, "\x1b]52;c;{}\x07", base64(text.as_bytes()))?;
    writer.flush()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(a >> 2) as usize] as char);
        output.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

pub trait SessionControl {
    fn set_mouse_capture(&mut self, enabled: bool) -> io::Result<()>;
    fn mouse_capture_enabled(&self) -> bool;
}
impl<A: TerminalActions> SessionControl for TerminalSession<A> {
    fn set_mouse_capture(&mut self, enabled: bool) -> io::Result<()> {
        TerminalSession::set_mouse_capture(self, enabled)
    }
    fn mouse_capture_enabled(&self) -> bool {
        self.mouse
    }
}

/// Crossterm, timer, and agent sources are merged by `select!`; exactly one
/// resulting [`AppEvent`] is sent to [`reduce`] each iteration.
pub async fn run_loop<B, I>(
    terminal: &mut ratatui::Terminal<B>,
    session: &mut impl SessionControl,
    mut input: I,
    mut agent_events: mpsc::UnboundedReceiver<AgentEvent>,
    refresh: &impl RefreshRequester,
) -> io::Result<AppState>
where
    B: Backend,
    B::Error: std::error::Error + Send + Sync + 'static,
    I: Stream<Item = io::Result<Event>> + Unpin,
{
    let size = terminal.size().map_err(io::Error::other)?;
    let mut state = AppState::new(PresentationState::default(), size.width, size.height);
    let mut timer = tokio::time::interval(TICK_RATE);
    let mut agent_events_open = true;
    loop {
        terminal
            .draw(|frame| render(frame, &state))
            .map_err(io::Error::other)?;
        if state.should_exit {
            return Ok(state);
        }
        let event = tokio::select! {
            input = input.next() => match input {
                Some(Ok(event)) => AppEvent::from(event),
                Some(Err(error)) => AppEvent::InputFailed(error.to_string()),
                None => return Ok(state),
            },
            instant = timer.tick() => AppEvent::Timer(instant.into_std()),
            agent = agent_events.recv(), if agent_events_open => match agent {
                Some(agent) => AppEvent::Agent(agent),
                None => {
                    agent_events_open = false;
                    continue;
                }
            },
        };
        if matches!(event, AppEvent::Mouse(_)) && !session.mouse_capture_enabled() {
            continue;
        }
        for effect in reduce(&mut state, event) {
            match effect {
                Effect::SetMouseCapture(enabled) => session.set_mouse_capture(enabled)?,
                Effect::Copy(text) => copy_to_terminal_clipboard(&mut io::stdout(), &text)?,
                Effect::Refresh => refresh.request_refresh()?,
                Effect::ActivateFocusedControl => {
                    // g3 attaches existing CLI command handlers here.
                }
            }
        }
    }
}

fn require_interactive_terminal(
    input_is_terminal: bool,
    output_is_terminal: bool,
) -> io::Result<()> {
    if input_is_terminal && output_is_terminal {
        Ok(())
    } else {
        Err(io::Error::other(
            "the terminal UI requires interactive stdin and stdout",
        ))
    }
}

/// Runs the production terminal against an injected agent-event receiver.
///
/// This is the composition seam for an in-process agent. The standalone
/// `runner-manager tui` process uses [`run_terminal`], while an embedding host
/// passes its real receiver here; the loop test exercises this exact path.
#[allow(dead_code, reason = "public embedding seam for an in-process agent")]
pub fn run_terminal_with_agent_events(
    agent_events: mpsc::UnboundedReceiver<AgentEvent>,
) -> io::Result<()> {
    require_interactive_terminal(io::stdin().is_terminal(), io::stdout().is_terminal())?;
    let mut session = TerminalSession::start(CrosstermActions::new(io::stdout(), SystemRawMode))?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;
    terminal.clear()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime
        .block_on(run_loop(
            &mut terminal,
            &mut session,
            EventStream::new(),
            agent_events,
            &NoopRefreshRequester,
        ))
        .map(|_| ());
    let _ = terminal.show_cursor();
    result
}

pub fn run_terminal(context: Arc<crate::cli::Context>) -> io::Result<()> {
    require_interactive_terminal(io::stdin().is_terminal(), io::stdout().is_terminal())?;
    let (source, agent_events) = LocalAgentEventSource::start(context, LOCAL_AGENT_POLL_RATE)?;
    let mut session = TerminalSession::start(CrosstermActions::new(io::stdout(), SystemRawMode))?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;
    terminal.clear()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime
        .block_on(run_loop(
            &mut terminal,
            &mut session,
            EventStream::new(),
            agent_events,
            &source,
        ))
        .map(|_| ());
    let _ = terminal.show_cursor();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventState;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Arc, Mutex};

    fn crossterm_key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }
    fn key(code: KeyCode) -> AppEvent {
        AppEvent::Key(crossterm_key(code))
    }
    fn crossterm_mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }
    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> AppEvent {
        AppEvent::Mouse(crossterm_mouse(kind, column, row))
    }
    fn rendered(width: u16, height: u16, state: &AppState) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, state)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn reducer_covers_key_mouse_resize_paste_timer_agent_and_focus() {
        let mut state = AppState::new(PresentationState::default(), 120, 30);
        reduce(&mut state, key(KeyCode::Char('r')));
        assert_eq!(state.screen, Screen::Repositories);
        let frame = rendered(120, 30, &state);
        let x = frame
            .lines()
            .nth(1)
            .unwrap()
            .find("[a] Activity & errors")
            .expect("the rendered Activity label") as u16;
        reduce(
            &mut state,
            mouse(MouseEventKind::Down(MouseButton::Left), x, 1),
        );
        assert_eq!(
            state.screen,
            Screen::Activity,
            "captured click must dispatch, not merely parse"
        );
        reduce(&mut state, AppEvent::from(Event::Resize(42, 12)));
        assert_eq!(state.size, Rect::new(0, 0, 42, 12));
        reduce(&mut state, key(KeyCode::Char('/')));
        reduce(
            &mut state,
            AppEvent::from(Event::Paste("needle".to_owned())),
        );
        assert_eq!(state.filter, "needle");
        reduce(&mut state, AppEvent::Timer(Instant::now()));
        assert_eq!(state.ticks, 1);
        reduce(
            &mut state,
            AppEvent::Agent(AgentEvent {
                summary: "runner busy".to_owned(),
                health: Health::Busy,
                snapshot: None,
            }),
        );
        assert_eq!(state.presentation.health, Health::Busy);
        reduce(&mut state, AppEvent::from(Event::FocusLost));
        assert!(!state.terminal_focused);
        reduce(&mut state, AppEvent::from(Event::FocusGained));
        assert!(state.terminal_focused);
    }

    #[test]
    fn compact_and_full_click_targets_follow_the_labels_actually_rendered() {
        for (width, height, rendered_label) in [(48, 12, "[a]"), (120, 30, "[a] Activity & errors")]
        {
            let mut state = AppState::new(PresentationState::default(), width, height);
            let frame = rendered(width, height, &state);
            let nav_row = frame.lines().nth(1).expect("navigation row");
            let x = nav_row
                .find(rendered_label)
                .unwrap_or_else(|| panic!("{rendered_label:?} was not rendered at width {width}"))
                as u16;

            reduce(
                &mut state,
                mouse(MouseEventKind::Down(MouseButton::Left), x, 1),
            );
            assert_eq!(
                state.screen,
                Screen::Activity,
                "the pixels spelling Activity at width {width} must be its hitbox"
            );
        }
    }

    #[test]
    fn every_screen_is_one_unique_key_away_from_every_other_screen() {
        let bindings = [
            ('d', Screen::Dashboard),
            ('r', Screen::Repositories),
            ('n', Screen::Runners),
            ('s', Screen::RepositorySettings),
            ('h', Screen::HostSettings),
            ('a', Screen::Activity),
        ];
        let mut keys = std::collections::HashSet::new();
        for (binding, destination) in bindings {
            assert!(keys.insert(binding), "key {binding} is bound twice");
            for origin in Screen::ALL {
                let mut state = AppState::new(PresentationState::default(), 80, 24);
                state.screen = origin;
                reduce(&mut state, key(KeyCode::Char(binding)));
                assert_eq!(state.screen, destination, "{binding} from {origin:?}");
            }
        }
        let every_binding = [
            "d",
            "r",
            "n",
            "s",
            "h",
            "a",
            "/",
            "F5",
            "?",
            "Esc",
            "q",
            "c",
            "m",
            "Tab",
            "Shift-Tab",
            "Enter",
            "Up",
            "Down",
            "Left",
            "Right",
        ];
        let unique = every_binding
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            unique.len(),
            every_binding.len(),
            "no shell key may be bound twice"
        );
    }

    #[test]
    fn q_only_exits_client_and_emits_no_daemon_effect() {
        let mut state = AppState::new(PresentationState::default(), 80, 24);
        let effects = reduce(&mut state, key(KeyCode::Char('q')));
        assert!(state.should_exit);
        assert!(effects.is_empty());

        let shell_source = include_str!("shell.rs");
        let key_reducer = shell_source
            .split_once("fn reduce_key")
            .unwrap()
            .1
            .split_once("fn reduce_mouse")
            .unwrap()
            .0;
        assert!(!key_reducer.contains("daemon"));
        assert!(!key_reducer.contains("stop("));

        let cli_source = include_str!("../cli/mod.rs");
        assert!(
            cli_source.contains("crate::tui::run(cli.data_dir.as_deref())"),
            "the real `runner-manager tui` route must pass its selected data root"
        );
        let tui_source = include_str!("mod.rs");
        assert!(tui_source.contains("Context::resolve(data_dir"));
        assert!(tui_source.contains("shell::run_terminal(context)"));
    }

    #[derive(Clone, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct NoopRawMode;
    impl RawModeActions for NoopRawMode {
        fn enable(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn disable(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct RecordingMouseCapture(Arc<Mutex<Vec<&'static str>>>);

    impl MouseCaptureActions<SharedWriter> for RecordingMouseCapture {
        fn enable(&mut self, _writer: &mut SharedWriter) -> io::Result<()> {
            self.0.lock().unwrap().push("mouse:on");
            Ok(())
        }

        fn disable(&mut self, _writer: &mut SharedWriter) -> io::Result<()> {
            self.0.lock().unwrap().push("mouse:off");
            Ok(())
        }
    }

    #[tokio::test]
    async fn capture_seam_and_merged_loop_causally_deliver_mouse_and_agent_events() {
        let output = SharedWriter::default();
        let capture_log = Arc::new(Mutex::new(Vec::new()));
        let mut session = TerminalSession::start(CrosstermActions::with_mouse_capture(
            output,
            NoopRawMode,
            RecordingMouseCapture(Arc::clone(&capture_log)),
        ))
        .expect("terminal setup through the injected capture seam");
        assert_eq!(*capture_log.lock().unwrap(), ["mouse:on"]);

        let width = 80;
        let height = 24;
        let initial = AppState::new(PresentationState::default(), width, height);
        let frame = rendered(width, height, &initial);
        let activity_x = frame
            .lines()
            .nth(1)
            .expect("navigation row")
            .find("[a]Activity")
            .expect("rendered Activity label") as u16;

        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let (input_sender, input) = futures::channel::mpsc::unbounded::<io::Result<Event>>();
        let data_root = tempfile::tempdir().unwrap();
        let mut warnings = Vec::new();
        let context = Arc::new(
            crate::cli::Context::resolve(Some(data_root.path()), &mut warnings)
                .expect("production TUI context"),
        );
        let (_source, mut produced_events) =
            LocalAgentEventSource::start(context, Duration::from_secs(60))
                .expect("production local-agent source");
        let initial_event = tokio::time::timeout(Duration::from_secs(5), produced_events.recv())
            .await
            .expect("production snapshot deadline")
            .expect("production source event");
        let (event_sender, agent_events) = mpsc::unbounded_channel();
        event_sender.send(initial_event).unwrap();
        let producer = async move {
            input_sender
                .unbounded_send(Ok(Event::Mouse(crossterm_mouse(
                    MouseEventKind::Down(MouseButton::Left),
                    activity_x,
                    1,
                ))))
                .unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
            input_sender
                .unbounded_send(Ok(Event::Key(crossterm_key(KeyCode::Char('q')))))
                .unwrap();
        };

        let (result, ()) = tokio::join!(
            run_loop(
                &mut terminal,
                &mut session,
                input,
                agent_events,
                &NoopRefreshRequester,
            ),
            producer
        );
        let final_state = result.expect("merged loop");
        assert_eq!(final_state.screen, Screen::Activity);
        assert_ne!(
            final_state.screen_model.snapshot.availability,
            Availability::Loading,
            "the shipped local source must replace the initial Loading snapshot"
        );
        assert!(
            final_state
                .presentation
                .diagnostics
                .iter()
                .any(|line| line.starts_with("Local agent journal:")),
            "the actual `tui` composition source must reach the reducer"
        );
        assert!(final_state.should_exit);
        drop(session);
        assert_eq!(
            *capture_log.lock().unwrap(),
            ["mouse:on", "mouse:off"],
            "the same capture controller must pair enable and disable"
        );
    }

    #[tokio::test]
    async fn shipped_source_produces_a_snapshot_and_f5_requests_an_immediate_refresh() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let produced = Arc::new(AtomicUsize::new(0));
        let producer_count = Arc::clone(&produced);
        let (source, agent_events) = LocalAgentEventSource::start_with(
            move |_| {
                let refresh = producer_count.fetch_add(1, Ordering::SeqCst);
                let snapshot = if refresh == 0 {
                    Snapshot::default()
                } else {
                    Snapshot {
                        availability: Availability::Ready,
                        repositories: vec![RepositoryRow {
                            id: "f5-repository".into(),
                            target: "acme/refreshed-by-f5".into(),
                            in_progress_workflows: 9,
                            mode: PolicyMode::Autoscale,
                            max_capacity: Some(4),
                            health: AgentHealth::Healthy,
                        }],
                        ..Snapshot::default()
                    }
                };
                AgentEvent {
                    summary: format!("production refresh {refresh}"),
                    health: Health::Ready,
                    snapshot: Some(snapshot),
                }
            },
            Duration::from_secs(60),
        )
        .expect("production source thread");

        let output = SharedWriter::default();
        let capture_log = Arc::new(Mutex::new(Vec::new()));
        let mut session = TerminalSession::start(CrosstermActions::with_mouse_capture(
            output,
            NoopRawMode,
            RecordingMouseCapture(capture_log),
        ))
        .unwrap();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        let (input_sender, input) = futures::channel::mpsc::unbounded::<io::Result<Event>>();
        let input_count = Arc::clone(&produced);
        let input_producer = async move {
            input_sender
                .unbounded_send(Ok(Event::Key(crossterm_key(KeyCode::F(5)))))
                .unwrap();
            for _ in 0..100 {
                if input_count.load(Ordering::SeqCst) >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            input_sender
                .unbounded_send(Ok(Event::Key(crossterm_key(KeyCode::Char('q')))))
                .unwrap();
        };
        let (result, ()) = tokio::join!(
            run_loop(&mut terminal, &mut session, input, agent_events, &source,),
            input_producer,
        );
        let final_state = result.unwrap();
        assert!(produced.load(Ordering::SeqCst) >= 2);
        assert_eq!(
            final_state.screen_model.snapshot.availability,
            Availability::Ready
        );
        assert_eq!(
            final_state.screen_model.snapshot.repositories[0].target,
            "acme/refreshed-by-f5"
        );
    }

    #[test]
    fn production_mouse_and_focus_commands_keep_crossterm_platform_dispatch() {
        let source = include_str!("shell.rs");
        let runtime_source = source
            .split_once("mod tests {")
            .expect("test module boundary")
            .0;
        assert!(runtime_source.contains("execute!(self.writer, command)"));
        assert!(runtime_source.contains("mouse_capture: CrosstermMouseCapture"));
        let native_capture = source
            .split_once("impl<W: Write> MouseCaptureActions<W> for CrosstermMouseCapture")
            .expect("native mouse capture implementation")
            .1
            .split_once("struct CrosstermActions")
            .expect("end of native mouse capture implementation")
            .0;
        assert!(native_capture.contains("execute!(writer, EnableMouseCapture)"));
        assert!(native_capture.contains("execute!(writer, DisableMouseCapture)"));

        let production_actions = source
            .split_once(
                "impl<W: Write, R: RawModeActions, M: MouseCaptureActions<W>> TerminalActions",
            )
            .expect("production terminal actions")
            .1
            .split_once("/// Owns all terminal modes")
            .expect("end of production terminal actions")
            .0;
        assert!(production_actions.contains("self.emit(EnableFocusChange)"));
        assert!(production_actions.contains("self.emit(DisableFocusChange)"));
    }

    #[test]
    fn tui_refuses_captured_or_redirected_stdio_instead_of_waiting_for_events() {
        assert!(require_interactive_terminal(true, true).is_ok());
        for (input, output) in [(false, true), (true, false), (false, false)] {
            let error = require_interactive_terminal(input, output).unwrap_err();
            assert_eq!(
                error.to_string(),
                "the terminal UI requires interactive stdin and stdout"
            );
        }
    }

    #[derive(Clone)]
    struct RecordingActions(Arc<Mutex<Vec<&'static str>>>);
    impl RecordingActions {
        fn record(&self, action: &'static str) {
            self.0.lock().unwrap().push(action);
        }
    }
    impl TerminalActions for RecordingActions {
        fn enable_raw(&mut self) -> io::Result<()> {
            self.record("raw:on");
            Ok(())
        }
        fn disable_raw(&mut self) -> io::Result<()> {
            self.record("raw:off");
            Ok(())
        }
        fn enter_alternate_screen(&mut self) -> io::Result<()> {
            self.record("alternate:on");
            Ok(())
        }
        fn leave_alternate_screen(&mut self) -> io::Result<()> {
            self.record("alternate:off");
            Ok(())
        }
        fn enable_mouse_capture(&mut self) -> io::Result<()> {
            self.record("mouse:on");
            Ok(())
        }
        fn disable_mouse_capture(&mut self) -> io::Result<()> {
            self.record("mouse:off");
            Ok(())
        }
        fn enable_focus_change(&mut self) -> io::Result<()> {
            self.record("focus:on");
            Ok(())
        }
        fn disable_focus_change(&mut self) -> io::Result<()> {
            self.record("focus:off");
            Ok(())
        }
        fn enable_bracketed_paste(&mut self) -> io::Result<()> {
            self.record("paste:on");
            Ok(())
        }
        fn disable_bracketed_paste(&mut self) -> io::Result<()> {
            self.record("paste:off");
            Ok(())
        }
    }

    #[test]
    fn recorded_session_enables_input_modes_and_restores_normally() {
        let log = Arc::new(Mutex::new(Vec::new()));
        {
            let _session = TerminalSession::start(RecordingActions(Arc::clone(&log))).unwrap();
        }
        assert_eq!(
            *log.lock().unwrap(),
            [
                "raw:on",
                "alternate:on",
                "mouse:on",
                "focus:on",
                "paste:on",
                "paste:off",
                "focus:off",
                "mouse:off",
                "alternate:off",
                "raw:off"
            ]
        );
    }

    #[test]
    fn terminal_restores_during_panic_unwind() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let caught = catch_unwind(AssertUnwindSafe({
            let log = Arc::clone(&log);
            move || {
                let _session = TerminalSession::start(RecordingActions(log)).unwrap();
                panic!("simulated panic");
            }
        }));
        assert!(caught.is_err());
        assert!(log.lock().unwrap().ends_with(&[
            "paste:off",
            "focus:off",
            "mouse:off",
            "alternate:off",
            "raw:off"
        ]));
    }

    struct FailingActions {
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FailingActions {
        fn record(&self, action: &'static str) {
            self.log.lock().unwrap().push(action);
        }
    }

    impl TerminalActions for FailingActions {
        fn enable_raw(&mut self) -> io::Result<()> {
            self.record("raw:on");
            Ok(())
        }
        fn disable_raw(&mut self) -> io::Result<()> {
            self.record("raw:off");
            Ok(())
        }
        fn enter_alternate_screen(&mut self) -> io::Result<()> {
            self.record("alternate:on");
            Ok(())
        }
        fn leave_alternate_screen(&mut self) -> io::Result<()> {
            self.record("alternate:off");
            Ok(())
        }
        fn enable_mouse_capture(&mut self) -> io::Result<()> {
            self.record("mouse:on");
            Ok(())
        }
        fn disable_mouse_capture(&mut self) -> io::Result<()> {
            self.record("mouse:off");
            Ok(())
        }
        fn enable_focus_change(&mut self) -> io::Result<()> {
            self.record("focus:on");
            Ok(())
        }
        fn disable_focus_change(&mut self) -> io::Result<()> {
            self.record("focus:off");
            Ok(())
        }
        fn enable_bracketed_paste(&mut self) -> io::Result<()> {
            self.record("paste:on:error");
            Err(io::Error::other("injected paste setup failure"))
        }
        fn disable_bracketed_paste(&mut self) -> io::Result<()> {
            self.record("paste:off");
            Ok(())
        }
    }

    #[test]
    fn terminal_restores_completed_setup_steps_on_error_exit() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let result = TerminalSession::start(FailingActions {
            log: Arc::clone(&log),
        });
        assert!(result.is_err());
        assert_eq!(
            *log.lock().unwrap(),
            [
                "raw:on",
                "alternate:on",
                "mouse:on",
                "focus:on",
                "paste:on:error",
                "focus:off",
                "mouse:off",
                "alternate:off",
                "raw:off"
            ]
        );
    }

    #[test]
    fn release_restores_selection_and_copy_works_during_capture() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = TerminalSession::start(RecordingActions(Arc::clone(&log))).unwrap();
        let mut state = AppState::new(
            PresentationState {
                diagnostics: vec!["copy me".to_owned()],
                ..PresentationState::default()
            },
            80,
            24,
        );
        let effects = reduce(&mut state, key(KeyCode::Char('c')));
        let Effect::Copy(text) = &effects[0] else {
            panic!("c must copy")
        };
        let mut output = Vec::new();
        copy_to_terminal_clipboard(&mut output, text).unwrap();
        assert_eq!(output, b"\x1b]52;c;Y29weSBtZQ==\x07");
        let release = reduce(&mut state, key(KeyCode::Char('m')));
        assert_eq!(release, [Effect::SetMouseCapture(false)]);
        session.set_mouse_capture(false).unwrap();
        assert!(log.lock().unwrap().ends_with(&["mouse:off"]));
    }

    #[test]
    fn small_terminal_snapshot_is_compact_with_help_and_no_clipping() {
        let state = AppState::new(
            PresentationState {
                heading: "Overview".to_owned(),
                health: Health::Offline,
                ..PresentationState::default()
            },
            48,
            12,
        );
        let frame = rendered(48, 12, &state);
        for visible_control in [
            "Key help - compact layout",
            "d Dashboard",
            "r Repositories",
            "n Runners",
            "s Repo settings",
            "h Host settings",
            "a Activity",
            "/ Filter",
            "F5 Refresh",
            "? Help",
            "Esc Back",
            "q Quit",
            "Tab Shift-Tab Arrows Focus",
            "Enter Activate",
            "c Copy diagnostics",
            "m Mouse capture",
            "Keys mirror every mouse action",
        ] {
            assert!(
                frame.contains(visible_control),
                "compact help clipped or omitted {visible_control:?}:\n{frame}"
            );
        }
        assert!(frame.lines().nth(1).unwrap().contains("[a]"));
        assert_eq!(frame.lines().count(), 12);
        assert!(frame.lines().all(|line| line.chars().count() == 48));
    }

    #[test]
    fn render_boundary_redacts_every_sensitive_value() {
        let token = "ghu_1234567890abcdefghijklmnopqrstuvwxyz";
        let jit =
            "eyJlbmNvZGVkX2ppdF9jb25maWciOiJ0aGlzLWlzLWEtbGl2ZS1zaG9ydC1saXZlZC1jcmVkZW50aWFsIn0=";
        let mut state = AppState::new(PresentationState::default(), 120, 30);
        state.open_screen(Screen::Activity);
        state.screen_model = ScreenModel::new(Snapshot {
            availability: screens::Availability::Ready,
            activity: vec![screens::ActivityRow {
                id: "sensitive".into(),
                occurred_at: "now".into(),
                outcome: screens::ActivityOutcome::Failed,
                summary: format!("VISIBLE_DIAGNOSTIC credential={token}"),
                remediation: format!("runner --jitconfig={jit}"),
            }],
            ..Snapshot::default()
        });
        state.open_screen(Screen::Activity);
        let frame = rendered(120, 30, &state);
        assert!(!frame.contains(token));
        assert!(!frame.contains(jit));
        assert!(frame.contains(runner_manager_platform::logging::REDACTION));
        assert!(frame.contains("VISIBLE_DIAGNOSTIC"));
        let Effect::Copy(copy) = &reduce(&mut state.clone(), key(KeyCode::Char('c')))[0] else {
            panic!()
        };
        assert!(!copy.contains(token) && !copy.contains(jit));
    }

    #[test]
    fn production_shell_routes_navigation_filter_activation_and_render_to_screen_model() {
        let snapshot = Snapshot {
            availability: screens::Availability::Ready,
            repositories: vec![screens::RepositoryRow {
                id: "wired-repo".into(),
                target: "acme/production-wiring".into(),
                in_progress_workflows: 3,
                mode: screens::PolicyMode::MonitorOnly,
                max_capacity: None,
                health: screens::AgentHealth::Healthy,
            }],
            ..Snapshot::default()
        };
        let mut state = AppState::new(PresentationState::default(), 120, 30);
        reduce(
            &mut state,
            AppEvent::Agent(AgentEvent {
                summary: "GitHub inventory refreshed".into(),
                health: Health::Ready,
                snapshot: Some(snapshot),
            }),
        );

        reduce(&mut state, key(KeyCode::Char('r')));
        let list = rendered(120, 30, &state);
        assert!(list.contains("acme/production-wiring"), "{list}");
        assert!(list.contains("[monitor-only]"), "{list}");

        reduce(&mut state, key(KeyCode::Char('/')));
        reduce(&mut state, AppEvent::Paste("production-wiring".to_owned()));
        assert_eq!(state.screen_model.repositories.filter, "production-wiring");
        reduce(&mut state, key(KeyCode::Enter));
        reduce(&mut state, key(KeyCode::Enter));
        let detail = rendered(120, 30, &state);
        assert!(detail.contains("REPOSITORY DETAIL"), "{detail}");
        assert!(
            detail.contains("Target: acme/production-wiring"),
            "{detail}"
        );

        let mut mouse_state = AppState::new(PresentationState::default(), 120, 30);
        mouse_state.screen_model = state.screen_model.clone();
        mouse_state
            .screen_model
            .apply(ScreenAction::CloseRepositoryDetail);
        reduce(&mut mouse_state, key(KeyCode::Char('r')));
        reduce(
            &mut mouse_state,
            mouse(MouseEventKind::Down(MouseButton::Left), 10, 6),
        );
        let mouse_detail = rendered(120, 30, &mouse_state);
        assert!(mouse_detail.contains("REPOSITORY DETAIL"), "{mouse_detail}");
    }

    #[test]
    fn production_keys_sort_inspect_runners_and_acknowledge_the_displayed_activity() {
        let snapshot = Snapshot {
            availability: Availability::Ready,
            runners: vec![
                RunnerRow {
                    id: "runner-a".into(),
                    name: "alpha".into(),
                    owner: "acme/alpha".into(),
                    os: "linux".into(),
                    labels: vec!["self-hosted".into()],
                    online: true,
                    busy: false,
                    ephemeral: true,
                    ownership: RunnerOwnership::Local,
                },
                RunnerRow {
                    id: "runner-z".into(),
                    name: "zulu".into(),
                    owner: "acme/zulu".into(),
                    os: "windows".into(),
                    labels: vec!["external".into()],
                    online: false,
                    busy: false,
                    ephemeral: false,
                    ownership: RunnerOwnership::External,
                },
            ],
            activity: vec![screens::ActivityRow {
                id: "visible-activity".into(),
                occurred_at: "now".into(),
                outcome: screens::ActivityOutcome::Failed,
                summary: "visible failure".into(),
                remediation: "inspect the runner log".into(),
            }],
            ..Snapshot::default()
        };
        let mut state = AppState::new(PresentationState::default(), 120, 30);
        reduce(
            &mut state,
            AppEvent::Agent(AgentEvent {
                summary: "production snapshot".into(),
                health: Health::Ready,
                snapshot: Some(snapshot),
            }),
        );

        reduce(&mut state, key(KeyCode::Char('n')));
        reduce(&mut state, key(KeyCode::Char('o')));
        assert_eq!(
            state.screen_model.runners.sort_order,
            screens::SortOrder::NameDescending
        );
        let sorted = screens::render_text(&state.screen_model);
        assert!(
            sorted.find("zulu").unwrap() < sorted.find("alpha").unwrap(),
            "{sorted}"
        );
        reduce(&mut state, key(KeyCode::Enter));
        assert!(screens::render_text(&state.screen_model).contains("RUNNER INSPECTION"));
        assert!(screens::render_text(&state.screen_model).contains("Name: alpha"));

        reduce(&mut state, key(KeyCode::Char('a')));
        assert!(screens::render_text(&state.screen_model).contains("[new]"));
        reduce(&mut state, key(KeyCode::Enter));
        let activity = screens::render_text(&state.screen_model);
        assert!(activity.contains("[acknowledged]"), "{activity}");
        assert!(!activity.contains("> [new]"), "{activity}");
    }

    #[test]
    fn durable_attempts_render_outcomes_retry_cleanup_and_remediation() {
        use runner_manager_domain::model::{AttemptId, PolicyId};

        let at = chrono::DateTime::parse_from_rfc3339("2026-08-23T10:00:00Z")
            .unwrap()
            .to_utc();
        let policy = PolicyId::from_u128(7);
        let mut idle = RunnerAttempt::allocate(AttemptId::from_u128(1), policy, "idle", at);
        idle.jit_received(at).unwrap();
        idle.started(10, at).unwrap();
        idle.registered_idle(100, at).unwrap();
        idle.conclude(AttemptOutcome::ExitedIdleWithoutWork, at)
            .unwrap();
        idle.clean(at).unwrap();
        let mut failed = RunnerAttempt::allocate(AttemptId::from_u128(2), policy, "failed", at);
        failed
            .conclude(
                AttemptOutcome::failed(FailureReason::RegistrationTimedOut),
                at,
            )
            .unwrap();
        let targets = HashMap::from([(policy, "acme/repo".to_owned())]);

        let rows = activity_rows(&[idle, failed], &targets);
        assert!(rows.iter().any(|row| {
            row.outcome == screens::ActivityOutcome::ExitedIdleWithoutWork
                && row.summary.contains("exited idle without accepting work")
        }));
        assert!(rows.iter().any(|row| {
            row.outcome == screens::ActivityOutcome::Failed
                && row.remediation.contains("network, DNS, proxy, firewall")
        }));
        assert!(
            rows.iter()
                .any(|row| row.outcome == screens::ActivityOutcome::Retry)
        );
        assert!(
            rows.iter()
                .any(|row| row.outcome == screens::ActivityOutcome::CleanupComplete)
        );
    }

    #[test]
    fn production_inventory_mapping_preserves_non_transport_meaning() {
        let root = tempfile::tempdir().unwrap();
        let mut warnings = Vec::new();
        let context = crate::cli::Context::resolve(Some(root.path()), &mut warnings).unwrap();
        let clock = context.clock();
        let offline = availability_from_refresh_state(&context, &clock, &RefreshState::Offline);
        let forbidden = availability_from_refresh_state(
            &context,
            &clock,
            &RefreshState::Forbidden {
                message: Some("missing administration grant".into()),
            },
        );
        let failed = availability_from_refresh_state(
            &context,
            &clock,
            &RefreshState::Failed {
                status: Some(500),
                message: "server error".into(),
            },
        );
        let cancelled = availability_from_refresh_state(&context, &clock, &RefreshState::Cancelled);
        assert!(matches!(offline, Availability::Offline { .. }));
        assert_eq!(
            forbidden,
            Availability::Forbidden {
                message: Some("missing administration grant".into())
            }
        );
        assert_eq!(
            failed,
            Availability::Failed {
                detail: "server error".into()
            }
        );
        assert_eq!(cancelled, Availability::Cancelled);
    }

    #[test]
    fn rate_limited_activity_opens_acknowledges_copies_and_survives_ready_refresh() {
        let row = screens::ActivityRow {
            id: "rate-limit-1".into(),
            occurred_at: "2026-08-23T10:00:00Z".into(),
            outcome: screens::ActivityOutcome::RateLimit,
            summary: "GitHub primary rate limit was reached".into(),
            remediation: "wait 90 seconds before retrying".into(),
        };
        let mut state = AppState::new(PresentationState::default(), 120, 30);
        reduce(
            &mut state,
            AppEvent::Agent(AgentEvent {
                summary: "rate limited".into(),
                health: Health::Error,
                snapshot: Some(Snapshot {
                    availability: Availability::RateLimited {
                        retry_after_seconds: 90,
                    },
                    activity: vec![row],
                    ..Snapshot::default()
                }),
            }),
        );
        reduce(&mut state, key(KeyCode::Char('a')));
        let detail = screens::render_text(&state.screen_model);
        assert!(detail.contains("RATE LIMITED"), "{detail}");
        assert!(detail.contains("RATE-LIMIT"), "{detail}");
        assert!(
            detail.contains("wait 90 seconds before retrying"),
            "{detail}"
        );
        reduce(&mut state, key(KeyCode::Enter));
        assert!(screens::render_text(&state.screen_model).contains("[acknowledged]"));
        let Effect::Copy(copied) = &reduce(&mut state, key(KeyCode::Char('c')))[0] else {
            panic!("Activity copy effect")
        };
        assert!(copied.contains("wait 90 seconds before retrying"));

        reduce(
            &mut state,
            AppEvent::Agent(AgentEvent {
                summary: "ready again".into(),
                health: Health::Ready,
                snapshot: Some(Snapshot {
                    availability: Availability::Ready,
                    ..Snapshot::default()
                }),
            }),
        );
        let retained = screens::render_text(&state.screen_model);
        assert!(retained.contains("RATE-LIMIT"), "{retained}");
        assert!(retained.contains("[acknowledged]"), "{retained}");
    }

    #[test]
    fn repeated_f5_cancels_stale_work_and_publishes_only_the_latest_collection() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let collections = Arc::new(AtomicUsize::new(0));
        let worker_collections = Arc::clone(&collections);
        let (first_started, first_started_rx) = std::sync::mpsc::sync_channel(0);
        let (source, mut events) = LocalAgentEventSource::start_with(
            move |cancel| {
                let number = worker_collections.fetch_add(1, Ordering::SeqCst) + 1;
                if number == 1 {
                    first_started.send(()).unwrap();
                    while !cancel.is_cancelled() {
                        thread::yield_now();
                    }
                }
                AgentEvent {
                    summary: format!("collection {number}"),
                    health: Health::Ready,
                    snapshot: None,
                }
            },
            Duration::from_secs(60),
        )
        .unwrap();
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        for _ in 0..100 {
            source.request_refresh().unwrap();
        }
        let published = events.blocking_recv().unwrap();
        assert_eq!(published.summary, "collection 2");
        assert!(matches!(
            events.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(collections.load(Ordering::SeqCst), 2);
        drop(source);
    }

    #[test]
    fn drop_cancels_active_collection_joins_worker_and_allows_no_post_exit_calls() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicBool::new(false));
        let worker_calls = Arc::clone(&calls);
        let worker_finished = Arc::clone(&finished);
        let (started, started_rx) = std::sync::mpsc::sync_channel(0);
        let (source, _events) = LocalAgentEventSource::start_with(
            move |cancel| {
                worker_calls.fetch_add(1, Ordering::SeqCst);
                started.send(()).unwrap();
                while !cancel.is_cancelled() {
                    thread::yield_now();
                }
                thread::sleep(Duration::from_millis(20));
                worker_finished.store(true, Ordering::SeqCst);
                AgentEvent {
                    summary: "cancelled collection".into(),
                    health: Health::Ready,
                    snapshot: None,
                }
            },
            Duration::from_secs(60),
        )
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(source);
        assert!(
            finished.load(Ordering::SeqCst),
            "Drop returned before worker exit"
        );
        let calls_at_exit = calls.load(Ordering::SeqCst);
        thread::sleep(Duration::from_millis(10));
        assert_eq!(calls.load(Ordering::SeqCst), calls_at_exit);
        assert_eq!(calls_at_exit, 1);
    }

    #[test]
    fn in_memory_frame_meets_budget_and_render_has_no_io_capability() {
        let mut state = AppState::new(PresentationState::default(), 120, 40);
        state.presentation.body = (0..100).map(|n| format!("row {n}")).collect();
        let started = Instant::now();
        let _ = rendered(120, 40, &state);
        assert!(
            started.elapsed() < FRAME_BUDGET,
            "frame exceeded {FRAME_BUDGET:?}"
        );
        let _structural_proof: fn(&mut Frame<'_>, &AppState) = render;

        let source = include_str!("shell.rs");
        let render_source = source
            .split_once("pub fn render(")
            .expect("render function")
            .1
            .split_once("const fn screen_key")
            .expect("end of render-only section")
            .0;
        for forbidden_capability in [
            "std::fs",
            "std::net",
            "reqwest",
            "Context",
            "Store",
            "Gateway",
            "File::",
            "TcpStream",
            "read_to_",
            "block_on",
            ".await",
        ] {
            assert!(
                !render_source.contains(forbidden_capability),
                "render acquired forbidden I/O capability {forbidden_capability:?}"
            );
        }
    }
}
