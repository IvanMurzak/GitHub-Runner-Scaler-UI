// owner: g2-tui-screens

#![allow(
    dead_code,
    reason = "the agent inventory gateway populates the complete screen vocabulary through AppState"
)]

//! Pure presentation model for the four read-only TUI screens.
//!
//! The daemon owns polling. This module receives an immutable, already
//! collected [`Snapshot`] and cannot perform filesystem or network I/O.

use std::cmp::Ordering;
use std::collections::HashSet;

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub const QUEUE_CANCELLATION_WARNING: &str = "GitHub cancels queued jobs after 24 hours.";
const TABLE_VIEWPORT_ROWS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadOnlyScreen {
    Dashboard,
    Repositories,
    Runners,
    Activity,
}

impl ReadOnlyScreen {
    pub const ALL: [Self; 4] = [
        Self::Dashboard,
        Self::Repositories,
        Self::Runners,
        Self::Activity,
    ];

    const fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Repositories => "Repositories",
            Self::Runners => "Runners",
            Self::Activity => "Activity & errors",
        }
    }
}

/// One vocabulary for all four screens. `Ready` with no relevant rows is the
/// separate empty state rather than zero workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Loading,
    Ready,
    Unauthorized,
    RateLimited {
        retry_after_seconds: u64,
    },
    Offline {
        last_successful_contact: String,
        retry_after_seconds: u64,
    },
    Forbidden {
        message: Option<String>,
    },
    Failed {
        detail: String,
    },
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    Autoscale,
    MonitorOnly,
}
impl PolicyMode {
    const fn marker(self) -> &'static str {
        match self {
            Self::Autoscale => "[autoscale]",
            Self::MonitorOnly => "[monitor-only]",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentHealth {
    Healthy,
    Degraded,
    Offline,
}
impl AgentHealth {
    const fn marker(self) -> &'static str {
        match self {
            Self::Healthy => "OK healthy",
            Self::Degraded => "! degraded",
            Self::Offline => "X offline",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerOwnership {
    Local,
    External,
}
impl RunnerOwnership {
    const fn marker(self) -> &'static str {
        match self {
            Self::Local => "[local-owned]",
            Self::External => "[external-read-only]",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityOutcome {
    Info,
    Retry,
    RateLimit,
    CleanupComplete,
    ExitedIdleWithoutWork,
    Failed,
}
impl ActivityOutcome {
    const fn marker(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Retry => "RETRY",
            Self::RateLimit => "RATE-LIMIT",
            Self::CleanupComplete => "CLEANUP-OK",
            Self::ExitedIdleWithoutWork => "IDLE-EXIT (normal, no work accepted)",
            Self::Failed => "FAILED (action required)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DashboardMetrics {
    pub in_progress_workflows: u32,
    pub assigned_jobs: u32,
    pub busy_runners: u32,
    pub online_runners: u32,
    pub host_capacity_used: u16,
    pub host_capacity_total: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryRow {
    pub id: String,
    pub target: String,
    pub in_progress_workflows: u32,
    pub mode: PolicyMode,
    pub max_capacity: Option<u16>,
    pub health: AgentHealth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerRow {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub os: String,
    pub labels: Vec<String>,
    pub online: bool,
    pub busy: bool,
    pub ephemeral: bool,
    pub ownership: RunnerOwnership,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityRow {
    pub id: String,
    pub occurred_at: String,
    pub outcome: ActivityOutcome,
    pub summary: String,
    pub remediation: String,
}

/// Complete in-memory input. Credentials have no field in this type, so a
/// frame cannot accidentally obtain one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub availability: Availability,
    pub metrics: DashboardMetrics,
    pub repositories: Vec<RepositoryRow>,
    pub runners: Vec<RunnerRow>,
    pub activity: Vec<ActivityRow>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            availability: Availability::Loading,
            metrics: DashboardMetrics::default(),
            repositories: vec![],
            runners: vec![],
            activity: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableFocus {
    Header,
    Rows,
    Footer,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    NameAscending,
    NameDescending,
    WorkloadDescending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableViewState {
    pub focus: TableFocus,
    pub selected_id: Option<String>,
    pub sort_order: SortOrder,
    pub scroll: usize,
    pub filter: String,
}
impl Default for TableViewState {
    fn default() -> Self {
        Self {
            focus: TableFocus::Rows,
            selected_id: None,
            sort_order: SortOrder::NameAscending,
            scroll: 0,
            filter: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenModel {
    pub screen: ReadOnlyScreen,
    pub snapshot: Snapshot,
    pub repositories: TableViewState,
    pub runners: TableViewState,
    pub activity: TableViewState,
    pub repository_detail: Option<String>,
    pub runner_detail: Option<String>,
    pub acknowledged_activity: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenAction {
    Open(ReadOnlyScreen),
    OpenStatus,
    Filter(String),
    MoveSelection(isize),
    SetSort(SortOrder),
    SetFocus(TableFocus),
    Activate,
    CloseRepositoryDetail,
    OpenRepositoryByMouse(String),
    Refresh(Snapshot),
}

impl ScreenModel {
    pub fn new(snapshot: Snapshot) -> Self {
        let mut model = Self {
            screen: ReadOnlyScreen::Dashboard,
            snapshot,
            repositories: TableViewState::default(),
            runners: TableViewState::default(),
            activity: TableViewState::default(),
            repository_detail: None,
            runner_detail: None,
            acknowledged_activity: HashSet::new(),
        };
        model.reconcile_all(None);
        model
    }

    /// Apply one user or refresh event. This reducer has no effects and no I/O.
    pub fn apply(&mut self, action: ScreenAction) {
        match action {
            ScreenAction::Open(screen) => self.screen = screen,
            ScreenAction::OpenStatus => self.screen = ReadOnlyScreen::Activity,
            ScreenAction::Filter(query) => {
                if let Some(table) = self.current_table_mut() {
                    table.filter = query;
                    self.reconcile_current(None);
                }
            }
            ScreenAction::MoveSelection(delta) => self.move_selection(delta),
            ScreenAction::SetSort(order) => {
                if let Some(table) = self.current_table_mut() {
                    table.sort_order = order;
                    self.reconcile_current(None);
                }
            }
            ScreenAction::SetFocus(focus) => {
                if let Some(table) = self.current_table_mut() {
                    table.focus = focus
                }
            }
            ScreenAction::Activate => match self.screen {
                ReadOnlyScreen::Repositories => {
                    self.repository_detail = self.repositories.selected_id.clone();
                }
                ReadOnlyScreen::Runners => {
                    self.runner_detail = self.runners.selected_id.clone();
                }
                ReadOnlyScreen::Activity => {
                    if let Some(id) = &self.activity.selected_id {
                        self.acknowledged_activity.insert(id.clone());
                    }
                }
                ReadOnlyScreen::Dashboard => {}
            },
            ScreenAction::CloseRepositoryDetail => {
                self.repository_detail = None;
                self.runner_detail = None;
            }
            ScreenAction::OpenRepositoryByMouse(id) => {
                if self.snapshot.repositories.iter().any(|row| row.id == id) {
                    self.repositories.selected_id = Some(id.clone());
                    self.repository_detail = Some(id);
                    self.screen = ReadOnlyScreen::Repositories;
                }
            }
            ScreenAction::Refresh(snapshot) => {
                let old = [
                    self.visible_repository_ids().len(),
                    self.visible_runner_ids().len(),
                    self.visible_activity_ids().len(),
                ];
                self.snapshot = snapshot;
                self.reconcile_all(Some(old));
            }
        }
    }

    fn current_table_mut(&mut self) -> Option<&mut TableViewState> {
        match self.screen {
            ReadOnlyScreen::Dashboard => None,
            ReadOnlyScreen::Repositories => Some(&mut self.repositories),
            ReadOnlyScreen::Runners => Some(&mut self.runners),
            ReadOnlyScreen::Activity => Some(&mut self.activity),
        }
    }

    fn reconcile_current(&mut self, old_len: Option<usize>) {
        match self.screen {
            ReadOnlyScreen::Dashboard => {}
            ReadOnlyScreen::Repositories => {
                let ids = self.visible_repository_ids();
                reconcile_table(&mut self.repositories, &ids, old_len);
            }
            ReadOnlyScreen::Runners => {
                let ids = self.visible_runner_ids();
                reconcile_table(&mut self.runners, &ids, old_len);
            }
            ReadOnlyScreen::Activity => {
                let ids = self.visible_activity_ids();
                reconcile_table(&mut self.activity, &ids, old_len);
            }
        }
    }

    fn reconcile_all(&mut self, old: Option<[usize; 3]>) {
        let repos = self.visible_repository_ids();
        let runners = self.visible_runner_ids();
        let activity = self.visible_activity_ids();
        reconcile_table(&mut self.repositories, &repos, old.map(|v| v[0]));
        reconcile_table(&mut self.runners, &runners, old.map(|v| v[1]));
        reconcile_table(&mut self.activity, &activity, old.map(|v| v[2]));
        if self
            .repository_detail
            .as_ref()
            .is_some_and(|id| !self.snapshot.repositories.iter().any(|row| &row.id == id))
        {
            self.repository_detail = None;
        }
        if self
            .runner_detail
            .as_ref()
            .is_some_and(|id| !self.snapshot.runners.iter().any(|row| &row.id == id))
        {
            self.runner_detail = None;
        }
        self.acknowledged_activity
            .retain(|id| self.snapshot.activity.iter().any(|row| &row.id == id));
    }

    fn move_selection(&mut self, delta: isize) {
        let ids = match self.screen {
            ReadOnlyScreen::Dashboard => return,
            ReadOnlyScreen::Repositories => self.visible_repository_ids(),
            ReadOnlyScreen::Runners => self.visible_runner_ids(),
            ReadOnlyScreen::Activity => self.visible_activity_ids(),
        };
        let Some(table) = self.current_table_mut() else {
            return;
        };
        if ids.is_empty() {
            table.selected_id = None;
            table.scroll = 0;
            return;
        }
        let current = table
            .selected_id
            .as_ref()
            .and_then(|id| ids.iter().position(|candidate| candidate == id))
            .unwrap_or(0);
        let next = current.saturating_add_signed(delta).min(ids.len() - 1);
        table.selected_id = Some(ids[next].clone());
        table.scroll = next;
    }

    fn visible_repository_ids(&self) -> Vec<String> {
        let mut rows: Vec<_> = self
            .snapshot
            .repositories
            .iter()
            .filter(|row| contains_folded(&row.target, &self.repositories.filter))
            .collect();
        rows.sort_by(|a, b| repository_cmp(a, b, self.repositories.sort_order));
        rows.into_iter().map(|row| row.id.clone()).collect()
    }

    pub fn repository_id_at_viewport_offset(&self, offset: usize) -> Option<String> {
        self.visible_repository_ids()
            .get(self.repositories.scroll.saturating_add(offset))
            .cloned()
    }
    fn visible_runner_ids(&self) -> Vec<String> {
        let mut rows: Vec<_> = self
            .snapshot
            .runners
            .iter()
            .filter(|row| {
                contains_folded(&row.name, &self.runners.filter)
                    || contains_folded(&row.owner, &self.runners.filter)
                    || row
                        .labels
                        .iter()
                        .any(|label| contains_folded(label, &self.runners.filter))
            })
            .collect();
        rows.sort_by(|a, b| named_cmp(&a.name, &b.name, self.runners.sort_order));
        rows.into_iter().map(|row| row.id.clone()).collect()
    }
    fn visible_activity_ids(&self) -> Vec<String> {
        let mut rows: Vec<_> = self
            .snapshot
            .activity
            .iter()
            .filter(|row| {
                contains_folded(&row.summary, &self.activity.filter)
                    || contains_folded(&row.remediation, &self.activity.filter)
            })
            .collect();
        rows.sort_by(|a, b| named_cmp(&a.occurred_at, &b.occurred_at, self.activity.sort_order));
        rows.into_iter().map(|row| row.id.clone()).collect()
    }
}

fn contains_folded(value: &str, query: &str) -> bool {
    query.is_empty() || value.to_lowercase().contains(&query.to_lowercase())
}
fn named_cmp(a: &str, b: &str, order: SortOrder) -> Ordering {
    match order {
        SortOrder::NameAscending => a.cmp(b),
        _ => b.cmp(a),
    }
}
fn repository_cmp(a: &RepositoryRow, b: &RepositoryRow, order: SortOrder) -> Ordering {
    match order {
        SortOrder::NameAscending => a.target.cmp(&b.target),
        SortOrder::NameDescending => b.target.cmp(&a.target),
        SortOrder::WorkloadDescending => b
            .in_progress_workflows
            .cmp(&a.in_progress_workflows)
            .then_with(|| a.target.cmp(&b.target)),
    }
}

fn reconcile_table(table: &mut TableViewState, ids: &[String], old_len: Option<usize>) {
    if ids.is_empty() {
        table.selected_id = None;
        table.scroll = 0;
        return;
    }
    if table
        .selected_id
        .as_ref()
        .is_some_and(|selected| ids.contains(selected))
    {
        table.scroll = table.scroll.min(ids.len() - 1);
        return;
    }
    let old_last = old_len.unwrap_or(ids.len()).saturating_sub(1);
    let index = table.scroll.min(old_last).min(ids.len() - 1);
    table.selected_id = Some(ids[index].clone());
    table.scroll = index;
}

/// Draw into the content area owned by `shell.rs`.
pub fn render(frame: &mut Frame<'_>, area: Rect, model: &ScreenModel) {
    let text = render_text(model);
    let border = match model.snapshot.availability {
        Availability::Ready => Style::default(),
        Availability::Loading => Style::default().fg(Color::Cyan),
        Availability::Unauthorized
        | Availability::Offline { .. }
        | Availability::Forbidden { .. }
        | Availability::Failed { .. } => Style::default().fg(Color::Red),
        Availability::RateLimited { .. } | Availability::Cancelled => {
            Style::default().fg(Color::Yellow)
        }
    };
    frame.render_widget(
        Paragraph::new(Text::from(text.lines().map(Line::from).collect::<Vec<_>>()))
            .block(
                Block::default()
                    .title(Span::styled(
                        model.screen.title(),
                        Style::default().add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL)
                    .border_style(border),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Stable colour-independent rendering, also used by the snapshot harness.
pub fn render_text(model: &ScreenModel) -> String {
    match &model.snapshot.availability {
        Availability::Loading => state_panel(
            "LOADING",
            "Waiting for the first GitHub inventory snapshot.",
            "Action: F5 refresh now",
        ),
        Availability::Unauthorized => state_panel(
            "UNAUTHORIZED",
            "GitHub authorization is missing or no longer valid.",
            "Action: runner-manager auth login",
        ),
        Availability::RateLimited {
            retry_after_seconds,
        } => state_panel(
            "RATE LIMITED",
            &format!("GitHub asked this host to wait {retry_after_seconds}s."),
            "Action: a opens rate-limit details; retry is automatic",
        ),
        Availability::Offline {
            last_successful_contact,
            retry_after_seconds,
        } => {
            let common = format!(
                "OFFLINE - no new runners will start\nLast successful GitHub contact: {last_successful_contact}\nRetry in: {retry_after_seconds}s\nLocal remediation: check this host's network, DNS, proxy, and system clock.\n{QUEUE_CANCELLATION_WARNING}\nAction: a opens Activity & errors"
            );
            if model.screen == ReadOnlyScreen::Activity {
                format!("{common}\n\n{}", render_activity(model))
            } else {
                common
            }
        }
        Availability::Forbidden { message } => state_panel(
            "FORBIDDEN",
            &format!(
                "GitHub is reachable but refused this target: {}",
                message
                    .as_deref()
                    .unwrap_or("required permission is missing")
            ),
            "Action: verify repository access and GitHub App/user permissions",
        ),
        Availability::Failed { detail } => state_panel(
            "REFRESH FAILED",
            &format!("GitHub answered, but inventory could not be collected: {detail}"),
            "Action: open Activity & errors and retry with F5",
        ),
        Availability::Cancelled => state_panel(
            "REFRESH CANCELLED",
            "The previous inventory collection was superseded or the TUI is stopping.",
            "Action: F5 starts one latest refresh",
        ),
        Availability::Ready => render_ready(model),
    }
}

fn state_panel(title: &str, message: &str, action: &str) -> String {
    format!("{title}\n{message}\n{action}")
}
fn render_ready(model: &ScreenModel) -> String {
    let globally_empty = match model.screen {
        ReadOnlyScreen::Dashboard => {
            model.snapshot.repositories.is_empty()
                && model.snapshot.runners.is_empty()
                && model.snapshot.metrics == DashboardMetrics::default()
        }
        ReadOnlyScreen::Repositories => model.snapshot.repositories.is_empty(),
        ReadOnlyScreen::Runners => model.snapshot.runners.is_empty(),
        ReadOnlyScreen::Activity => model.snapshot.activity.is_empty(),
    };
    if globally_empty {
        return match model.screen {
            ReadOnlyScreen::Dashboard | ReadOnlyScreen::Repositories => state_panel(
                "EMPTY",
                "No authorized targets are configured; workload is unknown, not zero.",
                "Action: runner-manager repo add OWNER/REPO",
            ),
            ReadOnlyScreen::Runners => state_panel(
                "EMPTY",
                "No authorized GitHub runners are visible.",
                "Action: F5 refresh or open Repositories",
            ),
            ReadOnlyScreen::Activity => state_panel(
                "EMPTY",
                "No lifecycle activity or errors have been recorded.",
                "Action: F5 refresh",
            ),
        };
    }
    let no_matches = match model.screen {
        ReadOnlyScreen::Dashboard => false,
        ReadOnlyScreen::Repositories => model.visible_repository_ids().is_empty(),
        ReadOnlyScreen::Runners => model.visible_runner_ids().is_empty(),
        ReadOnlyScreen::Activity => model.visible_activity_ids().is_empty(),
    };
    if no_matches {
        return state_panel(
            "NO MATCHES",
            "Rows exist, but none match the current filter.",
            "Action: Esc clears the filter",
        );
    }
    match model.screen {
        ReadOnlyScreen::Dashboard => render_dashboard(model),
        ReadOnlyScreen::Repositories => render_repositories(model),
        ReadOnlyScreen::Runners => render_runners(model),
        ReadOnlyScreen::Activity => render_activity(model),
    }
}

fn render_dashboard(model: &ScreenModel) -> String {
    let m = &model.snapshot.metrics;
    let mut output = vec![
        "HEALTH: OK live snapshot".into(),
        format!("In-progress workflows : {}", m.in_progress_workflows),
        format!("Assigned jobs         : {}", m.assigned_jobs),
        format!("Busy runners          : {}", m.busy_runners),
        format!("Online runners        : {}", m.online_runners),
        format!(
            "Host capacity         : {}/{}",
            m.host_capacity_used, m.host_capacity_total
        ),
        String::new(),
    ];
    output.push(render_table(
        &["Repository", "Workflows", "Mode", "Capacity", "Health"],
        &repository_rows(model),
        model.repositories.selected_id.as_deref(),
        0,
    ));
    output.join("\n")
}

fn repository_rows(model: &ScreenModel) -> Vec<(String, Vec<String>)> {
    model
        .visible_repository_ids()
        .into_iter()
        .filter_map(|id| {
            model
                .snapshot
                .repositories
                .iter()
                .find(|row| row.id == id)
                .map(|row| {
                    (
                        row.id.clone(),
                        vec![
                            row.target.clone(),
                            format!("({})", row.in_progress_workflows),
                            row.mode.marker().into(),
                            row.max_capacity
                                .map_or_else(|| "n/a".into(), |v| v.to_string()),
                            row.health.marker().into(),
                        ],
                    )
                })
        })
        .collect()
}
fn render_repositories(model: &ScreenModel) -> String {
    if let Some(detail_id) = model.repository_detail.as_deref()
        && let Some(row) = model
            .snapshot
            .repositories
            .iter()
            .find(|row| row.id == detail_id)
    {
        return format!(
            "REPOSITORY DETAIL\nTarget: {}\nIn-progress workflows: {}\nPolicy: {}\nMax capacity: {}\nAgent health: {}\nAction: Esc returns to the repository list",
            row.target,
            row.in_progress_workflows,
            row.mode.marker(),
            row.max_capacity
                .map_or_else(|| "n/a".into(), |capacity| capacity.to_string()),
            row.health.marker(),
        );
    }
    format!(
        "Filter: {} | Sort: {:?} | Focus: {:?} | Scroll: {}\n{}",
        visible_filter(&model.repositories.filter),
        model.repositories.sort_order,
        model.repositories.focus,
        model.repositories.scroll,
        render_table(
            &["Repository", "Workflows", "Mode", "Max", "Agent"],
            &repository_rows(model),
            model.repositories.selected_id.as_deref(),
            model.repositories.scroll,
        )
    )
}
fn render_runners(model: &ScreenModel) -> String {
    if let Some(detail_id) = model.runner_detail.as_deref()
        && let Some(row) = model
            .snapshot
            .runners
            .iter()
            .find(|row| row.id == detail_id)
    {
        return format!(
            "RUNNER INSPECTION\nName: {}\nOwner: {}\nOwnership: {}\nOS: {}\nLabels: {}\nOnline: {}\nBusy: {}\nEphemeral: {}\nAction: Esc returns to the runner list",
            row.name,
            row.owner,
            row.ownership.marker(),
            row.os,
            row.labels.join(","),
            row.online,
            row.busy,
            row.ephemeral,
        );
    }
    let rows = model
        .visible_runner_ids()
        .into_iter()
        .filter_map(|id| {
            model
                .snapshot
                .runners
                .iter()
                .find(|row| row.id == id)
                .map(|row| {
                    (
                        row.id.clone(),
                        vec![
                            row.name.clone(),
                            row.owner.clone(),
                            row.ownership.marker().into(),
                            row.os.clone(),
                            row.labels.join(","),
                            format!(
                                "{} {} {}",
                                if row.online { "online" } else { "offline" },
                                if row.busy { "busy" } else { "idle" },
                                if row.ephemeral {
                                    "ephemeral"
                                } else {
                                    "persistent"
                                }
                            ),
                        ],
                    )
                })
        })
        .collect::<Vec<_>>();
    format!(
        "Filter: {} | Sort: {:?} | Focus: {:?} | Scroll: {}\n{}",
        visible_filter(&model.runners.filter),
        model.runners.sort_order,
        model.runners.focus,
        model.runners.scroll,
        render_table(
            &["Runner", "Owner", "Ownership", "OS", "Labels", "State"],
            &rows,
            model.runners.selected_id.as_deref(),
            model.runners.scroll,
        )
    )
}
fn render_activity(model: &ScreenModel) -> String {
    let rows = model
        .visible_activity_ids()
        .into_iter()
        .filter_map(|id| {
            model
                .snapshot
                .activity
                .iter()
                .find(|row| row.id == id)
                .map(|row| {
                    (
                        row.id.clone(),
                        vec![
                            if model.acknowledged_activity.contains(&row.id) {
                                "[acknowledged]".into()
                            } else {
                                "[new]".into()
                            },
                            row.occurred_at.clone(),
                            row.outcome.marker().into(),
                            copy_safe(&row.summary),
                            copy_safe(&row.remediation),
                        ],
                    )
                })
        })
        .collect::<Vec<_>>();
    format!(
        "Diagnostics are redacted and copy-safe. Acknowledge: Enter | Copy: c\n{}",
        render_table(
            &["Ack", "When", "Outcome", "Summary", "Remediation"],
            &rows,
            model.activity.selected_id.as_deref(),
            model.activity.scroll,
        )
    )
}
fn visible_filter(filter: &str) -> &str {
    if filter.is_empty() { "<none>" } else { filter }
}

/// Shared by repositories, runners, and activity. Text markers preserve
/// meaning when colour is disabled.
fn render_table(
    headers: &[&str],
    rows: &[(String, Vec<String>)],
    selected_id: Option<&str>,
    scroll: usize,
) -> String {
    let mut output = headers.join(" | ");
    output.push('\n');
    output.push_str(
        &headers
            .iter()
            .map(|_| "---")
            .collect::<Vec<_>>()
            .join("-+-"),
    );
    let viewport_start = scroll.min(rows.len().saturating_sub(1));
    for (id, cells) in rows.iter().skip(viewport_start).take(TABLE_VIEWPORT_ROWS) {
        output.push('\n');
        output.push_str(if selected_id == Some(id.as_str()) {
            "> "
        } else {
            "  "
        });
        output.push_str(&cells.join(" | "));
    }
    output
}

/// Defensive final boundary for persisted diagnostics.
pub fn copy_safe(value: &str) -> String {
    // The shared scrubber understands credential-bearing keys, while command
    // line diagnostics can prefix the same key with `--`. Remove only that
    // syntactic decoration before applying the canonical shape rules.
    let normalized = value
        .replace("--jitconfig=", "jitconfig=")
        .replace("--jit-config=", "jit_config=");
    runner_manager_platform::logging::redact(&normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn populated() -> Snapshot {
        Snapshot {
            availability: Availability::Ready,
            metrics: DashboardMetrics {
                in_progress_workflows: 7,
                assigned_jobs: 4,
                busy_runners: 2,
                online_runners: 5,
                host_capacity_used: 2,
                host_capacity_total: 8,
            },
            repositories: vec![
                RepositoryRow {
                    id: "alpha".into(),
                    target: "acme/alpha".into(),
                    in_progress_workflows: 5,
                    mode: PolicyMode::Autoscale,
                    max_capacity: Some(4),
                    health: AgentHealth::Healthy,
                },
                RepositoryRow {
                    id: "observe".into(),
                    target: "acme/observe".into(),
                    in_progress_workflows: 2,
                    mode: PolicyMode::MonitorOnly,
                    max_capacity: None,
                    health: AgentHealth::Degraded,
                },
            ],
            runners: vec![
                RunnerRow {
                    id: "local".into(),
                    name: "rm-home-1".into(),
                    owner: "acme/alpha".into(),
                    os: "Windows".into(),
                    labels: vec!["self-hosted".into(), "rm-home-win-x64".into()],
                    online: true,
                    busy: true,
                    ephemeral: true,
                    ownership: RunnerOwnership::Local,
                },
                RunnerRow {
                    id: "legacy".into(),
                    name: "legacy-office".into(),
                    owner: "acme/observe".into(),
                    os: "Linux".into(),
                    labels: vec!["self-hosted".into()],
                    online: true,
                    busy: false,
                    ephemeral: false,
                    ownership: RunnerOwnership::External,
                },
            ],
            activity: vec![
                ActivityRow {
                    id: "idle".into(),
                    occurred_at: "12:00:00Z".into(),
                    outcome: ActivityOutcome::ExitedIdleWithoutWork,
                    summary: "surplus runner accepted no job".into(),
                    remediation: "none".into(),
                },
                ActivityRow {
                    id: "failed".into(),
                    occurred_at: "12:01:00Z".into(),
                    outcome: ActivityOutcome::Failed,
                    summary: "runner process exited before registration".into(),
                    remediation: "inspect local runner log".into(),
                },
            ],
        }
    }

    fn matrix_snapshot() -> String {
        let states = [
            "loading",
            "populated",
            "empty",
            "unauthorized",
            "rate-limited",
            "offline",
        ];
        let mut output = vec![];
        for screen in ReadOnlyScreen::ALL {
            for state in states {
                let mut snapshot = match state {
                    "populated" => populated(),
                    "empty" => Snapshot {
                        availability: Availability::Ready,
                        ..Snapshot::default()
                    },
                    "unauthorized" => Snapshot {
                        availability: Availability::Unauthorized,
                        ..Snapshot::default()
                    },
                    "rate-limited" => Snapshot {
                        availability: Availability::RateLimited {
                            retry_after_seconds: 37,
                        },
                        ..Snapshot::default()
                    },
                    "offline" => Snapshot {
                        availability: Availability::Offline {
                            last_successful_contact: "2026-08-23T12:00:00Z".into(),
                            retry_after_seconds: 13,
                        },
                        ..Snapshot::default()
                    },
                    _ => Snapshot::default(),
                };
                if state == "offline" {
                    snapshot.activity = populated().activity;
                }
                let mut model = ScreenModel::new(snapshot);
                model.screen = screen;
                let rendered = render_text(&model);
                let first = rendered.lines().next().unwrap_or_default();
                let action = rendered.lines().find(|line| line.starts_with("Action:"));
                output.push(format!(
                    "{screen:?}/{state}: lines={} bytes={} fnv={:016x} | {first}{}",
                    rendered.lines().count(),
                    rendered.len(),
                    stable_checksum(&rendered),
                    action.map_or(String::new(), |line| format!(" | {line}"))
                ));
            }
        }
        output.join("\n")
    }

    // Stable FNV-1a fingerprint makes the snapshot sensitive to every byte of
    // all 24 complete renders without turning the source file into 24 large
    // duplicated golden frames.
    fn stable_checksum(rendered: &str) -> u64 {
        rendered.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }

    #[test]
    fn snapshot_all_four_screens_in_every_required_state() {
        insta::assert_snapshot!(matrix_snapshot(), @r###"
        Dashboard/loading: lines=3 bytes=79 fnv=0773e12a4b1d7abf | LOADING | Action: F5 refresh now
        Dashboard/populated: lines=11 bytes=342 fnv=3d951ae304c63126 | HEALTH: OK live snapshot
        Dashboard/empty: lines=3 bytes=117 fnv=46b29f02007e5280 | EMPTY | Action: runner-manager repo add OWNER/REPO
        Dashboard/unauthorized: lines=3 bytes=98 fnv=b305c2db5095c2ad | UNAUTHORIZED | Action: runner-manager auth login
        Dashboard/rate-limited: lines=3 bytes=103 fnv=d96d37598270b0bb | RATE LIMITED | Action: a opens rate-limit details; retry is automatic
        Dashboard/offline: lines=6 bytes=255 fnv=7aca69b8a1025157 | OFFLINE - no new runners will start | Action: a opens Activity & errors
        Repositories/loading: lines=3 bytes=79 fnv=0773e12a4b1d7abf | LOADING | Action: F5 refresh now
        Repositories/populated: lines=5 bytes=241 fnv=1066b31991aed822 | Filter: <none> | Sort: NameAscending | Focus: Rows | Scroll: 0
        Repositories/empty: lines=3 bytes=117 fnv=46b29f02007e5280 | EMPTY | Action: runner-manager repo add OWNER/REPO
        Repositories/unauthorized: lines=3 bytes=98 fnv=b305c2db5095c2ad | UNAUTHORIZED | Action: runner-manager auth login
        Repositories/rate-limited: lines=3 bytes=103 fnv=d96d37598270b0bb | RATE LIMITED | Action: a opens rate-limit details; retry is automatic
        Repositories/offline: lines=6 bytes=255 fnv=7aca69b8a1025157 | OFFLINE - no new runners will start | Action: a opens Activity & errors
        Runners/loading: lines=3 bytes=79 fnv=0773e12a4b1d7abf | LOADING | Action: F5 refresh now
        Runners/populated: lines=5 bytes=351 fnv=97b976f456568517 | Filter: <none> | Sort: NameAscending | Focus: Rows | Scroll: 0
        Runners/empty: lines=3 bytes=87 fnv=2b42f5859f786d03 | EMPTY | Action: F5 refresh or open Repositories
        Runners/unauthorized: lines=3 bytes=98 fnv=b305c2db5095c2ad | UNAUTHORIZED | Action: runner-manager auth login
        Runners/rate-limited: lines=3 bytes=103 fnv=d96d37598270b0bb | RATE LIMITED | Action: a opens rate-limit details; retry is automatic
        Runners/offline: lines=6 bytes=255 fnv=7aca69b8a1025157 | OFFLINE - no new runners will start | Action: a opens Activity & errors
        Activity/loading: lines=3 bytes=79 fnv=0773e12a4b1d7abf | LOADING | Action: F5 refresh now
        Activity/populated: lines=5 bytes=358 fnv=a63d2d99b5477752 | Diagnostics are redacted and copy-safe. Acknowledge: Enter | Copy: c
        Activity/empty: lines=3 bytes=76 fnv=fa5e63cedb79d4d2 | EMPTY | Action: F5 refresh
        Activity/unauthorized: lines=3 bytes=98 fnv=b305c2db5095c2ad | UNAUTHORIZED | Action: runner-manager auth login
        Activity/rate-limited: lines=3 bytes=103 fnv=d96d37598270b0bb | RATE LIMITED | Action: a opens rate-limit details; retry is automatic
        Activity/offline: lines=12 bytes=615 fnv=296c39c4d1433810 | OFFLINE - no new runners will start | Action: a opens Activity & errors
        "###);
    }

    #[test]
    fn aggregates_are_three_distinct_values_and_labels() {
        let rendered = render_text(&ScreenModel::new(populated()));
        for expected in [
            "In-progress workflows : 7",
            "Assigned jobs         : 4",
            "Busy runners          : 2",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected:?}:\n{rendered}"
            );
        }
    }

    #[test]
    fn colourless_render_distinguishes_ownership_and_monitor_only() {
        let mut model = ScreenModel::new(populated());
        model.screen = ReadOnlyScreen::Repositories;
        assert!(render_text(&model).contains("[monitor-only]"));
        model.screen = ReadOnlyScreen::Runners;
        let rendered = render_text(&model);
        assert!(rendered.contains("[local-owned]"));
        assert!(rendered.contains("[external-read-only]"));
        assert!(rendered.contains("persistent"));
    }

    #[test]
    fn idle_without_work_is_not_rendered_as_failure() {
        let mut model = ScreenModel::new(populated());
        model.screen = ReadOnlyScreen::Activity;
        let rendered = render_text(&model);
        assert!(rendered.contains("IDLE-EXIT (normal, no work accepted)"));
        assert!(rendered.contains("FAILED (action required)"));
    }

    #[test]
    fn offline_detail_is_one_action_from_every_screen_and_has_required_copy() {
        for screen in ReadOnlyScreen::ALL {
            let snapshot = Snapshot {
                availability: Availability::Offline {
                    last_successful_contact: "yesterday".into(),
                    retry_after_seconds: 20,
                },
                ..Snapshot::default()
            };
            let mut model = ScreenModel::new(snapshot);
            model.screen = screen;
            model.apply(ScreenAction::OpenStatus);
            assert_eq!(model.screen, ReadOnlyScreen::Activity);
            let rendered = render_text(&model);
            for required in [
                "Last successful GitHub contact: yesterday",
                "Retry in: 20s",
                "Local remediation:",
                QUEUE_CANCELLATION_WARNING,
            ] {
                assert!(rendered.contains(required));
            }
        }
    }

    #[test]
    fn keyboard_and_mouse_repository_detail_meet_action_budgets() {
        let mut keyboard = ScreenModel::new(populated());
        let keyboard_actions = [
            ScreenAction::Open(ReadOnlyScreen::Repositories),
            ScreenAction::Activate,
        ];
        for action in keyboard_actions.clone() {
            keyboard.apply(action);
        }
        assert!(keyboard_actions.len() <= 3);
        assert_eq!(keyboard.repository_detail.as_deref(), Some("alpha"));
        let mut mouse = ScreenModel::new(populated());
        let mouse_actions = [ScreenAction::OpenRepositoryByMouse("observe".into())];
        for action in mouse_actions.clone() {
            mouse.apply(action);
        }
        assert!(mouse_actions.len() <= 2);
        assert_eq!(mouse.repository_detail.as_deref(), Some("observe"));
    }

    #[test]
    fn one_filter_action_reaches_arbitrary_row_in_a_long_list() {
        let mut snapshot = populated();
        snapshot.repositories = (0..10_000)
            .map(|i| RepositoryRow {
                id: format!("repo-{i}"),
                target: format!("acme/repository-{i:05}"),
                in_progress_workflows: 0,
                mode: PolicyMode::MonitorOnly,
                max_capacity: None,
                health: AgentHealth::Healthy,
            })
            .collect();
        let mut model = ScreenModel::new(snapshot);
        model.screen = ReadOnlyScreen::Repositories;
        model.apply(ScreenAction::Filter("repository-07341".into()));
        assert_eq!(model.repositories.selected_id.as_deref(), Some("repo-7341"));
    }

    #[test]
    fn refresh_preserves_table_state_and_degrades_predictably() {
        let mut model = ScreenModel::new(populated());
        model.screen = ReadOnlyScreen::Repositories;
        model.apply(ScreenAction::SetFocus(TableFocus::Footer));
        model.apply(ScreenAction::SetSort(SortOrder::WorkloadDescending));
        model.apply(ScreenAction::MoveSelection(1));
        assert_eq!(model.repositories.selected_id.as_deref(), Some("observe"));
        assert_eq!(model.repositories.scroll, 1);
        model.apply(ScreenAction::Refresh(populated()));
        assert_eq!(model.repositories.selected_id.as_deref(), Some("observe"));
        assert_eq!(model.repositories.scroll, 1);
        assert_eq!(model.repositories.focus, TableFocus::Footer);
        assert_eq!(model.repositories.sort_order, SortOrder::WorkloadDescending);
        let mut removed = populated();
        removed.repositories.retain(|row| row.id != "observe");
        model.apply(ScreenAction::Refresh(removed));
        assert_eq!(model.repositories.selected_id.as_deref(), Some("alpha"));
        assert_eq!(model.repositories.scroll, 0);
        assert_eq!(model.repositories.focus, TableFocus::Footer);
        assert_eq!(model.repositories.sort_order, SortOrder::WorkloadDescending);
    }

    #[test]
    fn activity_diagnostics_are_copy_safe_and_contain_no_credential() {
        let secret = "ghu_this_must_not_escape";
        let mut snapshot = populated();
        snapshot.activity.push(ActivityRow {
            id: "redact".into(),
            occurred_at: "12:02:00Z".into(),
            outcome: ActivityOutcome::Retry,
            summary: format!("request token={secret} authorization:bearer"),
            remediation: "retry --jitconfig=encoded-secret".into(),
        });
        let mut model = ScreenModel::new(snapshot);
        model.screen = ReadOnlyScreen::Activity;
        let rendered = render_text(&model);
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("encoded-secret"));
        assert!(rendered.contains(runner_manager_platform::logging::REDACTION));
    }

    #[test]
    fn copy_safe_reuses_the_shape_aware_redactor_for_adversarial_diagnostics() {
        let jit =
            "eyJlbmNvZGVkX2ppdF9jb25maWciOiJ0aGlzLWlzLWEtbGl2ZS1zaG9ydC1saXZlZC1jcmVkZW50aWFsIn0=";
        let credentials = [
            "gho_1234567890abcdefghijklmnopqrstuvwxyz",
            "ghs_1234567890abcdefghijklmnopqrstuvwxyz",
            "ghr_1234567890abcdefghijklmnopqrstuvwxyz",
            "gh_1234567890abcdefghijklmnopqrstuvwxyz",
            "ghu_1234567890abcdefghijklmnopqrstuvwxyz",
            jit,
        ];
        let corpus = [
            format!("embedded credential={}", credentials[4]),
            format!(
                "https://x-access-token:{}@github.com/acme/repo",
                credentials[0]
            ),
            format!("https://github.com/api?token={}", credentials[1]),
            format!("retry body={{\"encoded_jit_config\":\"{jit}\"}}"),
            format!(
                "families {} {} {}",
                credentials[2], credentials[3], credentials[4]
            ),
        ];
        for diagnostic in corpus {
            let safe = copy_safe(&diagnostic);
            for credential in credentials {
                assert!(
                    !safe.contains(credential),
                    "credential survived {diagnostic:?} as {safe:?}"
                );
            }
            assert!(safe.contains(runner_manager_platform::logging::REDACTION));
        }
    }

    #[test]
    fn repository_detail_is_a_visible_rendered_path() {
        let mut model = ScreenModel::new(populated());
        model.apply(ScreenAction::Open(ReadOnlyScreen::Repositories));
        model.apply(ScreenAction::Activate);
        let rendered = render_text(&model);
        assert!(rendered.contains("REPOSITORY DETAIL"), "{rendered}");
        assert!(rendered.contains("Target: acme/alpha"), "{rendered}");
        assert!(rendered.contains("Policy: [autoscale]"), "{rendered}");
        assert!(!rendered.contains("acme/observe"), "{rendered}");
    }

    #[test]
    fn tables_render_only_the_selected_viewport_and_filters_distinguish_no_matches() {
        let mut snapshot = populated();
        snapshot.repositories = (0..20)
            .map(|index| RepositoryRow {
                id: format!("repo-{index:02}"),
                target: format!("acme/repository-{index:02}"),
                in_progress_workflows: index,
                mode: PolicyMode::Autoscale,
                max_capacity: Some(2),
                health: AgentHealth::Healthy,
            })
            .collect();
        let mut model = ScreenModel::new(snapshot);
        model.apply(ScreenAction::Open(ReadOnlyScreen::Repositories));
        model.apply(ScreenAction::MoveSelection(10));
        let rendered = render_text(&model);
        assert!(rendered.contains("> acme/repository-10"), "{rendered}");
        assert!(rendered.contains("acme/repository-17"), "{rendered}");
        assert!(!rendered.contains("acme/repository-09"), "{rendered}");
        assert!(!rendered.contains("acme/repository-18"), "{rendered}");

        model.apply(ScreenAction::Filter("does-not-exist".into()));
        let no_matches = render_text(&model);
        assert!(no_matches.starts_with("NO MATCHES\n"), "{no_matches}");
        assert!(no_matches.contains("Esc clears the filter"), "{no_matches}");
        assert!(
            !no_matches.contains("No authorized targets"),
            "{no_matches}"
        );
    }

    #[test]
    fn rendering_has_no_io_capability() {
        let _pure: fn(&ScreenModel) -> String = render_text;
        let source = include_str!("screens.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        for forbidden in ["std::fs", "std::net", "reqwest", ".await", "block_on"] {
            assert!(
                !production.contains(forbidden),
                "screen acquired {forbidden}"
            );
        }
    }
}
