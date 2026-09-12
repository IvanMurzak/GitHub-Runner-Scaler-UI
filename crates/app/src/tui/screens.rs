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
    widgets::{Block, Borders, Padding, Paragraph},
};
use unicode_width::UnicodeWidthStr;

use super::table::{self, Cell, Column, Grid, Row as GridRow, Skin, Tone, Trim};

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

/// Whether this host could accept and execute its next assigned job.
///
/// Kept apart from GitHub [`Availability`]: the API may be reachable while the
/// local service is stopped, its supervisor is missing, or a managed WSL host
/// is unusable. The header reports the worse of the two truths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalReadiness {
    Unknown,
    Ready,
    Degraded,
    Blocked,
}

impl OperationalReadiness {
    const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Ready => "READY",
            Self::Degraded => "DEGRADED",
            Self::Blocked => "BLOCKED",
        }
    }

    const fn tone(self) -> Tone {
        match self {
            Self::Unknown => Tone::Muted,
            Self::Ready => Tone::Ok,
            Self::Degraded => Tone::Warn,
            Self::Blocked => Tone::Bad,
        }
    }
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
    /// Monitor-only is not a failure, but it is the reason a queued job will
    /// never be picked up here, so it reads as a caution rather than as normal.
    const fn tone(self) -> Tone {
        match self {
            Self::Autoscale => Tone::Ok,
            Self::MonitorOnly => Tone::Warn,
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
    /// Spelled out for the inspection views. The table shows the same three
    /// words through [`Self::badge`], so the vocabulary has one definition and
    /// renaming a state cannot leave the two screens disagreeing.
    fn marker(self) -> String {
        self.badge(&Skin::ASCII).text().into_owned()
    }
    const fn tone(self) -> Tone {
        match self {
            Self::Healthy => Tone::Ok,
            Self::Degraded => Tone::Warn,
            Self::Offline => Tone::Bad,
        }
    }
    /// The word carries the meaning under either skin; only the leading glyph
    /// changes, and the ASCII one is the marker this screen has always shown.
    fn badge(self, skin: &Skin) -> Cell {
        let glyph = match self {
            Self::Healthy => skin.pick("\u{25cf}", "OK"),
            Self::Degraded => skin.pick("\u{25b2}", "!"),
            Self::Offline => skin.pick("\u{00d7}", "X"),
        };
        let word = match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Offline => "offline",
        };
        Cell::new(format!("{glyph} {word}"), self.tone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerOwnership {
    Local,
    ManagedRemote,
    External,
}
impl RunnerOwnership {
    const fn marker(self) -> &'static str {
        match self {
            Self::Local => "[local-owned]",
            Self::ManagedRemote => "[managed-other-host]",
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
    /// A surplus runner exiting without work is the design working, so it is
    /// toned as success; only `Failed` is allowed to look like a failure.
    const fn tone(self) -> Tone {
        match self {
            Self::Info => Tone::Plain,
            Self::Retry | Self::RateLimit => Tone::Warn,
            Self::CleanupComplete | Self::ExitedIdleWithoutWork => Tone::Ok,
            Self::Failed => Tone::Bad,
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
    /// The immovable host-identity label this policy answers.
    ///
    /// `None` for a monitor-only policy, which reserves no label until it is
    /// promoted -- the same distinction `PolicySettings` draws between a label
    /// set and "not reserved until promotion". Kept apart from
    /// [`Self::extra_labels`] rather than stored as one positional list,
    /// because the two differ in what the operator may do to them: the host
    /// label cannot be removed (`RoutingLabels::remove`), and a row that
    /// coloured them alike would invite an edit the domain refuses.
    pub host_label: Option<String>,
    /// The optional descriptive labels, sorted and without the host label,
    /// exactly as `RoutingLabels::additional` yields them.
    pub extra_labels: Vec<String>,
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
    /// GitHub omits this field from some runner-inventory responses. `None`
    /// must remain unknown instead of being presented as persistent.
    pub ephemeral: Option<bool>,
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

/// Windows-side WSL capability. Kept in the immutable snapshot so rendering
/// never launches `wsl.exe` and non-Windows builds can state the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WslCapability {
    NotSupported,
    NotInstalled(String),
    NoDistributions,
    Unavailable(String),
    Available,
}

/// One distribution's operator-facing lifecycle state. Recovery-only states
/// are part of the vocabulary now so the watchdog can publish them without a
/// later TUI schema change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "recovery supervisor publishes the transitional states"
)]
pub enum WslHostState {
    Unmanaged,
    Healthy,
    Degraded,
    Unreachable,
    Draining,
    Recovering,
    Backoff,
    RecoveryBlocked,
}

impl WslHostState {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Unmanaged => "unmanaged",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unreachable => "unreachable",
            Self::Draining => "draining",
            Self::Recovering => "recovering",
            Self::Backoff => "backoff",
            Self::RecoveryBlocked => "recovery blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WslHostRow {
    pub distribution: String,
    pub state: WslHostState,
    pub detail: String,
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
    pub readiness: OperationalReadiness,
    pub readiness_summary: String,
    pub wsl_capability: WslCapability,
    pub wsl_hosts: Vec<WslHostRow>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            availability: Availability::Loading,
            metrics: DashboardMetrics::default(),
            repositories: vec![],
            runners: vec![],
            activity: vec![],
            readiness: OperationalReadiness::Unknown,
            readiness_summary: "Host readiness has not been checked yet.".to_owned(),
            wsl_capability: if cfg!(windows) {
                WslCapability::NoDistributions
            } else {
                WslCapability::NotSupported
            },
            wsl_hosts: vec![],
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardTable {
    Repositories,
    Runners,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableViewState {
    pub focus: TableFocus,
    pub selected_id: Option<String>,
    pub sort_order: SortOrder,
    pub sort_column: usize,
    pub sort_descending: bool,
    pub scroll: usize,
    /// Data rows the full-screen table can currently draw. Selection uses it
    /// to move the viewport only when it reaches an edge.
    pub viewport_rows: usize,
    pub filter: String,
}
impl Default for TableViewState {
    fn default() -> Self {
        Self {
            focus: TableFocus::Rows,
            selected_id: None,
            sort_order: SortOrder::NameAscending,
            sort_column: 0,
            sort_descending: false,
            scroll: 0,
            viewport_rows: TABLE_VIEWPORT_ROWS,
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
    pub dashboard_repository_sort: (usize, bool),
    pub dashboard_runner_sort: (usize, bool),
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
    SortColumn(usize),
    SortDashboardColumn(DashboardTable, usize),
    SetFocus(TableFocus),
    SetViewportRows(usize),
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
            dashboard_repository_sort: (0, false),
            dashboard_runner_sort: (2, false),
            repository_detail: None,
            runner_detail: None,
            acknowledged_activity: HashSet::new(),
        };
        model.runners.sort_column = 2;
        model.activity.sort_column = 1;
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
                let screen = self.screen;
                if let Some(table) = self.current_table_mut() {
                    set_legacy_sort(table, screen, order);
                    self.reconcile_current(None);
                }
            }
            ScreenAction::SortColumn(column) => {
                let screen = self.screen;
                if let Some(table) = self.current_table_mut() {
                    if table.sort_column == column {
                        table.sort_descending = !table.sort_descending;
                    } else {
                        table.sort_column = column;
                        table.sort_descending = false;
                    }
                    table.sort_order =
                        legacy_sort(screen, table.sort_column, table.sort_descending);
                    self.reconcile_current(None);
                }
            }
            ScreenAction::SortDashboardColumn(table, column) => {
                let sort = match table {
                    DashboardTable::Repositories => &mut self.dashboard_repository_sort,
                    DashboardTable::Runners => &mut self.dashboard_runner_sort,
                };
                if sort.0 == column {
                    sort.1 = !sort.1;
                } else {
                    *sort = (column, false);
                }
            }
            ScreenAction::SetFocus(focus) => {
                if let Some(table) = self.current_table_mut() {
                    table.focus = focus
                }
            }
            ScreenAction::SetViewportRows(rows) => {
                let rows = rows.max(1);
                for table in [
                    &mut self.repositories,
                    &mut self.runners,
                    &mut self.activity,
                ] {
                    table.viewport_rows = rows;
                }
                self.reconcile_all(None);
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
        keep_selection_visible(table, next, ids.len());
    }

    /// The repositories a reader can currently see, in the order they appear.
    /// Callers that want identifiers derive them from this rather than the
    /// other way round, so no caller has to find a row it already had.
    fn visible_repositories(&self) -> Vec<&RepositoryRow> {
        let mut rows: Vec<_> = self
            .snapshot
            .repositories
            .iter()
            .filter(|row| contains_folded(&row.target, &self.repositories.filter))
            .collect();
        rows.sort_by(|a, b| {
            repository_cmp(
                a,
                b,
                self.repositories.sort_column,
                self.repositories.sort_descending,
            )
        });
        rows
    }

    fn visible_repository_ids(&self) -> Vec<String> {
        ids(self.visible_repositories().into_iter().map(|row| &row.id))
    }

    pub fn repository_id_at_viewport_offset(&self, offset: usize) -> Option<String> {
        self.visible_repository_ids()
            .get(self.repositories.scroll.saturating_add(offset))
            .cloned()
    }
    fn visible_runners(&self) -> Vec<&RunnerRow> {
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
        rows.sort_by(|a, b| {
            runner_cmp(a, b, self.runners.sort_column, self.runners.sort_descending)
        });
        rows
    }

    fn visible_runner_ids(&self) -> Vec<String> {
        ids(self.visible_runners().into_iter().map(|row| &row.id))
    }

    fn current_table(&self) -> Option<&TableViewState> {
        match self.screen {
            ReadOnlyScreen::Dashboard => None,
            ReadOnlyScreen::Repositories => Some(&self.repositories),
            ReadOnlyScreen::Runners => Some(&self.runners),
            ReadOnlyScreen::Activity => Some(&self.activity),
        }
    }

    /// Dashboard previews are not the interactive tables. They always start
    /// from the complete, default-ordered inventory and therefore cannot
    /// inherit a full-screen filter, sort, selection, or viewport offset.
    fn dashboard_repositories(&self) -> Vec<&RepositoryRow> {
        let mut rows: Vec<_> = self.snapshot.repositories.iter().collect();
        rows.sort_by(|a, b| {
            repository_cmp(
                a,
                b,
                self.dashboard_repository_sort.0,
                self.dashboard_repository_sort.1,
            )
        });
        rows
    }

    fn dashboard_runners(&self) -> Vec<&RunnerRow> {
        let mut rows: Vec<_> = self.snapshot.runners.iter().collect();
        rows.sort_by(|a, b| {
            runner_cmp(
                a,
                b,
                self.dashboard_runner_sort.0,
                self.dashboard_runner_sort.1,
            )
        });
        rows
    }

    fn visible_activity(&self) -> Vec<&ActivityRow> {
        let mut rows: Vec<_> = self
            .snapshot
            .activity
            .iter()
            .filter(|row| {
                contains_folded(&row.summary, &self.activity.filter)
                    || contains_folded(&row.remediation, &self.activity.filter)
            })
            .collect();
        rows.sort_by(|a, b| {
            directed(
                a.occurred_at.cmp(&b.occurred_at),
                self.activity.sort_descending,
            )
        });
        rows
    }

    fn visible_activity_ids(&self) -> Vec<String> {
        ids(self.visible_activity().into_iter().map(|row| &row.id))
    }
}

fn ids<'a>(rows: impl Iterator<Item = &'a String>) -> Vec<String> {
    rows.cloned().collect()
}

fn contains_folded(value: &str, query: &str) -> bool {
    query.is_empty() || value.to_lowercase().contains(&query.to_lowercase())
}
fn directed(order: Ordering, descending: bool) -> Ordering {
    if descending { order.reverse() } else { order }
}

fn repository_cmp(
    a: &RepositoryRow,
    b: &RepositoryRow,
    column: usize,
    descending: bool,
) -> Ordering {
    let order = match column {
        1 => a.in_progress_workflows.cmp(&b.in_progress_workflows),
        2 => a.mode.marker().cmp(b.mode.marker()),
        3 => a.max_capacity.cmp(&b.max_capacity),
        4 => a.health.marker().cmp(&b.health.marker()),
        5 => (&a.host_label, &a.extra_labels).cmp(&(&b.host_label, &b.extra_labels)),
        _ => a.target.cmp(&b.target),
    };
    directed(order, descending).then_with(|| a.target.cmp(&b.target))
}

fn runner_cmp(a: &RunnerRow, b: &RunnerRow, column: usize, descending: bool) -> Ordering {
    let state = |row: &RunnerRow| (!row.online, row.busy, row.ephemeral, row.ownership.marker());
    let order = match column {
        0 => a.owner.cmp(&b.owner),
        1 => state(a).cmp(&state(b)),
        3 => a.os.cmp(&b.os),
        4 => a.labels.cmp(&b.labels),
        _ => a.name.cmp(&b.name),
    };
    directed(order, descending).then_with(|| a.name.cmp(&b.name))
}

fn set_legacy_sort(table: &mut TableViewState, screen: ReadOnlyScreen, order: SortOrder) {
    let (column, descending) = match (screen, order) {
        (ReadOnlyScreen::Repositories, SortOrder::WorkloadDescending) => (1, true),
        (ReadOnlyScreen::Runners, SortOrder::NameAscending) => (2, false),
        (ReadOnlyScreen::Runners, SortOrder::NameDescending) => (2, true),
        (ReadOnlyScreen::Activity, SortOrder::NameAscending) => (1, false),
        (ReadOnlyScreen::Activity, _) => (1, true),
        (_, SortOrder::NameDescending) => (0, true),
        _ => (0, false),
    };
    table.sort_order = order;
    table.sort_column = column;
    table.sort_descending = descending;
}

fn legacy_sort(screen: ReadOnlyScreen, column: usize, descending: bool) -> SortOrder {
    if screen == ReadOnlyScreen::Repositories && column == 1 && descending {
        SortOrder::WorkloadDescending
    } else if descending {
        SortOrder::NameDescending
    } else {
        SortOrder::NameAscending
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
        let selected = ids
            .iter()
            .position(|id| Some(id) == table.selected_id.as_ref())
            .expect("the selected id was just found in this list");
        keep_selection_visible(table, selected, ids.len());
        return;
    }
    let old_last = old_len.unwrap_or(ids.len()).saturating_sub(1);
    let index = table.scroll.min(old_last).min(ids.len() - 1);
    table.selected_id = Some(ids[index].clone());
    keep_selection_visible(table, index, ids.len());
}

/// Keep a one-row look-ahead around selection where the viewport has room.
/// Short lists never scroll; long ones move only when selection reaches an
/// edge, rather than pinning the selected row to the top on every key press.
fn keep_selection_visible(table: &mut TableViewState, selected: usize, len: usize) {
    let viewport = table.viewport_rows.max(1);
    if len <= viewport {
        table.scroll = 0;
        return;
    }
    let max_scroll = len.saturating_sub(viewport);
    table.scroll = table.scroll.min(max_scroll);
    let margin = usize::from(viewport >= 3);
    let lower = table.scroll.saturating_add(margin);
    let upper = table
        .scroll
        .saturating_add(viewport.saturating_sub(1 + margin));
    if selected < lower {
        table.scroll = selected.saturating_sub(margin);
    } else if selected > upper {
        table.scroll = selected
            .saturating_add(margin)
            .saturating_add(1)
            .saturating_sub(viewport);
    }
    table.scroll = table.scroll.min(max_scroll);
}

/// Data-row capacity of a full-screen read-only list inside its content area.
pub fn list_viewport_rows(area_height: u16) -> usize {
    usize::from(area_height)
        .saturating_sub(2 + 1 + table::GRID_CHROME)
        .max(1)
}

/// One block of a screen. Prose is reflowed to the terminal it lands on; a
/// grid must not be, because reflowing it is precisely what destroys the
/// columns.
enum Section {
    Prose(Vec<Line<'static>>),
    /// One line that always occupies exactly one terminal row. The filter and
    /// sort status line is this: [`REPOSITORY_ROW_ORIGIN`] counts it as a
    /// single row, so a wrap here would slide every table row down and a click
    /// would open the repository below the one the reader aimed at.
    Status(Line<'static>),
    Grid(Grid),
}

/// A section that knows what it costs. Prose costs whatever the terminal's
/// width makes it cost, which is why it is reflowed before the grids are told
/// how many rows they may have.
enum Laid {
    Fixed(Vec<Line<'static>>),
    Grid(Grid),
}

/// The dashboard draws the first five of these and the Repositories screen
/// draws all six, so the order is load-bearing on two screens exactly as
/// [`RUNNER_COLUMNS`] is: a reader scans the repository, its workload, and
/// whether anything is wrong before they need the label set that routes it.
///
/// `Labels` is last and the most willing to give up width because it is the
/// one column whose value the operator can reconstruct elsewhere -- the
/// settings screen shows the same set in full, with the `runs-on:` line beside
/// it. Losing its tail on a narrow terminal costs less than losing `Agent`.
const REPOSITORY_COLUMNS: [Column; 6] = [
    Column::flexible("Repository", 14, 0),
    Column::rigid("Workflows", 2).right(),
    Column::rigid("Mode", 3),
    Column::rigid("Capacity", 1).right(),
    Column::rigid("Agent", 0),
    Column::flexible("Labels", 10, 1).trimming(Trim::Tail),
];

/// The repository leads, the state follows, and the runner name comes third:
/// a reader scans down the repository they care about, checks whether anything
/// is wrong, and only then needs the identity of the individual runner. The
/// dashboard draws the first three of these, so their order is load-bearing on
/// two screens.
const RUNNER_COLUMNS: [Column; 5] = [
    Column::flexible("Repository", 14, 0),
    // The badge is three facts wide, and on a narrow terminal it gives up the
    // last of them first -- ownership, then lifetime. The state itself, which
    // is the one every reader is scanning for, is inside the first nine
    // columns and therefore always survives.
    Column::flexible("Status", 9, 0)
        .trimming(Trim::Tail)
        .reluctant(),
    Column::flexible("Runner", 12, 0),
    Column::rigid("OS", 2),
    Column::flexible("Labels", 8, 1),
];

const ACTIVITY_COLUMNS: [Column; 5] = [
    // Acknowledgement never leaves: Enter acknowledges the selected row, and a
    // control whose state is off-screen is a control nobody can use.
    Column::rigid("Ack", 0),
    Column::rigid("When", 2),
    Column::rigid("Outcome", 0),
    Column::flexible("Summary", 18, 0).trimming(Trim::Tail),
    Column::flexible("Remediation", 14, 1).trimming(Trim::Tail),
];

/// Terminal row the first repository row lands on, which is what a click has
/// to be measured from. Every term is a layout fact somebody could change, so
/// each one is named and the grid's share is taken from the grid.
pub const REPOSITORY_ROW_ORIGIN: u16 = 3 // title bar, navigation, content border
    + 1 // the filter and sort status line, which never wraps
    + table::GRID_CHROME as u16
    - 1; // the grid's top border, header, and rule

/// Header row shared by the two full-screen inventory grids.
pub const INVENTORY_HEADER_ROW: u16 = REPOSITORY_ROW_ORIGIN - 2;

/// Map a terminal x coordinate to a sortable inventory column using the same
/// width solver that renders the header. Hidden narrow-screen columns cannot
/// accidentally be selected.
pub fn inventory_sort_column_at(
    model: &ScreenModel,
    skin: &Skin,
    terminal_width: u16,
    terminal_column: u16,
) -> Option<usize> {
    // The screen block spends one column on its border and one on horizontal
    // padding at either side.
    let grid_width = terminal_width.saturating_sub(4);
    let offset = terminal_column.saturating_sub(2);
    let rows = model
        .current_table()
        .map_or(TABLE_VIEWPORT_ROWS, |table| table.viewport_rows);
    let grid = match model.screen {
        ReadOnlyScreen::Repositories => repository_grid(
            model,
            skin,
            "",
            &model.visible_repositories(),
            rows,
            &REPOSITORY_COLUMNS,
            GridPresentation::interactive((
                model.repositories.sort_column,
                model.repositories.sort_descending,
            )),
        ),
        ReadOnlyScreen::Runners => runner_grid(
            model,
            skin,
            "",
            &model.visible_runners(),
            rows,
            &RUNNER_COLUMNS,
            GridPresentation::interactive((
                model.runners.sort_column,
                model.runners.sort_descending,
            )),
        ),
        ReadOnlyScreen::Dashboard | ReadOnlyScreen::Activity => return None,
    };
    grid.column_at(grid_width, offset)
}

/// Resolve either Dashboard grid header using the same measured sections and
/// row allotment as the renderer. This stays correct when the terminal height
/// or the number of repository preview rows changes the Runners header's y.
pub fn dashboard_sort_column_at(
    model: &ScreenModel,
    skin: &Skin,
    terminal_width: u16,
    terminal_height: u16,
    terminal_column: u16,
    terminal_row: u16,
) -> Option<(DashboardTable, usize)> {
    if model.screen != ReadOnlyScreen::Dashboard
        || model.snapshot.availability != Availability::Ready
    {
        return None;
    }
    let inner = Rect::new(
        2,
        3,
        terminal_width.saturating_sub(4),
        terminal_height.saturating_sub(5),
    );
    if terminal_column < inner.x || terminal_column >= inner.right() {
        return None;
    }
    let height = usize::from(inner.height);
    let mut laid: Vec<Laid> = sections(model, skin, height, inner.width)
        .into_iter()
        .map(|section| Laid::measured(section, inner.width))
        .collect();
    allot(&mut laid, height);
    let mut y = inner.y;
    let mut grid_index = 0usize;
    for section in laid {
        match section {
            Laid::Fixed(lines) => {
                y = y.saturating_add(u16::try_from(lines.len()).unwrap_or(u16::MAX));
            }
            Laid::Grid(grid) => {
                if terminal_row == y.saturating_add(1) {
                    let table = match grid_index {
                        0 => DashboardTable::Repositories,
                        1 => DashboardTable::Runners,
                        _ => return None,
                    };
                    let column =
                        grid.column_at(inner.width, terminal_column.saturating_sub(inner.x))?;
                    return Some((table, column));
                }
                y = y.saturating_add(
                    u16::try_from(grid.compose(skin, Some(inner.width)).len()).unwrap_or(u16::MAX),
                );
                grid_index += 1;
            }
        }
    }
    None
}

/// Draw into the content area owned by `shell.rs`.
pub fn render(frame: &mut Frame<'_>, area: Rect, model: &ScreenModel, skin: &Skin) {
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
    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", model.screen.title()),
            Style::default().add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .padding(Padding::horizontal(1))
        .border_set(skin.border())
        .border_style(border);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    // Layout before content: no grid can show more rows than the screen is
    // tall, so that is the most any of them is asked to build. The prose is
    // then measured at the real width -- a state panel above the table, or a
    // metric line the terminal forced to wrap, costs whatever it costs -- and
    // only what survives it is divided between the grids. One pass, and the
    // last row of a table always arrives with its closing border.
    let height = usize::from(inner.height);
    let mut laid: Vec<Laid> = sections(model, skin, height, inner.width)
        .into_iter()
        .map(|section| Laid::measured(section, inner.width))
        .collect();
    allot(&mut laid, height);
    let mut y = inner.y;
    for section in laid {
        let room = inner.bottom().saturating_sub(y);
        if room == 0 {
            return;
        }
        let lines = match section {
            Laid::Fixed(lines) => lines,
            Laid::Grid(grid) => grid.compose(skin, Some(inner.width)),
        };
        // Already laid out to this width, so nothing here may reflow again.
        let rows = u16::try_from(lines.len()).unwrap_or(u16::MAX).min(room);
        frame.render_widget(
            Paragraph::new(Text::from(lines)),
            Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: rows,
            },
        );
        y += rows;
    }
}

impl Laid {
    /// Prose is reflowed here, once, and what comes out is both the
    /// measurement and the thing drawn -- so the two can never disagree about
    /// what a line costs.
    fn measured(section: Section, width: u16) -> Self {
        match section {
            Section::Prose(lines) => Self::Fixed(
                lines
                    .into_iter()
                    .flat_map(|line| wrapped(line, width))
                    .collect(),
            ),
            Section::Status(line) => Self::Fixed(vec![line]),
            Section::Grid(grid) => Self::Grid(grid),
        }
    }
}

/// Break one prose line to the terminal's width, carrying each word's own span
/// style across the break -- collapsing the line to a single style would
/// silently un-tone every wrapped value, and a dashboard metric would keep its
/// muted label and lose the bold number the reader is here for. Runs of spaces
/// inside a line are not preserved; that only shows below the width at which
/// the shell has already switched to its compact layout.
fn wrapped(line: Line<'static>, width: u16) -> Vec<Line<'static>> {
    let width = usize::from(width);
    if width == 0 || line.width() <= width {
        return vec![line];
    }
    let mut pieces: Vec<Vec<Span<'static>>> = vec![Vec::new()];
    let mut used = 0;
    for span in line.spans {
        for word in span.content.split_whitespace() {
            let lead = usize::from(used > 0);
            if used > 0 && used + lead + word.width() > width {
                pieces.push(Vec::new());
                used = 0;
            }
            let text = if used > 0 {
                format!(" {word}")
            } else {
                word.to_owned()
            };
            used += text.width();
            pieces
                .last_mut()
                .expect("a piece is always open")
                .push(Span::styled(text, span.style));
        }
    }
    pieces.into_iter().map(Line::from).collect()
}

/// Divide the rows the prose left over between the grids on the screen. The
/// first grid is the one the reader came for, so it takes the larger share; a
/// table with fewer rows than its share hands the surplus to the next one.
fn allot(laid: &mut [Laid], height: usize) {
    let mut grids = laid
        .iter()
        .filter(|section| matches!(section, Laid::Grid(_)))
        .count();
    if grids == 0 {
        return;
    }
    let fixed: usize = laid
        .iter()
        .map(|section| match section {
            Laid::Fixed(lines) => lines.len(),
            Laid::Grid(_) => 0,
        })
        .sum();
    let mut rows = height.saturating_sub(fixed + grids * table::GRID_CHROME);
    for section in laid {
        let Laid::Grid(grid) = section else { continue };
        // A grid never drops below one row: a screen with no room at all still
        // shows what it has rather than an empty frame.
        grid.rows.truncate(rows.div_ceil(grids).max(1));
        rows = rows.saturating_sub(grid.rows.len());
        grids -= 1;
    }
}

/// Stable colour-independent rendering, also used by the snapshot harness and
/// by the clipboard. ASCII at natural width: no glyph a legacy console cannot
/// print, and no cell shortened away from somebody about to paste it. The row
/// window is the one on screen, so what is copied is what was read.
pub fn render_text(model: &ScreenModel) -> String {
    sections(model, &Skin::ASCII, TABLE_VIEWPORT_ROWS, 120)
        .iter()
        .map(|section| match section {
            Section::Prose(lines) => table::text_of(lines),
            Section::Status(line) => line.to_string(),
            Section::Grid(grid) => grid.to_text(&Skin::ASCII),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build a screen. `rows` is the most any one grid on it may draw.
fn sections(model: &ScreenModel, skin: &Skin, rows: usize, width: u16) -> Vec<Section> {
    let plain = |message: String| vec![(message, Tone::Plain)];
    let (tone, title, body, action) = match &model.snapshot.availability {
        Availability::Ready => return ready(model, skin, rows, width),
        Availability::Loading => {
            return vec![state_panel(
                skin,
                Tone::Busy,
                "LOADING",
                plain("Waiting for the first GitHub inventory snapshot.".to_owned()),
                "Action: F5 refresh now",
            )];
        }
        Availability::Unauthorized => (
            Tone::Bad,
            "UNAUTHORIZED",
            plain("GitHub authorization is missing or no longer valid.".to_owned()),
            "Action: runner-manager auth login",
        ),
        Availability::RateLimited {
            retry_after_seconds,
        } => (
            Tone::Warn,
            "RATE LIMITED",
            plain(format!(
                "GitHub asked this host to wait {retry_after_seconds}s."
            )),
            "Action: a opens rate-limit details; retry is automatic",
        ),
        Availability::Offline {
            last_successful_contact,
            retry_after_seconds,
        } => (
            Tone::Bad,
            "OFFLINE - no new runners will start",
            vec![
                (
                    format!("Last successful GitHub contact: {last_successful_contact}"),
                    Tone::Plain,
                ),
                (format!("Retry in: {retry_after_seconds}s"), Tone::Plain),
                (
                    "Local remediation: check this host's network, DNS, proxy, and system clock."
                        .to_owned(),
                    Tone::Muted,
                ),
                (QUEUE_CANCELLATION_WARNING.to_owned(), Tone::Warn),
            ],
            "Action: a opens Activity & errors",
        ),
        Availability::Forbidden { message } => (
            Tone::Bad,
            "FORBIDDEN",
            plain(format!(
                "GitHub is reachable but refused this target: {}",
                message
                    .as_deref()
                    .unwrap_or("required permission is missing")
            )),
            "Action: verify repository access and GitHub App/user permissions",
        ),
        Availability::Failed { detail } => (
            Tone::Bad,
            "REFRESH FAILED",
            plain(format!(
                "GitHub answered, but inventory could not be collected: {detail}"
            )),
            "Action: open Activity & errors and retry with F5",
        ),
        Availability::Cancelled => (
            Tone::Warn,
            "REFRESH CANCELLED",
            plain(
                "The previous inventory collection was superseded or the TUI is stopping."
                    .to_owned(),
            ),
            "Action: F5 starts one latest refresh",
        ),
    };
    with_activity_details(
        model,
        skin,
        rows,
        state_panel(skin, tone, title, body, action),
    )
}

fn with_activity_details(
    model: &ScreenModel,
    skin: &Skin,
    rows: usize,
    panel: Section,
) -> Vec<Section> {
    let mut screen = vec![panel];
    if model.screen == ReadOnlyScreen::Activity && !model.snapshot.activity.is_empty() {
        screen.push(Section::Prose(vec![Line::default()]));
        screen.extend(activity_sections(
            model,
            skin,
            &model.visible_activity(),
            rows,
        ));
    }
    screen
}

fn state_panel(
    skin: &Skin,
    tone: Tone,
    title: &str,
    body: Vec<(String, Tone)>,
    action: &str,
) -> Section {
    let mut lines = vec![Line::from(Span::styled(
        title.to_owned(),
        skin.style(tone).add_modifier(Modifier::BOLD),
    ))];
    lines.extend(
        body.into_iter()
            .map(|(text, tone)| Line::from(Span::styled(text, skin.style(tone)))),
    );
    lines.push(Line::from(Span::styled(
        action.to_owned(),
        skin.style(Tone::Accent),
    )));
    Section::Prose(lines)
}

/// Every screen's list is built exactly once here, and handed to the builder
/// that needs it -- deriving it is a filter, a sort and a clone of the whole
/// collection, and the suite keeps a ten-thousand repository case honest.
fn ready(model: &ScreenModel, skin: &Skin, rows: usize, width: u16) -> Vec<Section> {
    match model.screen {
        ReadOnlyScreen::Dashboard => {
            let mut sections = dashboard_sections(model, skin, rows, width);
            if model.snapshot.repositories.is_empty()
                && model.snapshot.runners.is_empty()
                && model.snapshot.metrics == DashboardMetrics::default()
            {
                sections.push(empty_panel(skin, model.screen));
                return sections;
            }
            sections
        }
        ReadOnlyScreen::Repositories => {
            if model.snapshot.repositories.is_empty() {
                return vec![empty_panel(skin, model.screen)];
            }
            let visible = model.visible_repositories();
            if visible.is_empty() {
                return vec![no_matches(skin)];
            }
            repository_sections(model, skin, &visible, rows)
        }
        ReadOnlyScreen::Runners => {
            if model.snapshot.runners.is_empty() {
                return vec![empty_panel(skin, model.screen)];
            }
            let visible = model.visible_runners();
            if visible.is_empty() {
                return vec![no_matches(skin)];
            }
            runner_sections(model, skin, &visible, rows)
        }
        ReadOnlyScreen::Activity => {
            if model.snapshot.activity.is_empty() {
                return vec![empty_panel(skin, model.screen)];
            }
            let visible = model.visible_activity();
            if visible.is_empty() {
                return vec![no_matches(skin)];
            }
            activity_sections(model, skin, &visible, rows)
        }
    }
}

/// Nothing is configured, which is not the same as nothing being busy.
fn empty_panel(skin: &Skin, screen: ReadOnlyScreen) -> Section {
    let (tone, message, action) = match screen {
        ReadOnlyScreen::Dashboard | ReadOnlyScreen::Repositories => (
            Tone::Warn,
            "No authorized targets are configured; workload is unknown, not zero.",
            "Action: runner-manager repo add OWNER/REPO",
        ),
        ReadOnlyScreen::Runners => (
            Tone::Warn,
            "No authorized GitHub runners are visible.",
            "Action: F5 refresh or open Repositories",
        ),
        ReadOnlyScreen::Activity => (
            Tone::Ok,
            "No lifecycle activity or errors have been recorded.",
            "Action: F5 refresh",
        ),
    };
    state_panel(
        skin,
        tone,
        "EMPTY",
        vec![(message.to_owned(), Tone::Plain)],
        action,
    )
}

fn no_matches(skin: &Skin) -> Section {
    state_panel(
        skin,
        Tone::Warn,
        "NO MATCHES",
        vec![(
            "Rows exist, but none match the current filter.".to_owned(),
            Tone::Plain,
        )],
        "Action: Esc clears the filter",
    )
}

const DASHBOARD_TWO_COLUMN_MIN_WIDTH: u16 = 104;

fn dashboard_sections(model: &ScreenModel, skin: &Skin, rows: usize, width: u16) -> Vec<Section> {
    let m = &model.snapshot.metrics;
    let metric = |label: &str, value: String, tone: Tone| {
        Line::from(vec![
            Span::styled(label.to_owned(), skin.style(Tone::Muted)),
            Span::styled(value, skin.style(tone).add_modifier(Modifier::BOLD)),
        ])
    };
    let mut head_lines = vec![
        Line::from(Span::styled(
            "GITHUB INVENTORY: LIVE".to_owned(),
            skin.style(Tone::Ok).add_modifier(Modifier::BOLD),
        )),
        metric(
            "In-progress workflows : ",
            m.in_progress_workflows.to_string(),
            workload_tone(m.in_progress_workflows),
        ),
        metric(
            "Assigned jobs         : ",
            m.assigned_jobs.to_string(),
            workload_tone(m.assigned_jobs),
        ),
        metric(
            "Busy runners          : ",
            m.busy_runners.to_string(),
            workload_tone(m.busy_runners),
        ),
        metric(
            "Online runners        : ",
            m.online_runners.to_string(),
            Tone::Ok,
        ),
        metric(
            "Host capacity         : ",
            format!("{}/{}", m.host_capacity_used, m.host_capacity_total),
            Tone::Accent,
        ),
    ];
    let capability = match &model.snapshot.wsl_capability {
        WslCapability::NotSupported => "not supported on this operating system".to_owned(),
        WslCapability::NotInstalled(detail) => format!("not installed: {detail}"),
        WslCapability::NoDistributions => "installed; no distributions".to_owned(),
        WslCapability::Unavailable(detail) => format!("unavailable: {detail}"),
        WslCapability::Available => format!("{} distribution(s)", model.snapshot.wsl_hosts.len()),
    };
    head_lines.push(metric(
        "WSL                    : ",
        capability,
        Tone::Accent,
    ));
    for host in &model.snapshot.wsl_hosts {
        let tone = match host.state {
            WslHostState::Healthy => Tone::Ok,
            WslHostState::Unmanaged => Tone::Muted,
            WslHostState::Draining | WslHostState::Recovering | WslHostState::Backoff => Tone::Busy,
            WslHostState::Degraded | WslHostState::Unreachable | WslHostState::RecoveryBlocked => {
                Tone::Bad
            }
        };
        head_lines.push(metric(
            &format!("  {:<20} : ", host.distribution),
            format!("{} - {}", host.state.label(), host.detail),
            tone,
        ));
    }
    let has_readiness_issues = model
        .snapshot
        .activity
        .iter()
        .any(|row| row.id.starts_with("readiness:"));
    let mut readiness_lines = vec![
        Line::from(Span::styled(
            format!("RUNNER READINESS: {}", model.snapshot.readiness.label()),
            skin.style(model.snapshot.readiness.tone())
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            model.snapshot.readiness_summary.clone(),
            skin.style(Tone::Plain),
        )),
    ];
    let problem_lines = readiness_problem_lines(model, skin);
    let mut overview = if width >= DASHBOARD_TWO_COLUMN_MIN_WIDTH {
        let mut left = readiness_lines;
        left.push(Line::default());
        left.extend(head_lines);
        vec![Section::Prose(side_by_side(
            left,
            problem_lines,
            width,
            skin,
        ))]
    } else if !has_readiness_issues && model.snapshot.readiness == OperationalReadiness::Ready {
        readiness_lines.push(Line::from(Span::styled(
            "[F5] Recheck now".to_owned(),
            skin.style(Tone::Accent),
        )));
        vec![
            Section::Prose(readiness_lines),
            Section::Prose(vec![Line::default()]),
            Section::Prose(head_lines),
        ]
    } else {
        vec![
            Section::Prose(readiness_lines),
            Section::Prose(vec![Line::default()]),
            Section::Prose(problem_lines),
            Section::Prose(vec![Line::default()]),
            Section::Prose(head_lines),
        ]
    };
    overview.push(Section::Prose(vec![Line::default()]));
    let repositories = model.dashboard_repositories();
    let runners = model.dashboard_runners();
    overview.extend([
        Section::Grid(repository_grid(
            model,
            skin,
            "Repositories",
            &repositories,
            rows,
            // The dashboard is a summary beside a second grid, so it stops at
            // `Agent`; the Repositories screen owns the whole width and draws
            // the label set as well.
            &REPOSITORY_COLUMNS[..5],
            GridPresentation::preview(model.dashboard_repository_sort),
        )),
        Section::Prose(vec![Line::default()]),
        Section::Grid(runner_grid(
            model,
            skin,
            "Runners",
            &runners,
            rows,
            &RUNNER_COLUMNS[..3],
            GridPresentation::preview(model.dashboard_runner_sort),
        )),
    ]);
    overview
}

fn readiness_problem_lines(model: &ScreenModel, skin: &Skin) -> Vec<Line<'static>> {
    let issues: Vec<_> = model
        .snapshot
        .activity
        .iter()
        .filter(|row| row.id.starts_with("readiness:"))
        .collect();
    if issues.is_empty() && model.snapshot.readiness == OperationalReadiness::Ready {
        return vec![
            Line::from(Span::styled(
                "Problems & fixes: none".to_owned(),
                skin.style(Tone::Ok).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "The service and managed hosts are ready for the next job.".to_owned(),
                skin.style(Tone::Plain),
            )),
            Line::from(Span::styled(
                "[F5] Recheck now".to_owned(),
                skin.style(Tone::Accent),
            )),
        ];
    }
    if issues.is_empty() {
        return vec![
            Line::from(Span::styled(
                "Problems & fixes: checking".to_owned(),
                skin.style(Tone::Warn).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "No actionable diagnosis is available yet.".to_owned(),
                skin.style(Tone::Plain),
            )),
            Line::from(Span::styled(
                "[a] Open diagnostics   [F5] Recheck".to_owned(),
                skin.style(Tone::Accent),
            )),
        ];
    }

    let mut lines = vec![Line::from(Span::styled(
        format!("Problems & fixes ({})", issues.len()),
        skin.style(model.snapshot.readiness.tone())
            .add_modifier(Modifier::BOLD),
    ))];
    for (index, row) in issues.into_iter().enumerate() {
        lines.push(Line::from(Span::styled(
            format!("{}. {}", index + 1, copy_safe(&row.summary)),
            skin.style(row.outcome.tone()),
        )));
        lines.push(Line::from(vec![
            Span::styled("   Fix: ".to_owned(), skin.style(Tone::Muted)),
            Span::styled(copy_safe(&row.remediation), skin.style(Tone::Accent)),
        ]));
    }
    lines.push(Line::from(Span::styled(
        "[c] Copy fixes   [a] Open details   [F5] Recheck".to_owned(),
        skin.style(Tone::Accent),
    )));
    lines
}

/// Compose the overview as real terminal columns, not a fixed-width mockup.
/// Each side wraps inside its own allocation before the rows are zipped, so a
/// resize can never let the remediation text overwrite the workload summary.
fn side_by_side(
    left: Vec<Line<'static>>,
    right: Vec<Line<'static>>,
    width: u16,
    skin: &Skin,
) -> Vec<Line<'static>> {
    const SEPARATOR_WIDTH: usize = 3;
    let total = usize::from(width);
    let left_width = (total * 43 / 100).clamp(42, 72);
    let right_width = total.saturating_sub(left_width + SEPARATOR_WIDTH).max(1);
    let left: Vec<_> = left
        .into_iter()
        .flat_map(|line| wrapped(line, left_width as u16))
        .collect();
    let right: Vec<_> = right
        .into_iter()
        .flat_map(|line| wrapped(line, right_width as u16))
        .collect();
    let rows = left.len().max(right.len());

    (0..rows)
        .map(|index| {
            let mut spans = left
                .get(index)
                .map(|line| line.spans.clone())
                .unwrap_or_default();
            let used = left.get(index).map_or(0, Line::width);
            spans.push(Span::raw(" ".repeat(left_width.saturating_sub(used))));
            spans.push(Span::styled(
                format!(" {} ", skin.pick("│", "|")),
                skin.style(Tone::Muted),
            ));
            if let Some(line) = right.get(index) {
                spans.extend(line.spans.clone());
            }
            Line::from(spans)
        })
        .collect()
}

/// Copy-safe, actionable text for the Dashboard's `c` shortcut.
pub fn readiness_remediation_text(model: &ScreenModel) -> Option<String> {
    let issues: Vec<_> = model
        .snapshot
        .activity
        .iter()
        .filter(|row| row.id.starts_with("readiness:"))
        .collect();
    (!issues.is_empty()).then(|| {
        issues
            .into_iter()
            .enumerate()
            .map(|(index, row)| {
                format!(
                    "{}. {}\nFix: {}",
                    index + 1,
                    copy_safe(&row.summary),
                    copy_safe(&row.remediation)
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    })
}

const fn workload_tone(value: u32) -> Tone {
    if value == 0 { Tone::Muted } else { Tone::Busy }
}

fn repository_sections(
    model: &ScreenModel,
    skin: &Skin,
    visible: &[&RepositoryRow],
    rows: usize,
) -> Vec<Section> {
    if let Some(detail_id) = model.repository_detail.as_deref()
        && let Some(row) = model
            .snapshot
            .repositories
            .iter()
            .find(|row| row.id == detail_id)
    {
        return vec![detail(
            skin,
            "REPOSITORY DETAIL",
            vec![
                ("Target: ", row.target.clone(), Tone::Accent),
                (
                    "In-progress workflows: ",
                    row.in_progress_workflows.to_string(),
                    workload_tone(row.in_progress_workflows),
                ),
                ("Policy: ", row.mode.marker().to_owned(), row.mode.tone()),
                (
                    "Max capacity: ",
                    row.max_capacity
                        .map_or_else(|| "n/a".into(), |capacity| capacity.to_string()),
                    Tone::Plain,
                ),
                ("Agent health: ", row.health.marker(), row.health.tone()),
                (
                    "Host label: ",
                    row.host_label
                        .clone()
                        .unwrap_or_else(|| "not reserved until promotion".into()),
                    if row.host_label.is_some() {
                        Tone::Ok
                    } else {
                        Tone::Muted
                    },
                ),
                (
                    "Extra labels: ",
                    if row.extra_labels.is_empty() {
                        "none".into()
                    } else {
                        row.extra_labels.join(", ")
                    },
                    if row.extra_labels.is_empty() {
                        Tone::Muted
                    } else {
                        Tone::Busy
                    },
                ),
            ],
            "Action: Esc returns to the repository list | s opens settings to edit labels",
        )];
    }
    vec![
        table_status(skin, &model.repositories),
        Section::Grid(repository_grid(
            model,
            skin,
            "",
            visible,
            rows,
            &REPOSITORY_COLUMNS,
            GridPresentation::interactive((
                model.repositories.sort_column,
                model.repositories.sort_descending,
            )),
        )),
    ]
}

fn runner_sections(
    model: &ScreenModel,
    skin: &Skin,
    visible: &[&RunnerRow],
    rows: usize,
) -> Vec<Section> {
    if let Some(detail_id) = model.runner_detail.as_deref()
        && let Some(row) = model
            .snapshot
            .runners
            .iter()
            .find(|row| row.id == detail_id)
    {
        return vec![detail(
            skin,
            "RUNNER INSPECTION",
            vec![
                ("Name: ", row.name.clone(), Tone::Plain),
                ("Owner: ", row.owner.clone(), Tone::Accent),
                (
                    "Ownership: ",
                    row.ownership.marker().to_owned(),
                    Tone::Muted,
                ),
                ("OS: ", row.os.clone(), Tone::Muted),
                ("Labels: ", row.labels.join(","), Tone::Muted),
                ("Online: ", row.online.to_string(), online_tone(row.online)),
                ("Busy: ", row.busy.to_string(), Tone::Plain),
                (
                    "Lifetime: ",
                    match row.ephemeral {
                        Some(true) => "ephemeral",
                        Some(false) => "persistent",
                        None => "unknown",
                    }
                    .to_owned(),
                    Tone::Plain,
                ),
            ],
            "Action: Esc returns to the runner list",
        )];
    }
    vec![
        table_status(skin, &model.runners),
        Section::Grid(runner_grid(
            model,
            skin,
            "",
            visible,
            rows,
            &RUNNER_COLUMNS,
            GridPresentation::interactive((
                model.runners.sort_column,
                model.runners.sort_descending,
            )),
        )),
    ]
}

const fn online_tone(online: bool) -> Tone {
    if online { Tone::Ok } else { Tone::Bad }
}

fn activity_sections(
    model: &ScreenModel,
    skin: &Skin,
    visible: &[&ActivityRow],
    rows: usize,
) -> Vec<Section> {
    let notice = Section::Status(Line::from(Span::styled(
        "Diagnostics are redacted and copy-safe. Acknowledge: Enter | Copy: c".to_owned(),
        skin.style(Tone::Muted),
    )));
    let body = window(visible, model.activity.scroll, rows)
        .iter()
        .map(|row| {
            let acknowledged = model.acknowledged_activity.contains(&row.id);
            GridRow {
                selected: model.activity.selected_id.as_deref() == Some(row.id.as_str()),
                cells: vec![
                    Cell::new(
                        if acknowledged {
                            "[acknowledged]"
                        } else {
                            "[new]"
                        },
                        if acknowledged {
                            Tone::Muted
                        } else {
                            Tone::Warn
                        },
                    ),
                    Cell::new(row.occurred_at.clone(), Tone::Muted),
                    Cell::new(row.outcome.marker(), row.outcome.tone()),
                    Cell::plain(copy_safe(&row.summary)),
                    Cell::new(copy_safe(&row.remediation), Tone::Muted),
                ],
            }
        })
        .collect();
    vec![
        notice,
        Section::Grid(Grid {
            caption: String::new(),
            columns: ACTIVITY_COLUMNS.to_vec(),
            rows: body,
            sorted: Some((1, model.activity.sort_order != SortOrder::NameAscending)),
        }),
    ]
}

fn detail(skin: &Skin, title: &str, fields: Vec<(&str, String, Tone)>, action: &str) -> Section {
    let mut lines = vec![Line::from(Span::styled(
        title.to_owned(),
        skin.style(Tone::Accent).add_modifier(Modifier::BOLD),
    ))];
    lines.extend(fields.into_iter().map(|(label, value, tone)| {
        Line::from(vec![
            Span::styled(label.to_owned(), skin.style(Tone::Muted)),
            Span::styled(value, skin.style(tone)),
        ])
    }));
    lines.push(Line::from(Span::styled(
        action.to_owned(),
        skin.style(Tone::Accent),
    )));
    Section::Prose(lines)
}

fn visible_filter(filter: &str) -> &str {
    if filter.is_empty() { "<none>" } else { filter }
}

fn table_status(skin: &Skin, state: &TableViewState) -> Section {
    Section::Status(Line::from(Span::styled(
        format!(
            "Filter: {} | Sort: {:?} | Focus: {:?} | Scroll: {}",
            visible_filter(&state.filter),
            state.sort_order,
            state.focus,
            state.scroll,
        ),
        skin.style(Tone::Muted),
    )))
}

/// The routing label set of one repository, host label first.
///
/// Two tones rather than one, and the separator between them muted, because
/// the two halves are not the same kind of fact: the host label is this
/// machine's routing identity and cannot be removed, while the rest are
/// descriptive labels the operator chose and may take back. The words are
/// identical under both skins and the host label is always first, so the
/// distinction survives `NO_COLOR` -- the colour repeats the order, it does not
/// replace it.
fn label_cell(row: &RepositoryRow) -> Cell {
    let Some(host) = &row.host_label else {
        // The same sentence the settings screen shows for a monitor-only
        // policy, which reserves no label until it is promoted.
        return Cell::new("not reserved", Tone::Muted);
    };
    let mut parts = vec![(host.clone(), Tone::Ok)];
    for extra in &row.extra_labels {
        parts.push((", ".to_owned(), Tone::Muted));
        parts.push((extra.clone(), Tone::Busy));
    }
    Cell::compound(parts)
}

#[derive(Debug, Clone, Copy)]
struct GridPresentation {
    selects_rows: bool,
    sorted: Option<(usize, bool)>,
}

impl GridPresentation {
    const fn interactive(sorted: (usize, bool)) -> Self {
        Self {
            selects_rows: true,
            sorted: Some(sorted),
        }
    }

    const fn preview(sorted: (usize, bool)) -> Self {
        Self {
            selects_rows: false,
            sorted: Some(sorted),
        }
    }
}

fn repository_grid(
    model: &ScreenModel,
    skin: &Skin,
    caption: &str,
    visible: &[&RepositoryRow],
    rows: usize,
    columns: &[Column],
    presentation: GridPresentation,
) -> Grid {
    let scroll = if presentation.selects_rows {
        model.repositories.scroll
    } else {
        0
    };
    let body = window(visible, scroll, rows)
        .iter()
        .map(|row| {
            let selected = presentation.selects_rows
                && model.repositories.selected_id.as_deref() == Some(row.id.as_str());
            GridRow {
                selected,
                cells: vec![
                    Cell::new(
                        format!("{}{}", skin.marker(selected), row.target),
                        Tone::Accent,
                    ),
                    Cell::new(
                        row.in_progress_workflows.to_string(),
                        workload_tone(row.in_progress_workflows),
                    ),
                    Cell::new(row.mode.marker(), row.mode.tone()),
                    row.max_capacity.map_or_else(
                        || Cell::new("n/a", Tone::Muted),
                        |capacity| Cell::plain(capacity.to_string()),
                    ),
                    row.health.badge(skin),
                    label_cell(row),
                ],
            }
        })
        .collect();
    Grid {
        caption: caption.to_owned(),
        columns: columns.to_vec(),
        rows: body,
        sorted: presentation.sorted,
    }
}

fn runner_grid(
    model: &ScreenModel,
    skin: &Skin,
    caption: &str,
    visible: &[&RunnerRow],
    rows: usize,
    columns: &[Column],
    presentation: GridPresentation,
) -> Grid {
    let scroll = if presentation.selects_rows {
        model.runners.scroll
    } else {
        0
    };
    let body = window(visible, scroll, rows)
        .iter()
        .map(|row| {
            let selected = presentation.selects_rows
                && model.runners.selected_id.as_deref() == Some(row.id.as_str());
            GridRow {
                selected,
                cells: vec![
                    Cell::new(
                        format!("{}{}", skin.marker(selected), row.owner),
                        Tone::Accent,
                    ),
                    runner_status(row, skin),
                    Cell::plain(row.name.clone()),
                    Cell::new(row.os.clone(), Tone::Muted),
                    Cell::new(row.labels.join(","), Tone::Muted),
                ],
            }
        })
        .collect();
    Grid {
        caption: caption.to_owned(),
        columns: columns.to_vec(),
        rows: body,
        sorted: presentation.sorted,
    }
}

/// State, lifetime, and ownership in one cell, each keeping its own tone. The
/// words are identical under both skins, so the badge never depends on either
/// a colour or a glyph to be understood.
fn runner_status(row: &RunnerRow, skin: &Skin) -> Cell {
    let (glyph, word, tone) = if row.online {
        if row.busy {
            (skin.pick("\u{25cf}", "*"), "busy", Tone::Busy)
        } else {
            (skin.pick("\u{25cf}", "*"), "idle", Tone::Ok)
        }
    } else {
        (skin.pick("\u{25cb}", "o"), "offline", Tone::Bad)
    };
    let (mark, lifetime) = match row.ephemeral {
        Some(true) => (skin.pick("\u{25c7}", ""), "ephemeral"),
        Some(false) => (skin.pick("\u{25c6}", ""), "persistent"),
        None => (skin.pick("?", "?"), "unknown"),
    };
    let ownership = match row.ownership {
        RunnerOwnership::Local => "local",
        RunnerOwnership::ManagedRemote => "managed-remote",
        RunnerOwnership::External => "external",
    };
    Cell::compound(vec![
        (format!("{glyph} {word:<7}"), tone),
        (format!("  {mark}{lifetime:<10}"), Tone::Muted),
        (format!("  {ownership}"), Tone::Muted),
    ])
}

/// The rows a grid may draw, starting where the table is scrolled to.
fn window<T>(rows: &[T], scroll: usize, budget: usize) -> &[T] {
    let start = scroll.min(rows.len().saturating_sub(1));
    let end = start.saturating_add(budget).min(rows.len());
    &rows[start..end]
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
                    host_label: Some("rm-home-win-x64".into()),
                    extra_labels: vec!["self-hosted".into()],
                },
                RepositoryRow {
                    id: "observe".into(),
                    target: "acme/observe".into(),
                    in_progress_workflows: 2,
                    mode: PolicyMode::MonitorOnly,
                    max_capacity: None,
                    health: AgentHealth::Degraded,
                    host_label: None,
                    extra_labels: vec![],
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
                    ephemeral: Some(true),
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
                    ephemeral: Some(false),
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
            readiness: OperationalReadiness::Ready,
            readiness_summary:
                "Local service and every managed WSL host are ready for the next job.".into(),
            wsl_capability: WslCapability::Available,
            wsl_hosts: vec![WslHostRow {
                distribution: "Ubuntu".into(),
                state: WslHostState::Healthy,
                detail: "daemon and lifecycle task are ready".into(),
            }],
        }
    }

    #[test]
    fn dashboard_leads_with_operational_readiness_and_activity_carries_the_fix() {
        let mut snapshot = populated();
        snapshot.readiness = OperationalReadiness::Blocked;
        snapshot.readiness_summary = "The next job may not start: service is stopped.".into();
        snapshot.activity.insert(
            0,
            ActivityRow {
                id: "readiness:local:service-stopped".into(),
                occurred_at: "12:02:00Z".into(),
                outcome: ActivityOutcome::Failed,
                summary: "Local service is registered but stopped.".into(),
                remediation: "Run `runner-manager service start`.".into(),
            },
        );
        let mut model = ScreenModel::new(snapshot);
        let dashboard = render_text(&model);
        assert!(
            dashboard.starts_with("RUNNER READINESS: BLOCKED"),
            "{dashboard}"
        );
        assert!(dashboard.contains("Problems & fixes (1)"), "{dashboard}");
        assert!(
            dashboard.contains("runner-manager service start"),
            "{dashboard}"
        );
        assert!(dashboard.contains("[c] Copy fixes"), "{dashboard}");
        assert!(!dashboard.contains("HEALTH: OK"), "{dashboard}");

        model.apply(ScreenAction::Open(ReadOnlyScreen::Activity));
        let activity = render_text(&model);
        assert!(
            activity.contains("Local service is registered but stopped."),
            "{activity}"
        );
        assert!(
            activity.contains("runner-manager service start"),
            "{activity}"
        );
    }

    #[test]
    fn dashboard_uses_the_second_column_when_wide_and_stacks_fixes_when_narrow() {
        let mut snapshot = populated();
        snapshot.readiness = OperationalReadiness::Blocked;
        snapshot.readiness_summary =
            "The next job may not start: two conditions need attention.".into();
        snapshot.activity.splice(
            0..0,
            [
                ActivityRow {
                    id: "readiness:local:service-stopped".into(),
                    occurred_at: "12:02:00Z".into(),
                    outcome: ActivityOutcome::Failed,
                    summary: "Local service is registered but stopped.".into(),
                    remediation: "Run `runner-manager service start`.".into(),
                },
                ActivityRow {
                    id: "readiness:local:login-only".into(),
                    occurred_at: "12:02:00Z".into(),
                    outcome: ActivityOutcome::Retry,
                    summary: "The service starts only after sign in.".into(),
                    remediation: "Run `runner-manager service install --start-at boot`.".into(),
                },
            ],
        );
        let model = ScreenModel::new(snapshot);

        let wide = drawn(180, 32, &model);
        let wide_status = wide
            .lines()
            .find(|line| line.contains("RUNNER READINESS"))
            .expect("wide readiness row");
        assert!(wide_status.contains("Problems & fixes (2)"), "{wide}");
        assert!(wide.contains("runner-manager service start"), "{wide}");

        let narrow = drawn(80, 36, &model);
        let readiness_row = narrow.find("RUNNER READINESS").expect("narrow readiness");
        let problems_row = narrow.find("Problems & fixes (2)").expect("narrow fixes");
        assert!(problems_row > readiness_row, "{narrow}");
        assert!(
            !narrow
                .lines()
                .find(|line| line.contains("RUNNER READINESS"))
                .expect("narrow readiness row")
                .contains("Problems & fixes"),
            "{narrow}"
        );
        assert!(narrow.contains("runner-manager service start"), "{narrow}");
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
                        // The Dashboard now renders this field. Keep the golden
                        // fixture identical on Windows, Linux, and macOS rather
                        // than inheriting the host-specific production default.
                        wsl_capability: WslCapability::NotSupported,
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
        insta::assert_snapshot!(matrix_snapshot(), @"
        Dashboard/loading: lines=3 bytes=79 fnv=0773e12a4b1d7abf | LOADING | Action: F5 refresh now
        Dashboard/populated: lines=27 bytes=1657 fnv=df4952d47044b735 | RUNNER READINESS: READY                             | Problems & fixes: none
        Dashboard/empty: lines=23 bytes=1131 fnv=d745b466823d023c | RUNNER READINESS: UNKNOWN                           | Problems & fixes: checking | Action: runner-manager repo add OWNER/REPO
        Dashboard/unauthorized: lines=3 bytes=98 fnv=b305c2db5095c2ad | UNAUTHORIZED | Action: runner-manager auth login
        Dashboard/rate-limited: lines=3 bytes=103 fnv=d96d37598270b0bb | RATE LIMITED | Action: a opens rate-limit details; retry is automatic
        Dashboard/offline: lines=6 bytes=255 fnv=7aca69b8a1025157 | OFFLINE - no new runners will start | Action: a opens Activity & errors
        Repositories/loading: lines=3 bytes=79 fnv=0773e12a4b1d7abf | LOADING | Action: F5 refresh now
        Repositories/populated: lines=7 bytes=680 fnv=62f7540f925a9ab8 | Filter: <none> | Sort: NameAscending | Focus: Rows | Scroll: 0
        Repositories/empty: lines=3 bytes=117 fnv=46b29f02007e5280 | EMPTY | Action: runner-manager repo add OWNER/REPO
        Repositories/unauthorized: lines=3 bytes=98 fnv=b305c2db5095c2ad | UNAUTHORIZED | Action: runner-manager auth login
        Repositories/rate-limited: lines=3 bytes=103 fnv=d96d37598270b0bb | RATE LIMITED | Action: a opens rate-limit details; retry is automatic
        Repositories/offline: lines=6 bytes=255 fnv=7aca69b8a1025157 | OFFLINE - no new runners will start | Action: a opens Activity & errors
        Runners/loading: lines=3 bytes=79 fnv=0773e12a4b1d7abf | LOADING | Action: F5 refresh now
        Runners/populated: lines=7 bytes=716 fnv=5868bb636fe4722f | Filter: <none> | Sort: NameAscending | Focus: Rows | Scroll: 0
        Runners/empty: lines=3 bytes=87 fnv=2b42f5859f786d03 | EMPTY | Action: F5 refresh or open Repositories
        Runners/unauthorized: lines=3 bytes=98 fnv=b305c2db5095c2ad | UNAUTHORIZED | Action: runner-manager auth login
        Runners/rate-limited: lines=3 bytes=103 fnv=d96d37598270b0bb | RATE LIMITED | Action: a opens rate-limit details; retry is automatic
        Runners/offline: lines=6 bytes=255 fnv=7aca69b8a1025157 | OFFLINE - no new runners will start | Action: a opens Activity & errors
        Activity/loading: lines=3 bytes=79 fnv=0773e12a4b1d7abf | LOADING | Action: F5 refresh now
        Activity/populated: lines=7 bytes=860 fnv=7089d5ba5d29b844 | Diagnostics are redacted and copy-safe. Acknowledge: Enter | Copy: c
        Activity/empty: lines=3 bytes=76 fnv=fa5e63cedb79d4d2 | EMPTY | Action: F5 refresh
        Activity/unauthorized: lines=3 bytes=98 fnv=b305c2db5095c2ad | UNAUTHORIZED | Action: runner-manager auth login
        Activity/rate-limited: lines=3 bytes=103 fnv=d96d37598270b0bb | RATE LIMITED | Action: a opens rate-limit details; retry is automatic
        Activity/offline: lines=14 bytes=1117 fnv=9ec94493ae3b9622 | OFFLINE - no new runners will start | Action: a opens Activity & errors
        ");
    }

    /// One frame, exactly as the terminal receives it.
    fn drawn(width: u16, height: u16, model: &ScreenModel) -> String {
        skinned(width, height, model, &Skin::RICH)
    }

    fn skinned(width: u16, height: u16, model: &ScreenModel, skin: &Skin) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), model, skin))
            .unwrap();
        super::super::buffer_text(terminal.backend().buffer())
    }

    #[test]
    fn every_row_of_a_drawn_table_puts_its_columns_in_the_same_place() {
        // --------------------------------------------------------------------
        // THE BUG THIS MODULE HAD.
        // --------------------------------------------------------------------
        // Rows were `cells.join(" | ")`. Which terminal column a value landed
        // in therefore depended on how long the values to its left happened to
        // be, so a single long repository name shifted every later column of
        // that one row and the reader had to re-find the grid on every line.
        // The property is not "it looks nicer": it is that the boundaries the
        // header rule declares hold for every row beneath it, at every width.
        let mut snapshot = populated();
        snapshot.runners[0].name = "rm-home-win-x64-0f1e2d3c4b5a69788796a5b4c3d2e1f0".into();
        snapshot.repositories[0].target = "acme/a-repository-with-a-very-long-name".into();
        for width in [48_u16, 64, 80, 110, 160] {
            for screen in ReadOnlyScreen::ALL {
                let mut model = ScreenModel::new(snapshot.clone());
                model.screen = screen;
                let frame = drawn(width, 30, &model);
                let lines: Vec<Vec<char>> =
                    frame.lines().map(|line| line.chars().collect()).collect();
                for (index, line) in lines.iter().enumerate() {
                    let boundaries: Vec<usize> = line
                        .iter()
                        .enumerate()
                        .filter(|(_, glyph)| **glyph == '\u{253c}')
                        .map(|(column, _)| column)
                        .collect();
                    if boundaries.is_empty() {
                        continue;
                    }
                    for row in lines.iter().skip(index + 1) {
                        if row.contains(&'\u{2534}') {
                            break;
                        }
                        for &column in &boundaries {
                            assert_eq!(
                                row.get(column),
                                Some(&'\u{2502}'),
                                "{screen:?} at width {width} lost column {column}:\n{frame}"
                            );
                        }
                    }
                    for &column in &boundaries {
                        assert_eq!(
                            lines[index - 1].get(column),
                            Some(&'\u{2502}'),
                            "{screen:?} at width {width}: header off grid:\n{frame}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_state_panel_never_pushes_the_table_off_the_bottom_of_the_screen() {
        // The panel above an offline activity table is prose the grid's row
        // budget never spent, so the grid was drawn taller than the room left
        // and its last rows -- closing border and all -- fell off the screen,
        // with nothing left to say the table had been cut.
        let mut snapshot = populated();
        let template = snapshot.activity[0].clone();
        for ordinal in 0..10 {
            let mut row = template.clone();
            row.id = format!("filler-{ordinal}");
            snapshot.activity.push(row);
        }
        snapshot.availability = Availability::Offline {
            last_successful_contact: "2026-08-27T10:00:00Z".into(),
            retry_after_seconds: 30,
        };
        let mut model = ScreenModel::new(snapshot);
        model.screen = ReadOnlyScreen::Activity;
        for height in [18_u16, 20, 24, 30] {
            let frame = drawn(100, height, &model);
            assert!(
                frame.contains('\u{2534}'),
                "the table lost its closing border at height {height}:\n{frame}"
            );
        }
    }

    #[test]
    fn the_first_repository_row_lands_where_a_click_is_measured_from() {
        // `shell.rs` turns a click into a row index by subtracting
        // `REPOSITORY_ROW_ORIGIN`. If the status line above the table ever
        // takes two rows, every row slides down and a click opens the
        // repository below the one the reader aimed at.
        let mut model = ScreenModel::new(populated());
        model.screen = ReadOnlyScreen::Repositories;
        // The drawn frame here is the content area alone; the real origin also
        // counts the title bar and the navigation row above it.
        let offset = usize::from(REPOSITORY_ROW_ORIGIN) - 2;
        for width in [30_u16, 40, 56, 80, 120] {
            let frame = drawn(width, 20, &model);
            let row = frame.lines().nth(offset).expect("a first table row");
            assert!(
                row.contains('\u{25b8}'),
                "width {width}: the selected first row is not at the click origin:\n{frame}"
            );
        }
    }

    #[test]
    fn the_ascii_skin_draws_a_frame_a_legacy_console_can_print() {
        // The README promises that `TERM=dumb` and `RUNNER_MANAGER_TUI_ASCII`
        // remove the glyphs. The grid honoured that from the start; the block
        // around it did not, because Ratatui's `BorderType::Plain` is still
        // box drawing. Both now take their glyphs from the same skin.
        for screen in ReadOnlyScreen::ALL {
            let mut model = ScreenModel::new(populated());
            model.screen = screen;
            let frame = skinned(100, 24, &model, &Skin::ASCII);
            assert!(frame.is_ascii(), "{screen:?} kept a glyph:\n{frame}");
        }
    }

    #[test]
    fn the_runner_table_leads_with_the_repository_and_shortens_only_the_name() {
        // A just-in-time runner name is `<routing label>-<unique suffix>`, and
        // it is the widest thing on the screen. It is also the least useful
        // thing to lead with: a reader finds the repository first, asks whether
        // anything is wrong, and only then cares which runner it was.
        let mut snapshot = populated();
        snapshot.runners[0].name = "rm-home-win-x64-0f1e2d3c4b5a69788796a5b4c3d2e1f0".into();
        let mut model = ScreenModel::new(snapshot);
        model.screen = ReadOnlyScreen::Runners;

        let text = render_text(&model);
        let header = text
            .lines()
            .find(|line| line.contains("Repository"))
            .expect("a header row");
        let repository = header.find("Repository").expect("Repository column");
        let status = header.find("Status").expect("Status column");
        let runner = header.find("Runner").expect("Runner column");
        assert!(repository < status && status < runner, "{header}");

        // Natural width keeps the whole name; a real terminal takes its middle
        // and leaves both ends, because both ends are what tell two runners on
        // one host apart.
        assert!(text.contains("rm-home-win-x64-0f1e2d3c4b5a69788796a5b4c3d2e1f0"));
        let frame = drawn(110, 24, &model);
        assert!(!frame.contains("rm-home-win-x64-0f1e2d3c4b5a69788796a5b4c3d2e1f0"));
        assert!(frame.contains("rm-home-win"), "head is gone:\n{frame}");
        assert!(frame.contains("c3d2e1f0"), "tail is gone:\n{frame}");
        assert!(frame.contains('\u{2026}'), "no ellipsis:\n{frame}");
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
        // Every distinction the colours draw is also drawn by a word, because
        // `render_text` is the render a colour-blind reader, a `NO_COLOR`
        // terminal, and the clipboard all get.
        let mut model = ScreenModel::new(populated());
        model.screen = ReadOnlyScreen::Repositories;
        assert!(render_text(&model).contains("[monitor-only]"));
        model.screen = ReadOnlyScreen::Runners;
        let rendered = render_text(&model);
        for distinction in ["ephemeral", "persistent", "local", "external"] {
            assert!(rendered.contains(distinction), "{distinction}:\n{rendered}");
        }
        // The list abbreviates ownership; the inspection view spells it out.
        model.runner_detail = Some("legacy".into());
        assert!(
            render_text(&model).contains("[external-read-only]"),
            "{rendered}"
        );
        model.runner_detail = Some("local".into());
        assert!(render_text(&model).contains("[local-owned]"), "{rendered}");
    }

    #[test]
    fn an_omitted_github_lifetime_is_unknown_not_persistent() {
        let mut row = populated().runners.remove(0);
        row.id = "managed-remote".into();
        row.name = "runner-manager-1522f949-7875-4752-8cf9-7854dca2a0c2".into();
        row.ephemeral = None;
        row.ownership = RunnerOwnership::ManagedRemote;
        let mut model = ScreenModel::new(Snapshot {
            availability: Availability::Ready,
            runners: vec![row],
            ..Snapshot::default()
        });
        model.screen = ReadOnlyScreen::Runners;

        let list = render_text(&model);
        assert!(list.contains("unknown"), "{list}");
        assert!(list.contains("managed-remote"), "{list}");
        assert!(!list.contains("persistent"), "{list}");

        model.runner_detail = Some("managed-remote".into());
        let detail = render_text(&model);
        assert!(detail.contains("Lifetime: unknown"), "{detail}");
        assert!(detail.contains("[managed-other-host]"), "{detail}");
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
                host_label: None,
                extra_labels: vec![],
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
        assert_eq!(model.repositories.scroll, 0);
        model.apply(ScreenAction::Refresh(populated()));
        assert_eq!(model.repositories.selected_id.as_deref(), Some("observe"));
        assert_eq!(model.repositories.scroll, 0);
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
    fn selection_scrolls_only_at_the_viewport_margin_and_never_for_a_short_list() {
        let mut short = populated();
        short.repositories.extend((2..4).map(|index| RepositoryRow {
            id: format!("short-{index}"),
            target: format!("acme/short-{index}"),
            in_progress_workflows: 0,
            mode: PolicyMode::MonitorOnly,
            max_capacity: None,
            health: AgentHealth::Healthy,
            host_label: None,
            extra_labels: vec![],
        }));
        let mut model = ScreenModel::new(short);
        model.apply(ScreenAction::Open(ReadOnlyScreen::Repositories));
        for _ in 0..3 {
            model.apply(ScreenAction::MoveSelection(1));
        }
        assert_eq!(model.repositories.scroll, 0);

        model
            .snapshot
            .repositories
            .extend((4..10).map(|index| RepositoryRow {
                id: format!("long-{index}"),
                target: format!("acme/long-{index}"),
                in_progress_workflows: 0,
                mode: PolicyMode::MonitorOnly,
                max_capacity: None,
                health: AgentHealth::Healthy,
                host_label: None,
                extra_labels: vec![],
            }));
        model.apply(ScreenAction::SetViewportRows(4));
        model.repositories.selected_id = model.visible_repository_ids().first().cloned();
        model.repositories.scroll = 0;
        model.apply(ScreenAction::MoveSelection(1));
        model.apply(ScreenAction::MoveSelection(1));
        assert_eq!(model.repositories.scroll, 0);
        model.apply(ScreenAction::MoveSelection(1));
        assert_eq!(model.repositories.scroll, 1);
    }

    #[test]
    fn dashboard_previews_ignore_interactive_table_state() {
        let mut model = ScreenModel::new(populated());
        model.apply(ScreenAction::Open(ReadOnlyScreen::Repositories));
        model.apply(ScreenAction::Filter("observe".into()));
        model.repositories.scroll = 7;
        model.apply(ScreenAction::Open(ReadOnlyScreen::Runners));
        model.apply(ScreenAction::Filter("external".into()));
        model.runners.scroll = 9;
        model.apply(ScreenAction::Open(ReadOnlyScreen::Dashboard));

        let dashboard = render_text(&model);
        assert!(dashboard.contains("acme/alpha"), "{dashboard}");
        assert!(dashboard.contains("acme/observe"), "{dashboard}");
        assert!(dashboard.contains("rm-home-1"), "{dashboard}");
        assert!(dashboard.contains("legacy-office"), "{dashboard}");
        assert!(
            !dashboard.lines().any(|line| line.contains("| > ")),
            "{dashboard}"
        );
    }

    #[test]
    fn inventory_columns_sort_ascending_then_toggle_descending() {
        let mut model = ScreenModel::new(populated());
        model.apply(ScreenAction::Open(ReadOnlyScreen::Repositories));
        model.apply(ScreenAction::SortColumn(1));
        assert_eq!(model.repositories.sort_column, 1);
        assert!(!model.repositories.sort_descending);
        assert_eq!(model.visible_repository_ids(), vec!["observe", "alpha"]);
        model.apply(ScreenAction::SortColumn(1));
        assert!(model.repositories.sort_descending);
        assert_eq!(model.visible_repository_ids(), vec!["alpha", "observe"]);

        model.apply(ScreenAction::Open(ReadOnlyScreen::Runners));
        model.apply(ScreenAction::SortColumn(0));
        assert_eq!(model.visible_runner_ids(), vec!["local", "legacy"]);
        model.apply(ScreenAction::SortColumn(0));
        assert_eq!(model.visible_runner_ids(), vec!["legacy", "local"]);
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
                host_label: Some(format!("rm-home-{index:02}-win-x64")),
                extra_labels: vec![],
            })
            .collect();
        let mut model = ScreenModel::new(snapshot);
        model.apply(ScreenAction::Open(ReadOnlyScreen::Repositories));
        model.apply(ScreenAction::MoveSelection(10));
        let rendered = render_text(&model);
        assert!(rendered.contains("> acme/repository-10"), "{rendered}");
        assert!(rendered.contains("acme/repository-04"), "{rendered}");
        assert!(rendered.contains("acme/repository-11"), "{rendered}");
        assert!(!rendered.contains("acme/repository-03"), "{rendered}");
        assert!(!rendered.contains("acme/repository-12"), "{rendered}");

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
