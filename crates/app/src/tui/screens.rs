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
    widgets::{Block, BorderType, Borders, Padding, Paragraph},
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
    const fn marker(self) -> &'static str {
        match self {
            Self::Healthy => "OK healthy",
            Self::Degraded => "! degraded",
            Self::Offline => "X offline",
        }
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

/// One block of a screen. Prose may be re-wrapped to the terminal; a grid
/// must not be, because re-wrapping it is precisely what destroys the columns.
enum Section {
    Prose(Vec<Line<'static>>),
    Grid(Grid),
}

/// How many body rows each grid on a screen may draw. The dashboard is the
/// only screen with two, and `secondary` is the runner grid beneath.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Budget {
    primary: usize,
    secondary: usize,
}

const REPOSITORY_COLUMNS: [Column; 5] = [
    Column::flexible("Repository", 14, 0),
    Column::rigid("Workflows", 2).right(),
    Column::rigid("Mode", 3),
    Column::rigid("Capacity", 1).right(),
    Column::rigid("Agent", 0),
];

/// The repository leads, the state follows, and the runner name comes third:
/// a reader scans down the repository they care about, checks whether anything
/// is wrong, and only then needs the identity of the individual runner.
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

/// Metric lines plus the blank that separates them from the first grid.
const DASHBOARD_HEADER_LINES: usize = 7;

/// Terminal row the first repository row lands on, which is what a click has
/// to be measured from. It moved when the grid grew a frame of its own, so it
/// is derived here rather than left as a literal in the mouse reducer.
pub const REPOSITORY_ROW_ORIGIN: u16 = 3 // title bar, navigation, content border
    + 1 // the filter and sort status line
    + 3; // the grid's own top border, header, and header rule

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
        .border_type(if skin.unicode {
            BorderType::Rounded
        } else {
            BorderType::Plain
        })
        .border_style(border);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let mut lines = Vec::new();
    for section in sections(model, skin, viewport(model, inner.height)) {
        match section {
            Section::Prose(prose) => lines.extend(
                prose
                    .into_iter()
                    .flat_map(|line| wrapped(line, inner.width)),
            ),
            Section::Grid(grid) => lines.extend(grid.compose(skin, Some(inner.width))),
        }
    }
    frame.render_widget(Paragraph::new(Text::from(lines)), inner);
}

/// Rows each grid may spend, given the height the shell actually granted. The
/// grid frames and the dashboard's metric block are fixed costs; whatever
/// survives them is split between the grids on the screen.
fn viewport(model: &ScreenModel, height: u16) -> Budget {
    let height = usize::from(height);
    match model.screen {
        ReadOnlyScreen::Dashboard => {
            let rows = height
                .saturating_sub(DASHBOARD_HEADER_LINES + 1 + 2 * table::GRID_CHROME)
                .min(2 * TABLE_VIEWPORT_ROWS);
            let primary = rows.div_ceil(2).max(1);
            Budget {
                primary,
                secondary: rows.saturating_sub(primary).max(1),
            }
        }
        _ => Budget {
            primary: height.saturating_sub(1 + table::GRID_CHROME).max(1),
            secondary: 0,
        },
    }
}

/// Stable colour-independent rendering, also used by the snapshot harness and
/// by the clipboard. ASCII at natural width: no glyph a legacy console cannot
/// print, and no diagnostic shortened away from somebody about to paste it.
pub fn render_text(model: &ScreenModel) -> String {
    let budget = Budget {
        primary: TABLE_VIEWPORT_ROWS,
        secondary: TABLE_VIEWPORT_ROWS,
    };
    sections(model, &Skin::ASCII, budget)
        .iter()
        .map(|section| match section {
            Section::Prose(lines) => lines.iter().map(flatten).collect::<Vec<_>>().join("\n"),
            Section::Grid(grid) => grid.to_text(&Skin::ASCII),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn flatten(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}

fn sections(model: &ScreenModel, skin: &Skin, budget: Budget) -> Vec<Section> {
    match &model.snapshot.availability {
        Availability::Loading => vec![state_panel(
            skin,
            Tone::Busy,
            "LOADING",
            "Waiting for the first GitHub inventory snapshot.",
            "Action: F5 refresh now",
        )],
        Availability::Unauthorized => with_activity_details(
            model,
            skin,
            budget,
            vec![state_panel(
                skin,
                Tone::Bad,
                "UNAUTHORIZED",
                "GitHub authorization is missing or no longer valid.",
                "Action: runner-manager auth login",
            )],
        ),
        Availability::RateLimited {
            retry_after_seconds,
        } => with_activity_details(
            model,
            skin,
            budget,
            vec![state_panel(
                skin,
                Tone::Warn,
                "RATE LIMITED",
                &format!("GitHub asked this host to wait {retry_after_seconds}s."),
                "Action: a opens rate-limit details; retry is automatic",
            )],
        ),
        Availability::Offline {
            last_successful_contact,
            retry_after_seconds,
        } => {
            let panel = Section::Prose(
                [
                    (
                        "OFFLINE - no new runners will start".to_owned(),
                        skin.style(Tone::Bad).add_modifier(Modifier::BOLD),
                    ),
                    (
                        format!("Last successful GitHub contact: {last_successful_contact}"),
                        skin.style(Tone::Plain),
                    ),
                    (
                        format!("Retry in: {retry_after_seconds}s"),
                        skin.style(Tone::Plain),
                    ),
                    (
                        "Local remediation: check this host's network, DNS, proxy, and system clock."
                            .to_owned(),
                        skin.style(Tone::Muted),
                    ),
                    (
                        QUEUE_CANCELLATION_WARNING.to_owned(),
                        skin.style(Tone::Warn),
                    ),
                    (
                        "Action: a opens Activity & errors".to_owned(),
                        skin.style(Tone::Accent),
                    ),
                ]
                .into_iter()
                .map(|(text, style)| Line::from(Span::styled(text, style)))
                .collect(),
            );
            with_activity_details(model, skin, budget, vec![panel])
        }
        Availability::Forbidden { message } => with_activity_details(
            model,
            skin,
            budget,
            vec![state_panel(
                skin,
                Tone::Bad,
                "FORBIDDEN",
                &format!(
                    "GitHub is reachable but refused this target: {}",
                    message
                        .as_deref()
                        .unwrap_or("required permission is missing")
                ),
                "Action: verify repository access and GitHub App/user permissions",
            )],
        ),
        Availability::Failed { detail } => with_activity_details(
            model,
            skin,
            budget,
            vec![state_panel(
                skin,
                Tone::Bad,
                "REFRESH FAILED",
                &format!("GitHub answered, but inventory could not be collected: {detail}"),
                "Action: open Activity & errors and retry with F5",
            )],
        ),
        Availability::Cancelled => with_activity_details(
            model,
            skin,
            budget,
            vec![state_panel(
                skin,
                Tone::Warn,
                "REFRESH CANCELLED",
                "The previous inventory collection was superseded or the TUI is stopping.",
                "Action: F5 starts one latest refresh",
            )],
        ),
        Availability::Ready => ready(model, skin, budget),
    }
}

fn with_activity_details(
    model: &ScreenModel,
    skin: &Skin,
    budget: Budget,
    mut summary: Vec<Section>,
) -> Vec<Section> {
    if model.screen == ReadOnlyScreen::Activity && !model.snapshot.activity.is_empty() {
        summary.push(Section::Prose(vec![Line::default()]));
        summary.extend(activity_sections(model, skin, budget));
    }
    summary
}

fn state_panel(skin: &Skin, tone: Tone, title: &str, message: &str, action: &str) -> Section {
    Section::Prose(vec![
        Line::from(Span::styled(
            title.to_owned(),
            skin.style(tone).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(message.to_owned(), skin.style(Tone::Plain))),
        Line::from(Span::styled(action.to_owned(), skin.style(Tone::Accent))),
    ])
}

fn ready(model: &ScreenModel, skin: &Skin, budget: Budget) -> Vec<Section> {
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
        return vec![match model.screen {
            ReadOnlyScreen::Dashboard | ReadOnlyScreen::Repositories => state_panel(
                skin,
                Tone::Warn,
                "EMPTY",
                "No authorized targets are configured; workload is unknown, not zero.",
                "Action: runner-manager repo add OWNER/REPO",
            ),
            ReadOnlyScreen::Runners => state_panel(
                skin,
                Tone::Warn,
                "EMPTY",
                "No authorized GitHub runners are visible.",
                "Action: F5 refresh or open Repositories",
            ),
            ReadOnlyScreen::Activity => state_panel(
                skin,
                Tone::Ok,
                "EMPTY",
                "No lifecycle activity or errors have been recorded.",
                "Action: F5 refresh",
            ),
        }];
    }
    let no_matches = match model.screen {
        ReadOnlyScreen::Dashboard => false,
        ReadOnlyScreen::Repositories => model.visible_repository_ids().is_empty(),
        ReadOnlyScreen::Runners => model.visible_runner_ids().is_empty(),
        ReadOnlyScreen::Activity => model.visible_activity_ids().is_empty(),
    };
    if no_matches {
        return vec![state_panel(
            skin,
            Tone::Warn,
            "NO MATCHES",
            "Rows exist, but none match the current filter.",
            "Action: Esc clears the filter",
        )];
    }
    match model.screen {
        ReadOnlyScreen::Dashboard => dashboard_sections(model, skin, budget),
        ReadOnlyScreen::Repositories => repository_sections(model, skin, budget),
        ReadOnlyScreen::Runners => runner_sections(model, skin, budget),
        ReadOnlyScreen::Activity => activity_sections(model, skin, budget),
    }
}

fn dashboard_sections(model: &ScreenModel, skin: &Skin, budget: Budget) -> Vec<Section> {
    let m = &model.snapshot.metrics;
    let metric = |label: &str, value: String, tone: Tone| {
        Line::from(vec![
            Span::styled(label.to_owned(), skin.style(Tone::Muted)),
            Span::styled(value, skin.style(tone).add_modifier(Modifier::BOLD)),
        ])
    };
    let head = Section::Prose(vec![
        Line::from(Span::styled(
            "HEALTH: OK live snapshot".to_owned(),
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
        Line::default(),
    ]);
    vec![
        head,
        Section::Grid(repository_grid(model, skin, "Repositories", budget.primary)),
        Section::Prose(vec![Line::default()]),
        Section::Grid(runner_grid(
            model,
            skin,
            "Runners",
            budget.secondary,
            &RUNNER_COLUMNS[..3],
        )),
    ]
}

const fn workload_tone(value: u32) -> Tone {
    if value == 0 { Tone::Muted } else { Tone::Busy }
}

fn repository_sections(model: &ScreenModel, skin: &Skin, budget: Budget) -> Vec<Section> {
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
                (
                    "Agent health: ",
                    row.health.marker().to_owned(),
                    row.health.tone(),
                ),
            ],
            "Action: Esc returns to the repository list",
        )];
    }
    vec![
        table_status(skin, &model.repositories),
        Section::Grid(repository_grid(model, skin, "", budget.primary)),
    ]
}

fn runner_sections(model: &ScreenModel, skin: &Skin, budget: Budget) -> Vec<Section> {
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
                ("Ephemeral: ", row.ephemeral.to_string(), Tone::Plain),
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
            budget.primary,
            &RUNNER_COLUMNS,
        )),
    ]
}

const fn online_tone(online: bool) -> Tone {
    if online { Tone::Ok } else { Tone::Bad }
}

fn activity_sections(model: &ScreenModel, skin: &Skin, budget: Budget) -> Vec<Section> {
    let notice = Section::Prose(vec![Line::from(Span::styled(
        "Diagnostics are redacted and copy-safe. Acknowledge: Enter | Copy: c".to_owned(),
        skin.style(Tone::Muted),
    ))]);
    let rows = viewport_rows(
        &model.visible_activity_ids(),
        model.activity.scroll,
        budget.primary,
    )
    .into_iter()
    .filter_map(|id| {
        model
            .snapshot
            .activity
            .iter()
            .find(|row| row.id == id)
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
    })
    .collect();
    vec![
        notice,
        Section::Grid(Grid {
            caption: String::new(),
            columns: ACTIVITY_COLUMNS.to_vec(),
            rows,
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
    Section::Prose(vec![Line::from(Span::styled(
        format!(
            "Filter: {} | Sort: {:?} | Focus: {:?} | Scroll: {}",
            visible_filter(&state.filter),
            state.sort_order,
            state.focus,
            state.scroll,
        ),
        skin.style(Tone::Muted),
    ))])
}

fn repository_grid(model: &ScreenModel, skin: &Skin, caption: &str, rows: usize) -> Grid {
    let ids = model.visible_repository_ids();
    let body = viewport_rows(&ids, model.repositories.scroll, rows)
        .into_iter()
        .filter_map(|id| {
            model
                .snapshot
                .repositories
                .iter()
                .find(|row| row.id == id)
                .map(|row| {
                    let selected =
                        model.repositories.selected_id.as_deref() == Some(row.id.as_str());
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
                        ],
                    }
                })
        })
        .collect();
    Grid {
        caption: caption.to_owned(),
        columns: REPOSITORY_COLUMNS.to_vec(),
        rows: body,
        sorted: Some(match model.repositories.sort_order {
            SortOrder::NameAscending => (0, false),
            SortOrder::NameDescending => (0, true),
            SortOrder::WorkloadDescending => (1, true),
        }),
    }
}

fn runner_grid(
    model: &ScreenModel,
    skin: &Skin,
    caption: &str,
    rows: usize,
    columns: &[Column],
) -> Grid {
    let ids = model.visible_runner_ids();
    let body = viewport_rows(&ids, model.runners.scroll, rows)
        .into_iter()
        .filter_map(|id| {
            model
                .snapshot
                .runners
                .iter()
                .find(|row| row.id == id)
                .map(|row| {
                    let selected = model.runners.selected_id.as_deref() == Some(row.id.as_str());
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
        })
        .collect();
    Grid {
        caption: caption.to_owned(),
        columns: columns.to_vec(),
        rows: body,
        sorted: Some((2, model.runners.sort_order != SortOrder::NameAscending))
            .filter(|_| columns.len() > 2),
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
    let lifetime = if row.ephemeral {
        format!("{}ephemeral ", skin.pick("\u{25c7}", ""))
    } else {
        format!("{}persistent", skin.pick("\u{25c6}", ""))
    };
    let ownership = match row.ownership {
        RunnerOwnership::Local => "local",
        RunnerOwnership::External => "external",
    };
    Cell::compound(vec![
        (format!("{glyph} {word:<7}"), tone),
        (format!("  {lifetime}"), Tone::Muted),
        (format!("  {ownership}"), Tone::Muted),
    ])
}

/// The window of rows a grid may draw, starting where the table is scrolled to.
fn viewport_rows(ids: &[String], scroll: usize, rows: usize) -> Vec<String> {
    let start = scroll.min(ids.len().saturating_sub(1));
    ids.iter().skip(start).take(rows).cloned().collect()
}

/// Prose is the only thing the content area may reflow; a grid already fits.
fn wrapped(line: Line<'static>, width: u16) -> Vec<Line<'static>> {
    let text = flatten(&line);
    let width = usize::from(width);
    if width == 0 || text.width() <= width {
        return vec![line];
    }
    let style = line
        .spans
        .first()
        .map_or_else(Style::default, |span| span.style);
    let mut pieces: Vec<String> = Vec::new();
    for word in text.split_whitespace() {
        match pieces.last_mut() {
            Some(last) if last.width() + 1 + word.width() <= width => {
                last.push(' ');
                last.push_str(word);
            }
            _ => pieces.push(word.to_owned()),
        }
    }
    pieces
        .into_iter()
        .map(|piece| Line::from(Span::styled(piece, style)))
        .collect()
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
        Dashboard/populated: lines=20 bytes=1004 fnv=3b9b67f438345697 | HEALTH: OK live snapshot
        Dashboard/empty: lines=3 bytes=117 fnv=46b29f02007e5280 | EMPTY | Action: runner-manager repo add OWNER/REPO
        Dashboard/unauthorized: lines=3 bytes=98 fnv=b305c2db5095c2ad | UNAUTHORIZED | Action: runner-manager auth login
        Dashboard/rate-limited: lines=3 bytes=103 fnv=d96d37598270b0bb | RATE LIMITED | Action: a opens rate-limit details; retry is automatic
        Dashboard/offline: lines=6 bytes=255 fnv=7aca69b8a1025157 | OFFLINE - no new runners will start | Action: a opens Activity & errors
        Repositories/loading: lines=3 bytes=79 fnv=0773e12a4b1d7abf | LOADING | Action: F5 refresh now
        Repositories/populated: lines=7 bytes=494 fnv=0662e695ce8441f4 | Filter: <none> | Sort: NameAscending | Focus: Rows | Scroll: 0
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
        "###);
    }

    /// One frame, exactly as the terminal receives it.
    fn drawn(width: u16, height: u16, model: &ScreenModel) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), model, &Skin::RICH))
            .unwrap();
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
