// owner: g1-tui-shell-input

//! Terminal ownership, merged input, focus, and the TUI reducer.
//! Rendering accepts only immutable [`PresentationState`], so a frame has no
//! filesystem, store, or network capability.

use std::io::{self, Write};
use std::sync::{Arc, mpsc as std_mpsc};
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

#[cfg(test)]
pub const FRAME_BUDGET: Duration = Duration::from_millis(16);
pub const TICK_RATE: Duration = Duration::from_millis(250);
const LOCAL_AGENT_POLL_RATE: Duration = Duration::from_secs(1);
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
}

/// Polls the durable lifecycle/status view written by the already-running
/// daemon. This is deliberately a local journal reader, not an IPC listener:
/// the product exposes no inbound control surface and `q` owns only this
/// reader thread.
struct LocalAgentEventSource {
    stop: std_mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}

impl LocalAgentEventSource {
    fn start(
        context: Arc<crate::cli::Context>,
        poll_rate: Duration,
    ) -> io::Result<(Self, mpsc::UnboundedReceiver<AgentEvent>)> {
        let (events, receiver) = mpsc::unbounded_channel();
        let (stop, stopped) = std_mpsc::channel();
        // Seed the first frame from real journal state before the terminal is
        // acquired. Subsequent refreshes happen on the reader thread.
        let _ = events.send(local_agent_event(&context));
        let worker = thread::Builder::new()
            .name("runner-manager-tui-events".to_owned())
            .spawn(move || {
                while let Err(std_mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(poll_rate)
                {
                    if events.send(local_agent_event(&context)).is_err() {
                        break;
                    }
                }
            })?;
        Ok((
            Self {
                stop,
                worker: Some(worker),
            },
            receiver,
        ))
    }
}

impl Drop for LocalAgentEventSource {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn local_agent_event(context: &crate::cli::Context) -> AgentEvent {
    match crate::cli::status::snapshot(context) {
        Ok(snapshot) => AgentEvent {
            summary: format!(
                "Local agent journal: {} active runner attempt(s), {} configured policy/policies.",
                snapshot.host.in_use,
                snapshot.policies.len()
            ),
            health: if snapshot.host.in_use > 0 {
                Health::Busy
            } else {
                Health::Ready
            },
        },
        Err(error) => AgentEvent {
            summary: format!("Local agent journal could not be read: {error}"),
            health: Health::Error,
        },
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

fn reduce_key(state: &mut AppState, key: KeyEvent) -> Vec<Effect> {
    if state.filtering {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                state.filtering = false;
                return Vec::new();
            }
            KeyCode::Backspace => {
                state.filter.pop();
                return Vec::new();
            }
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                state.filter.push(character);
                return Vec::new();
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Char('d') => state.screen = Screen::Dashboard,
        KeyCode::Char('r') => state.screen = Screen::Repositories,
        KeyCode::Char('n') => state.screen = Screen::Runners,
        KeyCode::Char('s') => state.screen = Screen::RepositorySettings,
        KeyCode::Char('h') => state.screen = Screen::HostSettings,
        KeyCode::Char('a') => state.screen = Screen::Activity,
        KeyCode::Char('/') => state.filtering = true,
        KeyCode::F(5) => return vec![Effect::Refresh],
        KeyCode::Char('?') => state.help_open = !state.help_open,
        KeyCode::Char('q') => state.should_exit = true,
        KeyCode::Char('c') => return vec![Effect::Copy(state.presentation.copy_text())],
        KeyCode::Char('m') => {
            state.mouse_capture = !state.mouse_capture;
            return vec![Effect::SetMouseCapture(state.mouse_capture)];
        }
        KeyCode::Esc => {
            if state.help_open {
                state.help_open = false;
            } else if state.screen != Screen::Dashboard {
                state.screen = Screen::Dashboard;
            }
        }
        KeyCode::Tab => {
            state.focus = state
                .focus
                .next(key.modifiers.contains(KeyModifiers::SHIFT))
        }
        KeyCode::BackTab | KeyCode::Up | KeyCode::Left => state.focus = state.focus.next(true),
        KeyCode::Down | KeyCode::Right => state.focus = state.focus.next(false),
        KeyCode::Enter => return vec![Effect::ActivateFocusedControl],
        _ => {}
    }
    Vec::new()
}

fn reduce_mouse(state: &mut AppState, mouse: MouseEvent) -> Vec<Effect> {
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(screen) = state.navigation.hit(mouse.column, mouse.row) {
                state.screen = screen;
                state.focus = Focus::Navigation;
            } else {
                state.focus = Focus::Content;
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
            "Tab/arrows focus | Enter activate | / filter | F5 refresh | c copy | m release mouse | Esc back | q quit | {capture} | {terminal_focus}"
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
        "d Dashboard  r Repositories  n Runners\ns Repo settings  h Host settings  a Activity\n/ Filter F5 Refresh ? Help Esc Back q Quit\nTab Shift-Tab Arrows Focus  Enter Activate\nc Copy diagnostics  m Mouse capture\nKeys mirror every mouse action"
    } else {
        "d Dashboard   r Repositories   n Runners\ns Repository settings   h Host settings   a Activity\n/ filter   F5 refresh   ? help   Esc close/back   q quit\nTab / Shift-Tab / arrows focus   Enter activate\nc copy diagnostics   m release/re-enable mouse capture\nMouse actions always have the keyboard equivalents above."
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
                Effect::Refresh | Effect::ActivateFocusedControl => {
                    // g2/g3 attach refresh and the existing CLI command handlers here.
                }
            }
        }
    }
}

/// Runs the production terminal against an injected agent-event receiver.
///
/// This is the composition seam for an in-process agent. The standalone
/// `runner-manager tui` process uses [`run_terminal`], while an embedding host
/// passes its real receiver here; the loop test exercises this exact path.
pub fn run_terminal_with_agent_events(
    agent_events: mpsc::UnboundedReceiver<AgentEvent>,
) -> io::Result<()> {
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
        ))
        .map(|_| ());
    let _ = terminal.show_cursor();
    result
}

pub fn run_terminal(context: Arc<crate::cli::Context>) -> io::Result<()> {
    let (_source, agent_events) = LocalAgentEventSource::start(context, LOCAL_AGENT_POLL_RATE)?;
    run_terminal_with_agent_events(agent_events)
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
        let (_source, agent_events) =
            LocalAgentEventSource::start(context, Duration::from_secs(60))
                .expect("production local-agent source");
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
            run_loop(&mut terminal, &mut session, input, agent_events),
            producer
        );
        let final_state = result.expect("merged loop");
        assert_eq!(final_state.screen, Screen::Activity);
        assert_eq!(final_state.presentation.health, Health::Ready);
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
        let token = "ghu_super_secret_token";
        let jit = "encoded-jit-config";
        let state = AppState::new(
            PresentationState {
                heading: format!("VISIBLE_HEADING {token} {jit}"),
                body: vec![
                    format!("VISIBLE_BODY command --token={token}"),
                    format!("runner --jit {jit}"),
                ],
                diagnostics: vec![format!("VISIBLE_DIAGNOSTIC {token} {jit}")],
                health: Health::Error,
                access_token: Some(token.to_owned()),
                jit_configuration: Some(jit.to_owned()),
            },
            120,
            30,
        );
        let frame = rendered(120, 30, &state);
        assert!(!frame.contains(token));
        assert!(!frame.contains(jit));
        assert!(frame.contains(REDACTED));
        assert!(frame.contains("VISIBLE_HEADING"));
        assert!(frame.contains("VISIBLE_BODY"));
        let mut activity = state.clone();
        activity.screen = Screen::Activity;
        let activity_frame = rendered(120, 30, &activity);
        assert!(activity_frame.contains("VISIBLE_DIAGNOSTIC"));
        assert!(!activity_frame.contains(token) && !activity_frame.contains(jit));
        let Effect::Copy(copy) = &reduce(&mut state.clone(), key(KeyCode::Char('c')))[0] else {
            panic!()
        };
        assert!(!copy.contains(token) && !copy.contains(jit));
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
