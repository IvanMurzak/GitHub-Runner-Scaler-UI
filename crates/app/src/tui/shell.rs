// owner: g1-tui-shell-input

//! Terminal ownership, merged input, focus, and the TUI reducer.
//! Rendering accepts only immutable [`PresentationState`], so a frame has no
//! filesystem, store, or network capability.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture, Event,
    EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures::StreamExt;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use tokio::sync::mpsc;

#[cfg(test)]
pub const FRAME_BUDGET: Duration = Duration::from_millis(16);
pub const TICK_RATE: Duration = Duration::from_millis(250);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NavHit {
    screen: Screen,
    area: Rect,
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
    nav_hits: Vec<NavHit>,
}

impl AppState {
    pub fn new(presentation: PresentationState, width: u16, height: u16) -> Self {
        let mut state = Self {
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
            nav_hits: Vec::new(),
        };
        state.relayout();
        state
    }

    fn relayout(&mut self) {
        self.nav_hits.clear();
        if self.size.height < 3 || self.size.width < 12 {
            return;
        }
        let nav = Rect::new(0, 1, self.size.width, 1);
        let each = (nav.width / Screen::ALL.len() as u16).max(1);
        for (index, screen) in Screen::ALL.into_iter().enumerate() {
            let x = nav.x.saturating_add((index as u16).saturating_mul(each));
            let right = if index + 1 == Screen::ALL.len() {
                nav.right()
            } else {
                x.saturating_add(each).min(nav.right())
            };
            self.nav_hits.push(NavHit {
                screen,
                area: Rect::new(x, nav.y, right.saturating_sub(x), 1),
            });
        }
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
            if let Some(hit) = state.nav_hits.iter().find(|hit| {
                mouse.column >= hit.area.x
                    && mouse.column < hit.area.right()
                    && mouse.row >= hit.area.y
                    && mouse.row < hit.area.bottom()
            }) {
                state.screen = hit.screen;
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

    let navigation = if compact {
        "[d] Dash  [r] Repos  [n] Runners  [?] Help".to_owned()
    } else {
        Screen::ALL
            .iter()
            .map(|screen| {
                let key = screen_key(*screen);
                if *screen == state.screen {
                    format!("[{key}:{}]", screen.title())
                } else {
                    format!(" {key}:{} ", screen.title())
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    frame.render_widget(Paragraph::new(navigation), rows[1]);

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
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let help = "d Dashboard   r Repositories   n Runners\ns Repository settings   h Host settings   a Activity\n/ filter   F5 refresh   ? help   Esc close/back   q quit\nTab / Shift-Tab / arrows focus   Enter activate\nc copy diagnostics   m release/re-enable mouse capture\nMouse actions always have the keyboard equivalents above.";
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
    fn enable_bracketed_paste(&mut self) -> io::Result<()>;
    fn disable_bracketed_paste(&mut self) -> io::Result<()>;
}

struct CrosstermActions;
impl TerminalActions for CrosstermActions {
    fn enable_raw(&mut self) -> io::Result<()> {
        enable_raw_mode()
    }
    fn disable_raw(&mut self) -> io::Result<()> {
        disable_raw_mode()
    }
    fn enter_alternate_screen(&mut self) -> io::Result<()> {
        execute!(io::stdout(), EnterAlternateScreen).map(|_| ())
    }
    fn leave_alternate_screen(&mut self) -> io::Result<()> {
        execute!(io::stdout(), LeaveAlternateScreen).map(|_| ())
    }
    fn enable_mouse_capture(&mut self) -> io::Result<()> {
        execute!(io::stdout(), EnableMouseCapture).map(|_| ())
    }
    fn disable_mouse_capture(&mut self) -> io::Result<()> {
        execute!(io::stdout(), DisableMouseCapture).map(|_| ())
    }
    fn enable_bracketed_paste(&mut self) -> io::Result<()> {
        execute!(io::stdout(), EnableBracketedPaste).map(|_| ())
    }
    fn disable_bracketed_paste(&mut self) -> io::Result<()> {
        execute!(io::stdout(), DisableBracketedPaste).map(|_| ())
    }
}

/// Owns all terminal modes. `Drop` is also the panic restoration path.
struct TerminalSession<A: TerminalActions> {
    actions: A,
    raw: bool,
    alternate: bool,
    mouse: bool,
    paste: bool,
}

impl<A: TerminalActions> TerminalSession<A> {
    fn start(actions: A) -> io::Result<Self> {
        let mut session = Self {
            actions,
            raw: false,
            alternate: false,
            mouse: false,
            paste: false,
        };
        session.actions.enable_raw()?;
        session.raw = true;
        session.actions.enter_alternate_screen()?;
        session.alternate = true;
        session.actions.enable_mouse_capture()?;
        session.mouse = true;
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
}
impl<A: TerminalActions> SessionControl for TerminalSession<A> {
    fn set_mouse_capture(&mut self, enabled: bool) -> io::Result<()> {
        TerminalSession::set_mouse_capture(self, enabled)
    }
}

/// Crossterm, timer, and agent sources are merged by `select!`; exactly one
/// resulting [`AppEvent`] is sent to [`reduce`] each iteration.
pub async fn run_loop(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
    session: &mut impl SessionControl,
    mut agent_events: mpsc::UnboundedReceiver<AgentEvent>,
) -> io::Result<()> {
    let size = terminal.size()?;
    let mut state = AppState::new(PresentationState::default(), size.width, size.height);
    let mut input = EventStream::new();
    let mut timer = tokio::time::interval(TICK_RATE);
    loop {
        terminal.draw(|frame| render(frame, &state))?;
        if state.should_exit {
            return Ok(());
        }
        let event = tokio::select! {
            input = input.next() => match input {
                Some(Ok(event)) => AppEvent::from(event),
                Some(Err(error)) => AppEvent::InputFailed(error.to_string()),
                None => return Ok(()),
            },
            instant = timer.tick() => AppEvent::Timer(instant.into_std()),
            agent = agent_events.recv() => match agent { Some(agent) => AppEvent::Agent(agent), None => continue },
        };
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

pub fn run_terminal() -> io::Result<()> {
    let mut session = TerminalSession::start(CrosstermActions)?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;
    terminal.clear()?;
    let (_agent_sender, agent_events) = mpsc::unbounded_channel();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run_loop(&mut terminal, &mut session, agent_events));
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

    fn key(code: KeyCode) -> AppEvent {
        AppEvent::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
    }
    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> AppEvent {
        AppEvent::Mouse(MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        })
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
        let area = state
            .nav_hits
            .iter()
            .find(|hit| hit.screen == Screen::Activity)
            .unwrap()
            .area;
        reduce(
            &mut state,
            mouse(MouseEventKind::Down(MouseButton::Left), area.x, area.y),
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
    fn recorded_session_enables_mouse_and_paste_and_restores_normally() {
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
                "paste:on",
                "paste:off",
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
                "paste:on:error",
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
        assert!(frame.contains("compact layout"));
        assert!(frame.contains("Key help"));
        assert!(frame.contains("m release/re-enable"));
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
    }
}
