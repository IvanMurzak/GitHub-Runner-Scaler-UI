// owner: g2-tui-screens

//! The one column grid every read-only table is drawn with.
//!
//! Before this module a "table" was `cells.join(" | ")`: every row negotiated
//! its own widths, so no two rows agreed on where a column started and the
//! reader had to re-find the grid on every line. Here a table is a [`Grid`] --
//! typed [`Column`]s with a width policy, and [`Cell`]s carrying a semantic
//! [`Tone`] rather than a colour -- and this module owns the two things that
//! were missing: a width solver that gives one column exactly one width for
//! the whole table, and a composer that emits that grid twice, as styled
//! [`Line`]s for the frame and as plain ASCII for the snapshot harness and the
//! clipboard.
//!
//! Presentation only. The single environment read lives in [`Skin::detect`],
//! which is called once per process by the shell.

use ratatui::{
    style::{Color, Modifier, Style},
    symbols::{border, line},
    text::{Line, Span, Text},
};
use unicode_truncate::{Alignment, UnicodeTruncateStr};
use unicode_width::UnicodeWidthStr;

/// Lines of chrome a grid spends on its frame: top, header, rule, bottom.
pub const GRID_CHROME: usize = 4;

/// What a cell *means*. The skin turns it into a colour, and the colour-free
/// skin drops it entirely -- which is why every tone is also carried by a word
/// or a marker in the cell text, never by the colour alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Plain,
    Muted,
    Accent,
    Ok,
    Busy,
    Warn,
    Bad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

impl Align {
    const fn padding(self) -> Alignment {
        match self {
            Self::Left => Alignment::Left,
            Self::Right => Alignment::Right,
        }
    }
}

/// Where an over-long cell loses its middle. Identifiers keep both ends,
/// because a runner name is `<routing label>-<unique suffix>` and both halves
/// carry meaning; prose keeps its head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trim {
    Middle,
    Tail,
}

/// How one column negotiates for width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    pub header: &'static str,
    pub align: Align,
    pub trim: Trim,
    /// Narrowest body this column stays readable at.
    pub min_width: u16,
    /// A flexible column absorbs slack, and gives it back first.
    pub flex: bool,
    /// A reluctant flexible column is asked for width only after every other
    /// flexible column is already at its minimum. A status badge earns this:
    /// shortening it costs a whole fact, while shortening a name costs some
    /// characters of one.
    pub reluctant: bool,
    /// Columns leave the grid in ascending rank when the terminal cannot hold
    /// them all. Rank 0 never leaves.
    pub rank: u8,
}

impl Column {
    /// A column that always shows its widest value in full.
    pub const fn rigid(header: &'static str, rank: u8) -> Self {
        Self {
            header,
            align: Align::Left,
            trim: Trim::Tail,
            min_width: 0,
            flex: false,
            reluctant: false,
            rank,
        }
    }

    /// A column that absorbs the leftover width and shortens under pressure.
    pub const fn flexible(header: &'static str, min_width: u16, rank: u8) -> Self {
        Self {
            header,
            align: Align::Left,
            trim: Trim::Middle,
            min_width,
            flex: true,
            reluctant: false,
            rank,
        }
    }

    pub const fn right(mut self) -> Self {
        self.align = Align::Right;
        self
    }

    pub const fn trimming(mut self, trim: Trim) -> Self {
        self.trim = trim;
        self
    }

    /// Asked for width last, after every eager column is at its minimum.
    pub const fn reluctant(mut self) -> Self {
        self.reluctant = true;
        self
    }
}

/// One toned run inside a cell. A runner status cell is three of them: the
/// state, the lifetime, and the ownership each keep their own colour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub text: String,
    pub tone: Tone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub parts: Vec<Fragment>,
}

impl Cell {
    pub fn new(text: impl Into<String>, tone: Tone) -> Self {
        Self {
            parts: vec![Fragment {
                text: text.into(),
                tone,
            }],
        }
    }

    pub fn plain(text: impl Into<String>) -> Self {
        Self::new(text, Tone::Plain)
    }

    pub fn compound(parts: Vec<(String, Tone)>) -> Self {
        Self {
            parts: parts
                .into_iter()
                .map(|(text, tone)| Fragment { text, tone })
                .collect(),
        }
    }

    /// The whole cell as one string. Single-fragment cells -- almost all of
    /// them -- hand back what they already hold rather than rebuilding it.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        match self.parts.as_slice() {
            [only] => std::borrow::Cow::Borrowed(only.text.as_str()),
            parts => parts.iter().map(|part| part.text.as_str()).collect(),
        }
    }

    fn width(&self) -> usize {
        self.parts.iter().map(|part| part.text.width()).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub cells: Vec<Cell>,
    pub selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grid {
    pub caption: String,
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
    /// Column carrying the sort marker, and whether it descends.
    pub sorted: Option<(usize, bool)>,
}

/// One column's place in a solved grid: which column it is, and how wide it
/// came out. One value rather than two positionally-paired `Vec`s, so no
/// consumer has to re-thread a position back through an index to reach the
/// column it is already looking at.
#[derive(Debug, Clone, Copy)]
struct Fit {
    index: usize,
    column: Column,
    width: u16,
}

/// Which of a grid's three rules is being drawn. The glyphs differ; nothing
/// else does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edge {
    Top,
    Header,
    Bottom,
}

/// ASCII stand-ins for Ratatui's box-drawing sets, for a console that cannot
/// print the real ones.
const ASCII_LINES: line::Set<'static> = line::Set {
    vertical: "|",
    horizontal: "-",
    top_right: "+",
    top_left: "+",
    bottom_right: "+",
    bottom_left: "+",
    vertical_left: "+",
    vertical_right: "+",
    horizontal_down: "+",
    horizontal_up: "+",
    cross: "+",
};

const ASCII_BORDER: border::Set<'static> = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

/// Glyphs and colour, resolved once per process. Everything a skin decides is
/// decoration: the same grid says the same thing through either one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Skin {
    pub unicode: bool,
    pub colour: bool,
    /// Background of every other row, when the terminal can paint one.
    pub zebra: Option<Color>,
}

impl Skin {
    /// Colour-free ASCII. The snapshot harness and the clipboard use this, so
    /// it is also the standing proof that no meaning lives in a colour.
    pub const ASCII: Self = Self {
        unicode: false,
        colour: false,
        zebra: None,
    };

    /// Everything a modern terminal can do, which is what `detect` resolves to
    /// on one. Tests pin it so a frame's glyphs never depend on the machine
    /// running the suite.
    #[cfg(test)]
    pub const RICH: Self = Self {
        unicode: true,
        colour: true,
        zebra: Some(Color::Indexed(236)),
    };

    /// `NO_COLOR` and `TERM=dumb` are honoured because they are conventions the
    /// user already has. The `RUNNER_MANAGER_TUI_*` variables exist for the
    /// terminals that answer neither: a Windows console still on a legacy code
    /// page, and a light colour scheme that a dark zebra stripe would fight.
    pub fn detect() -> Self {
        let dumb = std::env::var("TERM").is_ok_and(|term| term == "dumb");
        let unicode = !dumb && !flag("RUNNER_MANAGER_TUI_ASCII") && utf8_capable();
        let colour = !dumb && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty());
        let zebra = if !colour || flag("RUNNER_MANAGER_TUI_PLAIN_ROWS") {
            None
        } else if flag("RUNNER_MANAGER_TUI_LIGHT") {
            Some(Color::Indexed(254))
        } else {
            Some(Color::Indexed(236))
        };
        Self {
            unicode,
            colour,
            zebra,
        }
    }

    /// The one place a glyph forks: `pick(rich, plain)`.
    pub const fn pick(self, rich: &'static str, plain: &'static str) -> &'static str {
        if self.unicode { rich } else { plain }
    }

    /// The grid's own rules and column separators.
    const fn lines(self) -> line::Set<'static> {
        if self.unicode {
            line::ROUNDED
        } else {
            ASCII_LINES
        }
    }

    /// The frame a screen draws around its content. Shares the grid's glyph
    /// vocabulary, so an ASCII terminal never gets a Unicode box around an
    /// ASCII table.
    pub const fn border(self) -> border::Set<'static> {
        if self.unicode {
            border::ROUNDED
        } else {
            ASCII_BORDER
        }
    }

    const fn ellipsis(self) -> &'static str {
        self.pick("\u{2026}", "..")
    }

    const fn sort_marker(self, descending: bool) -> &'static str {
        if descending {
            self.pick(" \u{25bc}", " v")
        } else {
            self.pick(" \u{25b2}", " ^")
        }
    }

    /// The marker a row carries inside its first cell, so a selection survives
    /// a terminal that paints no background at all.
    pub const fn marker(self, selected: bool) -> &'static str {
        if selected {
            self.pick("\u{25b8} ", "> ")
        } else {
            "  "
        }
    }

    pub fn style(self, tone: Tone) -> Style {
        if !self.colour {
            return Style::default();
        }
        match tone {
            Tone::Plain => Style::default(),
            Tone::Muted => Style::default().fg(Color::DarkGray),
            Tone::Accent => Style::default().fg(Color::Cyan),
            Tone::Ok => Style::default().fg(Color::Green),
            Tone::Busy => Style::default().fg(Color::LightBlue),
            Tone::Warn => Style::default().fg(Color::Yellow),
            Tone::Bad => Style::default().fg(Color::Red),
        }
    }

    fn chrome(self) -> Style {
        if self.colour {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default()
        }
    }
}

fn flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.is_empty() && value != "0")
}

fn utf8_capable() -> bool {
    if cfg!(windows) {
        // A Windows console Ratatui can drive at all is Windows Terminal or a
        // VT-enabled conhost, and both of those are UTF-8.
        return true;
    }
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.is_empty())
        .is_none_or(|value| {
            let folded = value.to_ascii_lowercase();
            folded.contains("utf-8") || folded.contains("utf8")
        })
}

/// Every span of every line, concatenated. `Line` and `Text` already know how
/// to do this; this is the one place that asks them.
pub fn text_of(lines: &[Line<'_>]) -> String {
    Text::from(lines.to_vec()).to_string()
}

impl Grid {
    /// Plain text at natural width: nothing is dropped and nothing is
    /// shortened, which is what makes this safe to put on the clipboard.
    pub fn to_text(&self, skin: &Skin) -> String {
        text_of(&self.compose(skin, None))
    }

    /// Styled lines occupying exactly `width` columns, or -- when `width` is
    /// `None` -- exactly as many as the widest value needs.
    pub fn compose(&self, skin: &Skin, width: Option<u16>) -> Vec<Line<'static>> {
        let fits = self.solve(width);
        if fits.is_empty() {
            return Vec::new();
        }
        let mut lines = Vec::with_capacity(self.rows.len() + GRID_CHROME);
        lines.push(self.rule(skin, &fits, Edge::Top, Some(self.caption.as_str())));
        lines.push(self.header(skin, &fits));
        lines.push(self.rule(skin, &fits, Edge::Header, None));
        for (ordinal, row) in self.rows.iter().enumerate() {
            lines.push(self.body(skin, &fits, row, ordinal));
        }
        lines.push(self.rule(skin, &fits, Edge::Bottom, None));
        lines
    }

    /// Widest value in a column, header and sort marker included.
    fn natural(&self, index: usize) -> u16 {
        let header = self.header_text(index).width();
        let widest = self
            .rows
            .iter()
            .filter_map(|row| row.cells.get(index))
            .map(Cell::width)
            .max()
            .unwrap_or(0);
        narrow(header.max(widest))
    }

    fn header_text(&self, index: usize) -> String {
        // The rich marker is never wider than the ASCII one, so measuring the
        // ASCII form gives one width that holds for both skins.
        let marker = match self.sorted {
            Some((sorted, descending)) if sorted == index => Skin::ASCII.sort_marker(descending),
            _ => "",
        };
        format!("{}{marker}", self.columns[index].header)
    }

    /// Decide which columns survive and how wide each one is. Flexible columns
    /// give up width first; only when they are all at their minimum does a
    /// column leave, lowest rank first.
    fn solve(&self, width: Option<u16>) -> Vec<Fit> {
        // Natural widths depend on the rows and the headers, neither of which
        // changes while columns are leaving -- so they are measured once, not
        // once per surviving column per dropped column.
        let mut fits: Vec<Fit> = self
            .columns
            .iter()
            .enumerate()
            .map(|(index, &column)| Fit {
                index,
                column,
                width: self.natural(index),
            })
            .collect();
        let Some(total) = width else {
            return fits;
        };
        loop {
            if fits.is_empty() {
                return fits;
            }
            let body = total.saturating_sub(chrome_width(fits.len()));
            // Summed in `u32` and narrowed back: a single pathological cell --
            // a multi-kilobyte diagnostic, say -- makes a `u16` sum wrap, and a
            // wrapped total reads as "everything fits" at the widest moment it
            // does not.
            let wanted = sum(fits.iter().map(|fit| fit.width));
            if wanted <= body {
                grow(&mut fits, body - wanted);
                return fits;
            }
            let rigid = sum(fits
                .iter()
                .filter(|fit| !fit.column.flex)
                .map(|fit| fit.width));
            let floor = sum(fits
                .iter()
                .filter(|fit| fit.column.flex)
                .map(|fit| fit.column.min_width));
            let flexible = fits.iter().any(|fit| fit.column.flex);
            if flexible && rigid.saturating_add(floor) <= body {
                shrink(&mut fits, body.saturating_sub(rigid));
                return fits;
            }
            match expendable(&fits) {
                Some(position) => {
                    fits.remove(position);
                }
                None => {
                    squeeze(&mut fits, body);
                    return fits;
                }
            }
        }
    }

    fn rule(&self, skin: &Skin, fits: &[Fit], edge: Edge, caption: Option<&str>) -> Line<'static> {
        let set = skin.lines();
        let (left, joint, right) = match edge {
            Edge::Top => (set.top_left, set.horizontal_down, set.top_right),
            Edge::Header => (set.vertical_right, set.cross, set.vertical_left),
            Edge::Bottom => (set.bottom_left, set.horizontal_up, set.bottom_right),
        };
        // Column positions, within the rule's interior, that carry a joint
        // rather than a plain horizontal.
        let mut joints = Vec::with_capacity(fits.len());
        let mut inner_width = 0;
        for (position, fit) in fits.iter().enumerate() {
            if position > 0 {
                joints.push(inner_width);
                inner_width += 1;
            }
            inner_width += usize::from(fit.width) + 2;
        }
        let segment = |range: std::ops::Range<usize>| -> String {
            range
                .map(|column| {
                    if joints.contains(&column) {
                        joint
                    } else {
                        set.horizontal
                    }
                })
                .collect()
        };
        let painted = |glyphs: String| Span::styled(glyphs, skin.chrome());
        // The caption is painted over the first column's own stretch of rule.
        // Letting it run past that column's joint would paint over the joint,
        // and the top rule would stop agreeing with every row beneath it --
        // exactly the boundary this grid exists to hold. So the caption is
        // shortened to the room the first column actually has.
        let room = if fits.len() > 1 {
            usize::from(fits[0].width).saturating_sub(1)
        } else {
            inner_width.saturating_sub(4)
        };
        let caption = caption
            .filter(|text| !text.is_empty())
            .map(|text| shorten(text, room, Trim::Tail, skin.ellipsis()))
            .filter(|text| !text.is_empty() && text.width() + 4 <= inner_width);
        match caption {
            Some(caption) => {
                let end = 1 + caption.width() + 2;
                Line::from(vec![
                    painted(left.to_owned()),
                    painted(segment(0..1)),
                    Span::styled(
                        format!(" {caption} "),
                        skin.style(Tone::Accent).add_modifier(Modifier::BOLD),
                    ),
                    painted(segment(end..inner_width)),
                    painted(right.to_owned()),
                ])
            }
            None => Line::from(vec![
                painted(left.to_owned()),
                painted(segment(0..inner_width)),
                painted(right.to_owned()),
            ]),
        }
    }

    fn header(&self, skin: &Skin, fits: &[Fit]) -> Line<'static> {
        let separator = skin.lines().vertical;
        let mut spans = vec![Span::styled(separator, skin.chrome())];
        let bold = skin.style(Tone::Plain).add_modifier(Modifier::BOLD);
        for fit in fits {
            spans.push(Span::styled(" ", skin.chrome()));
            spans.push(Span::styled(
                lay(
                    &self.header_text(fit.index),
                    fit.width,
                    fit.column.align,
                    Trim::Tail,
                    skin.ellipsis(),
                ),
                bold,
            ));
            spans.push(Span::styled(" ", skin.chrome()));
            spans.push(Span::styled(separator, skin.chrome()));
        }
        Line::from(spans)
    }

    fn body(&self, skin: &Skin, fits: &[Fit], row: &Row, ordinal: usize) -> Line<'static> {
        let background = match skin.zebra {
            Some(colour) if !row.selected && ordinal % 2 == 1 => Some(colour),
            _ => None,
        };
        let decorate = |style: Style| {
            if row.selected {
                // One highlight for the whole row, not one per tone. `REVERSED`
                // turns a foreground colour into a background, so keeping the
                // tones here would paint the selected row as a patchwork of
                // cyan, green and grey blocks instead of a single bar. Nothing
                // is lost: every tone on this row is also spelled out in words,
                // and the row still carries its `marker`.
                return Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD);
            }
            match background {
                Some(colour) => style.bg(colour),
                None => style,
            }
        };
        let separator = skin.lines().vertical;
        let chrome = decorate(skin.chrome());
        let blank = Cell::plain("");
        let mut spans = vec![Span::styled(separator, chrome)];
        for fit in fits {
            let cell = row.cells.get(fit.index).unwrap_or(&blank);
            let used = cell.width();
            spans.push(Span::styled(" ", chrome));
            if cell.parts.len() > 1 && used <= usize::from(fit.width) {
                // Every fragment keeps its own tone; padding closes the cell.
                let (before, after) = pad(usize::from(fit.width) - used, fit.column.align);
                spans.push(Span::styled(before, decorate(Style::default())));
                for part in &cell.parts {
                    spans.push(Span::styled(
                        part.text.clone(),
                        decorate(skin.style(part.tone)),
                    ));
                }
                spans.push(Span::styled(after, decorate(Style::default())));
            } else {
                let tone = cell.parts.first().map_or(Tone::Plain, |part| part.tone);
                spans.push(Span::styled(
                    lay(
                        &cell.text(),
                        fit.width,
                        fit.column.align,
                        fit.column.trim,
                        skin.ellipsis(),
                    ),
                    decorate(skin.style(tone)),
                ));
            }
            spans.push(Span::styled(" ", chrome));
            spans.push(Span::styled(separator, chrome));
        }
        Line::from(spans)
    }
}

/// Slack goes to the flexible columns, so the frame closes on the terminal
/// edge instead of leaving a ragged gap beside it.
fn grow(fits: &mut [Fit], slack: u16) {
    let mut targets: Vec<usize> = (0..fits.len()).filter(|&at| fits[at].column.flex).collect();
    if targets.is_empty() {
        targets = vec![fits.len() - 1];
    }
    let count = narrow(targets.len());
    for (step, &at) in targets.iter().enumerate() {
        let share = slack / count + u16::from(narrow(step) < slack % count);
        fits[at].width = fits[at].width.saturating_add(share);
    }
}

/// Bring the flexible columns down to `budget`. Eager columns give up their
/// slack first, in proportion to how much each has; only when they are all at
/// their minimum is a reluctant column asked for anything.
fn shrink(fits: &mut [Fit], budget: u16) {
    let flexible: Vec<usize> = (0..fits.len()).filter(|&at| fits[at].column.flex).collect();
    let wanted = sum(flexible.iter().map(|&at| fits[at].width));
    let mut deficit = wanted.saturating_sub(budget);
    for reluctant in [false, true] {
        if deficit == 0 {
            break;
        }
        let group: Vec<usize> = flexible
            .iter()
            .copied()
            .filter(|&at| fits[at].column.reluctant == reluctant)
            .collect();
        deficit = take_width(fits, &group, deficit);
    }
}

/// The next column to leave: lowest rank above zero, rightmost on a tie.
fn expendable(fits: &[Fit]) -> Option<usize> {
    fits.iter()
        .enumerate()
        .filter(|(_, fit)| fit.column.rank > 0)
        .min_by_key(|(position, fit)| (fit.column.rank, usize::MAX - *position))
        .map(|(position, _)| position)
}

/// Take up to `deficit` columns of width from `group`, in proportion to the
/// slack each column has above its minimum, and answer what could not be
/// taken. Integer division always leaves a remainder, and a grid that is one
/// column too wide overruns the terminal, so the remainder is collected too.
fn take_width(fits: &mut [Fit], group: &[usize], deficit: u16) -> u16 {
    let slack = |fit: &Fit| u32::from(fit.width.saturating_sub(fit.column.min_width));
    let total: u32 = group.iter().map(|&at| slack(&fits[at])).sum();
    if total == 0 {
        return deficit;
    }
    let take = u32::from(deficit).min(total);
    let mut taken = 0;
    for &at in group {
        let own = slack(&fits[at]);
        let share = (take * own / total).min(own);
        fits[at].width -= narrow_u32(share);
        taken += share;
    }
    let mut rest = take - taken;
    for &at in group {
        if rest == 0 {
            break;
        }
        let bite = slack(&fits[at]).min(rest);
        fits[at].width -= narrow_u32(bite);
        rest -= bite;
    }
    deficit - narrow_u32(take)
}

/// Last resort: nothing may leave and nothing fits, so every column is scaled
/// down together rather than one of them being starved.
fn squeeze(fits: &mut [Fit], budget: u16) {
    let wanted: u32 = fits.iter().map(|fit| u32::from(fit.width)).sum();
    if wanted == 0 {
        return;
    }
    for fit in fits.iter_mut() {
        fit.width = narrow_u32(u32::from(fit.width) * u32::from(budget) / wanted);
    }
    // Integer division always rounds down, and a grid that stops one column
    // short of the terminal edge is the ragged frame this module exists to
    // prevent, so the remainder is handed back out. It goes first to the
    // columns that rounded down to nothing -- a column only vanishes when the
    // budget genuinely cannot pay for it -- and never exceeds the budget,
    // because a grid one column too wide overruns the terminal instead.
    let mut spare = budget.saturating_sub(sum(fits.iter().map(|fit| fit.width)));
    for pass in [true, false] {
        for fit in fits.iter_mut() {
            if spare == 0 {
                return;
            }
            if pass == (fit.width == 0) {
                fit.width += 1;
                spare -= 1;
            }
        }
    }
}

/// Borders and padding: one glyph between every pair of columns, one at each
/// end, and one space either side of every body.
fn chrome_width(columns: usize) -> u16 {
    narrow(columns * 3 + 1)
}

/// Widths are summed in `u32` so a pathological cell cannot wrap the total.
fn sum(widths: impl Iterator<Item = u16>) -> u16 {
    narrow_u32(widths.map(u32::from).sum())
}

fn narrow(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn narrow_u32(value: u32) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

/// The spaces that close a cell whose content is narrower than its column.
fn pad(width: usize, align: Align) -> (String, String) {
    let spaces = " ".repeat(width);
    match align {
        Align::Left => (String::new(), spaces),
        Align::Right => (spaces, String::new()),
    }
}

/// Shorten to `width`, then pad to exactly `width`.
fn lay(text: &str, width: u16, align: Align, trim: Trim, ellipsis: &str) -> String {
    let width = usize::from(width);
    shorten(text, width, trim, ellipsis)
        .unicode_pad(width, align.padding(), false)
        .into_owned()
}

/// Drop the middle of an identifier, or the tail of prose. Both ends of a
/// runner name matter -- the routing label leads it and the unique suffix ends
/// it -- so a middle trim is the only one that keeps a name recognisable.
fn shorten(text: &str, width: usize, trim: Trim, ellipsis: &str) -> String {
    if text.width() <= width {
        return text.to_owned();
    }
    let marker = ellipsis.width();
    if width <= marker {
        return text.unicode_truncate(width).0.to_owned();
    }
    let keep = width - marker;
    match trim {
        Trim::Tail => format!("{}{ellipsis}", text.unicode_truncate(keep).0),
        Trim::Middle => {
            let head = keep.div_ceil(2);
            format!(
                "{}{ellipsis}{}",
                text.unicode_truncate(head).0,
                text.unicode_truncate_start(keep - head).0
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The grid as the terminal would show it, at a chosen width.
    fn drawn(grid: &Grid, skin: &Skin, width: u16) -> String {
        text_of(&grid.compose(skin, Some(width)))
    }

    fn column_widths(text: &str) -> Vec<usize> {
        text.lines()
            .map(|line| line.chars().count())
            .collect::<Vec<_>>()
    }

    fn grid() -> Grid {
        Grid {
            caption: "Runners".into(),
            columns: vec![
                Column::flexible("Repository", 10, 0),
                Column::rigid("Status", 0),
                Column::flexible("Runner", 10, 0),
                Column::rigid("OS", 2),
                Column::flexible("Labels", 6, 1),
            ],
            rows: vec![
                Row {
                    cells: vec![
                        Cell::new("  acme/alpha", Tone::Accent),
                        Cell::compound(vec![
                            ("busy".into(), Tone::Busy),
                            (" ephemeral".into(), Tone::Muted),
                        ]),
                        Cell::plain("rm-home-win-x64-0f1e2d3c4b5a"),
                        Cell::new("Windows", Tone::Muted),
                        Cell::new("self-hosted,rm-home-win-x64", Tone::Muted),
                    ],
                    selected: true,
                },
                Row {
                    cells: vec![
                        Cell::new("  acme/observatory-service", Tone::Accent),
                        Cell::compound(vec![
                            ("offline".into(), Tone::Bad),
                            (" persistent".into(), Tone::Muted),
                        ]),
                        Cell::plain("legacy-office"),
                        Cell::new("Linux", Tone::Muted),
                        Cell::new("self-hosted", Tone::Muted),
                    ],
                    selected: false,
                },
            ],
            sorted: Some((0, false)),
        }
    }

    #[test]
    fn every_line_of_a_grid_is_exactly_as_wide_as_every_other() {
        // ----------------------------------------------------------------
        // THE WHOLE POINT. The old renderer joined cells with " | ", so a
        // long repository name pushed every later column of that ONE row
        // right and the reader lost the grid. One width per column, applied
        // to the header, the rules, and every row, is the fix -- and it has
        // to hold at every terminal width, not just the comfortable ones.
        // ----------------------------------------------------------------
        for width in [10_u16, 13, 16, 20, 24, 40, 60, 80, 100, 120, 200] {
            let rendered = drawn(&grid(), &Skin::ASCII, width);
            let widths = column_widths(&rendered);
            assert!(
                widths.windows(2).all(|pair| pair[0] == pair[1]),
                "ragged grid at width {width}:\n{rendered}"
            );
            assert_eq!(
                widths[0],
                usize::from(width),
                "grid did not fill width {width}:\n{rendered}"
            );
        }
    }

    #[test]
    fn natural_width_never_shortens_and_never_drops() {
        let rendered = grid().to_text(&Skin::ASCII);
        assert!(
            rendered.contains("rm-home-win-x64-0f1e2d3c4b5a"),
            "{rendered}"
        );
        assert!(
            rendered.contains("self-hosted,rm-home-win-x64"),
            "{rendered}"
        );
        assert!(rendered.contains("Labels"), "{rendered}");
        assert!(!rendered.contains(".."), "{rendered}");
        let widths = column_widths(&rendered);
        assert!(
            widths.windows(2).all(|pair| pair[0] == pair[1]),
            "{rendered}"
        );
    }

    #[test]
    fn columns_leave_in_rank_order_and_the_named_three_never_do() {
        let narrow = drawn(&grid(), &Skin::ASCII, 46);
        assert!(!narrow.contains("Labels"), "rank 1 leaves first:\n{narrow}");
        assert!(!narrow.contains("OS"), "rank 2 leaves next:\n{narrow}");
        for survivor in ["Repository", "Status", "Runner"] {
            assert!(
                narrow.contains(survivor),
                "rank 0 must never leave, lost {survivor}:\n{narrow}"
            );
        }
    }

    #[test]
    fn an_over_long_runner_name_keeps_both_of_its_meaningful_ends() {
        // A just-in-time runner is `<routing label>-<unique suffix>`. Cutting
        // the tail off leaves every runner on a host looking identical, which
        // is exactly the case a reader is trying to tell apart.
        let shortened = shorten("rm-home-win-x64-0f1e2d3c4b5a", 16, Trim::Middle, "..");
        assert_eq!(shortened.width(), 16, "{shortened}");
        assert!(shortened.starts_with("rm-home"), "{shortened}");
        assert!(shortened.ends_with("3c4b5a"), "{shortened}");
        assert!(shortened.contains(".."), "{shortened}");

        let prose = shorten(
            "GitHub answered, but inventory failed",
            16,
            Trim::Tail,
            "..",
        );
        assert_eq!(prose.width(), 16, "{prose}");
        assert!(prose.starts_with("GitHub answer"), "{prose}");
        assert!(
            prose.ends_with(".."),
            "prose loses its tail, not its middle: {prose}"
        );
    }

    #[test]
    fn shortening_is_measured_in_terminal_columns_not_bytes() {
        // A CJK repository name is two columns per character; counting bytes
        // or chars would overrun the cell and re-break the grid it fixes.
        let wide = "\u{5e73}\u{6210}\u{6771}\u{4eac}\u{652f}\u{5e97}";
        assert_eq!(wide.width(), 12);
        for width in 1..=12 {
            assert!(
                shorten(wide, width, Trim::Middle, "..").width() <= width,
                "overran at {width}"
            );
            assert_eq!(
                lay(wide, narrow(width), Align::Left, Trim::Middle, "..").width(),
                width
            );
        }
    }

    #[test]
    fn the_ascii_skin_emits_no_glyph_a_legacy_console_cannot_print() {
        let rendered = grid().to_text(&Skin::ASCII);
        assert!(rendered.is_ascii(), "{rendered}");
        let rich = grid().to_text(&Skin::RICH);
        assert!(!rich.is_ascii(), "the rich skin is the one with the glyphs");
        // Both skins carry the same words, so meaning never rides on a glyph.
        for word in ["Repository", "busy", "offline", "ephemeral", "persistent"] {
            assert!(rendered.contains(word), "{rendered}");
            assert!(rich.contains(word), "{rich}");
        }
    }

    #[test]
    fn a_reluctant_column_pays_only_after_every_eager_one_is_at_its_minimum() {
        // Shortening a status badge costs a whole fact -- "is this runner mine
        // or somebody else's" simply disappears. Shortening a name costs some
        // characters of a value the reader can still recognise. So the names
        // pay the whole deficit first, and the badge only once they cannot.
        let mut reluctant = grid();
        reluctant.columns[1] = Column::flexible("Status", 9, 0)
            .trimming(Trim::Tail)
            .reluctant();
        let rendered = drawn(&reluctant, &Skin::ASCII, 86);
        assert!(
            rendered.contains("offline persistent"),
            "the badge paid before the names did:\n{rendered}"
        );
        assert!(
            !rendered.contains("rm-home-win-x64-0f1e2d3c4b5a"),
            "the name should have paid instead:\n{rendered}"
        );

        // Eager by default, and then the badge is shortened alongside the rest.
        let mut plain = grid();
        plain.columns[1] = Column::flexible("Status", 9, 0).trimming(Trim::Tail);
        assert_ne!(rendered, drawn(&plain, &Skin::ASCII, 86));
    }

    #[test]
    fn a_caption_never_paints_over_the_boundary_the_rows_beneath_it_keep() {
        // The caption sits on the first column's own stretch of the top rule.
        // When it was allowed to run past that column it painted over the
        // joint, so the top rule declared one set of boundaries and every row
        // beneath it drew another -- the ragged grid, back again, one line up.
        for width in [20_u16, 24, 30, 40, 60, 90] {
            let rendered = drawn(&grid(), &Skin::ASCII, width);
            let lines: Vec<Vec<char>> = rendered.lines().map(|l| l.chars().collect()).collect();
            let separators: Vec<usize> = lines[1]
                .iter()
                .enumerate()
                .filter(|(column, glyph)| {
                    **glyph == '|' && *column > 0 && *column + 1 < width.into()
                })
                .map(|(column, _)| column)
                .collect();
            for &column in &separators {
                assert_eq!(
                    lines[0].get(column),
                    Some(&'+'),
                    "caption ate the joint at {column}, width {width}:\n{rendered}"
                );
            }
        }
    }

    #[test]
    fn a_grid_with_no_room_left_still_renders_something_rectangular() {
        for width in [0_u16, 1, 4, 8, 12] {
            let rendered = drawn(&grid(), &Skin::ASCII, width);
            let widths = column_widths(&rendered);
            assert!(
                widths.windows(2).all(|pair| pair[0] == pair[1]),
                "ragged at {width}:\n{rendered}"
            );
        }
    }

    #[test]
    fn the_grid_can_reach_nothing_but_the_environment_it_reads_its_skin_from() {
        // `screens.rs` guards the same property for itself. This module is the
        // one it draws with, so the guard has to follow: a table that could
        // read a file or open a socket is a table that could put something on
        // screen the snapshot harness never saw.
        let source = include_str!("table.rs");
        // Split on the test module rather than on the first `#[cfg(test)]`:
        // `Skin::RICH` carries one, and splitting there would leave most of
        // the file unscanned while the assertion still passed.
        let production = source.split_once("mod tests {").unwrap().0;
        for forbidden in ["std::fs", "std::net", "reqwest", ".await", "block_on"] {
            assert!(!production.contains(forbidden), "grid acquired {forbidden}");
        }
    }
}
