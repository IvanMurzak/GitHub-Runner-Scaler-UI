// owner: e1-workspace-tui

//! One editable single-line path control.
//!
//! `05-user-workflows.md`, "TUI interaction requirements", asks for exactly this
//! much and no more: *"Keyboard typing, Backspace, Delete, Home, End, arrows,
//! paste, Escape cancel, and Enter accept work in path controls"*, and *"Paths
//! are horizontally scrollable during editing and copyable from detail view"*.
//!
//! # Why a control and not a `String` on the form
//!
//! A runner root is longer than the column it is shown in, so the three facts a
//! `String` cannot carry are the whole reason this type exists: where the cursor
//! is, which slice of the value is on screen, and what the value was **before**
//! the operator started typing — Escape has to put it back.
//!
//! # It validates nothing
//!
//! Not one rule about absolute paths, overlap, or locality lives here.
//! `02-target-architecture.md`'s eighth invariant is that CLI and TUI share one
//! validator, and `e1`'s scope says "do not duplicate path or active-attempt
//! policy in widgets". So this is a text editor that happens to hold a path: the
//! answer to "is this usable?" comes from
//! [`crate::cli::workspace::check_root`], through the same preflight
//! `host set-runtime-root` runs.

use unicode_width::UnicodeWidthChar;

/// The caret drawn at the cursor while editing.
///
/// A printed glyph rather than the terminal's own cursor, for two reasons: the
/// settings body is a `Paragraph`, which does not place a cursor, and a
/// snapshot test reads the frame's *symbols*. A styled-but-invisible cursor
/// would make "the cursor moved" unobservable to exactly the tests
/// `e1`'s Definition of Done requires. `|` cannot occur in a path on either
/// platform family, so it is never confused with the value.
pub const CARET: char = '|';

/// A single-line text control holding a filesystem path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathField {
    value: Vec<char>,
    /// The value Escape restores; only meaningful while [`Self::editing`].
    committed: Vec<char>,
    /// Cursor position, in `char`s, in `0..=value.len()`.
    cursor: usize,
    editing: bool,
}

impl PathField {
    #[must_use]
    pub fn new(value: &str) -> Self {
        let value: Vec<char> = value.chars().collect();
        Self {
            committed: value.clone(),
            cursor: value.len(),
            value,
            editing: false,
        }
    }

    /// Replaces the value from a fresh read of the store, discarding any draft.
    pub fn reset_to(&mut self, value: &str) {
        *self = Self::new(value);
    }

    #[must_use]
    pub fn text(&self) -> String {
        self.value.iter().collect()
    }

    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.value.iter().all(|c| c.is_whitespace())
    }

    #[must_use]
    pub const fn is_editing(&self) -> bool {
        self.editing
    }

    /// Only the control's own tests read the cursor: every production caller
    /// asks for [`Self::view`], which is where the cursor becomes visible.
    #[cfg(test)]
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Enters edit mode, remembering the value Escape restores.
    pub fn begin(&mut self) {
        self.committed = self.value.clone();
        self.cursor = self.value.len();
        self.editing = true;
    }

    /// Enter: keeps the draft and leaves edit mode.
    pub fn accept(&mut self) {
        self.committed = self.value.clone();
        self.editing = false;
    }

    /// Escape: restores the value the operator started from.
    ///
    /// Journey 6 says the TUI "preserves the operator's draft for correction",
    /// which is what *not* cancelling does; cancelling is the operator asking
    /// for the opposite, explicitly.
    pub fn cancel(&mut self) {
        self.value = self.committed.clone();
        self.cursor = self.value.len();
        self.editing = false;
    }

    /// Types one character. Control characters are dropped rather than stored.
    pub fn insert(&mut self, character: char) {
        if character.is_control() {
            return;
        }
        self.value.insert(self.cursor, character);
        self.cursor += 1;
    }

    /// Bracketed paste.
    ///
    /// A terminal paste arrives as one block that may carry a trailing newline,
    /// and a Windows path copied from Explorer or a shell arrives wrapped in
    /// double quotes. Both are the operator pasting the path they meant, so the
    /// wrapper is removed rather than being turned into a refusal about a
    /// character that is not part of any path. Everything else — including a
    /// path with an embedded quote — is inserted verbatim and answered by the
    /// shared validator.
    pub fn paste(&mut self, text: &str) {
        let first = text.lines().next().unwrap_or_default().trim();
        let unquoted = first
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or(first);
        for character in unquoted.chars() {
            self.insert(character);
        }
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.value.remove(self.cursor);
        }
    }

    pub fn delete(&mut self) {
        if self.cursor < self.value.len() {
            self.value.remove(self.cursor);
        }
    }

    pub const fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub const fn right(&mut self) {
        if self.cursor < self.value.len() {
            self.cursor += 1;
        }
    }

    pub const fn home(&mut self) {
        self.cursor = 0;
    }

    pub const fn end(&mut self) {
        self.cursor = self.value.len();
    }

    /// The slice of the value that fits in `columns`, with the caret in place.
    ///
    /// The window is derived from the cursor rather than stored, so a resize
    /// cannot leave a scroll offset pointing off the end of a value that has
    /// since been edited. It is anchored on the cursor: walking back from the
    /// cursor until the budget is spent, then forward with whatever is left.
    /// Typing at the end therefore shows the tail, and Home shows the head,
    /// which is the two things "horizontally scrollable" has to mean.
    #[must_use]
    pub fn view(&self, columns: usize) -> PathView {
        let mut rendered: Vec<char> = self.value.clone();
        let caret_at = self.cursor;
        if self.editing {
            rendered.insert(caret_at, CARET);
        }
        let budget = columns.max(1);
        // Anchor on the caret (or on the end of the value when not editing).
        let anchor = if self.editing {
            caret_at
        } else {
            rendered.len().saturating_sub(1)
        };
        let mut start = anchor.min(rendered.len().saturating_sub(1));
        let mut used = width_of(rendered.get(start).copied());
        while start > 0 {
            let candidate = width_of(rendered.get(start - 1).copied());
            if used + candidate > budget {
                break;
            }
            used += candidate;
            start -= 1;
        }
        let mut end = anchor.saturating_add(1).min(rendered.len());
        while end < rendered.len() {
            let candidate = width_of(rendered.get(end).copied());
            if used + candidate > budget {
                break;
            }
            used += candidate;
            end += 1;
        }
        PathView {
            text: rendered[start..end].iter().collect(),
            clipped_left: start > 0,
            clipped_right: end < rendered.len(),
        }
    }
}

fn width_of(character: Option<char>) -> usize {
    character.and_then(UnicodeWidthChar::width).unwrap_or(0)
}

/// What [`PathField::view`] puts on one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathView {
    pub text: String,
    pub clipped_left: bool,
    pub clipped_right: bool,
}

impl PathView {
    /// The row as drawn, with the two clipping markers the operator needs to
    /// know the value continues past the edge.
    #[must_use]
    pub fn rendered(&self) -> String {
        format!(
            "{}{}{}",
            if self.clipped_left { "<" } else { "" },
            self.text,
            if self.clipped_right { ">" } else { "" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value: &str) -> PathField {
        let mut field = PathField::new(value);
        field.begin();
        field
    }

    #[test]
    fn typing_backspace_delete_and_the_four_motions_edit_the_value() {
        let mut path = field("C:\\rman");
        path.insert('x');
        assert_eq!(path.text(), "C:\\rmanx");
        path.backspace();
        assert_eq!(path.text(), "C:\\rman");

        path.home();
        assert_eq!(path.cursor(), 0);
        path.delete();
        assert_eq!(path.text(), ":\\rman");
        path.right();
        path.insert('!');
        assert_eq!(path.text(), ":!\\rman");
        path.left();
        path.delete();
        assert_eq!(path.text(), ":\\rman");
        path.end();
        assert_eq!(path.cursor(), path.text().chars().count());

        // The cursor never leaves the value.
        path.home();
        path.left();
        assert_eq!(path.cursor(), 0);
        path.end();
        path.right();
        assert_eq!(path.cursor(), 6);
    }

    #[test]
    fn escape_restores_the_value_and_enter_keeps_the_draft() {
        let mut path = field("C:\\rman");
        path.insert('2');
        path.cancel();
        assert_eq!(path.text(), "C:\\rman");
        assert!(!path.is_editing());

        path.begin();
        path.insert('2');
        path.accept();
        assert_eq!(path.text(), "C:\\rman2");
        assert!(!path.is_editing());
        // A second edit cancels back to the accepted value, not the original.
        path.begin();
        path.insert('3');
        path.cancel();
        assert_eq!(path.text(), "C:\\rman2");
    }

    #[test]
    fn paste_takes_one_line_and_unwraps_the_shell_quoting_around_a_path() {
        let mut path = field("");
        path.paste("\"D:\\ci cache\\project\"\r\nignored second line\n");
        assert_eq!(path.text(), "D:\\ci cache\\project");

        // An embedded quote is the operator's problem, not ours to guess at.
        let mut path = field("");
        path.paste("D:\\wei\"rd");
        assert_eq!(path.text(), "D:\\wei\"rd");

        // Control characters never enter the value.
        let mut path = field("");
        path.paste("D:\\a\u{7}b");
        assert_eq!(path.text(), "D:\\ab");
    }

    #[test]
    fn a_long_value_scrolls_horizontally_around_the_cursor() {
        let long = format!("D:\\{}\\slots", "segment".repeat(12));
        let mut path = field(&long);

        let tail = path.view(20);
        assert!(tail.clipped_left, "{tail:?}");
        assert!(!tail.clipped_right, "{tail:?}");
        assert!(tail.text.ends_with("slots|"), "{tail:?}");
        assert!(tail.rendered().starts_with('<'), "{tail:?}");

        path.home();
        let head = path.view(20);
        assert!(!head.clipped_left, "{head:?}");
        assert!(head.clipped_right, "{head:?}");
        assert!(head.text.starts_with("|D:\\"), "{head:?}");
        assert!(head.rendered().ends_with('>'), "{head:?}");

        // Every window stays inside its column budget, markers included.
        for columns in 1..40 {
            let view = path.view(columns);
            assert!(
                view.text.chars().count() <= columns,
                "{columns}: {:?}",
                view.text
            );
        }
    }

    #[test]
    fn a_short_value_is_never_clipped_and_shows_no_caret_when_not_editing() {
        let mut path = PathField::new("C:\\rman");
        let view = path.view(40);
        assert_eq!(view.rendered(), "C:\\rman");
        assert!(!view.clipped_left && !view.clipped_right);

        path.begin();
        assert_eq!(path.view(40).rendered(), "C:\\rman|");
        path.home();
        assert_eq!(path.view(40).rendered(), "|C:\\rman");
    }

    #[test]
    fn an_empty_field_renders_nothing_and_reports_blank() {
        let mut path = PathField::new("");
        assert!(path.is_blank());
        assert_eq!(path.view(10).rendered(), "");
        path.begin();
        assert_eq!(path.view(10).rendered(), "|");
        path.insert(' ');
        assert!(path.is_blank(), "whitespace is not a configured path");
    }
}
