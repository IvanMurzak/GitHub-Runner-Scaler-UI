// owner: f1-cli-auth-host-status

//! Terminal presentation for the command surface.
//!
//! # One decorator, not one hundred styled call sites
//!
//! Every report this CLI prints already follows one convention: a heading, then
//! rows of two spaces, a key, a run of spaces, and a value. `host show`,
//! `status`, `service status` and `service install` all emit it, and the last of
//! those is rendered by a `Display` implementation in `crates/platform` that
//! this crate cannot reach into.
//!
//! So the styling reads that convention back rather than replacing it: a command
//! renders its text exactly as it always did, and [`Ui::decorate`] turns it into
//! a titled, aligned, coloured block on the way out. Two consequences worth
//! stating plainly, because both were the point:
//!
//! * **Piped output is byte-identical to what it was.** `Styling::for_stdout`
//!   answers plain for a pipe, a file and a captured test, and [`Ui::decorate`]
//!   then passes the text through untouched. `--json` documents, every exact
//!   assertion in the suite, and `runner-manager status | grep` are unaffected.
//! * **A writer needs no knowledge of any of this.** Nothing has to be threaded
//!   through `crates/platform`, and a new report is styled by existing.
//!
//! # Why no boxes around the values
//!
//! A grid with vertical rules has to choose a width, and this tool's values are
//! Windows paths, a service's whole argument vector, and a DPAPI blob location.
//! At any width that fits an 80-column terminal those either wrap into ragged
//! fragments or force horizontal scrolling, and a table that mangles the path an
//! operator needs to copy is worse than the plain line it replaced. What is
//! drawn instead is a rule under the title, aligned keys, and colour that says
//! what a value MEANS — healthy in green, an error in red, an absence in amber.

use std::io::{self, Write};

use super::Styling;

/// The presentation layer, bound to one styling decision.
#[derive(Debug, Clone, Copy)]
pub struct Ui {
    styling: Styling,
}

/// What a value says about the state of the thing it describes.
///
/// Deliberately a small closed set rather than a colour argument at each call
/// site: "this value is bad news" is a fact about the report, and letting the
/// renderer choose the colour is what keeps two reports from disagreeing about
/// what red means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tone {
    /// Working, present, healthy.
    Good,
    /// Absent, pending, or waiting on something.
    Waiting,
    /// Broken, and the operator has to do something.
    Bad,
    /// Nothing to say about it.
    Plain,
}

impl Ui {
    /// Binds the presentation to a styling decision taken once, in `dispatch`.
    #[must_use]
    pub const fn new(styling: Styling) -> Self {
        Self { styling }
    }

    /// Writes a report, decorated when the destination is a terminal.
    ///
    /// `text` is the plain rendering — exactly what this command printed before
    /// there was any styling, and exactly what a pipe still receives.
    ///
    /// # Errors
    /// Whatever `out` fails with.
    pub fn decorate(&self, out: &mut dyn Write, text: &str) -> io::Result<()> {
        if !self.styling.is_enabled() {
            return write!(out, "{text}");
        }

        // Tab-separated rows are the other convention in here: `repo list` and
        // `org list` emit one policy per line, tab-delimited, because that is
        // what `cut -f2` wants. A terminal wants columns, so they become a table
        // -- and the pipe still gets its tabs, because this whole branch is
        // skipped when styling is off.
        let table_widths = column_widths(text);

        // The widest key, so values line up in one column. Computed over the
        // whole block rather than per line: a value that starts two characters
        // to the left of its neighbour reads as a mistake even when it is not.
        let widest = text
            .lines()
            .filter_map(parse_row)
            .map(|(key, _)| key.chars().count())
            .max()
            .unwrap_or(0);

        for line in text.lines() {
            if let Some(widths) = table_widths.as_ref()
                && line.contains('\t')
            {
                self.write_table_row(out, line, widths)?;
                continue;
            }
            match classify(line) {
                Line::Blank => writeln!(out)?,
                Line::Title(title) => {
                    writeln!(out, "{}", self.styling.heading(title))?;
                    writeln!(
                        out,
                        "{}",
                        self.styling.rule(&"─".repeat(title.chars().count()))
                    )?;
                }
                Line::Row { key, value } => {
                    let padded = format!("{key:<widest$}");
                    writeln!(
                        out,
                        "  {}  {}",
                        self.styling.key(&padded),
                        self.paint(value, tone_of(key, value))
                    )?;
                }
                Line::Prose(text) => writeln!(out, "{text}")?,
            }
        }
        Ok(())
    }

    /// A failure, and the command that clears it.
    ///
    /// # Errors
    /// Whatever `err` fails with.
    pub fn error(
        &self,
        err: &mut dyn Write,
        message: &str,
        remedy: Option<&str>,
    ) -> io::Result<()> {
        writeln!(err, "{} {message}", self.styling.failure("error:"),)?;
        if let Some(remedy) = remedy {
            writeln!(
                err,
                "  {} {}",
                self.styling.key("try:"),
                self.styling.command(remedy)
            )?;
        }
        Ok(())
    }

    /// Something the operator should know that did not stop the command.
    ///
    /// # Errors
    /// Whatever `err` fails with.
    pub fn warning(&self, err: &mut dyn Write, message: &str) -> io::Result<()> {
        writeln!(err, "{} {message}", self.styling.caution("warning:"))
    }

    /// One tab-separated row, aligned into the block's columns.
    fn write_table_row(&self, out: &mut dyn Write, line: &str, widths: &[usize]) -> io::Result<()> {
        let cells: Vec<&str> = line.split('\t').collect();
        let last = cells.len().saturating_sub(1);
        for (index, cell) in cells.iter().enumerate() {
            // The first column is the thing being listed -- a repository, an
            // organization -- so it carries the emphasis. The rest are its
            // attributes, painted by what they say.
            let painted = if index == 0 {
                self.styling.heading(cell)
            } else {
                self.paint(cell, tone_of("", cell))
            };
            if index == last {
                writeln!(out, "{painted}")?;
            } else {
                let width = widths.get(index).copied().unwrap_or(0);
                let padding = width.saturating_sub(cell.chars().count());
                write!(out, "{painted}{:padding$}  ", "")?;
            }
        }
        Ok(())
    }

    fn paint(&self, value: &str, tone: Tone) -> String {
        match tone {
            Tone::Good => self.styling.good(value),
            Tone::Waiting => self.styling.caution(value),
            Tone::Bad => self.styling.failure(value),
            Tone::Plain => value.to_string(),
        }
    }
}

/// The width of each column across every tab-separated row in a block.
///
/// `None` when there are no such rows, which is every report that is not a
/// list. Computed once for the whole block so that the columns of two rows
/// cannot disagree.
fn column_widths(text: &str) -> Option<Vec<usize>> {
    let rows: Vec<Vec<&str>> = text
        .lines()
        .filter(|line| line.contains('\t'))
        .map(|line| line.split('\t').collect())
        .collect();
    if rows.is_empty() {
        return None;
    }
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    Some(
        (0..columns)
            .map(|index| {
                rows.iter()
                    .filter_map(|row| row.get(index))
                    .map(|cell| cell.chars().count())
                    .max()
                    .unwrap_or(0)
            })
            .collect(),
    )
}

/// What one line of a report is.
enum Line<'a> {
    Blank,
    /// A heading: no indentation, and it introduces the rows under it.
    Title(&'a str),
    /// `  key    value`
    Row {
        key: &'a str,
        value: &'a str,
    },
    /// Anything else — a sentence, a note, a continuation.
    Prose(&'a str),
}

fn classify(line: &str) -> Line<'_> {
    if line.trim().is_empty() {
        return Line::Blank;
    }
    if let Some((key, value)) = parse_row(line) {
        return Line::Row { key, value };
    }
    // A heading is unindented and short enough to be one: an unindented
    // paragraph is prose, and drawing a rule under a sentence looks like a bug.
    if !line.starts_with(' ') && line.chars().count() <= 60 && !line.ends_with('.') {
        return Line::Title(line);
    }
    Line::Prose(line)
}

/// Splits `  key    value` into its two halves.
///
/// The separator is a run of TWO OR MORE spaces, which is what every report
/// here uses and what a value containing single spaces — "the Windows Service
/// Control Manager" — does not.
fn parse_row(line: &str) -> Option<(&str, &str)> {
    let indented = line.strip_prefix("  ")?;
    if indented.starts_with(' ') {
        // Deeper indentation is a continuation of the row above, not a row.
        return None;
    }
    let gap = indented.find("  ")?;
    let (key, rest) = indented.split_at(gap);
    let value = rest.trim_start();
    if key.is_empty() || value.is_empty() {
        return None;
    }
    Some((key, value))
}

/// What a value means, from the vocabulary these reports actually use.
fn tone_of(key: &str, value: &str) -> Tone {
    let key = key.to_ascii_lowercase();
    let lowered = value.to_ascii_lowercase();

    // The key carries the verdict for exactly one field, and it is the field an
    // operator scans for first.
    if key == "verdict" {
        return if lowered.contains("not") {
            Tone::Bad
        } else {
            Tone::Good
        };
    }
    if key.starts_with("error") {
        return Tone::Bad;
    }

    match lowered.as_str() {
        "running" | "healthy" | "active" | "present in the machine-scoped store" | "enabled" => {
            Tone::Good
        }
        "stopped" | "never" | "pending" | "disabled" | "no" | "draining" => Tone::Waiting,
        "revoked" | "unreachable" | "stale" | "not installed" => Tone::Bad,
        _ => Tone::Plain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A literal tab, spelled once: the separator `repo list` writes.
    const TAB: &str = "\t";

    fn rendered(styling: Styling, text: &str) -> String {
        let mut out = Vec::new();
        Ui::new(styling)
            .decorate(&mut out, text)
            .expect("writing to a Vec");
        String::from_utf8(out).expect("UTF-8")
    }

    const REPORT: &str = "Service: runner-manager\n  installed                 the Windows Service Control Manager\n  state                     running\n  verdict                   healthy\n";

    #[test]
    fn plain_styling_passes_the_report_through_byte_for_byte() {
        // The contract every pipe, every `--json` consumer and every exact
        // assertion in the suite depends on. A decorator that "only" reflowed
        // whitespace here would break `runner-manager status | grep` for
        // everyone scripting against it.
        assert_eq!(rendered(Styling::plain(), REPORT), REPORT);
    }

    #[test]
    fn styled_output_keeps_every_key_and_value_it_was_given() {
        // Decoration may add escapes, padding and rules; it may not drop or
        // reword the report. Checked by looking for the text with the escapes
        // stripped, so the assertion is about content rather than about colour.
        let styled = rendered(Styling::styled(), REPORT);
        let visible: String = strip_escapes(&styled);
        for needle in [
            "Service: runner-manager",
            "installed",
            "the Windows Service Control Manager",
            "state",
            "running",
            "verdict",
            "healthy",
        ] {
            assert!(
                visible.contains(needle),
                "decoration lost `{needle}`:\n{visible}"
            );
        }
        assert!(
            styled.contains('\u{1b}'),
            "a terminal must actually get styling:\n{styled}"
        );
    }

    #[test]
    fn values_are_aligned_on_the_widest_key() {
        let styled = strip_escapes(&rendered(Styling::styled(), REPORT));
        let columns: Vec<usize> = styled
            .lines()
            .filter(|line| line.starts_with("  "))
            .filter_map(|line| line.find("  the ").or_else(|| line.find("  running")))
            .collect();
        assert!(
            columns.windows(2).all(|pair| pair[0] == pair[1]),
            "values must start in one column: {columns:?}\n{styled}"
        );
    }

    #[test]
    fn a_bad_verdict_and_a_good_one_are_not_painted_the_same() {
        // The one assertion that would catch a tone table wired to a constant:
        // "NOT healthy" and "healthy" must differ by more than their text.
        let good = rendered(
            Styling::styled(),
            "Service: x\n  verdict                   healthy\n",
        );
        let bad = rendered(
            Styling::styled(),
            "Service: x\n  verdict                   NOT healthy\n",
        );
        let good_codes: String = escapes_only(&good);
        let bad_codes: String = escapes_only(&bad);
        assert_ne!(
            good_codes, bad_codes,
            "a healthy and an unhealthy verdict render identically:\n{good}\n{bad}"
        );
    }

    #[test]
    fn a_value_containing_single_spaces_is_not_split_into_a_row() {
        // `the Windows Service Control Manager` is one value, not a key and a
        // value: the separator is two spaces, and reading it as one would put
        // half the sentence in the key column.
        let (key, value) =
            parse_row("  installed                 the Windows Service Control Manager")
                .expect("a row");
        assert_eq!(key, "installed");
        assert_eq!(value, "the Windows Service Control Manager");
    }

    #[test]
    fn tab_separated_rows_become_columns_on_a_terminal_and_tabs_in_a_pipe() {
        // `repo list` is machine-readable output that a human also reads. The
        // tabs are what `cut -f2` needs, so they survive a pipe untouched; a
        // terminal gets the same cells aligned into columns instead.
        let list = format!(
            "short/repo{T}autoscale{T}active{T}enabled=true{T}max=1
             a-much-longer/repository-name{T}monitor{T}pending{T}enabled=false{T}max=0
",
            T = TAB
        );

        assert_eq!(
            rendered(Styling::plain(), &list),
            list,
            "a pipe must still get tab-separated fields"
        );

        let styled = strip_escapes(&rendered(Styling::styled(), &list));
        assert!(
            !styled.contains(TAB),
            "a terminal should get columns, not tabs:
{styled}"
        );
        let starts: Vec<usize> = styled
            .lines()
            .filter_map(|line| line.find("autoscale").or_else(|| line.find("monitor")))
            .collect();
        assert!(
            starts.windows(2).all(|pair| pair[0] == pair[1]),
            "the second column must start in one place: {starts:?}
{styled}"
        );
    }

    #[test]
    fn prose_and_continuations_are_left_alone() {
        assert!(matches!(
            classify("This is a sentence that explains something at length."),
            Line::Prose(_)
        ));
        assert!(matches!(classify("    a continuation"), Line::Prose(_)));
        assert!(matches!(
            classify("Service: runner-manager"),
            Line::Title(_)
        ));
    }

    fn strip_escapes(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(character) = chars.next() {
            if character == '\u{1b}' {
                for skipped in chars.by_ref() {
                    if skipped == 'm' {
                        break;
                    }
                }
            } else {
                out.push(character);
            }
        }
        out
    }

    fn escapes_only(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(character) = chars.next() {
            if character == '\u{1b}' {
                out.push(character);
                for code in chars.by_ref() {
                    out.push(code);
                    if code == 'm' {
                        break;
                    }
                }
            }
        }
        out
    }
}
