// owner: a1-wsl-platform-adapter

//! Reading `wsl.exe --list --verbose`, and deciding that a name an operator
//! typed is exactly one distribution that is really installed.
//!
//! # `wsl.exe` answers in UTF-16, and sometimes does not
//!
//! Microsoft documents `wsl --list --verbose` as the way to enumerate
//! installed distributions and versions
//! (<https://learn.microsoft.com/en-us/windows/wsl/basic-commands>). What it
//! does *not* document is the encoding, and it has changed: for most of WSL's
//! life the output has been UTF-16 little-endian — which through a redirected
//! pipe reads as ASCII interleaved with NUL bytes — and newer builds have
//! started emitting plain UTF-8 for some subcommands. A parser that assumes
//! either one is a parser that reports "no distributions are installed" on the
//! other, which is the worst possible failure here: it looks exactly like a
//! machine with no WSL, and the remedy it suggests is to install one.
//!
//! So [`decode_console_output`] decides per call, from the bytes:
//!
//! | Signal | Read as |
//! |---|---|
//! | `FF FE` byte-order mark | UTF-16LE |
//! | `EF BB BF` byte-order mark | UTF-8 |
//! | even length, and most odd-indexed bytes are NUL | UTF-16LE |
//! | anything else | UTF-8 |
//!
//! The byte-order mark is authoritative and is checked first. The NUL
//! heuristic exists for the BOM-less UTF-16 that a redirected `wsl.exe`
//! produces, and it is deliberately a *majority* test rather than an "any NUL"
//! test, so that a distribution name in Cyrillic or Japanese — whose UTF-16
//! high bytes are not NUL — is still recognised as UTF-16 on the strength of
//! the ASCII around it.
//!
//! Anything that does not decode cleanly is kept, with the replacement
//! character, and [`DecodedOutput::is_lossy`] says so. Nothing here silently
//! repairs a name: a row whose name did not survive decoding is moved to
//! [`DistributionTable::unreadable`] rather than offered as something an
//! operator may install into.
//!
//! # A name may contain spaces, so the table is parsed from the right
//!
//! ```text
//!   NAME                   STATE           VERSION
//! * Ubuntu                 Running         2
//!   Debian GNU/Linux 12    Stopped         1
//! ```
//!
//! `split_whitespace` would turn the third row's name into four fields. The
//! last two columns, however, are a single word each, so the row is cut from
//! the end: the last token is the version, the one before it is the state, and
//! everything left — trimmed — is the name, spaces, punctuation and all. The
//! header row falls out of the same rule for free, because `VERSION` does not
//! parse as a number.

use super::WslError;

/// How [`decode_console_output`] read the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleEncoding {
    /// UTF-16 little-endian, with or without a byte-order mark.
    Utf16Le,
    /// UTF-8, with or without a byte-order mark.
    Utf8,
}

/// Console output, decoded, and how it had to be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedOutput {
    text: String,
    encoding: ConsoleEncoding,
    lossy: bool,
}

impl DecodedOutput {
    /// The decoded text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The decoded text, owned.
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }

    /// Which encoding the bytes were read as.
    #[must_use]
    pub fn encoding(&self) -> ConsoleEncoding {
        self.encoding
    }

    /// Whether anything had to be replaced to produce the text.
    ///
    /// A `true` here is not fatal on its own — a diagnostic sentence with one
    /// mangled character is still a useful diagnostic — but a *name* that
    /// carries a replacement character is refused rather than used.
    #[must_use]
    pub fn is_lossy(&self) -> bool {
        self.lossy
    }
}

/// The proportion of odd-indexed NUL bytes that reads as UTF-16LE, as a
/// numerator over [`UTF16_NUL_RATIO_DENOMINATOR`].
///
/// Six in ten rather than "any": see the module documentation. A name in a
/// non-Latin script contributes non-NUL high bytes, and the column padding,
/// the state words and the version digits around it are ASCII.
///
/// Compared as integers rather than as a ratio of `f64`s, so that the decision
/// is exact for every input length rather than exact for most of them.
const UTF16_NUL_RATIO_NUMERATOR: usize = 6;
/// See [`UTF16_NUL_RATIO_NUMERATOR`].
const UTF16_NUL_RATIO_DENOMINATOR: usize = 10;

/// Decodes what a Windows console program wrote to a pipe.
#[must_use]
pub fn decode_console_output(bytes: &[u8]) -> DecodedOutput {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16le(rest);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return decode_utf8(rest);
    }
    if looks_like_utf16le(bytes) {
        return decode_utf16le(bytes);
    }
    decode_utf8(bytes)
}

/// Whether BOM-less bytes are most likely UTF-16LE.
fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 2 || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let pairs = bytes.len() / 2;
    let nul_high_bytes = bytes
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|byte| **byte == 0)
        .count();
    if nul_high_bytes == 0 {
        return false;
    }
    nul_high_bytes * UTF16_NUL_RATIO_DENOMINATOR >= pairs * UTF16_NUL_RATIO_NUMERATOR
}

fn decode_utf16le(bytes: &[u8]) -> DecodedOutput {
    // An odd trailing byte is a truncated stream, not a code unit. It is
    // dropped and reported as lossy rather than being paired with a zero,
    // which would invent a character nobody wrote.
    let truncated = !bytes.len().is_multiple_of(2);
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units);
    let lossy = truncated || text.contains(char::REPLACEMENT_CHARACTER);
    DecodedOutput {
        text,
        encoding: ConsoleEncoding::Utf16Le,
        lossy,
    }
}

fn decode_utf8(bytes: &[u8]) -> DecodedOutput {
    match std::str::from_utf8(bytes) {
        Ok(text) => DecodedOutput {
            text: text.to_string(),
            encoding: ConsoleEncoding::Utf8,
            lossy: false,
        },
        Err(_) => DecodedOutput {
            text: String::from_utf8_lossy(bytes).into_owned(),
            encoding: ConsoleEncoding::Utf8,
            lossy: true,
        },
    }
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// The longest distribution name this adapter will handle.
///
/// WSL itself imposes no documented limit, but every use here becomes part of
/// a Task Scheduler name, a file name, and an argument vector. A bound stated
/// once is better than three different truncations discovered later.
pub const MAX_DISTRIBUTION_NAME: usize = 255;

/// Checks a name's *syntax*, before it is ever put in an argument vector.
///
/// This is not "is it installed" — that is [`DistributionTable::exactly`]. It
/// is the smaller question of whether the string is safe and meaningful to
/// pass at all, and it fails closed:
///
/// * empty, or only whitespace — there is nothing to select;
/// * leading or trailing whitespace — `"Ubuntu "` and `"Ubuntu"` would look
///   the same to an operator reading a status line and be different keys;
/// * a control character or a NUL — neither can survive an argument vector or
///   a task document intact;
/// * a leading `-` — the one genuinely dangerous shape. `wsl.exe
///   --distribution --shutdown` is a name that reads as an option, and the
///   whole argument-vector discipline in this module would not save it.
///
/// # Errors
///
/// [`WslError::InvalidName`] naming which rule was broken.
pub fn validate_distribution_name(name: &str) -> Result<(), WslError> {
    let refuse = |reason: &str| {
        Err(WslError::InvalidName {
            requested: name.to_string(),
            reason: reason.to_string(),
        })
    };
    if name.is_empty() {
        return refuse("it is empty, so it names no distribution");
    }
    if name.trim() != name {
        return refuse(
            "it starts or ends with whitespace, which no `wsl --list` row reports and which \
             would make two different names print identically",
        );
    }
    if name.trim().is_empty() {
        return refuse("it is only whitespace, so it names no distribution");
    }
    if name.chars().count() > MAX_DISTRIBUTION_NAME {
        return refuse("it is longer than a distribution name may be here");
    }
    if name.chars().any(char::is_control) {
        return refuse(
            "it contains a control character, which cannot survive an argument vector or a \
             scheduled-task document intact",
        );
    }
    if name.starts_with('-') {
        return refuse(
            "it starts with `-`, so `wsl.exe` would read it as an option rather than as the \
             distribution to select",
        );
    }
    if name.contains(char::REPLACEMENT_CHARACTER) {
        return refuse(
            "it contains a Unicode replacement character, which means it was already damaged \
             by a decoding step and is not the name of anything",
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

/// One row of `wsl --list --verbose`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledDistribution {
    name: String,
    state: String,
    wsl_version: u8,
    default: bool,
}

impl InstalledDistribution {
    /// The exact name, as WSL spells it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The state word WSL printed, verbatim.
    ///
    /// **Localised.** `Running` and `Stopped` are English; a Windows in
    /// another display language prints its own words. Nothing in this adapter
    /// branches on it — running a command starts a stopped distribution
    /// anyway — so it is carried for display and for nothing else.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// 1 or 2. A larger number from a future WSL is carried, not clamped.
    #[must_use]
    pub fn wsl_version(&self) -> u8 {
        self.wsl_version
    }

    /// Whether WSL marked this row with `*`.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.default
    }

    /// Whether this is a WSL2 distribution, which is the only kind supported.
    #[must_use]
    pub fn is_wsl2(&self) -> bool {
        self.wsl_version == 2
    }

    /// Refuses anything that is not WSL2.
    ///
    /// # Errors
    ///
    /// [`WslError::NotWsl2`].
    pub fn require_wsl2(&self) -> Result<(), WslError> {
        if self.is_wsl2() {
            return Ok(());
        }
        Err(WslError::NotWsl2 {
            distribution: self.name.clone(),
            version: self.wsl_version,
        })
    }
}

/// Everything `wsl --list --verbose` reported, and everything it reported that
/// could not be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DistributionTable {
    entries: Vec<InstalledDistribution>,
    unreadable: Vec<String>,
}

impl DistributionTable {
    /// Parses the decoded table.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        let mut unreadable = Vec::new();
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() {
                continue;
            }
            let Some(row) = split_row(line) else {
                // The header, and any banner WSL decides to print, land here
                // and are simply not rows. They are not reported as damage.
                continue;
            };
            if validate_distribution_name(&row.name).is_err() {
                unreadable.push(line.trim().to_string());
                continue;
            }
            entries.push(InstalledDistribution {
                name: row.name,
                state: row.state,
                wsl_version: row.version,
                default: row.default,
            });
        }
        Self {
            entries,
            unreadable,
        }
    }

    /// Parses raw console bytes, choosing the encoding.
    #[must_use]
    pub fn from_console_output(bytes: &[u8]) -> Self {
        Self::parse(decode_console_output(bytes).text())
    }

    /// Every row that parsed.
    #[must_use]
    pub fn entries(&self) -> &[InstalledDistribution] {
        &self.entries
    }

    /// Rows that looked like rows and whose name did not survive decoding.
    ///
    /// Reported rather than dropped: an operator whose distribution is missing
    /// from `wsl list` deserves to be told that a row was unreadable, not that
    /// nothing is installed.
    #[must_use]
    pub fn unreadable(&self) -> &[String] {
        &self.unreadable
    }

    /// Whether nothing at all parsed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The row WSL marked with `*`, if any.
    #[must_use]
    pub fn default_distribution(&self) -> Option<&InstalledDistribution> {
        self.entries.iter().find(|entry| entry.default)
    }

    /// The names that parsed, in order, for an error that has to list them.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect()
    }

    /// The one row whose name is exactly `name`.
    ///
    /// Exact and case-sensitive. WSL's own `--distribution` is case-sensitive,
    /// so accepting `ubuntu` for `Ubuntu` here would produce a provider record
    /// and a task naming a distribution that `wsl.exe` then cannot select.
    ///
    /// # Errors
    ///
    /// [`WslError::InvalidName`] when the name is not usable at all;
    /// [`WslError::NotInstalled`] when nothing matches, listing what is there;
    /// [`WslError::AmbiguousName`] when two rows carry it, which means the
    /// table is not something to act on.
    pub fn exactly(&self, name: &str) -> Result<&InstalledDistribution, WslError> {
        validate_distribution_name(name)?;
        let mut found = self.entries.iter().filter(|entry| entry.name == name);
        let Some(first) = found.next() else {
            return Err(WslError::NotInstalled {
                requested: name.to_string(),
                available: self.names(),
            });
        };
        if found.next().is_some() {
            return Err(WslError::AmbiguousName {
                requested: name.to_string(),
            });
        }
        Ok(first)
    }
}

/// The three fields of one row, before validation.
struct Row {
    name: String,
    state: String,
    version: u8,
    default: bool,
}

/// Cuts a row from the right: version, then state, then everything left.
fn split_row(line: &str) -> Option<Row> {
    let trimmed = line.trim_end();
    let without_marker = trimmed.trim_start();
    let (default, rest) = match without_marker.strip_prefix('*') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, without_marker),
    };

    let version_at = rest.rfind(char::is_whitespace)? + 1;
    let version: u8 = rest.get(version_at..)?.parse().ok()?;

    let before_version = rest.get(..version_at)?.trim_end();
    let state_at = before_version.rfind(char::is_whitespace)? + 1;
    let state = before_version.get(state_at..)?;
    if state.is_empty() {
        return None;
    }

    let name = before_version.get(..state_at)?.trim_end();
    if name.is_empty() {
        return None;
    }

    Some(Row {
        name: name.to_string(),
        state: state.to_string(),
        version,
        default,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes as `wsl.exe` does through a redirected pipe: UTF-16LE, and by
    /// default without a byte-order mark.
    fn utf16le(text: &str, bom: bool) -> Vec<u8> {
        let mut bytes = if bom { vec![0xFF, 0xFE] } else { Vec::new() };
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    const TABLE: &str = concat!(
        "  NAME                  STATE           VERSION\n",
        "* Ubuntu                Running         2\n",
        "  Debian GNU/Linux 12   Stopped         2\n",
        "  Legacy                Stopped         1\n",
    );

    // -- Decoding ------------------------------------------------------------

    #[test]
    fn utf16_with_a_byte_order_mark_is_decoded_as_utf16() {
        let decoded = decode_console_output(&utf16le(TABLE, true));
        assert_eq!(decoded.encoding(), ConsoleEncoding::Utf16Le);
        assert!(!decoded.is_lossy());
        assert_eq!(decoded.text(), TABLE);
    }

    #[test]
    fn utf16_without_a_byte_order_mark_is_recognised_from_its_nul_bytes() {
        let decoded = decode_console_output(&utf16le(TABLE, false));
        assert_eq!(decoded.encoding(), ConsoleEncoding::Utf16Le);
        assert_eq!(decoded.text(), TABLE);
    }

    #[test]
    fn plain_utf8_is_left_alone() {
        let decoded = decode_console_output(TABLE.as_bytes());
        assert_eq!(decoded.encoding(), ConsoleEncoding::Utf8);
        assert!(!decoded.is_lossy());
        assert_eq!(decoded.text(), TABLE);
    }

    #[test]
    fn a_utf8_byte_order_mark_is_removed_rather_than_kept_as_a_character() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(TABLE.as_bytes());
        let decoded = decode_console_output(&bytes);
        assert_eq!(decoded.encoding(), ConsoleEncoding::Utf8);
        assert_eq!(decoded.text(), TABLE);
    }

    #[test]
    fn a_non_latin_name_is_still_recognised_as_utf16() {
        // The name's own high bytes are not NUL; the rest of the row's are.
        // This is the case the "any NUL" test would get right and a "every
        // high byte is NUL" test would get wrong.
        let table = concat!(
            "  NAME       STATE      VERSION\n",
            "* Убунту     Running    2\n",
        );
        let decoded = decode_console_output(&utf16le(table, false));
        assert_eq!(decoded.encoding(), ConsoleEncoding::Utf16Le);
        assert_eq!(decoded.text(), table);
        assert_eq!(DistributionTable::parse(decoded.text()).names(), ["Убунту"]);
    }

    #[test]
    fn malformed_utf8_is_kept_lossily_and_says_so() {
        let bytes = b"  Ubuntu \xFF\xFE\xFD Running 2\n".to_vec();
        let decoded = decode_console_output(&bytes);
        assert_eq!(decoded.encoding(), ConsoleEncoding::Utf8);
        assert!(decoded.is_lossy());
        assert!(decoded.text().contains(char::REPLACEMENT_CHARACTER));
    }

    #[test]
    fn truncated_utf16_is_lossy_rather_than_padded_into_a_character() {
        let mut bytes = utf16le("Ubuntu", true);
        bytes.push(0x41); // half a code unit
        let decoded = decode_console_output(&bytes);
        assert_eq!(decoded.encoding(), ConsoleEncoding::Utf16Le);
        assert!(decoded.is_lossy());
        assert_eq!(decoded.text(), "Ubuntu");
    }

    #[test]
    fn an_unpaired_surrogate_decodes_lossily() {
        // 0xD800 with no low surrogate: the shape a cut-off UTF-16 stream has.
        let bytes = vec![0xFF, 0xFE, 0x00, 0xD8, 0x41, 0x00];
        let decoded = decode_console_output(&bytes);
        assert!(decoded.is_lossy());
        assert!(decoded.text().contains(char::REPLACEMENT_CHARACTER));
    }

    #[test]
    fn empty_output_decodes_to_nothing_rather_than_panicking() {
        let decoded = decode_console_output(&[]);
        assert_eq!(decoded.text(), "");
        assert!(!decoded.is_lossy());
    }

    // -- Parsing -------------------------------------------------------------

    #[test]
    fn the_header_row_is_not_a_distribution() {
        let table = DistributionTable::parse(TABLE);
        assert_eq!(table.names(), ["Ubuntu", "Debian GNU/Linux 12", "Legacy"]);
        assert!(table.unreadable().is_empty());
    }

    #[test]
    fn the_default_marker_is_read_and_does_not_become_part_of_the_name() {
        let table = DistributionTable::parse(TABLE);
        assert_eq!(
            table
                .default_distribution()
                .map(InstalledDistribution::name),
            Some("Ubuntu")
        );
        assert!(!table.exactly("Legacy").expect("present").is_default());
    }

    #[test]
    fn a_name_with_spaces_and_punctuation_survives_whole() {
        let table = DistributionTable::parse(TABLE);
        let debian = table.exactly("Debian GNU/Linux 12").expect("present");
        assert_eq!(debian.name(), "Debian GNU/Linux 12");
        assert_eq!(debian.state(), "Stopped");
        assert!(debian.is_wsl2());
    }

    #[test]
    fn a_name_with_two_consecutive_spaces_keeps_both() {
        // The reason the row is cut by index rather than re-joined from
        // `split_whitespace`: re-joining would silently rename it.
        let table = DistributionTable::parse("  Two  Spaces        Running     2\n");
        assert_eq!(table.names(), ["Two  Spaces"]);
    }

    #[test]
    fn wsl1_is_listed_and_then_refused_rather_than_hidden() {
        let table = DistributionTable::parse(TABLE);
        let legacy = table.exactly("Legacy").expect("it is installed");
        assert_eq!(legacy.wsl_version(), 1);
        assert!(!legacy.is_wsl2());
        let error = legacy.require_wsl2().expect_err("WSL1 is not supported");
        assert!(
            matches!(&error, WslError::NotWsl2 { distribution, version } if distribution == "Legacy" && *version == 1),
            "{error:?}"
        );
        // The refusal has to name the distribution and the version an operator
        // would have to change.
        let message = error.to_string();
        assert!(message.contains("Legacy"), "{message}");
        assert!(
            message.contains("WSL1") || message.contains(" 1"),
            "{message}"
        );
    }

    #[test]
    fn a_row_whose_name_did_not_decode_is_reported_rather_than_offered() {
        let table = DistributionTable::parse("  Ubu\u{FFFD}ntu    Running    2\n");
        assert!(table.is_empty());
        assert_eq!(table.unreadable().len(), 1);
        assert!(table.unreadable()[0].contains("Running"));
    }

    #[test]
    fn output_with_no_rows_at_all_is_empty_and_not_an_error() {
        let table = DistributionTable::parse(
            "Windows Subsystem for Linux has no installed distributions.\n",
        );
        assert!(table.is_empty());
        assert!(table.unreadable().is_empty());
    }

    #[test]
    fn a_name_that_is_not_installed_names_what_is() {
        let table = DistributionTable::parse(TABLE);
        let error = table
            .exactly("ubuntu")
            .expect_err("the list is case-sensitive");
        let WslError::NotInstalled {
            requested,
            available,
        } = &error
        else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(requested, "ubuntu");
        assert_eq!(available, &["Ubuntu", "Debian GNU/Linux 12", "Legacy"]);
        assert!(error.to_string().contains("Ubuntu"));
    }

    #[test]
    fn two_rows_with_one_name_refuse_rather_than_pick_one() {
        let table = DistributionTable::parse(concat!(
            "  Ubuntu   Running   2\n",
            "  Ubuntu   Stopped   2\n",
        ));
        let error = table.exactly("Ubuntu").expect_err("ambiguous");
        assert!(matches!(error, WslError::AmbiguousName { .. }), "{error:?}");
    }

    #[test]
    fn a_future_wsl_version_is_carried_rather_than_clamped() {
        let table = DistributionTable::parse("  Next   Running   3\n");
        assert_eq!(table.exactly("Next").expect("present").wsl_version(), 3);
        assert!(
            table
                .exactly("Next")
                .expect("present")
                .require_wsl2()
                .is_err(),
            "only version 2 is supported, and 3 is not 2"
        );
    }

    // -- Names ---------------------------------------------------------------

    #[test]
    fn a_name_that_would_read_as_an_option_is_refused() {
        let error = validate_distribution_name("--shutdown").expect_err("refused");
        assert!(error.to_string().contains("option"), "{error}");
    }

    #[test]
    fn surrounding_whitespace_control_characters_and_emptiness_are_refused() {
        for name in ["", "   ", " Ubuntu", "Ubuntu ", "Ub\nuntu", "Ub\u{0}untu"] {
            assert!(
                validate_distribution_name(name).is_err(),
                "{name:?} should not be accepted"
            );
        }
    }

    #[test]
    fn ordinary_names_including_shell_metacharacters_are_accepted() {
        // Accepted because nothing here ever builds a shell command: the name
        // is one element of an argument vector and the metacharacters are just
        // characters. Refusing them would be security theatre that stopped an
        // operator using a distribution WSL is perfectly happy with.
        for name in ["Ubuntu", "Ubuntu-24.04", "Debian GNU/Linux 12", "a&b|c;d"] {
            validate_distribution_name(name)
                .unwrap_or_else(|error| panic!("{name:?} should be accepted: {error}"));
        }
    }

    #[test]
    fn a_name_longer_than_the_bound_is_refused() {
        let name = "u".repeat(MAX_DISTRIBUTION_NAME + 1);
        assert!(validate_distribution_name(&name).is_err());
        let name = "u".repeat(MAX_DISTRIBUTION_NAME);
        assert!(validate_distribution_name(&name).is_ok());
    }
}
