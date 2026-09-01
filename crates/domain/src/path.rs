// owner: a1-workspace-domain

//! The stored shape of an operator-configured local filesystem path.
//!
//! `02-target-architecture.md`, "Path validation", splits validation into two
//! layers "so opening the database never depends on current filesystem
//! availability". This module is the **pure** layer and nothing else: it decides
//! whether a string is a shape the product is willing to persist, and it does so
//! with no syscall, no probe, and no ambient state. The operational layer —
//! local filesystem identity, writability, canonical containment, overlap with
//! `AppPaths` — belongs to `b1` in `crates/platform`, runs before a mutation is
//! committed, and is explicitly *not* run by database load.
//!
//! Two properties follow from being pure, and both are load-bearing:
//!
//! 1. **A corrupt row is refused at load.** [`LocalAbsolutePath`] is the only way
//!    to hold a configured path, so a hand-edited `\\nas\builds` in SQLite fails
//!    closed in the domain rather than becoming a runner root on a network share
//!    (D10).
//! 2. **The rules are testable off their own platform.** Every decision here is
//!    taken against an explicit [`PathPlatform`], so the Windows UNC, device,
//!    drive-relative and reserved-name cases are covered by a Linux CI leg and
//!    the Unix cases by a Windows one. [`LocalAbsolutePath::new`] is the
//!    native-only entry point that database load, the CLI and the TUI use;
//!    [`LocalAbsolutePath::parse_for`] is the seam the tests use.
//!
//! What this module deliberately does **not** do is resolve `..`. Lexically
//! collapsing `a/../b` is wrong in the presence of a symlink, and this layer is
//! forbidden from asking the filesystem which one it has, so a traversal
//! component is rejected outright ([`LocalPathError::Traversal`]) rather than
//! normalised away. A `.` component carries no such ambiguity and is dropped.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a string is not a storable local absolute path.
///
/// Every variant carries the offending text so the CLI and TUI can say which
/// part of the operator's input failed. Paths are not credentials — no variant
/// here may ever be given a token, a JIT configuration, or any other secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocalPathError {
    #[error("a configured path must not be empty")]
    Empty,

    #[error(
        "a configured path must be absolute; {got:?} is relative, and what it \
         resolves to depends on the process working directory"
    )]
    NotAbsolute { got: String },

    #[error(
        "a configured path must name a directory below a filesystem root; {got:?} \
         is a root itself"
    )]
    RootPath { got: String },

    #[error(
        "a configured path must not contain a `..` component; {got:?} does, and \
         resolving it without the filesystem would be wrong across a symlink"
    )]
    Traversal { got: String },

    #[error(
        "a configured path must be local; {got:?} is a UNC path, and runner \
         correctness and recovery may not depend on a remote filesystem (D10)"
    )]
    Unc { got: String },

    #[error(
        "a configured path must use ordinary filesystem syntax; {got:?} is in the \
         Windows device namespace, which bypasses the rules validated here"
    )]
    DeviceNamespace { got: String },

    #[error(
        "the path component {component:?} contains a character that cannot be \
         stored: {found:?}"
    )]
    UnrepresentableCharacter { component: String, found: char },

    #[error(
        "the path component {component:?} ends with a space or a dot, which \
         Windows silently strips, so the stored path would not name the \
         directory it appears to"
    )]
    TrailingDotOrSpace { component: String },

    #[error("the path component {component:?} is a reserved Windows device name")]
    ReservedName { component: String },

    #[error("{got:?} is not a single path component")]
    NotASingleComponent { got: String },
}

// ---------------------------------------------------------------------------
// Platform seam
// ---------------------------------------------------------------------------

/// Which platform's path syntax a string is judged against.
///
/// This exists so the rules are decided by an argument rather than by
/// `cfg!(windows)` at every branch. The Windows cases below — UNC, the device
/// namespace, drive-relative paths, reserved names — are the ones that motivate
/// this whole module, and a table that only ran its Windows half on Windows
/// would not be one table, it would be two half-tested ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathPlatform {
    Windows,
    Unix,
}

impl PathPlatform {
    /// The platform this build runs on, and the only one
    /// [`LocalAbsolutePath::new`] accepts.
    pub const NATIVE: Self = if cfg!(windows) {
        PathPlatform::Windows
    } else {
        PathPlatform::Unix
    };

    /// The separator a normalised path is rendered with.
    #[must_use]
    pub const fn separator(self) -> char {
        match self {
            PathPlatform::Windows => '\\',
            PathPlatform::Unix => '/',
        }
    }

    /// Windows accepts both separators on input; Unix accepts only `/`, because
    /// a backslash is an ordinary character in a Unix file name.
    #[must_use]
    pub const fn is_separator(self, c: char) -> bool {
        match self {
            PathPlatform::Windows => c == '\\' || c == '/',
            PathPlatform::Unix => c == '/',
        }
    }
}

impl fmt::Display for PathPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathPlatform::Windows => "windows",
            PathPlatform::Unix => "unix",
        })
    }
}

// ---------------------------------------------------------------------------
// LocalAbsolutePath
// ---------------------------------------------------------------------------

/// An absolute, non-root, normalised local path, validated without touching the
/// filesystem.
///
/// This is the type `Host.runner_root_override` and
/// [`crate::workspace::WorkspacePolicy::Persistent`] are written in, so "the
/// stored value has a legal shape" is a property of the type rather than a check
/// a caller may forget — the same reasoning [`crate::model`] gives for
/// `NonZeroU16` capacity.
///
/// The stored text is normalised: separators are the platform's own, repeated
/// separators are collapsed, `.` components are dropped, a trailing separator is
/// removed, and a Windows drive letter is upper-cased. Two operators who type
/// `c:/rman/` and `C:\rman` therefore configure one value, which is what makes
/// the overlap comparisons `b1` layers on top meaningful.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LocalAbsolutePath {
    text: String,
    platform: PathPlatform,
}

impl LocalAbsolutePath {
    /// Validate against the platform this build runs on.
    ///
    /// This is the entry point for database load, the CLI and the TUI:
    /// `02-target-architecture.md` requires "an absolute path native to the
    /// current host", so a Windows path in a database opened on Linux is corrupt
    /// state and fails closed here.
    ///
    /// # Errors
    /// Any [`LocalPathError`].
    pub fn new(raw: impl AsRef<str>) -> Result<Self, LocalPathError> {
        Self::parse_for(raw, PathPlatform::NATIVE)
    }

    /// Validate against an explicit platform.
    ///
    /// # Errors
    /// Any [`LocalPathError`].
    pub fn parse_for(raw: impl AsRef<str>, platform: PathPlatform) -> Result<Self, LocalPathError> {
        let raw = raw.as_ref();
        if raw.trim().is_empty() {
            return Err(LocalPathError::Empty);
        }
        // A NUL terminates the string at every operating system API this value
        // ever reaches, so a path containing one names a different directory
        // than it reads as. It is checked before anything else because no later
        // rule would see the truncated remainder.
        if raw.contains('\0') {
            return Err(LocalPathError::UnrepresentableCharacter {
                component: raw.to_string(),
                found: '\0',
            });
        }
        let (prefix, rest) = match platform {
            PathPlatform::Windows => windows_prefix(raw)?,
            PathPlatform::Unix => unix_prefix(raw)?,
        };
        let components = normalise_components(raw, rest, platform)?;
        if components.is_empty() {
            return Err(LocalPathError::RootPath {
                got: raw.to_string(),
            });
        }
        let separator = platform.separator();
        let mut text = prefix;
        for (index, component) in components.iter().enumerate() {
            if index > 0 {
                text.push(separator);
            }
            text.push_str(component);
        }
        Ok(Self { text, platform })
    }

    /// The normalised text, exactly as it is persisted.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The same value as a [`Path`], for callers that do filesystem work with it
    /// *after* the operational preflight has passed.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.text)
    }

    /// Which platform's rules this value was accepted under.
    #[must_use]
    pub const fn platform(&self) -> PathPlatform {
        self.platform
    }

    /// A validated child directory of this path, one component down.
    ///
    /// Containment is by construction rather than by comparison: the child name
    /// is required to be a single component, so `<root>/sN` — the slot path
    /// `02-target-architecture.md` describes — cannot escape the root it was
    /// derived from however the caller spells `N`. The canonical, symlink-aware
    /// half of that check is `b1`'s operational preflight; this is the lexical
    /// half.
    ///
    /// # Errors
    /// [`LocalPathError::NotASingleComponent`] for an empty name, a separator, a
    /// `.` or a `..`, plus the platform's own component rules.
    pub fn join_child(&self, name: impl AsRef<str>) -> Result<Self, LocalPathError> {
        let name = name.as_ref();
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.chars().any(|c| self.platform.is_separator(c))
        {
            return Err(LocalPathError::NotASingleComponent {
                got: name.to_string(),
            });
        }
        validate_component(name, self.platform)?;
        let mut text = self.text.clone();
        text.push(self.platform.separator());
        text.push_str(name);
        Ok(Self {
            text,
            platform: self.platform,
        })
    }
}

impl fmt::Display for LocalAbsolutePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl TryFrom<String> for LocalAbsolutePath {
    type Error = LocalPathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LocalAbsolutePath> for String {
    fn from(value: LocalAbsolutePath) -> Self {
        value.text
    }
}

impl FromStr for LocalAbsolutePath {
    type Err = LocalPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// The rendered root of a Unix path, and the remainder to split into components.
fn unix_prefix(raw: &str) -> Result<(String, &str), LocalPathError> {
    match raw.strip_prefix('/') {
        Some(rest) => Ok(("/".to_string(), rest)),
        None => Err(LocalPathError::NotAbsolute {
            got: raw.to_string(),
        }),
    }
}

/// The rendered root of a Windows path, and the remainder to split.
///
/// The two-separator prefixes are decided first and rejected outright. Both are
/// "absolute" in the sense that they do not depend on the working directory, so
/// a plain `is_absolute` test would accept them; D10 and the device-namespace
/// rule are the reasons they are refused, not addressability.
fn windows_prefix(raw: &str) -> Result<(String, &str), LocalPathError> {
    let mut chars = raw.chars();
    let first = chars.next();
    let second = chars.next();
    if first.is_some_and(|c| PathPlatform::Windows.is_separator(c))
        && second.is_some_and(|c| PathPlatform::Windows.is_separator(c))
    {
        // `\\?\…` and `\\.\…` are the device namespace; `\\?\UNC\…` is reached
        // through it and is refused by the same arm.
        let rest = &raw[2..];
        let mut rest_chars = rest.chars();
        let marker = rest_chars.next();
        let after = rest_chars.next();
        if matches!(marker, Some('?' | '.'))
            && after.is_some_and(|c| PathPlatform::Windows.is_separator(c))
        {
            return Err(LocalPathError::DeviceNamespace {
                got: raw.to_string(),
            });
        }
        return Err(LocalPathError::Unc {
            got: raw.to_string(),
        });
    }

    let (Some(drive), Some(':')) = (first.filter(char::is_ascii_alphabetic), second) else {
        return Err(LocalPathError::NotAbsolute {
            got: raw.to_string(),
        });
    };
    // `C:work` is drive-*relative*: it resolves against the working directory
    // recorded for that drive, which is exactly the ambiguity a stored path may
    // not have.
    let rest = &raw[drive.len_utf8() + 1..];
    match rest.chars().next() {
        Some(c) if PathPlatform::Windows.is_separator(c) => {
            let prefix = format!("{}:{}", drive.to_ascii_uppercase(), '\\');
            Ok((prefix, &rest[c.len_utf8()..]))
        }
        _ => Err(LocalPathError::NotAbsolute {
            got: raw.to_string(),
        }),
    }
}

/// Split `rest` into validated components, dropping `.` and empty ones.
fn normalise_components<'a>(
    raw: &str,
    rest: &'a str,
    platform: PathPlatform,
) -> Result<Vec<&'a str>, LocalPathError> {
    let mut components = Vec::new();
    for component in rest.split(|c| platform.is_separator(c)) {
        match component {
            "" | "." => continue,
            ".." => {
                return Err(LocalPathError::Traversal {
                    got: raw.to_string(),
                });
            }
            component => {
                validate_component(component, platform)?;
                components.push(component);
            }
        }
    }
    Ok(components)
}

/// The characters Windows refuses in a file name, minus the separators, which
/// have already been consumed by the split.
const WINDOWS_RESERVED_CHARACTERS: [char; 7] = ['<', '>', ':', '"', '|', '?', '*'];

/// The device names Windows resolves before it looks at the directory tree, so a
/// directory of this name cannot be created and a path through one does not name
/// what it reads as.
const WINDOWS_RESERVED_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn validate_component(component: &str, platform: PathPlatform) -> Result<(), LocalPathError> {
    if let Some(found) = component.chars().find(|c| *c == '\0') {
        return Err(LocalPathError::UnrepresentableCharacter {
            component: component.to_string(),
            found,
        });
    }
    if platform == PathPlatform::Unix {
        // Every byte except NUL and `/` is a legal Unix file name, and inventing
        // a stricter rule here would refuse directories an operator already has.
        return Ok(());
    }
    if let Some(found) = component
        .chars()
        .find(|c| WINDOWS_RESERVED_CHARACTERS.contains(c) || c.is_control())
    {
        return Err(LocalPathError::UnrepresentableCharacter {
            component: component.to_string(),
            found,
        });
    }
    if component.ends_with(' ') || component.ends_with('.') {
        return Err(LocalPathError::TrailingDotOrSpace {
            component: component.to_string(),
        });
    }
    // Windows resolves a device name from the part before the first `.`, so
    // `com1.txt` is `COM1`. A component with no `.` at all is its own stem.
    let (stem, _) = component.split_once('.').unwrap_or((component, ""));
    let stem = stem.trim_end_matches(' ');
    if WINDOWS_RESERVED_NAMES
        .iter()
        .any(|name| stem.eq_ignore_ascii_case(name))
    {
        return Err(LocalPathError::ReservedName {
            component: component.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use PathPlatform::{Unix, Windows};

    fn parse(raw: &str, platform: PathPlatform) -> Result<LocalAbsolutePath, LocalPathError> {
        LocalAbsolutePath::parse_for(raw, platform)
    }

    fn text(raw: &str, platform: PathPlatform) -> String {
        parse(raw, platform)
            .expect("the fixture is a valid path")
            .as_str()
            .to_string()
    }

    // -- accepted shapes ----------------------------------------------------

    #[test]
    fn unix_absolute_paths_are_accepted_and_normalised() {
        let cases = [
            ("/srv/rman", "/srv/rman"),
            ("/srv/rman/", "/srv/rman"),
            ("//srv///rman//", "/srv/rman"),
            ("/srv/./rman", "/srv/rman"),
            ("/srv/rman workspaces", "/srv/rman workspaces"),
            // A backslash is an ordinary character in a Unix file name, not a
            // separator, so this is one component and not two.
            ("/srv/a\\b", "/srv/a\\b"),
            ("/rman", "/rman"),
        ];
        for (raw, expected) in cases {
            assert_eq!(text(raw, Unix), expected, "input {raw:?}");
        }
    }

    #[test]
    fn windows_drive_paths_are_accepted_and_normalised() {
        let cases = [
            ("C:\\rman", "C:\\rman"),
            ("c:/rman", "C:\\rman"),
            ("c:\\rman\\", "C:\\rman"),
            ("D:\\rman\\\\workspaces//x", "D:\\rman\\workspaces\\x"),
            ("C:\\rman\\.\\slots", "C:\\rman\\slots"),
            ("Z:/builds/runner root", "Z:\\builds\\runner root"),
        ];
        for (raw, expected) in cases {
            assert_eq!(text(raw, Windows), expected, "input {raw:?}");
        }
    }

    #[test]
    fn the_windows_default_root_shape_is_representable() {
        // D1: `%SystemDrive%\rman`, normally `C:\rman`. The drive letter is not
        // assumed anywhere in this crate; both spellings must survive.
        assert_eq!(text("C:\\rman", Windows), "C:\\rman");
        assert_eq!(text("E:\\rman", Windows), "E:\\rman");
    }

    // -- rejected shapes ----------------------------------------------------

    #[test]
    fn relative_paths_are_rejected_on_both_platforms() {
        for raw in ["rman", "./rman", "../rman", "srv/rman", ""] {
            assert!(
                parse(raw, Unix).is_err(),
                "unix accepted the relative path {raw:?}"
            );
            assert!(
                parse(raw, Windows).is_err(),
                "windows accepted the relative path {raw:?}"
            );
        }
        assert_eq!(
            parse("rman", Unix),
            Err(LocalPathError::NotAbsolute {
                got: "rman".to_string()
            })
        );
        assert_eq!(parse("   ", Unix), Err(LocalPathError::Empty));
    }

    #[test]
    fn windows_rooted_and_drive_relative_paths_are_not_absolute() {
        // `\rman` is rooted on the current drive and `C:rman` on the current
        // directory of drive C: both depend on process state.
        for raw in ["\\rman", "/rman", "C:rman", "C:"] {
            assert_eq!(
                parse(raw, Windows),
                Err(LocalPathError::NotAbsolute {
                    got: raw.to_string()
                }),
                "input {raw:?}"
            );
        }
    }

    #[test]
    fn filesystem_roots_are_rejected() {
        for raw in ["/", "/.", "/./"] {
            assert_eq!(
                parse(raw, Unix),
                Err(LocalPathError::RootPath {
                    got: raw.to_string()
                }),
                "input {raw:?}"
            );
        }
        for raw in ["C:\\", "c:/", "C:\\.\\", "D:\\\\"] {
            assert_eq!(
                parse(raw, Windows),
                Err(LocalPathError::RootPath {
                    got: raw.to_string()
                }),
                "input {raw:?}"
            );
        }
    }

    #[test]
    fn traversal_is_rejected_rather_than_resolved() {
        for raw in ["/srv/../etc", "/srv/rman/..", "/../srv"] {
            assert_eq!(
                parse(raw, Unix),
                Err(LocalPathError::Traversal {
                    got: raw.to_string()
                }),
                "input {raw:?}"
            );
        }
        for raw in ["C:\\rman\\..\\Windows", "C:\\..", "C:/rman/../x"] {
            assert_eq!(
                parse(raw, Windows),
                Err(LocalPathError::Traversal {
                    got: raw.to_string()
                }),
                "input {raw:?}"
            );
        }
    }

    #[test]
    fn unc_paths_are_rejected() {
        for raw in [
            "\\\\nas\\builds",
            "//nas/builds",
            "\\\\nas\\builds\\rman",
            "\\\\127.0.0.1\\c$",
        ] {
            assert_eq!(
                parse(raw, Windows),
                Err(LocalPathError::Unc {
                    got: raw.to_string()
                }),
                "input {raw:?}"
            );
        }
    }

    #[test]
    fn device_namespace_paths_are_rejected() {
        for raw in [
            "\\\\?\\C:\\rman",
            "\\\\.\\PhysicalDrive0",
            "\\\\?\\UNC\\nas\\builds",
            "//?/C:/rman",
        ] {
            assert_eq!(
                parse(raw, Windows),
                Err(LocalPathError::DeviceNamespace {
                    got: raw.to_string()
                }),
                "input {raw:?}"
            );
        }
    }

    #[test]
    fn windows_unrepresentable_components_are_rejected() {
        // The offending *component* is asserted alongside the variant: an error
        // that reported the whole raw path would tell the operator to fix the
        // wrong part of their input.
        let cases = [
            (
                "C:\\rman\\a<b",
                LocalPathError::UnrepresentableCharacter {
                    component: "a<b".to_string(),
                    found: '<',
                },
            ),
            (
                "C:\\rman\\a|b",
                LocalPathError::UnrepresentableCharacter {
                    component: "a|b".to_string(),
                    found: '|',
                },
            ),
            (
                "C:\\rman\\a:b",
                LocalPathError::UnrepresentableCharacter {
                    component: "a:b".to_string(),
                    found: ':',
                },
            ),
            (
                "C:\\rman\\slots.",
                LocalPathError::TrailingDotOrSpace {
                    component: "slots.".to_string(),
                },
            ),
            (
                "C:\\rman\\slots ",
                LocalPathError::TrailingDotOrSpace {
                    component: "slots ".to_string(),
                },
            ),
            (
                "C:\\rman\\NUL",
                LocalPathError::ReservedName {
                    component: "NUL".to_string(),
                },
            ),
            (
                "C:\\rman\\com1.txt",
                LocalPathError::ReservedName {
                    component: "com1.txt".to_string(),
                },
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(parse(raw, Windows), Err(expected), "input {raw:?}");
        }
    }

    #[test]
    fn an_interior_nul_is_rejected_on_every_platform() {
        for platform in [Unix, Windows] {
            assert_eq!(
                parse("/srv/rm\0an", platform),
                Err(LocalPathError::UnrepresentableCharacter {
                    component: "/srv/rm\0an".to_string(),
                    found: '\0',
                }),
                "platform {platform}"
            );
        }
    }

    #[test]
    fn a_windows_path_is_not_a_unix_path_and_the_reverse() {
        // The property database load depends on: a row written by a Windows host
        // is corrupt state on a Linux host rather than a silently relative path.
        assert!(parse("C:\\rman", Unix).is_err());
        assert!(parse("/srv/rman", Windows).is_err());
    }

    // -- derived paths ------------------------------------------------------

    #[test]
    fn join_child_appends_one_validated_component() {
        let root = parse("/srv/rman", Unix).expect("valid root");
        assert_eq!(
            root.join_child("s1").expect("valid child").as_str(),
            "/srv/rman/s1"
        );

        let root = parse("C:\\rman", Windows).expect("valid root");
        assert_eq!(
            root.join_child("s12").expect("valid child").as_str(),
            "C:\\rman\\s12"
        );
    }

    #[test]
    fn join_child_refuses_anything_that_is_not_one_component() {
        let root = parse("/srv/rman", Unix).expect("valid root");
        for name in ["", ".", "..", "a/b", "/abs"] {
            assert_eq!(
                root.join_child(name),
                Err(LocalPathError::NotASingleComponent {
                    got: name.to_string()
                }),
                "child {name:?}"
            );
        }

        let root = parse("C:\\rman", Windows).expect("valid root");
        for name in ["a\\b", "a/b", ".."] {
            assert_eq!(
                root.join_child(name),
                Err(LocalPathError::NotASingleComponent {
                    got: name.to_string()
                }),
                "child {name:?}"
            );
        }
        assert!(matches!(
            root.join_child("NUL"),
            Err(LocalPathError::ReservedName { .. })
        ));
    }

    // -- representation -----------------------------------------------------

    /// A path this build's own platform accepts, for the round-trip tests.
    fn native_fixture() -> &'static str {
        if cfg!(windows) {
            "C:\\rman"
        } else {
            "/srv/rman"
        }
    }

    #[test]
    fn the_native_entry_point_uses_the_native_platform() {
        let value = LocalAbsolutePath::new(native_fixture()).expect("valid native path");
        assert_eq!(value.platform(), PathPlatform::NATIVE);
        assert_eq!(value.as_path(), Path::new(value.as_str()));
    }

    #[test]
    fn serde_round_trips_through_the_normalised_string() {
        let value = LocalAbsolutePath::new(native_fixture()).expect("valid native path");
        let encoded = serde_json::to_string(&value).expect("serialisable");
        assert_eq!(
            encoded,
            serde_json::to_string(value.as_str()).expect("serialisable")
        );
        let decoded: LocalAbsolutePath = serde_json::from_str(&encoded).expect("deserialisable");
        assert_eq!(decoded, value);
    }

    #[test]
    fn deserialising_an_illegal_shape_fails_closed() {
        for encoded in ["\"\"", "\"rman\"", "\"\\\\\\\\nas\\\\builds\""] {
            assert!(
                serde_json::from_str::<LocalAbsolutePath>(encoded).is_err(),
                "accepted {encoded}"
            );
        }
    }

    #[test]
    fn display_and_from_str_agree_with_the_stored_text() {
        let value: LocalAbsolutePath = native_fixture().parse().expect("valid native path");
        assert_eq!(value.to_string(), value.as_str());
        assert_eq!(String::from(value.clone()), value.as_str());
    }
}
