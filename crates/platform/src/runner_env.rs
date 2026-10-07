//! The environment a native runner starts with, beyond what the daemon has.
//!
//! A runner inherits the daemon's environment, and a service's environment is
//! not a login shell's. On macOS launchd starts the agent with
//! `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and no `LANG`, so a job finds no
//! Homebrew tool (`actions/cache` falls back from `zstd` to gzip and never
//! hits), and nothing the operator put in a shell profile reaches it. A classic
//! runner gets those from the `.env` and `.path` files its `config.sh` writes;
//! a just-in-time runner never runs `config.sh`.
//!
//! Two things fill the gap, applied to every native runner in this order, each
//! overriding the one before:
//!
//! 1. **Platform defaults** ([`platform_defaults`]): on macOS, Homebrew's
//!    directories ahead of the inherited `PATH` and a UTF-8 `LANG`; on Windows,
//!    a profile of the runner's own (`USERPROFILE`, `HOME`, `APPDATA`,
//!    `LOCALAPPDATA`) inside the attempt, so concurrent jobs stop sharing the
//!    service account's `~/.bun`, npm cache and pnpm store. Linux has none.
//! 2. **The host's `runner.env`** ([`RunnerEnv`]): `KEY=VALUE` lines in the
//!    configuration directory, edited with `runner-manager host env`. A name
//!    set here replaces the platform default of the same name outright.
//!
//! The per-attempt temporary directory (`TMPDIR`, `TEMP`, `TMP`) is applied
//! last and cannot be overridden, and neither can GitHub's
//! `ACTIONS_RUNNER_INPUT_*` inputs, one of which carries the JIT
//! configuration: [`RESERVED_NAMES`] and [`RESERVED_PREFIX`].
//!
//! # Not a secret store
//!
//! The file is plain text in the configuration directory and every runner's
//! environment can read it back. Nothing here logs or prints a value except
//! `host env show`, which exists to show them; errors name a line or a
//! variable, never what it was set to.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

/// The file's name inside the configuration directory.
pub const RUNNER_ENV_FILE: &str = "runner.env";

/// Names `runner.env` may not set, compared without regard to case: the
/// temporary directory is per attempt, and cleanup and isolation rely on it.
pub const RESERVED_NAMES: [&str; 3] = ["TMPDIR", "TEMP", "TMP"];

/// The prefix of every name `runner.env` may not set: the listener reads each
/// such variable as a command-line input, including the JIT configuration
/// that registers it.
pub const RESERVED_PREFIX: &str = "ACTIONS_RUNNER_INPUT_";

/// macOS directories put ahead of the inherited `PATH`, when they exist and
/// are not on it already: Apple Silicon Homebrew, then Intel Homebrew.
pub const MACOS_TOOL_DIRECTORIES: [&str; 3] =
    ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin"];

/// The `PATH` launchd gives a service, kept behind Homebrew's directories when
/// the daemon has no `PATH` of its own.
pub const MACOS_SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The `LANG` a macOS runner gets when the daemon has none. It is what
/// `config.sh` would have recorded from a default macOS terminal, and without a
/// UTF-8 locale Ruby, CocoaPods and Python mis-handle non-ASCII text.
pub const MACOS_DEFAULT_LANG: &str = "en_US.UTF-8";

/// The `runner.env` path for a configuration directory.
#[must_use]
pub fn path_in(config_dir: &Path) -> PathBuf {
    config_dir.join(RUNNER_ENV_FILE)
}

/// Why a `runner.env` line or assignment was refused, or the file could not
/// be read or written. No variant carries a value.
#[derive(Debug, thiserror::Error)]
pub enum RunnerEnvError {
    #[error("{}is not KEY=VALUE", at(*.line))]
    NotAnAssignment { line: Option<usize> },
    #[error(
        "{}the name before `=` is not a valid environment variable name; use letters, \
         digits and `_`, not starting with a digit",
        at(*.line)
    )]
    InvalidName { line: Option<usize> },
    #[error(
        "{}`{name}` is set by runner-manager for every runner and cannot be changed",
        at(*.line)
    )]
    Reserved { line: Option<usize>, name: String },
    #[error("line {line} sets `{name}` a second time")]
    Duplicate { line: usize, name: String },
    #[error(
        "{}the value of `{name}` contains a line break or a NUL character, which runner.env \
         cannot hold",
        at(*.line)
    )]
    LineBreak { line: Option<usize>, name: String },
    #[error("cannot {action} {}: {source}", path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn at(line: Option<usize>) -> String {
    line.map_or_else(String::new, |line| format!("line {line}: "))
}

/// One line of the file. Comments and blank lines are kept so that
/// `host env set` and `unset` do not discard what an operator wrote by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Text(String),
    Entry { name: String, value: String },
}

/// The parsed `runner.env`: ordered, one entry per name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunnerEnv {
    lines: Vec<Line>,
}

impl RunnerEnv {
    /// Parses the file's text. Blank lines and lines starting with `#` are
    /// kept as text; every other line must be `NAME=VALUE`. The value is
    /// everything after the first `=`, verbatim: no quoting, no expansion.
    ///
    /// # Errors
    /// The first line that is not an assignment, has an invalid or reserved
    /// name, or repeats a name.
    pub fn parse(text: &str) -> Result<Self, RunnerEnvError> {
        let mut env = Self::default();
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let raw = raw.strip_suffix('\r').unwrap_or(raw);
            let trimmed = raw.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                env.lines.push(Line::Text(raw.to_owned()));
                continue;
            }
            let (name, value) = trimmed
                .split_once('=')
                .ok_or(RunnerEnvError::NotAnAssignment { line: Some(line) })?;
            let name = name.trim_end();
            validate_name(name, Some(line))?;
            // A NUL cannot reach a process environment: the launch would fail
            // with nothing naming this file as the cause.
            if value.contains('\0') {
                return Err(RunnerEnvError::LineBreak {
                    line: Some(line),
                    name: name.to_owned(),
                });
            }
            if env.get(name).is_some() {
                return Err(RunnerEnvError::Duplicate {
                    line,
                    name: name.to_owned(),
                });
            }
            env.lines.push(Line::Entry {
                name: name.to_owned(),
                value: value.to_owned(),
            });
        }
        Ok(env)
    }

    /// Reads `path`; a file that does not exist is an empty environment.
    ///
    /// # Errors
    /// [`RunnerEnvError::Io`] when the file exists and cannot be read, and the
    /// [`Self::parse`] errors.
    pub fn load(path: &Path) -> Result<Self, RunnerEnvError> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(RunnerEnvError::Io {
                action: "read",
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Writes the file atomically: a reader sees the old file or the new one,
    /// never a partial one. Created owner-only where the platform has modes,
    /// since an operator may put something sensitive here regardless.
    ///
    /// On Unix the replacement keeps the existing file's owner and mode, and a
    /// new file takes its directory's owner, best effort: the daemon may run as
    /// another account than this command (a `sudo` edit of a user agent's
    /// file), and a file it cannot read stops every native launch.
    ///
    /// # Errors
    /// [`RunnerEnvError::Io`].
    pub fn save(&self, path: &Path) -> Result<(), RunnerEnvError> {
        let failed = |action, source| RunnerEnvError::Io {
            action,
            path: path.to_path_buf(),
            source,
        };
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| failed("create the directory of", source))?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|source| failed("write", source))?;
        temporary
            .write_all(self.render().as_bytes())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|source| failed("write", source))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            let existing = fs::metadata(path).ok();
            if let Some(owner) = existing.clone().or_else(|| fs::metadata(parent).ok()) {
                // Fails without privilege unless the owner is already this
                // account, which is the case this exists for.
                let _ = std::os::unix::fs::chown(
                    temporary.path(),
                    Some(owner.uid()),
                    Some(owner.gid()),
                );
            }
            if let Some(existing) = existing {
                let mode = existing.permissions().mode() & 0o777;
                temporary
                    .as_file()
                    .set_permissions(fs::Permissions::from_mode(mode))
                    .map_err(|source| failed("write", source))?;
            }
        }
        temporary
            .persist(path)
            .map(|_| ())
            .map_err(|error| failed("replace", error.error))
    }

    /// The file's text.
    fn render(&self) -> String {
        let mut text = String::new();
        for line in &self.lines {
            match line {
                Line::Text(raw) => text.push_str(raw),
                Line::Entry { name, value } => {
                    text.push_str(name);
                    text.push('=');
                    text.push_str(value);
                }
            }
            text.push('\n');
        }
        text
    }

    /// Sets `name`, replacing its value in place if it is already set.
    /// Returns whether it was already set.
    ///
    /// # Errors
    /// An invalid or reserved name, or a value with a line break.
    pub fn set(&mut self, name: &str, value: &str) -> Result<bool, RunnerEnvError> {
        validate_name(name, None)?;
        if value.contains(['\n', '\r', '\0']) {
            return Err(RunnerEnvError::LineBreak {
                line: None,
                name: name.to_owned(),
            });
        }
        for line in &mut self.lines {
            if let Line::Entry {
                name: existing,
                value: current,
            } = line
                && same_name(existing, name)
            {
                *current = value.to_owned();
                return Ok(true);
            }
        }
        self.lines.push(Line::Entry {
            name: name.to_owned(),
            value: value.to_owned(),
        });
        Ok(false)
    }

    /// Removes `name`. Returns whether it was set.
    pub fn unset(&mut self, name: &str) -> bool {
        let before = self.lines.len();
        self.lines.retain(
            |line| !matches!(line, Line::Entry { name: existing, .. } if same_name(existing, name)),
        );
        self.lines.len() != before
    }

    /// The value of `name`, if set.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries()
            .find(|(existing, _)| same_name(existing, name))
            .map(|(_, value)| value)
    }

    /// Every `(name, value)`, in file order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.lines.iter().filter_map(|line| match line {
            Line::Entry { name, value } => Some((name.as_str(), value.as_str())),
            Line::Text(_) => None,
        })
    }

    /// How many variables are set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries().count()
    }

    /// Whether no variable is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Splits a `NAME=VALUE` command-line argument.
///
/// # Errors
/// [`RunnerEnvError::NotAnAssignment`] without an `=`.
pub fn split_assignment(raw: &str) -> Result<(&str, &str), RunnerEnvError> {
    raw.split_once('=')
        .ok_or(RunnerEnvError::NotAnAssignment { line: None })
}

/// Whether `name` is one this file may set: a portable environment variable
/// name that is not [reserved](RESERVED_NAMES).
fn validate_name(name: &str, line: Option<usize>) -> Result<(), RunnerEnvError> {
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(RunnerEnvError::InvalidName { line });
    }
    if is_reserved(name) {
        return Err(RunnerEnvError::Reserved {
            line,
            name: name.to_owned(),
        });
    }
    Ok(())
}

/// Whether `name` is reserved, without regard to case: Windows treats `Tmp`
/// and `TMP` as one variable.
fn is_reserved(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with(RESERVED_PREFIX) || RESERVED_NAMES.contains(&upper.as_str())
}

/// Whether two names are the same variable on this platform.
pub(crate) fn same_name(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

// ---------------------------------------------------------------------------
// Platform defaults
// ---------------------------------------------------------------------------

/// Which platform's defaults to compute. A parameter rather than a `cfg` so
/// that every leg of CI tests every platform's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerPlatform {
    Windows,
    MacOs,
    Linux,
}

impl RunnerPlatform {
    /// The platform this binary was built for.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

/// What the daemon's own environment holds, as far as the defaults care.
#[derive(Debug, Clone, Default)]
pub struct Inherited {
    pub path: Option<OsString>,
    /// Whether `LANG` or `LC_ALL` is set.
    pub has_locale: bool,
}

impl Inherited {
    /// This process's environment.
    #[must_use]
    pub fn current() -> Self {
        Self {
            path: std::env::var_os("PATH"),
            has_locale: std::env::var_os("LANG").is_some() || std::env::var_os("LC_ALL").is_some(),
        }
    }
}

/// The directory inside an attempt that is its runner's profile on Windows.
pub const RUNNER_HOME_DIR: &str = "home";

/// The variables [`platform_defaults`] sets on Windows, in order: the profile
/// directory twice, then its roaming and local application data.
pub const WINDOWS_PROFILE_VARIABLES: [&str; 4] = ["USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA"];

/// The [`platform_defaults`] that name a directory the caller must create.
/// Creating them creates the profile directory above them too.
pub const DIRECTORY_VARIABLES: [&str; 2] = ["APPDATA", "LOCALAPPDATA"];

/// The variables `platform` sets for a runner whose attempt directory is
/// `runtime`, before `runner.env` is applied.
///
/// - **macOS:** `PATH` with each of [`MACOS_TOOL_DIRECTORIES`] that exists
///   (`exists`) and is not already listed put in front, when any is; `LANG`
///   as [`MACOS_DEFAULT_LANG`] when the daemon has no locale.
/// - **Windows:** `USERPROFILE` and `HOME` at `<runtime>\home`, and `APPDATA`
///   and `LOCALAPPDATA` under it, as a logged-in profile lays them out. The
///   directories are the caller's to create. Per attempt rather than shared,
///   so one job's caches and configuration cannot reach the next job, and
///   they go when the attempt's directory goes. .NET's known-folder APIs
///   (`Environment.GetFolderPath`) ask Windows rather than these variables
///   and still answer with the service account's profile.
/// - **Linux:** nothing.
#[must_use]
pub fn platform_defaults(
    platform: RunnerPlatform,
    runtime: &Path,
    inherited: &Inherited,
    exists: impl Fn(&Path) -> bool,
) -> Vec<(&'static str, OsString)> {
    match platform {
        RunnerPlatform::Linux => Vec::new(),
        RunnerPlatform::Windows => {
            let home = runtime.join(RUNNER_HOME_DIR);
            let app_data = home.join("AppData");
            let [user_profile, home_name, roaming, local] = WINDOWS_PROFILE_VARIABLES;
            vec![
                (user_profile, home.clone().into_os_string()),
                (home_name, home.into_os_string()),
                (roaming, app_data.join("Roaming").into_os_string()),
                (local, app_data.join("Local").into_os_string()),
            ]
        }
        RunnerPlatform::MacOs => {
            let mut defaults = Vec::new();
            let listed: Vec<&OsStr> = inherited
                .path
                .as_deref()
                .map(|path| split_colon_path(path))
                .unwrap_or_default();
            let missing: Vec<&str> = MACOS_TOOL_DIRECTORIES
                .into_iter()
                .filter(|dir| exists(Path::new(dir)) && !listed.contains(&OsStr::new(dir)))
                .collect();
            if !missing.is_empty() {
                let mut path = OsString::from(missing.join(":"));
                path.push(":");
                // With no `PATH` at all a program search falls back to the
                // system's own directories; a `PATH` naming only Homebrew would
                // take those away, so they are spelled out instead.
                match inherited.path.as_deref().filter(|p| !p.is_empty()) {
                    Some(inherited) => path.push(inherited),
                    None => path.push(MACOS_SYSTEM_PATH),
                }
                defaults.push(("PATH", path));
            }
            if !inherited.has_locale {
                defaults.push(("LANG", OsString::from(MACOS_DEFAULT_LANG)));
            }
            defaults
        }
    }
}

/// The entries of a `:`-separated `PATH`, as bytes on Unix and as text
/// elsewhere (where this is only ever exercised by tests).
fn split_colon_path(path: &OsStr) -> Vec<&OsStr> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_bytes()
            .split(|byte| *byte == b':')
            .map(OsStr::from_bytes)
            .collect()
    }
    #[cfg(not(unix))]
    {
        path.to_str()
            .map(|text| text.split(':').map(OsStr::new).collect())
            .unwrap_or_default()
    }
}

/// The variables a native runner starts with on top of the daemon's
/// environment, in the order they must be applied: the platform defaults, then
/// the dependency caches (`crate::dependency_cache`), then `file`. Applied in
/// order the last value for a name wins, as it does for `Command::env`, so
/// `file` overrides a cache or a default of the same name.
#[must_use]
pub fn runner_environment(
    defaults: Vec<(&'static str, OsString)>,
    caches: Vec<(&'static str, OsString)>,
    file: &RunnerEnv,
) -> Vec<(OsString, OsString)> {
    defaults
        .into_iter()
        .chain(caches)
        .map(|(name, value)| (OsString::from(name), value))
        .chain(
            file.entries()
                .map(|(name, value)| (OsString::from(name), OsString::from(value))),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_parses_keeps_comments_and_round_trips() {
        let text = "# caches off the boot volume\n\nELECTRON_CACHE=/Volumes/NVME/cache/electron\n\
                    npm_config_cache=/Volumes/NVME/cache/npm\nEMPTY=\nURL=https://x/?a=b\n";
        let env = RunnerEnv::parse(text).unwrap();
        assert_eq!(
            env.entries().collect::<Vec<_>>(),
            [
                ("ELECTRON_CACHE", "/Volumes/NVME/cache/electron"),
                ("npm_config_cache", "/Volumes/NVME/cache/npm"),
                ("EMPTY", ""),
                ("URL", "https://x/?a=b"),
            ]
        );
        assert_eq!(env.render(), text);
        assert_eq!(
            RunnerEnv::parse("A=1\r\nB=2\r\n").unwrap().get("B"),
            Some("2")
        );
    }

    #[test]
    fn a_bad_line_is_named_by_number_and_never_echoed() {
        let secret = "ghp_notarealtokenbutshapedlikeone";
        for (text, expected) in [
            (format!("A=1\n{secret}\n"), "line 2: is not KEY=VALUE"),
            (format!("A=1\n1BAD={secret}\n"), "line 2: the name"),
            (
                format!("TMP={secret}\n"),
                "line 1: `TMP` is set by runner-manager",
            ),
            (
                format!("actions_runner_input_url={secret}\n"),
                "`actions_runner_input_url` is set by runner-manager",
            ),
            (
                format!("A=1\nA={secret}\n"),
                "line 2 sets `A` a second time",
            ),
            (
                format!("A=1\nB={secret}\0\n"),
                "line 2: the value of `B` contains a line break or a NUL",
            ),
        ] {
            let error = RunnerEnv::parse(&text).unwrap_err().to_string();
            assert!(error.contains(expected), "{error:?} lacks {expected:?}");
            assert!(!error.contains(secret), "an error echoed a value: {error}");
        }
    }

    #[test]
    fn reserved_names_cover_the_temporary_directory_and_every_runner_input() {
        for name in [
            "TMPDIR",
            "TEMP",
            "TMP",
            "Tmp",
            "ACTIONS_RUNNER_INPUT_JITCONFIG",
            "ACTIONS_RUNNER_INPUT_URL",
        ] {
            assert!(is_reserved(name), "{name}");
        }
        for name in ["TMPX", "PATH", "ACTIONS_RUNNER_HOOK_JOB_STARTED", "HOME"] {
            assert!(!is_reserved(name), "{name}");
        }
    }

    #[test]
    fn set_replaces_in_place_and_unset_removes_only_the_entry() {
        let mut env = RunnerEnv::parse("# keep me\nA=1\nB=2\n").unwrap();
        assert!(env.set("A", "one").unwrap());
        assert!(!env.set("C", "3").unwrap());
        assert!(env.unset("B"));
        assert!(!env.unset("B"));
        assert_eq!(env.render(), "# keep me\nA=one\nC=3\n");
        assert!(matches!(
            env.set("D", "two\nlines"),
            Err(RunnerEnvError::LineBreak { .. })
        ));
        assert!(matches!(
            env.set("TEMP", "x"),
            Err(RunnerEnvError::Reserved { .. })
        ));
        assert!(matches!(
            env.set("NOT-A-NAME", "x"),
            Err(RunnerEnvError::InvalidName { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn saving_keeps_the_mode_of_the_file_it_replaces() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = path_in(directory.path());
        let mut env = RunnerEnv::default();
        env.set("A", "1").unwrap();
        env.save(&path).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "a new file is owner-only");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        env.set("B", "2").unwrap();
        env.save(&path).unwrap();
        assert_eq!(mode(&path), 0o644, "the replacement reset the file's mode");
    }

    #[test]
    fn a_missing_file_is_empty_and_a_saved_file_loads_back() {
        let directory = tempfile::tempdir().unwrap();
        let path = path_in(directory.path());
        assert!(RunnerEnv::load(&path).unwrap().is_empty());

        let mut env = RunnerEnv::default();
        env.set("npm_config_cache", "/cache/npm").unwrap();
        env.save(&path).unwrap();
        assert_eq!(RunnerEnv::load(&path).unwrap(), env);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "npm_config_cache=/cache/npm\n"
        );
    }

    fn defaults(platform: RunnerPlatform, inherited: &Inherited) -> Vec<(&'static str, OsString)> {
        platform_defaults(platform, Path::new("/rman/a1"), inherited, |dir| {
            dir != Path::new("/usr/local/bin")
        })
    }

    #[test]
    fn macos_puts_existing_homebrew_directories_ahead_of_the_service_path() {
        let launchd = Inherited {
            path: Some("/usr/bin:/bin:/usr/sbin:/sbin".into()),
            has_locale: false,
        };
        assert_eq!(
            defaults(RunnerPlatform::MacOs, &launchd),
            [
                (
                    "PATH",
                    OsString::from(
                        "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin"
                    )
                ),
                ("LANG", OsString::from(MACOS_DEFAULT_LANG)),
            ]
        );

        // A directory already listed is not added twice, and a daemon with a
        // locale keeps it.
        let login = Inherited {
            path: Some("/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin".into()),
            has_locale: true,
        };
        assert!(defaults(RunnerPlatform::MacOs, &login).is_empty());

        // A daemon with no PATH keeps the system directories behind Homebrew's.
        let bare = Inherited {
            path: None,
            has_locale: true,
        };
        assert_eq!(
            defaults(RunnerPlatform::MacOs, &bare),
            [(
                "PATH",
                OsString::from(format!(
                    "/opt/homebrew/bin:/opt/homebrew/sbin:{MACOS_SYSTEM_PATH}"
                ))
            )]
        );
    }

    #[test]
    fn windows_gives_each_runner_a_profile_inside_its_attempt() {
        let windows = defaults(RunnerPlatform::Windows, &Inherited::default());
        let home = Path::new("/rman/a1").join(RUNNER_HOME_DIR);
        assert_eq!(
            windows,
            [
                ("USERPROFILE", home.clone().into_os_string()),
                ("HOME", home.clone().into_os_string()),
                (
                    "APPDATA",
                    home.join("AppData").join("Roaming").into_os_string()
                ),
                (
                    "LOCALAPPDATA",
                    home.join("AppData").join("Local").into_os_string()
                ),
            ]
        );
        assert!(defaults(RunnerPlatform::Linux, &Inherited::default()).is_empty());
    }

    #[test]
    fn runner_env_replaces_a_default_of_the_same_name_and_adds_the_rest() {
        let file = RunnerEnv::parse("PATH=/custom/bin\nELECTRON_CACHE=/cache/electron\n").unwrap();
        let defaults = vec![
            ("PATH", OsString::from("/opt/homebrew/bin:/usr/bin")),
            ("LANG", OsString::from(MACOS_DEFAULT_LANG)),
        ];
        assert_eq!(
            runner_environment(defaults, Vec::new(), &file),
            [
                (
                    OsString::from("PATH"),
                    OsString::from("/opt/homebrew/bin:/usr/bin")
                ),
                (OsString::from("LANG"), OsString::from(MACOS_DEFAULT_LANG)),
                (OsString::from("PATH"), OsString::from("/custom/bin")),
                (
                    OsString::from("ELECTRON_CACHE"),
                    OsString::from("/cache/electron")
                ),
            ]
        );
    }

    /// Platform defaults < dependency caches < `runner.env`: a cache variable
    /// replaces a default of the same name, and `runner.env` replaces both.
    #[test]
    fn caches_sit_between_the_platform_defaults_and_runner_env() {
        let file = RunnerEnv::parse("npm_config_cache=/operator/npm\n").unwrap();
        let defaults = vec![("HOME", OsString::from("/attempt/home"))];
        let caches = vec![
            ("npm_config_cache", OsString::from("/cache/o/r/npm")),
            ("HOME", OsString::from("/cache-would-never-set-this")),
        ];
        let applied = runner_environment(defaults, caches, &file);
        let last = |name: &str| {
            applied
                .iter()
                .rev()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(last("npm_config_cache"), Some("/operator/npm".into()));
        assert_eq!(last("HOME"), Some("/cache-would-never-set-this".into()));
        let position = |value: &str| applied.iter().position(|(_, v)| v == value).unwrap();
        assert!(position("/attempt/home") < position("/cache/o/r/npm"));
        assert!(position("/cache/o/r/npm") < position("/operator/npm"));
    }
}
