// owner: f1-cli-auth-host-status

//! `runner-manager update`: bring this installation up to the newest release.
//!
//! # What "everything" means here
//!
//! Before this command existed, upgrading was a channel-specific ritual an
//! operator had to remember: `npm i -g` for one machine, `brew upgrade` for the
//! next, `curl … | sh` for the host with no Node.js on it — and then, on every
//! one of them, the question nobody thinks to ask, which is what happens to the
//! service that is running the *old* binary right now. This command is the
//! whole ritual, in one line, on every channel.
//!
//! It does four things, in this order:
//!
//! 1. works out **how this copy was installed**, from the path it is running
//!    from ([`Channel`]);
//! 2. asks the GitHub Release **what the newest version is**, by reading the
//!    `SHA256SUMS` that release publishes — the same document `install.sh`
//!    reads, parsed by the same rules, so the two can never disagree about
//!    which archive belongs to this host;
//! 3. **performs the update the way this channel expects**: a package manager
//!    is asked to do its own job, and a standalone binary is replaced here,
//!    from an archive whose SHA-256 matched the digest published beside it;
//! 4. **says what it means for the running service**, which is the step an
//!    operator doing this by hand forgets.
//!
//! # Why the version comes from `SHA256SUMS` and not from the GitHub API
//!
//! `GET /repos/{owner}/{repo}/releases/latest` is the obvious call and it is
//! the wrong one. It is rate-limited to 60 requests an hour for an
//! unauthenticated client, which is a limit a machine behind one NAT address
//! can reach without anybody doing anything wrong; and it answers with a
//! release *name*, which is a string a human typed, rather than with the set of
//! artifacts that actually exist. `releases/latest/download/SHA256SUMS` is a
//! static, unauthenticated, unlimited redirect to the newest release's own
//! checksum document — and every line in it names an artifact that is really
//! there. Reading the version out of the asset name therefore answers "what is
//! the newest release **for this host**", which is the question, rather than
//! "what is the newest release", which is not: a release that skipped this
//! platform must be reported as such and not offered.
//!
//! # Why the replacement is not a `curl | sh`
//!
//! The install script is the documented way to install, and shelling out to it
//! would have been fewer lines. It would also mean this command could not run
//! on a host without `curl`, could not run on Windows without a second
//! implementation in PowerShell, and — the part that decides it — could not be
//! tested without a network. The archive, the digest and the atomic replacement
//! are about eighty lines of Rust against dependencies this workspace already
//! builds, and [`crate::cli::update`]'s own suite drives all of them against a
//! synthetic release on local disk.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use super::{CliError, Context, Failure, UpdateArgs, write_failed};
use runner_manager_platform::service::InstallRecord;

#[path = "update_force.rs"]
pub(super) mod force;
use force::{force_service_handover, preflight_force, report_force_check};

// ---------------------------------------------------------------------------
// Where the assets come from
// ---------------------------------------------------------------------------

/// Points the update at another release origin, or at a directory of assets.
///
/// # This is a test seam, and the http(s) half is restricted to loopback
///
/// What this variable redirects is the source of an executable that then
/// replaces the one the operator is running. An override that could name an
/// arbitrary origin would therefore be a remote-code-execution primitive aimed
/// at whoever runs `update` next — strictly worse than
/// [`super::GITHUB_BASE_URL_VARIABLE`], which can only redirect a token. So the
/// same restriction applies and for a stronger reason: an `http(s)` value must
/// be loopback, and the command says on stderr that it is not talking to
/// GitHub.
///
/// A value that is not an `http(s)` URL is read as a **local directory holding
/// the release assets flat**, which is what `install.sh` does with
/// `RUNNER_MANAGER_INSTALL_BASE_URL` and what an air-gapped mirror looks like.
/// That path is not a redirection of anything: it names files the operator
/// already has, and the digest check still runs against the `SHA256SUMS` beside
/// them.
pub const UPDATE_BASE_URL_VARIABLE: &str = "RUNNER_MANAGER_UPDATE_BASE_URL";

/// The npm package that owns an npm installation.
///
/// Scoped, and the scope matters: plain `runner-manager` on npmjs.com is an
/// unrelated project, so an unscoped `npm install -g runner-manager` here would
/// replace this program with somebody else's.
const NPM_PACKAGE: &str = "@ivan-murzak/runner-manager";

/// The Homebrew formula, fully qualified by its tap.
///
/// `brew upgrade runner-manager` without the tap resolves against homebrew-core
/// first, and homebrew-core does not carry this formula — so the unqualified
/// spelling is either a "no available formula" refusal or, if one is ever
/// added there, the wrong package.
const BREW_FORMULA: &str = "IvanMurzak/tap/runner-manager";

/// The crates.io crate name, which is the package name and not the scope.
const CARGO_CRATE: &str = "runner-manager";

/// Where the assets for one release live.
#[derive(Debug, Clone)]
pub(crate) enum AssetSource {
    /// A URL prefix; `<base>/<asset>` is fetched over HTTP.
    Remote { base: String },
    /// A directory holding the assets flat.
    Local { directory: PathBuf },
}

impl std::fmt::Display for AssetSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Remote { base } => f.write_str(base),
            Self::Local { directory } => write!(f, "{}", display_path(directory)),
        }
    }
}

impl AssetSource {
    /// Production GitHub, unless the override says otherwise.
    ///
    /// # Errors
    /// [`Failure::InvalidArgument`] when [`UPDATE_BASE_URL_VARIABLE`] holds an
    /// `http(s)` URL this refuses to trust, or a directory that is not there.
    pub(crate) fn resolve(err: &mut dyn Write) -> Result<Self, CliError> {
        let Some(raw) = std::env::var_os(UPDATE_BASE_URL_VARIABLE) else {
            return Ok(Self::Remote {
                base: format!(
                    "{}/releases/latest/download",
                    env!("CARGO_PKG_REPOSITORY").trim_end_matches('/')
                ),
            });
        };
        let raw = raw.to_string_lossy().into_owned();
        if !raw.starts_with("http://") && !raw.starts_with("https://") {
            let directory = PathBuf::from(&raw);
            if !directory.is_dir() {
                return Err(CliError::with_remedy(
                    Failure::InvalidArgument,
                    format!(
                        "{UPDATE_BASE_URL_VARIABLE} is not an http(s) URL and not a directory: {raw}"
                    ),
                    "unset RUNNER_MANAGER_UPDATE_BASE_URL",
                ));
            }
            let _ = writeln!(
                err,
                "warning: reading release assets from {raw} instead of GitHub, because \
                 {UPDATE_BASE_URL_VARIABLE} is set."
            );
            return Ok(Self::Local { directory });
        }
        let parsed = reqwest::Url::parse(&raw).map_err(|source| {
            CliError::new(
                Failure::InvalidArgument,
                format!("{UPDATE_BASE_URL_VARIABLE} is not usable as a URL: {source}"),
            )
        })?;
        let host = parsed.host_str().unwrap_or_default();
        if !super::is_loopback_host(host) {
            return Err(CliError::with_remedy(
                Failure::InvalidArgument,
                format!(
                    "{UPDATE_BASE_URL_VARIABLE} points at {host}, which is not this machine. \
                     This variable redirects where a replacement executable is downloaded from, \
                     so it accepts only a loopback origin or a local directory."
                ),
                "unset RUNNER_MANAGER_UPDATE_BASE_URL",
            ));
        }
        let _ = writeln!(
            err,
            "warning: reading release assets from {raw} instead of GitHub, because \
             {UPDATE_BASE_URL_VARIABLE} is set."
        );
        Ok(Self::Remote {
            base: raw.trim_end_matches('/').to_string(),
        })
    }

    /// The assets of **one exact released version**, for `wsl install`.
    ///
    /// # Why not `releases/latest/download`, which is what `update` uses
    ///
    /// The two commands are asking different questions. `update` asks "what is
    /// the newest release", and `latest` is the only URL that answers it
    /// without the GitHub API. `wsl install` asks for "the Linux release
    /// artifact whose semantic version exactly matches the controlling Windows
    /// binary" (`02-target-architecture.md`), and that is a *named* release:
    /// the release workflow tags `v<X.Y.Z>`, so
    /// `releases/download/v<X.Y.Z>/SHA256SUMS` is the document that describes
    /// the same build as the process asking. Reading `latest` here would make
    /// `wsl install` fail on a workstation one release behind — with "the
    /// release publishes no archive for version 0.4.0", about a release that is
    /// perfectly fine — rather than install the matching pair.
    ///
    /// [`UPDATE_BASE_URL_VARIABLE`] still wins when it is set, unchanged and
    /// under the same loopback/local-directory restriction: a fixture serving
    /// one release's assets flat has no `v<X.Y.Z>` directory to descend into.
    ///
    /// # Errors
    /// As [`AssetSource::resolve`].
    pub(crate) fn for_version(version: &str, err: &mut dyn Write) -> Result<Self, CliError> {
        let resolved = Self::resolve(err)?;
        if std::env::var_os(UPDATE_BASE_URL_VARIABLE).is_some() {
            return Ok(resolved);
        }
        Ok(Self::Remote {
            base: format!(
                "{}/releases/download/v{version}",
                env!("CARGO_PKG_REPOSITORY").trim_end_matches('/')
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// Which archive this host needs
// ---------------------------------------------------------------------------

/// The published artifact for one operating system and architecture.
///
/// Must name the same five rows as `PUBLISHED_TARGETS` in
/// `.github/scripts/channels.sh` and `RELEASE_TARGETS` in `release.yml`. Those
/// two are asserted equal to each other by `release_channels.rs`; this third
/// copy is bound to them by `update_command.rs`, because a target this command
/// asks for and the release does not publish is a `update` that reports "your
/// platform was dropped" about a release that is perfectly fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostTarget {
    /// The Rust target triple the archive is named after.
    triple: &'static str,
    /// `tar.gz` or `zip`.
    extension: &'static str,
    /// The executable's name inside the archive.
    binary: &'static str,
}

/// The artifact this host runs, or a refusal naming what it saw.
///
/// A guess is worse than a refusal here for the reason `install.sh` gives:
/// "probably the right one" produces a binary that fails to exec with a message
/// about the dynamic loader, which is a far worse thing to debug.
///
/// The pair read is what this program was **compiled** for, not what the CPU
/// is. That is deliberate: an x86-64 build running under Rosetta or under
/// Windows' ARM64 emulation must keep updating to the x86-64 archive, because
/// that is the one it is a copy of. `uname -m` inside the same emulated process
/// answers the same way, so `install.sh` and this agree.
fn host_target() -> Result<HostTarget, CliError> {
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    let target = match (os, arch) {
        ("windows", "x86_64") => HostTarget {
            triple: "x86_64-pc-windows-msvc",
            extension: "zip",
            binary: "runner-manager.exe",
        },
        ("macos", "aarch64") => HostTarget {
            triple: "aarch64-apple-darwin",
            extension: "tar.gz",
            binary: "runner-manager",
        },
        ("macos", "x86_64") => HostTarget {
            triple: "x86_64-apple-darwin",
            extension: "tar.gz",
            binary: "runner-manager",
        },
        ("linux", "x86_64") => HostTarget {
            triple: "x86_64-unknown-linux-gnu",
            extension: "tar.gz",
            binary: "runner-manager",
        },
        ("linux", "aarch64") => HostTarget {
            triple: "aarch64-unknown-linux-gnu",
            extension: "tar.gz",
            binary: "runner-manager",
        },
        _ => {
            return Err(CliError::with_remedy(
                Failure::UnsupportedHost,
                format!(
                    "no release archive is published for {os}/{arch}, so there is nothing to \
                     update to. This build was compiled for a platform the release does not cover."
                ),
                "cargo install runner-manager",
            ));
        }
    };
    Ok(target)
}

// ---------------------------------------------------------------------------
// How this copy was installed
// ---------------------------------------------------------------------------

/// The install channel, worked out from the path this process is running from.
///
/// # Why the path and not a recorded marker
///
/// A file written at install time saying "npm put me here" would be the tidier
/// answer and it cannot be made true: four of the five channels are somebody
/// else's installer, and none of them will write this project's marker. The
/// path is what those installers *do* leave behind, and each of them leaves an
/// unmistakable one — a `node_modules` component, Homebrew's `Cellar`, cargo's
/// `bin` under `CARGO_HOME`. So the detection reads the evidence that exists
/// rather than the evidence that would be convenient.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Channel {
    /// The install script's layout, or any copy an operator placed by hand.
    /// This is the one channel this command updates itself.
    Archive,
    /// A binary inside an npm package's `node_modules` tree.
    Npm,
    /// A binary inside a Homebrew `Cellar`.
    Homebrew,
    /// A binary in `$CARGO_HOME/bin`, put there by `cargo install`.
    Cargo,
    /// A `cargo build` output inside a checkout of this repository.
    SourceBuild,
    /// The private copy `service install` made for the service to run.
    ServiceCopy,
}

impl Channel {
    /// How this channel is described in a report.
    const fn describe(&self) -> &'static str {
        match self {
            Self::Archive => "release archive",
            Self::Npm => "npm",
            Self::Homebrew => "Homebrew",
            Self::Cargo => "cargo install",
            Self::SourceBuild => "a build in a checkout",
            Self::ServiceCopy => "the copy the service runs",
        }
    }
}

/// The binary this command would replace, and how it got there.
#[derive(Debug, Clone)]
struct Installation {
    channel: Channel,
    /// Absolute and symlink-free: Homebrew's `bin` entry is a symlink into
    /// `Cellar`, and the `Cellar` component is the whole of how that channel is
    /// recognised.
    path: PathBuf,
}

impl Installation {
    /// Reads the running process's own path and classifies it.
    ///
    /// # Errors
    /// [`Failure::LocalState`] when the platform will not say where this
    /// process came from, which leaves nothing to update and no way to name it.
    fn detect(context: &Context) -> Result<Self, CliError> {
        let raw = std::env::current_exe().map_err(|source| {
            CliError::new(
                Failure::LocalState,
                format!("cannot work out which file this process is running from: {source}"),
            )
        })?;
        // Canonicalised, not just absolutised. A failure here is not fatal: a
        // path that cannot be canonicalised is still a path that can be
        // replaced, and refusing the whole command over it would be a refusal
        // caused by the diagnosis rather than by the problem.
        let path = std::fs::canonicalize(&raw).unwrap_or(raw);
        Ok(Self {
            channel: classify(&path, context.paths().state_dir()),
            path,
        })
    }

    /// Why this copy cannot be updated in place, when it cannot.
    ///
    /// Both cases are files this command is able to overwrite and must not.
    /// A checkout build belongs to whoever is working in the checkout, and
    /// dropping a release binary on top of it would silently discard their
    /// build. The service's copy is replaced by the daemon itself, from the
    /// binary an operator owns -- writing it here would put a version under the
    /// registration that the next `service install` overwrites anyway, and
    /// would leave the operator's own binary still on the old release.
    fn refusal(&self) -> Option<CliError> {
        match self.channel {
            Channel::SourceBuild => Some(CliError::with_remedy(
                Failure::UpdateUnsupported,
                format!(
                    "this is a build in a checkout ({}), not an installation. Updating it means \
                     updating the checkout, which is a thing only its owner should do.",
                    display_path(&self.path)
                ),
                "git pull && cargo build --release -p runner-manager",
            )),
            Channel::ServiceCopy => Some(CliError::with_remedy(
                Failure::UpdateUnsupported,
                format!(
                    "this is the private copy `service install` made for the service to run ({}), \
                     not the installation an operator owns. Update the binary you installed; the \
                     daemon replaces this copy with it by itself.",
                    display_path(&self.path)
                ),
                "runner-manager service status",
            )),
            Channel::Npm => self.npm_prefix().err(),
            Channel::Archive | Channel::Homebrew | Channel::Cargo => None,
        }
    }

    /// The global npm prefix holding this copy, as an operator would type it,
    /// or why there is none. See [`npm_global_prefix`].
    fn npm_prefix(&self) -> Result<String, CliError> {
        npm_global_prefix(&self.path, cfg!(windows))
            // `\\?\UNC\server\share` is `\\server\share` to npm.
            .map(
                |prefix| match display_path(&prefix).strip_prefix(r"\\?\UNC\") {
                    Some(share) => format!(r"\\{share}"),
                    None => display_path(&prefix),
                },
            )
            .ok_or_else(|| {
                CliError::with_remedy(
                    Failure::UpdateUnsupported,
                    format!(
                        "this copy is inside a node_modules tree ({}), but not in the layout of a \
                         global npm install, so there is no npm prefix to update it in. \
                         `npm install --global` would put a new copy somewhere else and leave \
                         this one as it is.",
                        display_path(&self.path)
                    ),
                    format!("npm install --global {NPM_PACKAGE}"),
                )
            })
    }
}

/// The global npm prefix that holds the npm copy at `binary`.
///
/// # Why `update` names the prefix instead of letting npm pick one
///
/// `npm install --global` installs into *the invoking account's* configured
/// prefix, which need not be the one holding the copy being updated. On a
/// Windows machine with two accounts, each with its own copy under
/// `%APPDATA%\npm`, the machine `PATH` can list the first account's copy
/// ahead of the second's -- so the second account runs the first account's
/// binary, and a bare `npm install --global` from it updates the second
/// account's copy and reports success while the copy that ran stays old.
/// Passing `--prefix` makes npm update the copy this process is.
///
/// A global install puts the package at `<prefix>/node_modules/<package>` on
/// Windows and at `<prefix>/lib/node_modules/<package>` elsewhere, with the
/// platform package (which holds this binary) nested inside it. `None` when
/// the path is not in that layout -- a project-local install, or another
/// package manager's tree -- where no `--prefix` would update this copy.
fn npm_global_prefix(binary: &Path, windows: bool) -> Option<PathBuf> {
    let components: Vec<_> = binary.components().collect();
    let named = |index: usize, wanted: &str| {
        components
            .get(index)
            .and_then(|component| component.as_os_str().to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
    };
    let (package_scope, package_name) = NPM_PACKAGE.split_once('/')?;
    let modules = (0..components.len()).find(|&index| named(index, "node_modules"))?;
    // The first `node_modules` must hold the package itself: one holding
    // another package means this is that package's dependency, not a global
    // install of this one.
    if !(named(modules + 1, package_scope) && named(modules + 2, package_name)) {
        return None;
    }
    let root: PathBuf = components[..modules].iter().collect();
    // A project directory, not a prefix: npm writes no `package.json` into a
    // global prefix.
    if root.join("package.json").exists() {
        return None;
    }
    if windows {
        return Some(root);
    }
    if root.file_name().and_then(|name| name.to_str()) == Some("lib") {
        return root.parent().map(Path::to_path_buf);
    }
    None
}

/// The classification, split out so it can be exercised on paths this machine
/// does not have.
fn classify(path: &Path, state_dir: &Path) -> Channel {
    let component_named = |wanted: &str| {
        path.components()
            .any(|component| component.as_os_str() == wanted)
    };
    // Checked before everything else: a service copy lives under this host's
    // own state directory, and replacing it would put a binary under a service
    // registration that a later `service install` overwrites anyway.
    if let Ok(service_bin) = std::fs::canonicalize(state_dir.join("bin"))
        && path.parent() == Some(service_bin.as_path())
    {
        return Channel::ServiceCopy;
    }
    if component_named("node_modules") {
        return Channel::Npm;
    }
    if component_named("Cellar") {
        return Channel::Homebrew;
    }
    if path.parent() == Some(cargo_bin().as_path()) {
        return Channel::Cargo;
    }
    // `target/debug/runner-manager` or `target/release/runner-manager`. Both
    // segments are required: a release archive unpacked into a directory
    // somebody happened to call `release` is not a checkout.
    if let Some(parent) = path.parent()
        && matches!(
            parent.file_name().and_then(|name| name.to_str()),
            Some("debug" | "release")
        )
        && parent.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("target"))
    {
        return Channel::SourceBuild;
    }
    Channel::Archive
}

/// `$CARGO_HOME/bin`, or the default `~/.cargo/bin`.
fn cargo_bin() -> PathBuf {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .or_else(|| std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".cargo")))
        .unwrap_or_default();
    let bin = home.join("bin");
    std::fs::canonicalize(&bin).unwrap_or(bin)
}

// ---------------------------------------------------------------------------
// Reading SHA256SUMS
// ---------------------------------------------------------------------------

/// One release artifact: the name it is published under and its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PublishedArchive {
    version: String,
    asset: String,
    digest: String,
}

/// Reads `SHA256SUMS` and returns the one archive this host needs.
///
/// # Two forms of checksum line are in circulation, and both are accepted
///
/// `sha256sum -c` verifies `<hash>  <name>` and `<hash> *<name>` alike, and GNU
/// `sha256sum` writes the second by default on Windows. The README tells a
/// reader to check a release by hand with `sha256sum -c SHA256SUMS`, so a
/// parser here that is stricter than the tool the documentation recommends
/// would refuse a release that command accepts — and would refuse it by
/// announcing that this platform was dropped, which is entirely the wrong
/// conclusion. `install.sh` makes the same allowance for the same reason.
///
/// # Errors
/// [`Failure::UnusableResponse`] when nothing in the document parses, or when
/// more than one archive claims this target; [`Failure::UnsupportedHost`] when
/// the document parses and simply has no archive for this host.
fn read_published_archive(
    document: &str,
    target: HostTarget,
    source: &AssetSource,
) -> Result<PublishedArchive, CliError> {
    let mut usable = 0_usize;
    let mut matched: Vec<PublishedArchive> = Vec::new();
    for line in document.lines() {
        let fields: Vec<&str> = line.trim_end_matches('\r').split_whitespace().collect();
        let [digest, name] = fields[..] else { continue };
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        usable += 1;
        let name = name.strip_prefix('*').unwrap_or(name);
        let Some(version) = version_of_asset(name, target) else {
            continue;
        };
        matched.push(PublishedArchive {
            version,
            asset: name.to_string(),
            digest: digest.to_ascii_lowercase(),
        });
    }

    // A document nothing could be read out of is a different failure from one
    // that carries no line for this host, and it needs a different sentence.
    // The first is a truncated download, a proxy's error page, or a file that
    // is not SHA256SUMS at all.
    if usable == 0 {
        return Err(CliError::with_remedy(
            Failure::UnusableResponse,
            format!(
                "the SHA256SUMS at {source} has no line this command can read. Expected \
                 '<64 hex digits><spaces><asset name>' on each line; this document is empty, \
                 truncated, or not a checksum file at all."
            ),
            "runner-manager update --check",
        ));
    }
    match matched.len() {
        1 => Ok(matched.remove(0)),
        0 => Err(CliError::with_remedy(
            Failure::UnsupportedHost,
            format!(
                "the release at {source} publishes no archive for {} (it publishes {usable} \
                 assets), so there is nothing to update to on this platform.",
                target.triple
            ),
            "cargo install runner-manager",
        )),
        count => Err(CliError::with_remedy(
            Failure::UnusableResponse,
            format!(
                "the release at {source} publishes {count} archives for {}; refusing to guess \
                 which one is meant.",
                target.triple
            ),
            "runner-manager update --check",
        )),
    }
}

/// The version in `runner-manager-<X.Y.Z>-<target>.<extension>`, when the name
/// is exactly that and nothing else.
///
/// Matched whole rather than by prefix: `…-x86_64-apple-darwin.tar.gz` is a
/// prefix of `…-x86_64-apple-darwin.tar.gz.sig`, and a signature file is not an
/// archive.
fn version_of_asset(name: &str, target: HostTarget) -> Option<String> {
    let rest = name.strip_prefix("runner-manager-")?;
    let rest = rest.strip_suffix(&format!(".{}", target.extension))?;
    let version = rest.strip_suffix(&format!("-{}", target.triple))?;
    parse_version(version).map(|_| version.to_string())
}

/// `X.Y.Z`, as three numbers, so versions order rather than compare as strings.
///
/// Without this, `0.1.9` sorts after `0.1.10` and an operator on the newer
/// build is told to downgrade. Pre-release and build metadata are rejected
/// rather than ignored: the release workflow refuses to publish them, so a tag
/// carrying one is not a release this command should be following.
fn parse_version(raw: &str) -> Option<(u64, u64, u64)> {
    let mut parts = raw.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

/// The version this binary was compiled as.
fn running_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// `runner-manager update`.
///
/// # Errors
/// Every class named on the helpers below, plus [`Failure::Unclassified`] when
/// the report cannot be written.
pub fn dispatch(context: &Context, args: &UpdateArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("this update");
    let mut err = std::io::stderr();

    let installation = Installation::detect(context)?;
    let target = host_target()?;
    let source = AssetSource::resolve(&mut err)?;

    // Printed and flushed BEFORE the network call. Everything on these three
    // lines is known locally, and an operator on a slow link should be looking
    // at what this command found rather than at a blank terminal while it waits
    // on GitHub.
    writeln!(out, "runner-manager update").map_err(failed)?;
    writeln!(out, "  installed                 {}", running_version()).map_err(failed)?;
    writeln!(
        out,
        "  installed by              {} ({})",
        installation.channel.describe(),
        display_path(&installation.path)
    )
    .map_err(failed)?;
    writeln!(out, "  release assets            {source}").map_err(failed)?;
    out.flush().map_err(failed)?;

    let runtime = super::runtime()?;
    let document = runtime.block_on(fetch_text(&source, "SHA256SUMS"))?;
    let published = read_published_archive(&document, target, &source)?;
    writeln!(out, "  published                 {}", published.version).map_err(failed)?;
    let refusal = installation.refusal();

    let ordering = compare_versions(&published.version, running_version());
    if ordering != std::cmp::Ordering::Greater {
        if ordering == std::cmp::Ordering::Equal && args.force {
            if let Some(problem) = refusal {
                if args.check {
                    writeln!(
                        out,
                        "`runner-manager update --force` would refuse here: {problem}"
                    )
                    .map_err(failed)?;
                    return Ok(());
                }
                return Err(problem);
            }
            if args.check {
                match preflight_force(context) {
                    Ok(()) => report_force_check(context, &installation, &published.version, out)?,
                    Err(problem) => writeln!(
                        out,
                        "`runner-manager update --force` would refuse here: {problem}"
                    )
                    .map_err(failed)?,
                }
            } else {
                force_service_handover(context, &installation, &published.version, out)?;
            }
            return Ok(());
        }
        writeln!(out).map_err(failed)?;
        // The newest release can be installed while the service still runs an
        // older one: npm run by hand, or the update of a copy whose service
        // missed the change. "Nothing to do" would be false there.
        let installed = running_version();
        if ordering == std::cmp::Ordering::Equal
            && let Some(behind) = service_behind(context, &installation, installed)
        {
            report_service_behind(&behind, installed, args.check, out)?;
            return report_managed_wsl_hosts(context.paths(), installed, out);
        }
        let sentence = if ordering == std::cmp::Ordering::Equal {
            format!(
                "runner-manager {} is the newest release. Nothing to do.",
                running_version()
            )
        } else {
            format!(
                "This host runs {}, which is newer than the {} the release publishes. \
                 Nothing to do; `update` never installs an older build over a newer one.",
                running_version(),
                published.version
            )
        };
        writeln!(out, "{sentence}").map_err(failed)?;
        // This machine is current, which says nothing about the hosts it
        // manages: one installed before this binary was updated still runs
        // the version it was given.
        return report_managed_wsl_hosts(context.paths(), running_version(), out);
    }

    // ------------------------------------------------------------------
    // WHETHER THIS COPY CAN BE UPDATED IS DECIDED BEFORE `--check` RETURNS.
    // ------------------------------------------------------------------
    // Otherwise `--check` ends every run with "Install it with: runner-manager
    // update" -- including on a checkout build and on the service's private
    // copy, where the command it just recommended refuses. A dry run that
    // predicts the wrong outcome is worse than no dry run: it is the one thing
    // an operator uses it to avoid.
    if args.check {
        writeln!(out).map_err(failed)?;
        writeln!(
            out,
            "{} is available. Nothing has been changed, because --check was given.",
            published.version
        )
        .map_err(failed)?;
        match &refusal {
            None => {
                if args.force
                    && let Err(problem) = preflight_force(context)
                {
                    writeln!(
                        out,
                        "`runner-manager update --force` would refuse here: {problem}"
                    )
                    .map_err(failed)?;
                    return Ok(());
                }
                let command = if args.force {
                    "runner-manager update --force"
                } else {
                    "runner-manager update"
                };
                writeln!(out, "Install it with: {command}").map_err(failed)?;
                if args.force {
                    report_force_check(context, &installation, &published.version, out)?;
                }
            }
            Some(problem) => {
                writeln!(out, "`runner-manager update` would refuse here: {problem}")
                    .map_err(failed)?;
                if let Some(remedy) = problem.remedy() {
                    writeln!(out, "  try: {remedy}").map_err(failed)?;
                }
            }
        }
        return Ok(());
    }

    if let Some(problem) = refusal {
        return Err(problem);
    }

    if args.force {
        // A newer CLI is useful only if the service can receive the handover.
        // Detect a stale or unobserved registration before changing that CLI.
        preflight_force(context)?;
    }

    writeln!(out).map_err(failed)?;
    match installation.channel {
        Channel::Archive => {
            runtime.block_on(replace_from_archive(
                &source,
                &published,
                target,
                &installation.path,
                out,
            ))?;
        }
        Channel::Npm => {
            // npm replaces the package directory this process runs from. On
            // Windows that works while the binary runs (measured with npm
            // 12.2.0: it renames the directory aside, exits 0, and warns that
            // it could not delete the old one).
            let prefix = installation.npm_prefix()?;
            let package = format!("{NPM_PACKAGE}@{}", published.version);
            run_package_manager(
                "npm",
                &["install", "--global", "--prefix", &prefix, &package],
                format!("npm install --global --prefix \"{prefix}\" {package}"),
                out,
            )?;
            confirm_npm_copy(&installation.path, &published.version, out)?;
        }
        Channel::Homebrew => {
            // `brew upgrade` resolves against the tap as it was last fetched,
            // so without this the formula it sees is whatever was current when
            // the operator last ran `brew update` -- which for a machine that
            // only ever installed this one formula can be the day it was
            // installed. A failure here is a warning rather than the end of the
            // command: `brew update` reaches homebrew-core as well as this tap,
            // and a network failure fetching somebody else's repository must
            // not stop an upgrade that may still be possible from cache.
            if let Err(problem) = run_package_manager(
                "brew",
                &["update"],
                "brew update && brew upgrade IvanMurzak/tap/runner-manager",
                out,
            ) {
                writeln!(out, "warning: {}", problem.message()).map_err(failed)?;
            }
            run_package_manager(
                "brew",
                &["upgrade", BREW_FORMULA],
                "brew upgrade IvanMurzak/tap/runner-manager",
                out,
            )?;
            // ----------------------------------------------------------------
            // BREW IS THE ONE CHANNEL THIS CANNOT PIN, SO IT IS THE ONE THAT
            // CAN SUCCEED WITHOUT CHANGING ANYTHING.
            // ----------------------------------------------------------------
            // `npm` and `cargo` are both given the exact version read out of
            // the release, so their exit status answers the question. A formula
            // is whatever the tap currently pins, and the tap is updated by
            // step 8 of the same release run that publishes the archives -- so
            // for a few minutes after a release, `brew upgrade` correctly
            // reports that the formula it can see is already installed and
            // exits zero. Claiming the update happened would be a false
            // success; this says where to look instead.
            writeln!(
                out,
                "\nIf brew reported nothing to upgrade, the tap has not caught up with the \n\
                 release yet. It is updated by the same release run, usually within minutes."
            )
            .map_err(failed)?;
            confirm_with_version(out)?;
        }
        Channel::Cargo => {
            run_package_manager(
                "cargo",
                &[
                    "install",
                    CARGO_CRATE,
                    "--version",
                    &published.version,
                    "--locked",
                    "--force",
                ],
                "cargo install runner-manager --locked",
                out,
            )?;
            confirm_with_version(out)?;
        }
        // Both were turned into a refusal above, before `--check` could
        // promise an update that would not happen.
        Channel::SourceBuild | Channel::ServiceCopy => {
            return Err(installation.refusal().unwrap_or_else(|| {
                CliError::new(Failure::UpdateUnsupported, "nothing to update")
            }));
        }
    }

    if args.force {
        force_service_handover(context, &installation, &published.version, out)?;
    } else {
        report_service_consequence(context, &installation, &published.version, out)?;
    }
    report_managed_wsl_hosts(context.paths(), &published.version, out)
}

// ---------------------------------------------------------------------------
// What it means for managed WSL hosts
// ---------------------------------------------------------------------------

/// Names every managed WSL host that runs a version older than `version`, and
/// the command that brings it up to date.
///
/// # Why `update` says this rather than doing it
///
/// A managed WSL distribution is a second runner host with its own binary, its
/// own service and its own credential. Updating one is `wsl install`'s
/// convergent transaction, and that transaction waits -- with no deadline, on
/// purpose -- for every job the Linux service is running to finish before its
/// service copy is replaced, and signs in through the device flow if the
/// distribution holds no credential. Neither belongs inside `update`, which
/// returns as soon as this machine's own binary is replaced and lets its
/// service drain in the background. Updating a host with `wsl install` needs
/// no administrator rights, except once for a host whose lifecycle task 0.4.34
/// or earlier registered from an elevated prompt; it asks for them itself.
///
/// Never a failure: a record this build cannot read is `wsl list`'s business.
fn report_managed_wsl_hosts(
    paths: &runner_manager_platform::paths::AppPaths,
    version: &str,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this update");
    let Ok(records) = runner_manager_platform::wsl::record::WslProviderRecord::all(paths) else {
        return Ok(());
    };
    let behind: Vec<_> = records
        .iter()
        .filter(|record| {
            compare_versions(&record.installed_version, version) == std::cmp::Ordering::Less
        })
        .collect();
    if behind.is_empty() {
        return Ok(());
    }
    writeln!(out).map_err(failed)?;
    writeln!(
        out,
        "Managed WSL hosts are updated separately, because updating one drains its own jobs. \
         Run, from this prompt (no administrator rights needed, except once for a host first \
         set up before 0.4.35 from an elevated prompt, which asks for them itself):"
    )
    .map_err(failed)?;
    for record in behind {
        writeln!(
            out,
            "  {}   (runs {})",
            super::wsl::install_remediation(&record.distribution),
            record.installed_version
        )
        .map_err(failed)?;
    }
    Ok(())
}

/// `left` against `right`, both `X.Y.Z`.
///
/// An unparseable version compares as *not newer*, which is the safe direction:
/// a release whose asset name this command cannot read is one it must not
/// install over a working binary.
fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    match (parse_version(left), parse_version(right)) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => std::cmp::Ordering::Less,
    }
}

// ---------------------------------------------------------------------------
// The archive channel: download, verify, replace
// ---------------------------------------------------------------------------

/// Downloads the published archive, checks its digest, and puts the binary it
/// carries where this process is running from.
///
/// # Errors
/// [`Failure::GithubUnavailable`] when the assets cannot be fetched,
/// [`Failure::UnusableResponse`] on a digest mismatch or an archive that does
/// not carry the binary it should, and [`Failure::LocalState`] when the
/// replacement cannot be written.
async fn replace_from_archive(
    source: &AssetSource,
    published: &PublishedArchive,
    target: HostTarget,
    destination: &Path,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this update");
    let work = tempfile::tempdir().map_err(|source| {
        CliError::new(
            Failure::LocalState,
            format!("cannot create a temporary directory to download into: {source}"),
        )
    })?;

    writeln!(out, "Downloading {}", published.asset).map_err(failed)?;
    out.flush().map_err(failed)?;
    let archive = work.path().join(&published.asset);
    fetch_file(source, &published.asset, &archive).await?;

    // ------------------------------------------------------------------
    // THE DIGEST IS THE WHOLE SECURITY VALUE OF THIS PATH.
    // ------------------------------------------------------------------
    // Everything below writes an executable that will replace the one the
    // operator is running, and this is the only step that decides whether the
    // bytes are the ones the release published. A mismatch is a refusal that
    // leaves the existing binary untouched -- never a warning, never a retry
    // that installs anyway.
    let actual = sha256_of(&archive)?;
    if actual != published.digest {
        return Err(CliError::with_remedy(
            Failure::UnusableResponse,
            format!(
                "CHECKSUM MISMATCH: {} does not match the digest published beside it, so nothing \
                 has been installed and the binary in place is untouched.\n  expected \
                 (SHA256SUMS): {}\n  actually downloaded:   {actual}\nThat is either a corrupted \
                 download or a tampered artifact. Retry, and if it happens again report it at \
                 {}/issues rather than installing by hand.",
                published.asset,
                published.digest,
                env!("CARGO_PKG_REPOSITORY").trim_end_matches('/'),
            ),
            "runner-manager update",
        ));
    }
    writeln!(out, "SHA-256 OK: {}", published.digest).map_err(failed)?;

    // Every published archive holds exactly one top-level directory named after
    // the release, and the binary sits directly inside it.
    let inside = format!(
        "runner-manager-{}-{}/{}",
        published.version, target.triple, target.binary
    );
    let unpacked = work.path().join(target.binary);
    if target.extension == "zip" {
        extract_from_zip(&archive, &inside, &unpacked)?;
    } else {
        extract_from_tar_gz(&archive, &inside, &unpacked)?;
    }

    // Windows login tasks run the no-console supervisor shipped beside the
    // CLI. Updating only the CLI would make the next `service install` fail on
    // a machine originally installed before the supervisor existed. Extract
    // and replace the stable companion first; it is intentionally compatible
    // with both the old and new daemon protocol, so a later main-binary
    // replacement failure still leaves a runnable pair.
    if cfg!(windows) {
        let supervisor_name = "runner-manager-supervisor.exe";
        let supervisor_inside = format!(
            "runner-manager-{}-{}/{}",
            published.version, target.triple, supervisor_name
        );
        let unpacked_supervisor = work.path().join(supervisor_name);
        extract_from_zip(&archive, &supervisor_inside, &unpacked_supervisor)?;
        let supervisor_destination = destination.with_file_name(supervisor_name);
        install_over(&unpacked_supervisor, &supervisor_destination)?;
    }

    install_over(&unpacked, destination)?;
    writeln!(
        out,
        "Installed runner-manager {} to {}",
        published.version,
        display_path(destination)
    )
    .map_err(failed)?;
    Ok(())
}

/// Reads one asset into memory as text. Used only for `SHA256SUMS`.
pub(crate) async fn fetch_text(source: &AssetSource, asset: &str) -> Result<String, CliError> {
    match source {
        AssetSource::Local { directory } => {
            std::fs::read_to_string(directory.join(asset)).map_err(|error| {
                CliError::with_remedy(
                    Failure::GithubUnavailable,
                    format!(
                        "cannot read {asset} from {}: {error}",
                        display_path(directory)
                    ),
                    "runner-manager update --check",
                )
            })
        }
        AssetSource::Remote { base } => {
            let url = format!("{base}/{asset}");
            let response = reqwest::get(&url)
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|error| unreachable_release(&url, &error))?;
            response
                .text()
                .await
                .map_err(|error| unreachable_release(&url, &error))
        }
    }
}

/// Streams one asset to a file.
///
/// Streamed rather than buffered for the reason the `stream` feature is in this
/// workspace at all: the archive is tens of megabytes, and a home host should
/// not have to hold it in RAM to install it.
pub(crate) async fn fetch_file(
    source: &AssetSource,
    asset: &str,
    into: &Path,
) -> Result<(), CliError> {
    let write_failure = |error: std::io::Error| {
        CliError::new(
            Failure::LocalState,
            format!(
                "cannot write the downloaded archive to {}: {error}",
                display_path(into)
            ),
        )
    };
    match source {
        AssetSource::Local { directory } => std::fs::copy(directory.join(asset), into)
            .map(|_| ())
            .map_err(|error| {
                CliError::new(
                    Failure::GithubUnavailable,
                    format!(
                        "cannot read {asset} from {}: {error}",
                        display_path(directory)
                    ),
                )
            }),
        AssetSource::Remote { base } => {
            use futures::StreamExt as _;
            use tokio::io::AsyncWriteExt as _;

            let url = format!("{base}/{asset}");
            let response = reqwest::get(&url)
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|error| unreachable_release(&url, &error))?;
            let mut file = tokio::fs::File::create(into).await.map_err(write_failure)?;
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| unreachable_release(&url, &error))?;
                file.write_all(&chunk).await.map_err(write_failure)?;
            }
            file.flush().await.map_err(write_failure)?;
            file.sync_all().await.map_err(write_failure)?;
            Ok(())
        }
    }
}

fn unreachable_release(url: &str, error: &reqwest::Error) -> CliError {
    CliError::with_remedy(
        Failure::GithubUnavailable,
        format!("cannot fetch {url}: {error}"),
        "runner-manager update --check",
    )
}

/// The SHA-256 of a file, lower-case hex.
///
/// Read in chunks rather than into a `Vec`: the same reason the download is
/// streamed, and it keeps the peak cost of an update to one buffer.
fn sha256_of(path: &Path) -> Result<String, CliError> {
    let failed = |error: std::io::Error| {
        CliError::new(
            Failure::LocalState,
            format!(
                "cannot read the downloaded archive at {} back to check it: {error}",
                display_path(path)
            ),
        )
    };
    let mut file = std::fs::File::open(path).map_err(failed)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(failed)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Writes the one entry named `inside` out of a `.tar.gz` to `into`.
///
/// Exactly one entry, named in full, written to a path this function chose:
/// there is no traversal to guard against because no path out of the archive is
/// ever used as a destination.
fn extract_from_tar_gz(archive: &Path, inside: &str, into: &Path) -> Result<(), CliError> {
    let file = std::fs::File::open(archive).map_err(|error| unreadable_archive(archive, &error))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let entries = tar
        .entries()
        .map_err(|error| unreadable_archive(archive, &error))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| unreadable_archive(archive, &error))?;
        let path = entry
            .path()
            .map_err(|error| unreadable_archive(archive, &error))?
            .into_owned();
        if path_matches(&path, inside) {
            let mut destination =
                std::fs::File::create(into).map_err(|error| cannot_stage(into, &error))?;
            std::io::copy(&mut entry, &mut destination)
                .map_err(|error| cannot_stage(into, &error))?;
            return Ok(());
        }
    }
    Err(missing_entry(archive, inside))
}

/// The same for a `.zip`, which is what Windows releases ship.
fn extract_from_zip(archive: &Path, inside: &str, into: &Path) -> Result<(), CliError> {
    let file = std::fs::File::open(archive).map_err(|error| unreadable_archive(archive, &error))?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|error| unreadable_archive(archive, &error))?;
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|error| unreadable_archive(archive, &error))?;
        let Some(path) = entry.enclosed_name() else {
            continue;
        };
        if path_matches(&path, inside) {
            let mut destination =
                std::fs::File::create(into).map_err(|error| cannot_stage(into, &error))?;
            std::io::copy(&mut entry, &mut destination)
                .map_err(|error| cannot_stage(into, &error))?;
            return Ok(());
        }
    }
    Err(missing_entry(archive, inside))
}

/// Whether an archive entry is the file wanted, comparing separator-insensitively.
///
/// A `tar` entry's path uses `/` on every platform and a `zip` entry's may use
/// either, while `Path` on Windows compares with `\`. Normalising both sides to
/// `/` is what keeps one spelling of `inside` correct on all three operating
/// systems.
fn path_matches(entry: &Path, wanted: &str) -> bool {
    entry.to_string_lossy().replace('\\', "/") == wanted
}

fn unreadable_archive(archive: &Path, error: &dyn std::fmt::Display) -> CliError {
    CliError::with_remedy(
        Failure::UnusableResponse,
        format!(
            "the downloaded archive {} could not be read: {error}. Nothing has been installed.",
            display_path(archive)
        ),
        "runner-manager update",
    )
}

fn missing_entry(archive: &Path, inside: &str) -> CliError {
    CliError::with_remedy(
        Failure::UnusableResponse,
        format!(
            "the downloaded archive {} does not contain {inside}, so there is no binary to \
             install. Nothing has been changed.",
            display_path(archive)
        ),
        "runner-manager update --check",
    )
}

fn cannot_stage(into: &Path, error: &dyn std::fmt::Display) -> CliError {
    CliError::new(
        Failure::LocalState,
        format!(
            "cannot write the new binary to {}: {error}",
            display_path(into)
        ),
    )
}

/// Puts `new_binary` at `destination`, replacing whatever is there.
///
/// # The staging file is beside the destination, and it has to be
///
/// A rename is atomic only within one filesystem, so the new binary is copied
/// next to the file it replaces and renamed onto it. Copying straight over the
/// destination would leave a half-written executable on any failure, and on
/// Unix would corrupt the copy a *running* process is paging in from.
///
/// # Windows cannot rename onto a running executable, and can rename one aside
///
/// The destination is very often this process's own file — `runner-manager
/// update` replacing the binary that is running it — and Windows holds an image
/// section on it that refuses `MoveFileEx`. It permits renaming that same file
/// away, which is the whole trick: move the running binary aside, move the new
/// one in, and delete the leftover if the OS lets us. `daemon run` does exactly
/// this when it swaps its own copy.
///
/// Unix needs none of that: a rename over a running binary replaces the
/// directory entry and leaves the running image alone. It gets the single
/// atomic rename, and leaves no `.old` file behind for somebody to wonder about.
fn install_over(new_binary: &Path, destination: &Path) -> Result<(), CliError> {
    let failed = |what: &'static str| {
        move |error: std::io::Error| {
            CliError::with_remedy(
                Failure::LocalState,
                format!("cannot {what}: {error}"),
                "runner-manager update",
            )
        }
    };

    if destination.is_dir() {
        // `rename` onto a directory fails on Unix and can succeed at the wrong
        // thing elsewhere; either way, deleting a directory somebody else made
        // is not this command's call. `install.sh` carries the same guard.
        return Err(CliError::with_remedy(
            Failure::LocalState,
            format!(
                "{} is a directory, not a file, so it cannot be replaced with a binary.",
                display_path(destination)
            ),
            "remove it and run runner-manager update again",
        ));
    }

    let directory = destination.parent().ok_or_else(|| {
        CliError::new(
            Failure::LocalState,
            format!(
                "{} has no parent directory to stage a replacement in",
                display_path(destination)
            ),
        )
    })?;
    let staged = directory.join(format!(
        ".runner-manager.update-tmp{}",
        std::env::consts::EXE_SUFFIX
    ));
    let _ = std::fs::remove_file(&staged);
    std::fs::copy(new_binary, &staged).map_err(|error| {
        // The likeliest failure of the whole command, and the one whose default
        // remedy -- "run it again" -- is useless. A binary under `/usr/local/bin`
        // or `%ProgramFiles%` belongs to root or to Administrators, and the
        // operator has to say so; a binary under `~/.local/bin`, which is what
        // the install script produces, never needs this.
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return CliError::with_remedy(
                Failure::LocalState,
                format!(
                    "cannot write into {}, so the binary there cannot be replaced: {error}",
                    display_path(directory)
                ),
                "sudo runner-manager update",
            );
        }
        failed("stage the new binary beside the old one")(error)
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
            .map_err(failed("make the new binary executable"))?;
    }

    if cfg!(windows) {
        let aside = destination.with_extension("old");
        let _ = std::fs::remove_file(&aside);
        if destination.exists() {
            std::fs::rename(destination, &aside).map_err(|error| {
                let _ = std::fs::remove_file(&staged);
                failed("move the binary being replaced aside")(error)
            })?;
        }
        if let Err(error) = std::fs::rename(&staged, destination) {
            // Put back what was working, so a failed update never leaves the
            // machine with no runner-manager at all.
            let _ = std::fs::rename(&aside, destination);
            let _ = std::fs::remove_file(&staged);
            return Err(failed("put the new binary in place")(error));
        }
        // Refused while the old image is still running, which is the normal
        // case for `update` replacing itself. Harmless: nothing names it, and
        // the next install or upgrade removes it.
        let _ = std::fs::remove_file(&aside);
        return Ok(());
    }

    std::fs::rename(&staged, destination).map_err(|error| {
        let _ = std::fs::remove_file(&staged);
        failed("put the new binary in place")(error)
    })
}

// ---------------------------------------------------------------------------
// The package-manager channels
// ---------------------------------------------------------------------------

/// Runs a package manager and turns its exit status into this taxonomy.
///
/// Its output is inherited rather than captured. `npm`, `brew` and `cargo` all
/// print progress an operator is used to watching, and swallowing it to
/// re-print it at the end would turn a visible three-minute `cargo install`
/// into three minutes of silence.
fn run_package_manager(
    program: &str,
    arguments: &[&str],
    remedy: impl Into<String>,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this update");
    let remedy: String = remedy.into();
    let not_on_path = || {
        CliError::with_remedy(
            Failure::UpdateUnsupported,
            format!(
                "this copy was installed by {program}, and {program} is not on this PATH{}, so it \
                 cannot be asked to update it.",
                if cfg!(windows) {
                    format!(" (searched for {program} with each PATHEXT extension)")
                } else {
                    String::new()
                }
            ),
            remedy.clone(),
        )
    };
    let executable = resolve_program(program).ok_or_else(not_on_path)?;
    writeln!(
        out,
        "Running: {} {}",
        display_path(&executable),
        arguments.join(" ")
    )
    .map_err(failed)?;
    // Flushed before the child starts, so this line is not printed after the
    // output of the command it announces.
    out.flush().map_err(failed)?;

    // A resolved `.cmd` or `.bat` is run by the standard library through
    // `cmd.exe`, which quotes every argument for it (and refuses one it cannot
    // quote safely, CVE-2024-24576) -- so no command line is assembled here.
    let status = Command::new(&executable).args(arguments).status();
    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(CliError::with_remedy(
            Failure::UpdateFailed,
            match status.code() {
                Some(code) => format!(
                    "`{program} {}` exited {code}. The message above is {program}'s own; nothing \
                     here can add to it.",
                    arguments.join(" ")
                ),
                None => format!(
                    "`{program} {}` was killed by a signal.",
                    arguments.join(" ")
                ),
            },
            remedy,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(not_on_path()),
        Err(error) => Err(CliError::with_remedy(
            Failure::UpdateFailed,
            format!("cannot run {}: {error}", display_path(&executable)),
            remedy,
        )),
    }
}

/// The file to spawn for a package manager named `name`.
///
/// # Why Windows needs its own search
///
/// `Command::new("npm")` on Windows looks only for `npm.exe`: the standard
/// library appends `.exe` to a bare name and ignores `PATHEXT`. npm ships as
/// `npm.cmd`, so a machine with Node.js on its `PATH` read as "npm is not on
/// this PATH". Elsewhere `Command` searches `PATH` itself and the name is
/// returned as it is.
fn resolve_program(name: &str) -> Option<PathBuf> {
    if cfg!(windows) {
        runner_manager_platform::host_fitness::find_on_path(name, &std::env::var_os("PATH")?)
    } else {
        Some(PathBuf::from(name))
    }
}

/// Says whether npm really replaced the copy this process is, by running it.
///
/// An exit status of zero from npm says npm did *something*. Running the
/// binary at the path that was updated is the only statement about this copy,
/// and `runner-manager --version` typed afterwards may resolve to another
/// account's copy that comes first on `PATH`.
fn confirm_npm_copy(binary: &Path, version: &str, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("this update");
    // Compared without build metadata: a build outside the release workflow
    // reports `X.Y.Z+git.<sha>`.
    match super::status::binary_version(binary) {
        Some(reported) if reported.split('+').next() == Some(version) => writeln!(
            out,
            "\nInstalled runner-manager {version} to {}",
            display_path(binary)
        )
        .map_err(failed),
        Some(reported) => writeln!(
            out,
            "\nwarning: npm finished, but {} still reports {reported}, not {version}.",
            display_path(binary)
        )
        .map_err(failed),
        None => confirm_with_version(out),
    }
}

/// Points at the one command that answers "did that work".
///
/// Printed only for the package-manager channels. The archive channel already
/// names the version it wrote and the file it wrote it to, which is a stronger
/// statement than anything a package manager's exit status supports.
fn confirm_with_version(out: &mut dyn Write) -> Result<(), CliError> {
    writeln!(out, "\nConfirm with: runner-manager --version").map_err(write_failed("this update"))
}

// ---------------------------------------------------------------------------
// What it means for the service
// ---------------------------------------------------------------------------

/// Says what the host's service will do about the binary that just changed.
///
/// # This is the step an operator upgrading by hand forgets
///
/// `service install` registers a **copy** of the binary, precisely so a package
/// manager can replace its own file while the service is running. The
/// consequence is that replacing the installed binary does not, by itself,
/// change what the service runs — the daemon notices the source changed, drains
/// every job it is holding, swaps its own copy and exits for the service
/// manager to restart. That takes up to a minute plus however long the running
/// jobs take, and an operator who does not know it is happening reads
/// `service status` in the meantime and sees the old version.
///
/// Never a failure. The update succeeded; this is what happens next.
fn report_service_consequence(
    context: &Context,
    installation: &Installation,
    version: &str,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this update");
    let record = match InstallRecord::read(context.paths()) {
        Ok(Some(record)) => record,
        // No registration, or a record this build cannot read. Neither is this
        // command's business: `service status` is the command that diagnoses a
        // record, and saying nothing here is better than guessing.
        Ok(None) | Err(_) => return Ok(()),
    };

    writeln!(out).map_err(failed)?;
    match recorded_source(&record, installation) {
        RecordedSource::ThisCopy(_) => writeln!(
            out,
            "The service runs its own copy of this binary. It will finish every job it is \
             holding, replace that copy with {version}, and be restarted by the service \
             manager. Nothing else is needed."
        )
        .map_err(failed),
        RecordedSource::Other(source) => write_hand_over_with_force(&source, version, out),
        RecordedSource::None => write_reregister(version, out),
    }
}

/// Where the service's recorded source is, relative to this copy.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RecordedSource {
    /// A registration that names its binary directly, from before the service
    /// ran a copy of its own.
    None,
    /// The daemon watches this very copy.
    ThisCopy(PathBuf),
    /// The daemon watches another copy.
    Other(PathBuf),
}

fn recorded_source(record: &InstallRecord, installation: &Installation) -> RecordedSource {
    match &record.source_binary {
        Some(source) if same_file(source, &installation.path) => {
            RecordedSource::ThisCopy(source.clone())
        }
        Some(source) => RecordedSource::Other(source.clone()),
        None => RecordedSource::None,
    }
}

/// `update --force`, not `service install`: the latter refuses while the
/// daemon it would replace holds the agent lock, which is whenever it runs.
fn write_hand_over_with_force(
    source: &Path,
    version: &str,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this update");
    writeln!(
        out,
        "The service was installed from {}, not from this copy, so it keeps running the version \
         there. Hand {version} over to it (the service finishes every running job first):",
        display_path(source)
    )
    .map_err(failed)?;
    writeln!(out, "  runner-manager update --force").map_err(failed)
}

/// A registration from before the service ran a copy of its own cannot be
/// upgraded underneath a running service -- which is why the copy exists.
fn write_reregister(version: &str, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("this update");
    writeln!(
        out,
        "This host's service registration names a binary directly rather than a copy this \
         product owns, so it cannot pick up {version} by itself. Re-register it:"
    )
    .map_err(failed)?;
    writeln!(out, "  runner-manager service install").map_err(failed)
}

/// A service running an older build than the newest release this copy is.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceBehind {
    /// The version the service's private copy reports.
    service: String,
    source: RecordedSource,
    /// The command that starts the daemon, when the service manager is not
    /// running the one the record describes. A swap is the running daemon's
    /// own drain, so without one nothing swaps until it starts. Only read for
    /// [`RecordedSource::ThisCopy`].
    not_running: Option<String>,
}

/// The decision, split out so each state can be tested without a service.
/// `None` when the service's version is unknown or not older than `installed`.
///
/// Another copy is never executed to learn its version: it may be another
/// account's file, and `update --force` -- the step that would act on it --
/// examines it itself.
fn decide_service_behind(
    installed: &str,
    service: Option<&str>,
    source: RecordedSource,
) -> Option<ServiceBehind> {
    let service = service?;
    // Without build metadata: a build outside the release workflow reports
    // `X.Y.Z+git.<sha>`.
    let core = service.split('+').next().unwrap_or(service);
    (compare_versions(installed, core) == std::cmp::Ordering::Greater).then(|| ServiceBehind {
        service: service.to_owned(),
        source,
        not_running: None,
    })
}

/// Reads this host's service and decides whether it is behind.
///
/// The version is read by running the service's private copy, which lives in
/// this account's own state directory. Anything unreadable is `None`:
/// `service status` diagnoses a record, and this command saying nothing beats
/// guessing.
fn service_behind(
    context: &Context,
    installation: &Installation,
    installed: &str,
) -> Option<ServiceBehind> {
    let record = InstallRecord::read(context.paths()).ok()??;
    let service = super::status::binary_version(&record.binary);
    let mut behind = decide_service_behind(
        installed,
        service.as_deref(),
        recorded_source(&record, installation),
    )?;
    if matches!(behind.source, RecordedSource::ThisCopy(_)) {
        behind.not_running = restart_unless_running(context, &record);
    }
    Some(behind)
}

/// `None` when the service manager runs the daemon `record` describes;
/// otherwise the command that starts it. The registration must name the
/// record's own private copy, as `update --force` requires: a record from
/// another data directory says nothing about the machine's registration.
fn restart_unless_running(context: &Context, record: &InstallRecord) -> Option<String> {
    let Ok(status) = super::service::operations(context).status() else {
        return Some("runner-manager service status".to_owned());
    };
    let running = status.registration().is_some_and(|registration| {
        registration.running
            && registration
                .binary()
                .is_some_and(|binary| same_file(&binary, &record.binary))
    });
    (!running).then(|| status.restart_command())
}

/// Reports, and with `check` false performs, what a service behind the newest
/// release needs.
fn report_service_behind(
    behind: &ServiceBehind,
    installed: &str,
    check: bool,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this update");
    let service = &behind.service;
    writeln!(
        out,
        "runner-manager {installed} is the newest release and is installed, but the service still \
         runs {service}."
    )
    .map_err(failed)?;
    let source = match &behind.source {
        RecordedSource::ThisCopy(source) => source,
        RecordedSource::Other(source) => return write_hand_over_with_force(source, installed, out),
        RecordedSource::None => return write_reregister(installed, out),
    };
    // Marked whether or not the daemon runs: a daemon that starts later swaps
    // as soon as it starts anyway, and the mark is harmless.
    let marked = if check { Ok(()) } else { nudge_watcher(source) };
    if let Err(error) = &marked {
        writeln!(
            out,
            "warning: could not mark {} as changed ({error}), so the running service may not \
             notice it until it restarts.",
            display_path(source)
        )
        .map_err(failed)?;
    }
    match &behind.not_running {
        Some(start) => writeln!(
            out,
            "The service is not running (or its registration does not match its record), so \
             nothing swaps it now. It swaps to {installed} as soon as it starts; to start it now: \
             {start}"
        )
        .map_err(failed)?,
        None if marked.is_ok() => writeln!(
            out,
            "{} {service} -> {installed}: the service finishes every job it is running, then \
             restarts on {installed}. No job is interrupted.",
            if check { "Would swap" } else { "Swapping" }
        )
        .map_err(failed)?,
        None => {}
    }
    if check {
        writeln!(out, "Nothing has been changed, because --check was given.").map_err(failed)?;
    }
    writeln!(out, "Check progress with: runner-manager service status").map_err(failed)
}

/// Gives `path` a new modification time, so a daemon watching it looks again.
///
/// The daemon notices a new binary by its length and modification time (two
/// `stat` fields, every 30 seconds) and confirms it by running `--version`. A
/// copy that changed while that check could not see it -- the daemon was
/// started from another record, or the stamp happened to match -- is otherwise
/// never looked at again until the service restarts. A fresh modification time
/// makes the next check run `--version`, and the daemon then drains and swaps
/// exactly as after an update. The bytes are not touched.
///
/// The file may be the one this process is running from, so it is opened for
/// attributes only on Windows (a running image refuses a write handle) and
/// read-only elsewhere (Linux refuses one with `ETXTBSY`; setting the times of
/// a file one owns needs no write access).
fn nudge_watcher(path: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        /// `FILE_WRITE_ATTRIBUTES`, the one right `SetFileTime` needs.
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
        options.access_mode(FILE_WRITE_ATTRIBUTES);
    }
    #[cfg(not(windows))]
    options.read(true);
    options
        .open(path)?
        .set_modified(std::time::SystemTime::now())
}

/// Whether two paths name the same file, falling back to comparing the paths.
///
/// `canonicalize` is the reliable answer and needs both files to exist; the
/// recorded source may not, which is itself worth reporting rather than
/// crashing on.
fn same_file(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

// ---------------------------------------------------------------------------
// Rendering a path
// ---------------------------------------------------------------------------

/// A path as an operator would type it.
///
/// `std::fs::canonicalize` on Windows returns the `\\?\C:\…` extended-length
/// form, which is correct, is what the API hands back, and is not a path
/// anybody recognises as their own install directory. The prefix is stripped
/// for display only; every path this module *acts* on keeps it.
fn display_path(path: &Path) -> String {
    let rendered = path.display().to_string();
    match rendered.strip_prefix(r"\\?\") {
        Some(stripped) if !stripped.starts_with("UNC\\") => stripped.to_string(),
        _ => rendered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINUX: HostTarget = HostTarget {
        triple: "x86_64-unknown-linux-gnu",
        extension: "tar.gz",
        binary: "runner-manager",
    };

    fn sums(lines: &[&str]) -> String {
        format!("{}\n", lines.join("\n"))
    }

    fn a_source() -> AssetSource {
        AssetSource::Remote {
            base: "https://example.invalid/download".to_string(),
        }
    }

    #[test]
    fn managed_wsl_hosts_behind_the_new_version_are_named_with_the_command_that_updates_them() {
        use runner_manager_platform::wsl::record::WslProviderRecord;
        let root = tempfile::tempdir().unwrap();
        let paths = runner_manager_platform::paths::AppPaths::rooted_at(root.path());
        paths.create_all().unwrap();

        let mut out = Vec::new();
        report_managed_wsl_hosts(&paths, "0.4.35", &mut out).unwrap();
        assert!(out.is_empty(), "no managed host, nothing to say");

        for (distribution, version) in [
            ("Ubuntu", "0.4.34"),
            ("My Debian", "0.4.30"),
            ("Current", "0.4.35"),
            ("Newer", "0.4.100"),
        ] {
            WslProviderRecord::new(distribution, "task", version, chrono::Utc::now())
                .write(&paths)
                .unwrap();
        }
        report_managed_wsl_hosts(&paths, "0.4.35", &mut out).unwrap();
        let said = String::from_utf8(out).unwrap();
        assert!(
            said.contains("runner-manager wsl install --distribution \"Ubuntu\"   (runs 0.4.34)"),
            "{said}"
        );
        assert!(
            said.contains(
                "runner-manager wsl install --distribution \"My Debian\"   (runs 0.4.30)"
            ),
            "{said}"
        );
        assert!(
            !said.contains("Current") && !said.contains("Newer"),
            "a current or newer host is not named: {said}"
        );
        assert!(said.contains("no administrator rights"), "{said}");
    }

    #[test]
    fn the_archive_for_this_target_is_read_out_of_a_checksum_document() {
        let document = sums(&[
            &format!(
                "{}  runner-manager-1.2.3-aarch64-apple-darwin.tar.gz",
                "a".repeat(64)
            ),
            &format!(
                "{}  runner-manager-1.2.3-x86_64-unknown-linux-gnu.tar.gz",
                "b".repeat(64)
            ),
        ]);
        let found = read_published_archive(&document, LINUX, &a_source()).expect("one match");
        assert_eq!(found.version, "1.2.3");
        assert_eq!(found.digest, "b".repeat(64));
        assert_eq!(
            found.asset,
            "runner-manager-1.2.3-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    /// `sha256sum -b` writes `<hash> *<name>`, and the README tells a reader to
    /// verify a release with `sha256sum -c`, which accepts it. A parser
    /// stricter than that tool would call an intact release a dropped platform.
    #[test]
    fn the_binary_mode_checksum_line_is_accepted_too() {
        let document = sums(&[&format!(
            "{} *runner-manager-1.2.3-x86_64-unknown-linux-gnu.tar.gz",
            "c".repeat(64)
        )]);
        let found = read_published_archive(&document, LINUX, &a_source()).expect("one match");
        assert_eq!(found.digest, "c".repeat(64));
    }

    /// A truncated download and a release that skipped this platform are
    /// different failures, and telling an operator the first is the second
    /// sends them to entirely the wrong conclusion.
    #[test]
    fn an_unreadable_document_and_a_missing_platform_are_different_classes() {
        let unreadable =
            read_published_archive("<html>404</html>\n", LINUX, &a_source()).unwrap_err();
        assert_eq!(unreadable.class(), Failure::UnusableResponse);

        let elsewhere = sums(&[&format!(
            "{}  runner-manager-1.2.3-aarch64-apple-darwin.tar.gz",
            "d".repeat(64)
        )]);
        let missing = read_published_archive(&elsewhere, LINUX, &a_source()).unwrap_err();
        assert_eq!(missing.class(), Failure::UnsupportedHost);
    }

    #[test]
    fn two_archives_for_one_target_are_refused_rather_than_guessed() {
        let document = sums(&[
            &format!(
                "{}  runner-manager-1.2.3-x86_64-unknown-linux-gnu.tar.gz",
                "e".repeat(64)
            ),
            &format!(
                "{}  runner-manager-1.2.4-x86_64-unknown-linux-gnu.tar.gz",
                "f".repeat(64)
            ),
        ]);
        let refused = read_published_archive(&document, LINUX, &a_source()).unwrap_err();
        assert_eq!(refused.class(), Failure::UnusableResponse);
    }

    /// A signature file is a prefix match on the archive name and is not an
    /// archive.
    #[test]
    fn a_detached_signature_is_not_mistaken_for_the_archive() {
        assert_eq!(
            version_of_asset(
                "runner-manager-1.2.3-x86_64-unknown-linux-gnu.tar.gz.sig",
                LINUX
            ),
            None
        );
        assert_eq!(
            version_of_asset(
                "runner-manager-1.2.3-x86_64-unknown-linux-gnu.tar.gz",
                LINUX
            )
            .as_deref(),
            Some("1.2.3")
        );
    }

    /// Ordered as numbers, not as strings: `0.1.9` is older than `0.1.10`, and
    /// comparing them as text tells an operator on the newer build to downgrade.
    #[test]
    fn versions_order_numerically() {
        use std::cmp::Ordering;
        assert_eq!(compare_versions("0.1.10", "0.1.9"), Ordering::Greater);
        assert_eq!(compare_versions("0.1.9", "0.1.10"), Ordering::Less);
        assert_eq!(compare_versions("1.0.0", "1.0.0"), Ordering::Equal);
        // Unparseable compares as not-newer, so nothing is installed over a
        // working binary on the strength of a name this cannot read.
        assert_eq!(compare_versions("1.2.3-rc.1", "1.0.0"), Ordering::Less);
    }

    #[test]
    fn each_install_layout_is_recognised() {
        let state = PathBuf::from("/var/lib/runner-manager/state");
        assert_eq!(
            classify(
                Path::new(
                    "/usr/lib/node_modules/@ivan-murzak/runner-manager-linux-x64/bin/runner-manager"
                ),
                &state
            ),
            Channel::Npm
        );
        assert_eq!(
            classify(
                Path::new("/opt/homebrew/Cellar/runner-manager/0.1.17/bin/runner-manager"),
                &state
            ),
            Channel::Homebrew
        );
        assert_eq!(
            classify(
                Path::new("/home/me/checkout/target/release/runner-manager"),
                &state
            ),
            Channel::SourceBuild
        );
        assert_eq!(
            classify(Path::new("/home/me/.local/bin/runner-manager"), &state),
            Channel::Archive
        );
        // A release archive unpacked into a directory somebody called
        // `release` is not a checkout: both segments are required.
        assert_eq!(
            classify(Path::new("/opt/release/runner-manager"), &state),
            Channel::Archive
        );
    }

    // -- Which npm prefix holds this copy ----------------------------------------

    fn parts(components: &[&str]) -> PathBuf {
        components.iter().collect()
    }

    /// Windows: `<prefix>\node_modules\@ivan-murzak\runner-manager\node_modules\
    /// @ivan-murzak\runner-manager-win32-x64\bin\runner-manager.exe`, the layout
    /// `npm install --global --prefix` writes (observed with npm 12). Two
    /// accounts' copies give two prefixes, so each updates its own.
    #[test]
    fn the_npm_prefix_is_read_from_the_copy_being_updated() {
        let copy_of = |account: &str| {
            parts(&[
                "C:",
                "Users",
                account,
                "AppData",
                "Roaming",
                "npm",
                "node_modules",
                "@ivan-murzak",
                "runner-manager",
                "node_modules",
                "@ivan-murzak",
                "runner-manager-win32-x64",
                "bin",
                "runner-manager.exe",
            ])
        };
        let prefix_of =
            |account: &str| parts(&["C:", "Users", account, "AppData", "Roaming", "npm"]);
        assert_eq!(
            npm_global_prefix(&copy_of("ivand"), true),
            Some(prefix_of("ivand"))
        );
        assert_eq!(
            npm_global_prefix(&copy_of("yuriv"), true),
            Some(prefix_of("yuriv"))
        );

        // Elsewhere a global install lives under `<prefix>/lib/node_modules`.
        let linux = parts(&[
            "/",
            "usr",
            "lib",
            "node_modules",
            "@ivan-murzak",
            "runner-manager",
            "node_modules",
            "@ivan-murzak",
            "runner-manager-linux-x64",
            "bin",
            "runner-manager",
        ]);
        assert_eq!(npm_global_prefix(&linux, false), Some(parts(&["/", "usr"])));
    }

    /// A project-local install is not a global one, and naming a prefix for it
    /// would install a second copy somewhere else.
    #[test]
    fn a_copy_outside_a_global_npm_layout_has_no_prefix_and_is_refused() {
        let hoisted = parts(&[
            "/",
            "home",
            "me",
            "project",
            "node_modules",
            "@ivan-murzak",
            "runner-manager-linux-x64",
            "bin",
            "runner-manager",
        ]);
        assert_eq!(npm_global_prefix(&hoisted, true), None);
        assert_eq!(npm_global_prefix(&hoisted, false), None);
        let local_wrapper = parts(&[
            "/",
            "home",
            "me",
            "project",
            "node_modules",
            "@ivan-murzak",
            "runner-manager",
            "node_modules",
            "@ivan-murzak",
            "runner-manager-linux-x64",
            "bin",
            "runner-manager",
        ]);
        assert_eq!(npm_global_prefix(&local_wrapper, false), None);

        // Windows has no `lib` to tell a prefix from a project, so a project
        // is recognised by its `package.json`.
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), b"{}").unwrap();
        let in_project = [
            "node_modules",
            "@ivan-murzak",
            "runner-manager",
            "node_modules",
            "@ivan-murzak",
            "runner-manager-win32-x64",
            "bin",
            "runner-manager.exe",
        ]
        .iter()
        .fold(project.path().to_path_buf(), |path, part| path.join(part));
        assert_eq!(npm_global_prefix(&in_project, true), None);
        // The same layout under a directory with no `package.json` is a prefix.
        let prefix = tempfile::tempdir().unwrap();
        let in_prefix = in_project
            .strip_prefix(project.path())
            .map(|rest| prefix.path().join(rest))
            .unwrap();
        assert_eq!(
            npm_global_prefix(&in_prefix, true),
            Some(prefix.path().to_path_buf())
        );

        // A dependency of another global package is not this package's install.
        let dependency = parts(&[
            "C:",
            "npm",
            "node_modules",
            "other-tool",
            "node_modules",
            "@ivan-murzak",
            "runner-manager",
            "node_modules",
            "@ivan-murzak",
            "runner-manager-win32-x64",
            "bin",
            "runner-manager.exe",
        ]);
        assert_eq!(npm_global_prefix(&dependency, true), None);

        let installation = Installation {
            channel: Channel::Npm,
            path: hoisted,
        };
        let refusal = installation
            .refusal()
            .expect("refused before --check returns");
        assert!(
            refusal.message().contains("global npm install"),
            "{refusal:?}"
        );
    }

    // -- The service after `update` finds nothing newer --------------------------

    fn behind(source: RecordedSource) -> Option<ServiceBehind> {
        Some(ServiceBehind {
            service: "0.4.38".into(),
            source,
            not_running: None,
        })
    }

    /// ANASTASIIA: 0.4.39 installed by hand, the service still on 0.4.38.
    #[test]
    fn an_older_service_behind_the_newest_release_is_a_swap_not_nothing_to_do() {
        for source in [
            RecordedSource::ThisCopy(PathBuf::from("this-copy")),
            RecordedSource::Other(PathBuf::from("another-copy")),
            RecordedSource::None,
        ] {
            assert_eq!(
                decide_service_behind("0.4.39", Some("0.4.38"), source.clone()),
                behind(source)
            );
        }
        // A service built outside the release workflow is still compared.
        assert!(
            decide_service_behind("0.4.39", Some("0.4.38+git.0123abcd"), RecordedSource::None)
                .is_some()
        );
    }

    #[test]
    fn a_service_at_the_installed_version_or_unreadable_needs_nothing() {
        let this_copy = || RecordedSource::ThisCopy(PathBuf::from("this-copy"));
        assert_eq!(
            decide_service_behind("0.4.39", Some("0.4.39"), this_copy()),
            None
        );
        assert_eq!(
            decide_service_behind("0.4.39", Some("0.4.40"), this_copy()),
            None
        );
        assert_eq!(decide_service_behind("0.4.39", None, this_copy()), None);
        assert_eq!(
            decide_service_behind("0.4.39", Some("0.4.39+git.0123abcd"), this_copy()),
            None
        );
    }

    fn modified(path: &Path) -> std::time::SystemTime {
        std::fs::metadata(path).unwrap().modified().unwrap()
    }

    fn long_ago() -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000)
    }

    /// The swap is the daemon's own drain, set off by the watched file
    /// changing; `--check` changes nothing.
    #[test]
    fn a_swap_marks_the_watched_copy_changed_and_check_does_not() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("runner-manager");
        std::fs::write(&source, b"the newer build").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_modified(long_ago())
            .unwrap();
        let follow_up = ServiceBehind {
            service: "0.4.38".into(),
            source: RecordedSource::ThisCopy(source.clone()),
            not_running: None,
        };

        let mut out = Vec::new();
        report_service_behind(&follow_up, "0.4.39", true, &mut out).unwrap();
        let said = String::from_utf8(out).unwrap();
        assert!(said.contains("still runs 0.4.38"), "{said}");
        assert!(said.contains("Would swap 0.4.38 -> 0.4.39"), "{said}");
        assert_eq!(modified(&source), long_ago(), "--check changed the file");

        let mut out = Vec::new();
        report_service_behind(&follow_up, "0.4.39", false, &mut out).unwrap();
        let said = String::from_utf8(out).unwrap();
        assert!(said.contains("Swapping 0.4.38 -> 0.4.39"), "{said}");
        assert!(said.contains("No job is interrupted"), "{said}");
        assert!(!said.contains("warning"), "{said}");
        assert!(
            modified(&source) > long_ago(),
            "the watched file was not marked"
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"the newer build");
    }

    /// No running daemon means no drain to set off: the report says so and
    /// names the start command instead of claiming a swap, and the copy is
    /// still marked for the daemon that starts later.
    #[test]
    fn a_service_that_is_not_running_is_told_how_to_start_not_that_it_swaps() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("runner-manager");
        std::fs::write(&source, b"the newer build").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_modified(long_ago())
            .unwrap();
        let follow_up = ServiceBehind {
            service: "0.4.38".into(),
            source: RecordedSource::ThisCopy(source.clone()),
            not_running: Some("the-start-command".into()),
        };

        let mut out = Vec::new();
        report_service_behind(&follow_up, "0.4.39", false, &mut out).unwrap();
        let said = String::from_utf8(out).unwrap();
        assert!(said.contains("is not running"), "{said}");
        assert!(said.contains("the-start-command"), "{said}");
        assert!(!said.contains("Swapping"), "{said}");
        assert!(modified(&source) > long_ago());
    }

    /// A copy watched by another daemon is named with the job-safe command
    /// that hands this one over -- not `service install`, which refuses while
    /// the daemon runs -- and nothing is written.
    #[test]
    fn a_service_from_another_copy_is_told_to_hand_over_with_force() {
        let follow_up = ServiceBehind {
            service: "0.4.38".into(),
            source: RecordedSource::Other(PathBuf::from("another-copy")),
            not_running: None,
        };
        let mut out = Vec::new();
        report_service_behind(&follow_up, "0.4.39", false, &mut out).unwrap();
        let said = String::from_utf8(out).unwrap();
        assert!(said.contains("another-copy"), "{said}");
        assert!(said.contains("runner-manager update --force"), "{said}");
        assert!(!said.contains("service install"), "{said}");
    }

    /// The copy being marked is very often the one this process runs from: a
    /// running image refuses a write handle on Windows and `ETXTBSY` refuses
    /// one on Linux, so the mark must not need one.
    #[test]
    fn a_running_executable_can_be_marked_changed() {
        let (system_binary, argument) = if cfg!(windows) {
            let root = std::env::var_os("SystemRoot").expect("SystemRoot");
            (
                PathBuf::from(root).join("System32").join("findstr.exe"),
                "x",
            )
        } else {
            (PathBuf::from("/bin/cat"), "-")
        };
        let root = tempfile::tempdir().unwrap();
        let copy = root
            .path()
            .join(system_binary.file_name().expect("a file name"));
        std::fs::copy(&system_binary, &copy).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&copy)
            .unwrap()
            .set_modified(long_ago())
            .unwrap();

        /// `ETXTBSY`.
        const TEXT_FILE_BUSY: i32 = 26;
        // Retried past `ETXTBSY`: another test thread forking while the copy
        // was open for writing leaves a short window where Linux refuses it.
        let mut child = (0..100)
            .find_map(|_| {
                match std::process::Command::new(&copy)
                    .arg(argument)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .spawn()
                {
                    Ok(child) => Some(child),
                    Err(error) if error.raw_os_error() == Some(TEXT_FILE_BUSY) => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        None
                    }
                    Err(error) => panic!("cannot run {}: {error}", copy.display()),
                }
            })
            .expect("the copy ran");
        let marked = nudge_watcher(&copy);
        let still_running = child.try_wait().unwrap().is_none();
        // EOF on stdin ends it; nothing is killed.
        drop(child.stdin.take());
        child.wait().unwrap();

        assert!(still_running, "the copy exited before it was marked");
        marked.expect("a running executable can be marked");
        assert!(modified(&copy) > long_ago());
    }
}
