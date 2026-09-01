// owner: b1-domain-core

//! Value types shared by every other module in this crate.
//!
//! These are the types named in
//! `.taskflow/2026-08-21-local-runner-manager/04-subsystem-contracts.md`,
//! "Persistent local data". Two rules shape every type here:
//!
//! 1. **No I/O.** Nothing in this crate opens a socket, a file, or a database.
//!    `rusqlite` is declared in `crates/domain/Cargo.toml` for `b2`, which owns
//!    `store.rs`; no module owned by `b1` refers to it.
//! 2. **An illegal configuration should be unrepresentable, not merely
//!    rejected.** Where the contract document writes a plain integer that has a
//!    documented floor or ceiling — `host_capacity`, `refresh_interval_secs` —
//!    this module gives it a type that cannot hold the illegal value, so a
//!    caller who forgets to validate still cannot build one.
//!
//! D4 removed `scale_set_id`, `scale_set_name`, and `protocol_flag` from the
//! model. They are not here under another name, and they must not come back:
//! the routing token is now [`crate::policy::RoutingLabels`].

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::num::{NonZeroU16, NonZeroUsize};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::path::LocalAbsolutePath;

/// Every timestamp in the domain is UTC.
///
/// The domain never reads this from the operating system. Decisions that depend
/// on elapsed time take a [`Clock`], which the tests replace with
/// `runner_manager_testkit::clock::FakeClock`.
pub type Timestamp = chrono::DateTime<chrono::Utc>;

/// A span of time, re-exported so callers need not name `chrono` directly.
pub type Elapsed = chrono::TimeDelta;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A value that cannot be constructed because it would violate a documented
/// constraint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("{what} must not be empty")]
    Empty { what: &'static str },

    #[error("{what} must be at most {max} characters, got {actual}")]
    TooLong {
        what: &'static str,
        max: usize,
        actual: usize,
    },

    #[error("{what} contains a character that is not allowed here: {found:?}")]
    IllegalCharacter { what: &'static str, found: char },

    #[error("{what} must not start or end with {edge:?}")]
    IllegalEdge { what: &'static str, edge: char },

    #[error(
        "a repository target must be written as OWNER/REPO; got {got:?} with {slashes} separator(s)"
    )]
    MalformedOwnerRepo { got: String, slashes: usize },

    #[error("{what} must be at least {min}, got {actual}")]
    BelowFloor {
        what: &'static str,
        min: u16,
        actual: u16,
    },

    #[error("a non-empty collection of {what} was required, but none were supplied")]
    NonEmptyRequired { what: &'static str },

    #[error("{what} is not a recognised value: {got:?}")]
    Unrecognised { what: &'static str, got: String },
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// The domain's only source of "now".
///
/// `b1`'s Definition of Done requires that recovery decisions be testable with
/// no real time dependency, so every function in this crate that compares
/// timestamps takes one of these rather than calling the system clock.
pub trait Clock: fmt::Debug + Send + Sync {
    fn now(&self) -> Timestamp;
}

/// The production adapter.
///
/// It is an adapter and nothing more: **no decision function in this crate
/// constructs one**. Every such function takes `&dyn Clock`, which is what makes
/// `FakeClock` a complete substitute in tests. It lives here rather than in
/// `crates/platform` because the port lives here and `platform` depends on
/// `domain`, not the other way round.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        chrono::Utc::now()
    }
}

impl<T: Clock + ?Sized> Clock for &T {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

impl<T: Clock + ?Sized> Clock for std::sync::Arc<T> {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

macro_rules! uuid_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// A fresh random identifier.
            #[must_use]
            pub fn new_random() -> Self {
                Self(Uuid::new_v4())
            }

            /// A deterministic identifier, for fixtures and tests.
            #[must_use]
            pub const fn from_u128(value: u128) -> Self {
                Self(Uuid::from_u128(value))
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

uuid_newtype!(HostId, "Identifies one physical machine running one agent.");
uuid_newtype!(PolicyId, "Identifies one `ScalePolicy`.");
uuid_newtype!(AttemptId, "Identifies one `RunnerAttempt`.");

// ---------------------------------------------------------------------------
// Host operating system and architecture
// ---------------------------------------------------------------------------

/// The host operating systems this product supports.
///
/// The supported-version matrix — Windows 10/11 and Server 2016/2019/2022,
/// macOS 11.0+, and the nine listed Linux distributions — is `d1`'s to validate
/// (`01-current-architecture.md`, "Authoritative external constraints"). The
/// domain only needs the three families, because that is what a routing label
/// encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    Windows,
    MacOs,
    Linux,
}

impl Os {
    pub const ALL: [Os; 3] = [Os::Windows, Os::MacOs, Os::Linux];

    /// The token this OS contributes to a derived routing label.
    ///
    /// These are GitHub's own runner-package OS tokens (`win`, `osx`, `linux`),
    /// which is what `e2` will select a download by, so a label and a package
    /// name never disagree about what "this host" is. `02-target-architecture.md`
    /// gives `rm-home-win-x64` as the worked example, which fixes `win`.
    #[must_use]
    pub const fn label_token(self) -> &'static str {
        match self {
            Os::Windows => "win",
            Os::MacOs => "osx",
            Os::Linux => "linux",
        }
    }

    /// Container actions and service containers require Linux
    /// (`01-current-architecture.md`, edge case 2). `f2` surfaces this on a
    /// macOS or Windows policy.
    #[must_use]
    pub const fn supports_container_actions(self) -> bool {
        matches!(self, Os::Linux)
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label_token())
    }
}

impl FromStr for Os {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "win" | "windows" => Ok(Os::Windows),
            "osx" | "macos" | "mac" | "darwin" => Ok(Os::MacOs),
            "linux" => Ok(Os::Linux),
            other => Err(ValidationError::Unrecognised {
                what: "host operating system",
                got: other.to_string(),
            }),
        }
    }
}

/// The host architectures this product supports.
///
/// ARM64 is public preview on all three operating systems and ARM32 is Linux
/// only (`01-current-architecture.md`). Enforcing that pairing is `d1`'s job;
/// this enum only has to be able to name the values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X64,
    Arm64,
    Arm32,
}

impl Arch {
    pub const ALL: [Arch; 3] = [Arch::X64, Arch::Arm64, Arch::Arm32];

    /// The token this architecture contributes to a derived routing label.
    /// GitHub's runner-package architecture tokens; `x64` is fixed by the
    /// `rm-home-win-x64` example in `02-target-architecture.md`.
    #[must_use]
    pub const fn label_token(self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::Arm64 => "arm64",
            Arch::Arm32 => "arm",
        }
    }

    /// ARM64 is public preview, which `f2` must warn about rather than reject.
    #[must_use]
    pub const fn is_public_preview(self) -> bool {
        matches!(self, Arch::Arm64)
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label_token())
    }
}

impl FromStr for Arch {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "x64" | "x86_64" | "amd64" => Ok(Arch::X64),
            "arm64" | "aarch64" => Ok(Arch::Arm64),
            "arm" | "arm32" | "armv7" => Ok(Arch::Arm32),
            other => Err(ValidationError::Unrecognised {
                what: "host architecture",
                got: other.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Service start mode and cache policy
// ---------------------------------------------------------------------------

/// When the installed service starts (`05-infrastructure.md`, "Service
/// behavior"). D13 makes `Boot` the default; `Login` is available for operators
/// who prefer a user-scoped secret store.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum StartMode {
    #[default]
    Boot,
    Login,
}

impl fmt::Display for StartMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StartMode::Boot => "boot",
            StartMode::Login => "login",
        })
    }
}

impl FromStr for StartMode {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "boot" => Ok(StartMode::Boot),
            "login" => Ok(StartMode::Login),
            other => Err(ValidationError::Unrecognised {
                what: "service start mode",
                got: other.to_string(),
            }),
        }
    }
}

/// What survives an attempt's cleanup.
///
/// `04-subsystem-contracts.md`, precedence rule 6: "Runtime cache retention is
/// optional; job workspace retention is **always disabled** in v1."
///
/// The first half is the choice this enum offers. The second half is enforced by
/// having no representation at all: [`CachePolicy::retains_job_workspace`] is a
/// `const fn` returning `false`, and there is no variant, field, or constructor
/// that could make it return anything else. A future version that wants
/// workspace retention has to add one deliberately, which is the point — a
/// retained workspace is the two-job contamination path that `e3` and
/// `07-security.md` test against.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    /// Keep the verified runner package cache between attempts (the default;
    /// re-downloading it on every cold start would be the main avoidable cost).
    #[default]
    RetainRunnerPackage,
    /// Discard the runner package cache after each attempt.
    DiscardRunnerPackage,
}

impl CachePolicy {
    #[must_use]
    pub const fn retains_runner_package(self) -> bool {
        matches!(self, CachePolicy::RetainRunnerPackage)
    }

    /// Always `false`, by construction rather than by policy.
    ///
    /// D4 is the deliberate addition the type comment anticipated, and it was
    /// made **on another type**: job-workspace retention is
    /// [`crate::workspace::WorkspacePolicy`], repository-scoped, opt-in, and
    /// carrying its own root. Nothing was added here, so a caller reading a
    /// `CachePolicy` still cannot conclude anything about the job workspace —
    /// which is the point of keeping them apart
    /// (`02-target-architecture.md`, "Repository policy").
    #[must_use]
    pub const fn retains_job_workspace(self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Refresh interval
// ---------------------------------------------------------------------------

/// The agent's per-target refresh interval.
///
/// `04-subsystem-contracts.md`, "Refresh and backpressure": "a bounded interval,
/// default 60 seconds with a hard floor of 30 seconds per target". The floor is
/// a rate-budget constraint, not a preference — below it, one target's demand,
/// inventory, and workflow-count polling alone consumes roughly a tenth of the
/// hourly ceiling. Making it a type means a caller cannot write `5` into
/// `Host.refresh_interval_secs` at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct RefreshInterval(u16);

impl RefreshInterval {
    pub const MIN_SECS: u16 = 30;
    pub const DEFAULT_SECS: u16 = 60;

    /// # Errors
    /// [`ValidationError::BelowFloor`] if `secs` is under the documented
    /// 30-second floor.
    pub fn from_secs(secs: u16) -> Result<Self, ValidationError> {
        if secs < Self::MIN_SECS {
            return Err(ValidationError::BelowFloor {
                what: "refresh interval (seconds)",
                min: Self::MIN_SECS,
                actual: secs,
            });
        }
        Ok(Self(secs))
    }

    #[must_use]
    pub const fn as_secs(self) -> u16 {
        self.0
    }
}

impl Default for RefreshInterval {
    fn default() -> Self {
        Self(Self::DEFAULT_SECS)
    }
}

impl TryFrom<u16> for RefreshInterval {
    type Error = ValidationError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_secs(value)
    }
}

impl From<RefreshInterval> for u16 {
    fn from(value: RefreshInterval) -> Self {
        value.0
    }
}

impl fmt::Display for RefreshInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0)
    }
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

/// One GitHub runner label, normalised.
///
/// **Normalisation is lower-casing, and it is not cosmetic.** The `v1` spike
/// registered a runner with `["rm-d18-spike","Windows","X64","self-hosted-rm"]`
/// and GitHub returned `windows` and `x64`
/// (`docs/spikes/d18-org-jit-verification.md`, Point 3, finding 3). A label read
/// back from the API therefore never matches a mixed-case label held locally
/// unless both sides are folded first. Folding on construction makes every
/// comparison in this crate — `Eq`, `Ord`, `Hash`, set membership — case
/// insensitive for free, so no call site can forget.
///
/// **The fold is ASCII, matching [`HostLabel`] and the target [`Name`] types.**
/// The only case folding this crate has evidence for is GitHub's, and the only
/// evidence is the spike above, which is entirely ASCII. Unicode
/// `to_lowercase()` would also make folding length-changing — `İ` (U+0130)
/// lowercases to two chars — which is how a 256-character label could exceed
/// [`Self::MAX_LEN`] *after* construction. ASCII folding is length-preserving,
/// so that class of bug cannot occur, and the length check below is applied to
/// the folded value regardless so the stored string is what was measured.
///
/// **What the character rules are for.** They are round-trippability rules, not
/// injection defences, and reading them as the latter is how a rule that
/// defends nothing gets added. A `Label` is never interpolated into a shell: it
/// travels as one element of the runner's comma-separated `--labels` argument
/// and as a JSON string. So exactly two characters break the round trip — the
/// comma, which is the separator itself, and control characters, which break
/// both the argument and the JSON framing. Nothing else does, and a quote rule
/// in particular is neither necessary (no shell is involved) nor sufficient
/// (`<`, `>`, `$`, `` ` ``, `;`, `|`, `&` and whitespace would all still pass).
///
/// An explicit allow-list was considered and rejected: real GitHub labels
/// include `c#`, `.net`, `x86_64` and similar, so any allow-list narrow enough
/// to be worth having would reject legitimate `runs-on` values and turn a
/// cosmetic concern into a demand-matching failure in
/// [`crate::policy::RunsOn::required_labels`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Label(String);

impl Label {
    /// GitHub's documented maximum label length.
    pub const MAX_LEN: usize = 256;

    /// # Errors
    /// Empty, over-long, comma-bearing, or control-character-bearing input. A
    /// comma is rejected because it separates labels in the runner's own
    /// configuration, so a label containing one is not round-trippable; control
    /// characters break the same argument and the JSON encoding around it. See
    /// the type documentation for why the list stops there.
    pub fn new(raw: impl AsRef<str>) -> Result<Self, ValidationError> {
        let trimmed = raw.as_ref().trim();
        if trimmed.is_empty() {
            return Err(ValidationError::Empty { what: "a label" });
        }
        if let Some(bad) = trimmed.chars().find(|c| *c == ',' || c.is_control()) {
            return Err(ValidationError::IllegalCharacter {
                what: "a label",
                found: bad,
            });
        }
        // Folded first, then measured: the length that matters is the length of
        // the value this type will actually hold and hand to GitHub.
        let folded = trimmed.to_ascii_lowercase();
        if folded.chars().count() > Self::MAX_LEN {
            return Err(ValidationError::TooLong {
                what: "a label",
                max: Self::MAX_LEN,
                actual: folded.chars().count(),
            });
        }
        Ok(Self(folded))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Label {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Label {
    type Error = ValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Label> for String {
    fn from(value: Label) -> Self {
        value.0
    }
}

impl FromStr for Label {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// The operator's `--host-label` value: the human-chosen half of a routing
/// label.
///
/// Narrower than a [`Label`] on purpose. This value is concatenated into
/// `rm-<host>-<os>-<arch>`, so a host label containing a space or an upper-case
/// letter would produce a routing label an operator could not retype into
/// `runs-on` from memory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostLabel(String);

impl HostLabel {
    pub const MAX_LEN: usize = 64;

    /// # Errors
    /// Empty, over-long, or containing anything but ASCII alphanumerics,
    /// `-`, and `_`; or starting or ending with `-`.
    pub fn new(raw: impl AsRef<str>) -> Result<Self, ValidationError> {
        let trimmed = raw.as_ref().trim();
        if trimmed.is_empty() {
            return Err(ValidationError::Empty {
                what: "a host label",
            });
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(ValidationError::TooLong {
                what: "a host label",
                max: Self::MAX_LEN,
                actual: trimmed.len(),
            });
        }
        if let Some(bad) = trimmed
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
        {
            return Err(ValidationError::IllegalCharacter {
                what: "a host label",
                found: bad,
            });
        }
        if trimmed.starts_with('-') || trimmed.ends_with('-') {
            return Err(ValidationError::IllegalEdge {
                what: "a host label",
                edge: '-',
            });
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for HostLabel {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<HostLabel> for String {
    fn from(value: HostLabel) -> Self {
        value.0
    }
}

impl FromStr for HostLabel {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// ---------------------------------------------------------------------------
// NonEmpty
// ---------------------------------------------------------------------------

/// A collection that cannot be empty.
///
/// `04-subsystem-contracts.md` types the routing token as
/// `Option<NonEmpty<Label>>`, and the `v1` spike shows why the inner
/// non-emptiness is load-bearing rather than tidy: `generate-jitconfig` with
/// `labels: []` returns `422 Invalid property /labels: 1 item required`
/// (`docs/spikes/d18-org-jit-verification.md`, Point 3). An empty label set is
/// not a degenerate case to handle at the gateway; it is a value the domain
/// should not be able to hand out.
///
/// [`crate::policy::RoutingLabels`] gives a *stronger* guarantee than this type
/// and is what a policy actually stores; this type is the shape the contract
/// document names, and [`crate::policy::RoutingLabels::to_non_empty`] produces
/// it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonEmpty<T> {
    items: Vec<T>,
}

impl<T> NonEmpty<T> {
    #[must_use]
    pub fn of(first: T) -> Self {
        Self { items: vec![first] }
    }

    /// # Errors
    /// [`ValidationError::NonEmptyRequired`] when `items` is empty.
    pub fn try_from_vec(items: Vec<T>, what: &'static str) -> Result<Self, ValidationError> {
        if items.is_empty() {
            return Err(ValidationError::NonEmptyRequired { what });
        }
        Ok(Self { items })
    }

    #[must_use]
    pub fn first(&self) -> &T {
        // Safe: no constructor produces an empty `items`.
        &self.items[0]
    }

    /// The number of elements. Never zero, which is why this returns
    /// [`NonZeroUsize`] rather than `usize` and is not called `len`.
    #[must_use]
    pub fn count(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.items.len()).expect("NonEmpty is never empty")
    }

    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.items.iter()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    pub fn push(&mut self, item: T) {
        self.items.push(item);
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.items
    }

    #[must_use]
    pub fn contains(&self, needle: &T) -> bool
    where
        T: PartialEq,
    {
        self.items.contains(needle)
    }
}

impl<'a, T> IntoIterator for &'a NonEmpty<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl<T> IntoIterator for NonEmpty<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// A GitHub name compared the way GitHub compares it: without regard to case.
///
/// The original spelling is preserved for display — an operator who typed
/// `IvanMurzak/GitHub-Runner-Scaler-UI` should see it back — while `Eq`, `Ord`,
/// and `Hash` fold case, so `f2`'s duplicate-policy check cannot be defeated by
/// re-adding the same repository in different capitalisation.
#[derive(Debug, Clone)]
struct Name(String);

impl Name {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for Name {}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .bytes()
            .map(|b| b.to_ascii_lowercase())
            .cmp(other.0.bytes().map(|b| b.to_ascii_lowercase()))
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.0.bytes() {
            state.write_u8(byte.to_ascii_lowercase());
        }
        state.write_u8(0xff);
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn validate_login(raw: &str, what: &'static str) -> Result<Name, ValidationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::Empty { what });
    }
    if trimmed.len() > 39 {
        return Err(ValidationError::TooLong {
            what,
            max: 39,
            actual: trimmed.len(),
        });
    }
    if let Some(bad) = trimmed
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '-'))
    {
        return Err(ValidationError::IllegalCharacter { what, found: bad });
    }
    if trimmed.starts_with('-') || trimmed.ends_with('-') {
        return Err(ValidationError::IllegalEdge { what, edge: '-' });
    }
    Ok(Name(trimmed.to_string()))
}

fn validate_repo_name(raw: &str) -> Result<Name, ValidationError> {
    const WHAT: &str = "a repository name";
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::Empty { what: WHAT });
    }
    if trimmed.len() > 100 {
        return Err(ValidationError::TooLong {
            what: WHAT,
            max: 100,
            actual: trimmed.len(),
        });
    }
    if trimmed == "." || trimmed == ".." {
        return Err(ValidationError::Unrecognised {
            what: WHAT,
            got: trimmed.to_string(),
        });
    }
    if let Some(bad) = trimmed
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    {
        return Err(ValidationError::IllegalCharacter {
            what: WHAT,
            found: bad,
        });
    }
    Ok(Name(trimmed.to_string()))
}

/// One repository, as `OWNER/REPO`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OwnerRepo {
    owner: Name,
    repo: Name,
}

impl OwnerRepo {
    /// # Errors
    /// Either half failing GitHub's naming rules.
    pub fn new(owner: impl AsRef<str>, repo: impl AsRef<str>) -> Result<Self, ValidationError> {
        Ok(Self {
            owner: validate_login(owner.as_ref(), "a repository owner")?,
            repo: validate_repo_name(repo.as_ref())?,
        })
    }

    /// # Errors
    /// Input that is not exactly one `owner/repo` pair.
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, ValidationError> {
        let raw = raw.as_ref().trim();
        let slashes = raw.matches('/').count();
        if slashes != 1 {
            return Err(ValidationError::MalformedOwnerRepo {
                got: raw.to_string(),
                slashes,
            });
        }
        let (owner, repo) = raw.split_once('/').expect("exactly one separator");
        Self::new(owner, repo)
    }

    #[must_use]
    pub fn owner(&self) -> &str {
        self.owner.as_str()
    }

    #[must_use]
    pub fn repo(&self) -> &str {
        self.repo.as_str()
    }
}

impl fmt::Display for OwnerRepo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.repo)
    }
}

impl TryFrom<String> for OwnerRepo {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<OwnerRepo> for String {
    fn from(value: OwnerRepo) -> Self {
        value.to_string()
    }
}

impl FromStr for OwnerRepo {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// One organization login.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Org(Name);

impl Org {
    /// # Errors
    /// Input failing GitHub's login rules.
    pub fn new(raw: impl AsRef<str>) -> Result<Self, ValidationError> {
        Ok(Self(validate_login(raw.as_ref(), "an organization login")?))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for Org {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl TryFrom<String> for Org {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Org> for String {
    fn from(value: Org) -> Self {
        value.to_string()
    }
}

impl FromStr for Org {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Which scope a target has. D18's *whole* difference lives in this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    Repository,
    Organization,
}

/// What one policy scales for (D18).
///
/// `04-subsystem-contracts.md`: "The two differ only in which GitHub endpoints
/// and which App permission the gateway uses; ownership, capacity, and lifecycle
/// rules are identical."
///
/// That sentence is a design constraint on *this crate*, and it is why nothing
/// below branches on the variant: there is no `is_repository()` shortcut, no
/// per-variant capacity rule, and no endpoint string. Endpoints belong to `c3`
/// and `c4`; the only thing the domain exposes is [`ScaleTarget::scope`], so a
/// gateway can select one. `policy::tests::repository_and_organization_targets_
/// are_equivalent` runs one body over both variants to keep it that way.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "scope", content = "value", rename_all = "snake_case")]
pub enum ScaleTarget {
    Repository(OwnerRepo),
    Organization(Org),
}

impl ScaleTarget {
    /// # Errors
    /// A malformed `OWNER/REPO`.
    pub fn repository(raw: impl AsRef<str>) -> Result<Self, ValidationError> {
        Ok(Self::Repository(OwnerRepo::parse(raw)?))
    }

    /// # Errors
    /// A malformed organization login.
    pub fn organization(raw: impl AsRef<str>) -> Result<Self, ValidationError> {
        Ok(Self::Organization(Org::new(raw)?))
    }

    #[must_use]
    pub const fn scope(&self) -> TargetScope {
        match self {
            ScaleTarget::Repository(_) => TargetScope::Repository,
            ScaleTarget::Organization(_) => TargetScope::Organization,
        }
    }

    /// The target as an operator would type it: `owner/repo` or `org`.
    #[must_use]
    pub fn slug(&self) -> String {
        match self {
            ScaleTarget::Repository(r) => r.to_string(),
            ScaleTarget::Organization(o) => o.to_string(),
        }
    }
}

impl fmt::Display for ScaleTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.slug())
    }
}

// ---------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------

/// One machine running one agent.
///
/// `host_capacity` is the ceiling on concurrent runner attempts across **every**
/// policy on this machine (D9). It is a [`NonZeroU16`] because a host that
/// declares zero capacity is not a configured host, it is a disabled one, and
/// the two should not be spelled the same way. [`crate::capacity::HostAllocator`]
/// is the only thing that spends it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub id: HostId,
    pub display_name: String,
    pub os: Os,
    pub architecture: Arch,
    pub host_capacity: NonZeroU16,
    pub service_start_mode: StartMode,
    pub refresh_interval: RefreshInterval,
    /// Where disposable runner attempts are created, when the operator has said
    /// (D2).
    ///
    /// `None` means "use the platform default", which is resolved at runtime by
    /// `b1` and shown as `platform-default` rather than baked into the row.
    /// `02-target-architecture.md`: "Storing only the override allows a future
    /// platform-default correction without rewriting every database" — a stored
    /// `C:\rman` would silently become the operator's explicit choice the day
    /// the default moves.
    ///
    /// This is **runner** placement and not application data: config, SQLite,
    /// logs, diagnostics and the verified package cache stay under `AppPaths`,
    /// and `--data-dir` continues to move those and only those (invariant 1).
    pub runner_root_override: Option<LocalAbsolutePath>,
    pub created_at: Timestamp,
}

impl Host {
    /// # Errors
    /// An empty display name.
    pub fn new(
        id: HostId,
        display_name: impl AsRef<str>,
        os: Os,
        architecture: Arch,
        host_capacity: NonZeroU16,
        created_at: Timestamp,
    ) -> Result<Self, ValidationError> {
        let display_name = display_name.as_ref().trim();
        if display_name.is_empty() {
            return Err(ValidationError::Empty {
                what: "a host display name",
            });
        }
        Ok(Self {
            id,
            display_name: display_name.to_string(),
            os,
            architecture,
            host_capacity,
            service_start_mode: StartMode::default(),
            refresh_interval: RefreshInterval::default(),
            // D3: a newly registered host places attempts under the platform
            // default. Nothing but an explicit `host set-runtime-root` fills
            // this in.
            runner_root_override: None,
            created_at,
        })
    }

    #[must_use]
    pub fn host_capacity(&self) -> u16 {
        self.host_capacity.get()
    }

    /// Whether the runner root came from the operator rather than the platform.
    ///
    /// D11 requires CLI and TUI to show "the effective path \[and] configured
    /// source"; the effective path needs `b1`'s platform default, but which of
    /// the two sources produced it is decidable here, with no I/O.
    #[must_use]
    pub const fn has_configured_runner_root(&self) -> bool {
        self.runner_root_override.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> Timestamp {
        chrono::DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    // -- labels -------------------------------------------------------------

    #[test]
    fn a_label_is_folded_to_lower_case_because_github_stores_it_that_way() {
        // `docs/spikes/d18-org-jit-verification.md`, Point 3, finding 3:
        // "`Windows` and `X64` came back as `windows` and `x64`."
        assert_eq!(Label::new("Windows").unwrap().as_str(), "windows");
        assert_eq!(Label::new("X64").unwrap().as_str(), "x64");
        assert_eq!(
            Label::new("  RM-Home-Win-X64 ").unwrap().as_str(),
            "rm-home-win-x64"
        );
        assert_eq!(
            Label::new("Windows").unwrap(),
            Label::new("windows").unwrap()
        );
    }

    #[test]
    fn label_case_folding_reaches_eq_ord_and_hash_together() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(Label::new("Windows").unwrap());
        set.insert(Label::new("windows").unwrap());
        set.insert(Label::new("WINDOWS").unwrap());
        assert_eq!(
            set.len(),
            1,
            "three spellings of one GitHub label must collapse to one member, \
             or a routing-label set can silently hold duplicates"
        );
    }

    #[test]
    fn an_unusable_label_cannot_be_constructed() {
        assert!(matches!(Label::new(""), Err(ValidationError::Empty { .. })));
        assert!(matches!(
            Label::new("   "),
            Err(ValidationError::Empty { .. })
        ));
        assert!(
            matches!(
                Label::new("a,b"),
                Err(ValidationError::IllegalCharacter { found: ',', .. })
            ),
            "a comma separates labels in the runner's own configuration, so a \
             label containing one does not round-trip"
        );
        assert!(matches!(
            Label::new("a\nb"),
            Err(ValidationError::IllegalCharacter { .. })
        ));
        assert!(matches!(
            Label::new("x".repeat(Label::MAX_LEN + 1)),
            Err(ValidationError::TooLong { .. })
        ));
        assert!(Label::new("x".repeat(Label::MAX_LEN)).is_ok());
    }

    #[test]
    fn the_label_character_rules_are_about_round_tripping_not_injection() {
        // A quote is not rejected. It has no authority behind it: a Label is
        // never interpolated into a shell, so quoting cannot break anything, and
        // rejecting quotes while accepting every one of the characters below
        // would be a rule that defends nothing while looking like it defends
        // something.
        assert_eq!(Label::new(r#"say"hi"#).unwrap().as_str(), r#"say"hi"#);
        assert_eq!(Label::new("it's").unwrap().as_str(), "it's");

        // The characters an injection rule would have to cover, all accepted --
        // this is the "neither necessary nor sufficient" half, pinned so that a
        // future quote-style rule has to confront it.
        for raw in ["a<b", "a>b", "a$b", "a`b", "a;b", "a|b", "a&b", "a b"] {
            assert!(
                Label::new(raw).is_ok(),
                "{raw:?} must construct: the rule set is round-trippability, not \
                 shell safety"
            );
        }

        // Real GitHub labels an allow-list would have had to enumerate.
        for raw in ["c#", ".net", "x86_64", "ubuntu-22.04"] {
            assert!(Label::new(raw).is_ok(), "{raw:?} is a real GitHub label");
        }
    }

    #[test]
    fn label_folding_is_ascii_and_the_length_is_measured_after_folding() {
        // Consistent with HostLabel and with the target Name type, both of which
        // fold with to_ascii_lowercase.
        assert_eq!(
            Label::new("RM-Home-Win-X64").unwrap().as_str(),
            "rm-home-win-x64"
        );

        // U+0130 lowercases to two chars under Unicode folding. Under ASCII
        // folding it is left alone, so a MAX_LEN input stays MAX_LEN and cannot
        // exceed the ceiling after construction -- which is what the old
        // fold-after-measure order allowed.
        let mut raw = "x".repeat(Label::MAX_LEN - 1);
        raw.push('\u{0130}');
        let label = Label::new(&raw).expect("exactly MAX_LEN characters");
        assert_eq!(
            label.as_str().chars().count(),
            Label::MAX_LEN,
            "a constructed Label must never be longer than MAX_LEN"
        );
    }

    #[test]
    fn a_host_label_is_narrower_than_a_label() {
        assert_eq!(HostLabel::new("Home-Win").unwrap().as_str(), "home-win");
        assert!(matches!(
            HostLabel::new("home win"),
            Err(ValidationError::IllegalCharacter { found: ' ', .. })
        ));
        assert!(matches!(
            HostLabel::new("-home"),
            Err(ValidationError::IllegalEdge { edge: '-', .. })
        ));
        assert!(matches!(
            HostLabel::new("home-"),
            Err(ValidationError::IllegalEdge { edge: '-', .. })
        ));
        assert!(matches!(
            HostLabel::new(""),
            Err(ValidationError::Empty { .. })
        ));
        assert!(HostLabel::new("home_win2").is_ok());
    }

    // -- NonEmpty -----------------------------------------------------------

    #[test]
    fn non_empty_rejects_an_empty_vec_and_reports_count_as_non_zero() {
        assert!(matches!(
            NonEmpty::<Label>::try_from_vec(Vec::new(), "labels"),
            Err(ValidationError::NonEmptyRequired { what: "labels" })
        ));

        let one = NonEmpty::of(Label::new("a").unwrap());
        assert_eq!(one.count().get(), 1);
        assert_eq!(one.first().as_str(), "a");

        let mut two = one;
        two.push(Label::new("b").unwrap());
        assert_eq!(two.count().get(), 2);
        assert!(two.contains(&Label::new("B").unwrap()));
    }

    // -- refresh interval ---------------------------------------------------

    #[test]
    fn the_refresh_interval_floor_is_unrepresentable_rather_than_validated() {
        // `04-subsystem-contracts.md`: "default 60 seconds with a hard floor of
        // 30 seconds per target".
        assert_eq!(RefreshInterval::default().as_secs(), 60);
        assert_eq!(RefreshInterval::from_secs(30).unwrap().as_secs(), 30);
        assert!(matches!(
            RefreshInterval::from_secs(29),
            Err(ValidationError::BelowFloor {
                min: 30,
                actual: 29,
                ..
            })
        ));
        assert!(matches!(
            RefreshInterval::from_secs(0),
            Err(ValidationError::BelowFloor { .. })
        ));
        // Deserialisation goes through the same gate, so `b2` cannot load a
        // hand-edited row that polls every second.
        assert!(serde_json::from_str::<RefreshInterval>("29").is_err());
        assert_eq!(
            serde_json::from_str::<RefreshInterval>("45")
                .unwrap()
                .as_secs(),
            45
        );
    }

    // -- cache policy -------------------------------------------------------

    #[test]
    fn job_workspace_retention_has_no_representation_in_v1() {
        // `04-subsystem-contracts.md`, precedence rule 6.
        for policy in [
            CachePolicy::RetainRunnerPackage,
            CachePolicy::DiscardRunnerPackage,
        ] {
            assert!(
                !policy.retains_job_workspace(),
                "no CachePolicy value may retain a job workspace in v1; a \
                 retained workspace is the two-job contamination path"
            );
        }
        assert!(CachePolicy::default().retains_runner_package());
    }

    // -- targets ------------------------------------------------------------

    #[test]
    fn owner_repo_parsing_accepts_one_separator_and_nothing_else() {
        let ok = OwnerRepo::parse("IvanMurzak/GitHub-Runner-Scaler-UI").unwrap();
        assert_eq!(ok.owner(), "IvanMurzak");
        assert_eq!(ok.repo(), "GitHub-Runner-Scaler-UI");
        assert_eq!(ok.to_string(), "IvanMurzak/GitHub-Runner-Scaler-UI");

        for bad in ["owner", "owner/repo/extra", "/repo", "owner/"] {
            assert!(
                OwnerRepo::parse(bad).is_err(),
                "{bad:?} must not parse as a repository target"
            );
        }
    }

    #[test]
    fn github_names_compare_without_regard_to_case_but_display_as_typed() {
        use std::collections::HashSet;

        let typed = OwnerRepo::parse("IvanMurzak/Repo").unwrap();
        let other = OwnerRepo::parse("ivanmurzak/repo").unwrap();
        assert_eq!(
            typed, other,
            "GitHub resolves these to one repository, so `f2`'s duplicate check \
             must too"
        );
        assert_eq!(
            typed.to_string(),
            "IvanMurzak/Repo",
            "the operator's spelling survives for display"
        );

        let mut seen = HashSet::new();
        seen.insert(typed.clone());
        assert!(
            !seen.insert(other),
            "Hash must agree with Eq, or a HashSet-based duplicate check leaks"
        );

        assert_eq!(
            Org::new("Tap-Top-Fun").unwrap(),
            Org::new("tap-top-fun").unwrap()
        );
    }

    #[test]
    fn a_scale_target_exposes_its_scope_and_nothing_endpoint_shaped() {
        let repo = ScaleTarget::repository("o/r").unwrap();
        let org = ScaleTarget::organization("o").unwrap();
        assert_eq!(repo.scope(), TargetScope::Repository);
        assert_eq!(org.scope(), TargetScope::Organization);
        assert_eq!(repo.slug(), "o/r");
        assert_eq!(org.slug(), "o");
    }

    #[test]
    fn a_scale_target_round_trips_through_serde_at_both_scopes() {
        for target in [
            ScaleTarget::repository("owner/repo").unwrap(),
            ScaleTarget::organization("org").unwrap(),
        ] {
            let json = serde_json::to_string(&target).unwrap();
            let back: ScaleTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(target, back, "{json} did not round-trip");
        }
    }

    // -- os / arch ----------------------------------------------------------

    #[test]
    fn os_and_arch_tokens_are_the_ones_the_worked_example_fixes() {
        // `02-target-architecture.md`: "encodes the product, host identity, and
        // host OS — for example `rm-home-win-x64`".
        assert_eq!(Os::Windows.label_token(), "win");
        assert_eq!(Arch::X64.label_token(), "x64");
        assert_eq!(Os::MacOs.label_token(), "osx");
        assert_eq!(Os::Linux.label_token(), "linux");
        assert_eq!(Arch::Arm64.label_token(), "arm64");
        assert_eq!(Arch::Arm32.label_token(), "arm");

        for os in Os::ALL {
            assert_eq!(os.label_token().parse::<Os>().unwrap(), os);
        }
        for arch in Arch::ALL {
            assert_eq!(arch.label_token().parse::<Arch>().unwrap(), arch);
        }
        assert!("plan9".parse::<Os>().is_err());
        assert!("riscv".parse::<Arch>().is_err());
    }

    #[test]
    fn only_linux_supports_container_actions_and_only_arm64_is_preview() {
        // `01-current-architecture.md`, edge case 2 and the architecture row.
        assert!(Os::Linux.supports_container_actions());
        assert!(!Os::Windows.supports_container_actions());
        assert!(!Os::MacOs.supports_container_actions());

        assert!(Arch::Arm64.is_public_preview());
        assert!(!Arch::X64.is_public_preview());
    }

    // -- host ---------------------------------------------------------------

    #[test]
    fn a_host_cannot_be_built_with_zero_capacity_or_a_blank_name() {
        assert!(
            NonZeroU16::new(0).is_none(),
            "zero host capacity is unrepresentable"
        );
        assert!(matches!(
            Host::new(
                HostId::from_u128(1),
                "  ",
                Os::Windows,
                Arch::X64,
                NonZeroU16::new(2).unwrap(),
                ts(0),
            ),
            Err(ValidationError::Empty { .. })
        ));

        let host = Host::new(
            HostId::from_u128(1),
            " home-pc ",
            Os::Windows,
            Arch::X64,
            NonZeroU16::new(2).unwrap(),
            ts(0),
        )
        .unwrap();
        assert_eq!(host.display_name, "home-pc");
        assert_eq!(host.host_capacity(), 2);
        assert_eq!(host.service_start_mode, StartMode::Boot);
        assert_eq!(host.refresh_interval.as_secs(), 60);
    }

    // -- runner root --------------------------------------------------------

    fn a_host() -> Host {
        Host::new(
            HostId::from_u128(1),
            "home-pc",
            Os::Windows,
            Arch::X64,
            NonZeroU16::new(2).unwrap(),
            ts(0),
        )
        .expect("a valid host")
    }

    #[test]
    fn a_new_host_uses_the_platform_default_runner_root() {
        // D3: nothing but an explicit `host set-runtime-root` configures one, so
        // a host registered by this build behaves exactly as it did before the
        // setting existed.
        let host = a_host();
        assert_eq!(host.runner_root_override, None);
        assert!(!host.has_configured_runner_root());
    }

    #[test]
    fn a_configured_runner_root_round_trips_through_serde() {
        let root = LocalAbsolutePath::new(if cfg!(windows) {
            "C:\\rman"
        } else {
            "/srv/rman"
        })
        .expect("a valid native root");
        let mut host = a_host();
        host.runner_root_override = Some(root.clone());
        assert!(host.has_configured_runner_root());

        let encoded = serde_json::to_string(&host).expect("serialisable");
        let decoded: Host = serde_json::from_str(&encoded).expect("deserialisable");
        assert_eq!(decoded, host);
        assert_eq!(decoded.runner_root_override, Some(root));
        // Placement is not authentication: the host record carries no credential
        // before this change and must carry none after it.
        for needle in ["token", "secret", "password"] {
            assert!(
                !encoded.to_ascii_lowercase().contains(needle),
                "the host record leaked {needle:?}: {encoded}"
            );
        }
    }

    #[test]
    fn a_host_row_carrying_an_illegal_runner_root_fails_closed() {
        // The stored shape is re-validated by `LocalAbsolutePath`'s own
        // deserializer, so a hand-edited network share never becomes a runner
        // root (D10).
        let host = a_host();
        let encoded = serde_json::to_string(&host).expect("serialisable");
        let corrupted = encoded.replace(
            "\"runner_root_override\":null",
            "\"runner_root_override\":\"rman\"",
        );
        assert_ne!(corrupted, encoded, "the fixture must actually be corrupted");
        assert!(serde_json::from_str::<Host>(&corrupted).is_err());
    }

    #[test]
    fn a_fake_clock_is_a_complete_substitute_for_the_system_clock() {
        // Proves the port is object safe and that nothing here needs the real
        // one; `crate::attempt` is where it actually matters.
        #[derive(Debug)]
        struct Fixed(Timestamp);
        impl Clock for Fixed {
            fn now(&self) -> Timestamp {
                self.0
            }
        }
        let clock: &dyn Clock = &Fixed(ts(1_700_000_000));
        assert_eq!(clock.now(), ts(1_700_000_000));
    }
}
