// owner: b1-local-model-corpus
//
//! Equivalence-class values: the only names, labels, capacities and paths the
//! local chain corpus may put on a command line.
//!
//! # Why a closed set rather than generated strings
//!
//! `03-coverage-model.md`: "Names, labels, and paths come from small
//! equivalence-class sets containing ordinary, repeated, boundary,
//! case-sensitive, and invalid values." Every value here is an enum variant with
//! a fixed literal spelling, so a corpus case can only ever name one of them.
//! Nothing in this directory turns free text into an argument.
//!
//! # Validity is stated per value, not re-derived
//!
//! Each variant says whether the product accepts it and what it folds to. That
//! is a restatement of the published rules (`OWNER/REPO` naming, the 64-byte
//! host label, the 256-character label, case-insensitive targets), written down
//! independently of `crates/domain` so that the model can disagree with the
//! product. It must never import the production validators: a model that asks
//! the code under test what the right answer is cannot catch that code being
//! wrong.

use std::fmt;

/// Which policy family a target belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Repository,
    Organization,
}

impl Scope {
    /// The command-line family word: `repo` or `org`.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Scope::Repository => "repo",
            Scope::Organization => "org",
        }
    }

    /// The token `status --json` uses for the scope.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Scope::Repository => "repository",
            Scope::Organization => "organization",
        }
    }
}

/// A repository argument.
///
/// `Fleet(n)` exists for the REST-budget boundary: only the `wide` fixture
/// installs those repositories, and eleven of them are needed to cross the
/// ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RepoName {
    /// `acme/widgets` — the ordinary, reachable repository.
    Widgets,
    /// `acme/gadgets` — a second reachable repository in the same account.
    Gadgets,
    /// `globex/portal` — a reachable repository in a second organization.
    Portal,
    /// `Acme/Widgets` — the same target as [`RepoName::Widgets`], differently
    /// cased. GitHub compares names without regard to case.
    WidgetsCase,
    /// `acme/fleet-NN` — reachable only through the `wide` fixture.
    Fleet(u8),
    /// `outside/tools` — well-formed and not covered by any installation.
    Outside,
    /// `acme` — no `/`, so not an `OWNER/REPO` pair.
    Malformed,
    /// `acme/wid gets` — a space is not a repository-name character.
    IllegalChar,
}

impl RepoName {
    /// The literal argument.
    #[must_use]
    pub fn token(self) -> String {
        match self {
            RepoName::Widgets => "acme/widgets".to_string(),
            RepoName::Gadgets => "acme/gadgets".to_string(),
            RepoName::Portal => "globex/portal".to_string(),
            RepoName::WidgetsCase => "Acme/Widgets".to_string(),
            RepoName::Fleet(n) => format!("acme/fleet-{n:02}"),
            RepoName::Outside => "outside/tools".to_string(),
            RepoName::Malformed => "acme".to_string(),
            RepoName::IllegalChar => "acme/wid gets".to_string(),
        }
    }

    /// The case-folded identity, or `None` when the product refuses the
    /// spelling before looking anything up.
    #[must_use]
    pub fn canonical(self) -> Option<String> {
        match self {
            RepoName::Malformed | RepoName::IllegalChar => None,
            other => Some(other.token().to_ascii_lowercase()),
        }
    }

    /// The equivalence class, for value coverage.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            RepoName::Widgets | RepoName::Gadgets => "ordinary",
            RepoName::Portal => "second-account",
            RepoName::WidgetsCase => "case-variant",
            RepoName::Fleet(_) => "budget-fleet",
            RepoName::Outside => "not-installed",
            RepoName::Malformed => "malformed",
            RepoName::IllegalChar => "illegal-character",
        }
    }
}

/// An organization argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OrgName {
    /// `acme` — the ordinary, reachable organization.
    Acme,
    /// `globex` — a second reachable organization.
    Globex,
    /// `ACME` — [`OrgName::Acme`], differently cased.
    AcmeCase,
    /// `outside` — well-formed and not installed.
    Outside,
    /// `acme-` — a login may not end with `-`. (A *leading* dash would be read
    /// by the argument parser as an option, which is a usage error rather than
    /// the domain refusal this value exists to reach.)
    TrailingDash,
}

impl OrgName {
    #[must_use]
    pub fn token(self) -> String {
        match self {
            OrgName::Acme => "acme",
            OrgName::Globex => "globex",
            OrgName::AcmeCase => "ACME",
            OrgName::Outside => "outside",
            OrgName::TrailingDash => "acme-",
        }
        .to_string()
    }

    #[must_use]
    pub fn canonical(self) -> Option<String> {
        match self {
            OrgName::TrailingDash => None,
            other => Some(other.token().to_ascii_lowercase()),
        }
    }

    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            OrgName::Acme => "ordinary",
            OrgName::Globex => "second-account",
            OrgName::AcmeCase => "case-variant",
            OrgName::Outside => "not-installed",
            OrgName::TrailingDash => "illegal-edge",
        }
    }
}

/// A `--host-label` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostLabelValue {
    /// `home`.
    Home,
    /// `office`.
    Office,
    /// `Home` — folds to `home`.
    HomeCase,
    /// Exactly 64 bytes: the longest accepted host label.
    Max64,
    /// 65 bytes: one past the limit.
    TooLong65,
    /// `home pc` — a space is not a host-label character.
    Space,
    /// `home-` — a host label may not end with `-`.
    TrailingDash,
}

impl HostLabelValue {
    #[must_use]
    pub fn token(self) -> String {
        match self {
            HostLabelValue::Home => "home".to_string(),
            HostLabelValue::Office => "office".to_string(),
            HostLabelValue::HomeCase => "Home".to_string(),
            HostLabelValue::Max64 => format!("host-{}", "x".repeat(59)),
            HostLabelValue::TooLong65 => format!("host-{}", "x".repeat(60)),
            HostLabelValue::Space => "home pc".to_string(),
            HostLabelValue::TrailingDash => "home-".to_string(),
        }
    }

    /// The folded host label the product stores, or `None` when refused.
    #[must_use]
    pub fn canonical(self) -> Option<String> {
        match self {
            HostLabelValue::TooLong65 | HostLabelValue::Space | HostLabelValue::TrailingDash => {
                None
            }
            other => Some(other.token().to_ascii_lowercase()),
        }
    }

    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            HostLabelValue::Home | HostLabelValue::Office => "ordinary",
            HostLabelValue::HomeCase => "case-variant",
            HostLabelValue::Max64 => "boundary-64",
            HostLabelValue::TooLong65 => "too-long-65",
            HostLabelValue::Space => "illegal-character",
            HostLabelValue::TrailingDash => "illegal-edge",
        }
    }
}

/// A `--label` value.
///
/// `Derived(h)` is the routing label the product derives from host label `h`,
/// `rm-<h>-<os>-<arch>`. Its OS and architecture segments are platform facts,
/// so the model holds it symbolically and the runner resolves it through
/// [`Resolver::derived_label`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LabelValue {
    /// `gpu`.
    Gpu,
    /// `GPU` — folds to `gpu`.
    GpuCase,
    /// `large-disk`.
    LargeDisk,
    /// `self-hosted` — the label GitHub never adds implicitly.
    SelfHosted,
    /// 256 characters: the longest accepted label.
    Max256,
    /// 257 characters: one past the limit.
    TooLong257,
    /// `gpu,fast` — a comma separates labels in the runner's own
    /// configuration, so it cannot be part of one.
    Comma,
    /// Three spaces: empty once trimmed.
    Blank,
    /// The derived routing label of the given host label.
    Derived(HostLabelValue),
    /// The derived routing label, upper-cased.
    DerivedCase(HostLabelValue),
}

impl LabelValue {
    /// The literal argument.
    #[must_use]
    pub fn token(self, resolver: &dyn Resolver) -> String {
        match self {
            LabelValue::Gpu => "gpu".to_string(),
            LabelValue::GpuCase => "GPU".to_string(),
            LabelValue::LargeDisk => "large-disk".to_string(),
            LabelValue::SelfHosted => "self-hosted".to_string(),
            LabelValue::Max256 => "l".repeat(256),
            LabelValue::TooLong257 => "l".repeat(257),
            LabelValue::Comma => "gpu,fast".to_string(),
            LabelValue::Blank => "   ".to_string(),
            LabelValue::Derived(host) => resolver.derived_label(&host_segment(host)),
            LabelValue::DerivedCase(host) => resolver
                .derived_label(&host_segment(host))
                .to_ascii_uppercase(),
        }
    }

    /// The folded label the model stores, or `None` when the product refuses
    /// the value.
    ///
    /// Derived labels fold to [`derived_symbol`], the model's platform-neutral
    /// spelling of `rm-<host>-<os>-<arch>`.
    #[must_use]
    pub fn canonical(self) -> Option<String> {
        match self {
            LabelValue::Gpu | LabelValue::GpuCase => Some("gpu".to_string()),
            LabelValue::LargeDisk => Some("large-disk".to_string()),
            LabelValue::SelfHosted => Some("self-hosted".to_string()),
            LabelValue::Max256 => Some("l".repeat(256)),
            LabelValue::TooLong257 | LabelValue::Comma | LabelValue::Blank => None,
            LabelValue::Derived(host) | LabelValue::DerivedCase(host) => {
                Some(derived_symbol(&host_segment(host)))
            }
        }
    }

    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            LabelValue::Gpu | LabelValue::LargeDisk => "ordinary",
            LabelValue::GpuCase => "case-variant",
            LabelValue::SelfHosted => "github-default-name",
            LabelValue::Max256 => "boundary-256",
            LabelValue::TooLong257 => "too-long-257",
            LabelValue::Comma => "separator",
            LabelValue::Blank => "blank",
            LabelValue::Derived(_) => "derived-host-label",
            LabelValue::DerivedCase(_) => "derived-host-label-case-variant",
        }
    }
}

/// The host segment a derived label is built from: the folded host label when
/// the value is valid, the folded raw text otherwise.
fn host_segment(host: HostLabelValue) -> String {
    host.canonical()
        .unwrap_or_else(|| host.token().to_ascii_lowercase())
}

/// The model's spelling of `rm-<host>-<os>-<arch>`.
///
/// The two platform segments are placeholders. Every comparison the model
/// makes is between two symbols built by this function, so the placeholders
/// never have to be resolved inside the model; the runner resolves them only
/// when it compares a model value against real output.
#[must_use]
pub fn derived_symbol(host_label: &str) -> String {
    format!("rm-{host_label}-<os>-<arch>")
}

/// A capacity argument: zero, one (the product default host capacity), a
/// normal configured value, another normal value, and `u16::MAX`.
///
/// The argument is a `u16` on the command line, so anything above `u16::MAX` is
/// a usage error the parser raises; the action constructor cannot express it,
/// which is the "the constructor enforces CLI syntax" rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capacity {
    Zero,
    One,
    Two,
    Five,
    Max,
}

impl Capacity {
    pub const ALL: [Capacity; 5] = [
        Capacity::Zero,
        Capacity::One,
        Capacity::Two,
        Capacity::Five,
        Capacity::Max,
    ];

    #[must_use]
    pub const fn value(self) -> u16 {
        match self {
            Capacity::Zero => 0,
            Capacity::One => 1,
            Capacity::Two => 2,
            Capacity::Five => 5,
            Capacity::Max => u16::MAX,
        }
    }

    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Capacity::Zero => "zero",
            Capacity::One => "one-product-default",
            Capacity::Two => "normal",
            Capacity::Five => "normal-other",
            Capacity::Max => "u16-max",
        }
    }
}

/// A `--path` argument.
///
/// Every scenario owns two sibling temporary directories: `<data>` (the
/// `--data-dir`) and `<roots>`, a scratch directory for runner roots. `<roots>`
/// must **not** contain `<data>`, and neither may be a filesystem root; the
/// runner creates `<roots>` and the file `<roots>/occupied.txt` before the first
/// step and nothing else. Everything below is relative to those two anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathValue {
    /// `<roots>/alpha` — absent until a command creates it.
    Alpha,
    /// `<roots>/beta` — absent until a command creates it.
    Beta,
    /// `<roots>/alpha/inner` — inside `alpha`; creatable only once `alpha`
    /// exists.
    AlphaInner,
    /// `<roots>` itself — exists, and contains every other scratch path.
    RootsDir,
    /// `<roots>/missing/deep` — two components are missing.
    DeepMissing,
    /// `<roots>/occupied.txt` — an existing file, not a directory.
    OccupiedFile,
    /// `relative/root` — not an absolute path.
    Relative,
    /// `<data>/state/rman` — inside the application data tree.
    InsideAppState,
}

impl PathValue {
    pub const ALL: [PathValue; 8] = [
        PathValue::Alpha,
        PathValue::Beta,
        PathValue::AlphaInner,
        PathValue::RootsDir,
        PathValue::DeepMissing,
        PathValue::OccupiedFile,
        PathValue::Relative,
        PathValue::InsideAppState,
    ];

    /// The path's anchor and components below it, or `None` for the relative
    /// value.
    #[must_use]
    pub const fn location(self) -> Option<(Anchor, &'static [&'static str])> {
        match self {
            PathValue::Alpha => Some((Anchor::Roots, &["alpha"])),
            PathValue::Beta => Some((Anchor::Roots, &["beta"])),
            PathValue::AlphaInner => Some((Anchor::Roots, &["alpha", "inner"])),
            PathValue::RootsDir => Some((Anchor::Roots, &[])),
            PathValue::DeepMissing => Some((Anchor::Roots, &["missing", "deep"])),
            PathValue::OccupiedFile => Some((Anchor::Roots, &["occupied.txt"])),
            PathValue::InsideAppState => Some((Anchor::Data, &["state", "rman"])),
            PathValue::Relative => None,
        }
    }

    /// The platform-neutral spelling used by the inventory.
    #[must_use]
    pub fn symbolic(self) -> String {
        match self.location() {
            None => "relative/root".to_string(),
            Some((anchor, parts)) => {
                let mut text = anchor.symbol().to_string();
                for part in parts {
                    text.push('/');
                    text.push_str(part);
                }
                text
            }
        }
    }

    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            PathValue::Alpha | PathValue::Beta => "fresh-leaf",
            PathValue::AlphaInner => "nested-leaf",
            PathValue::RootsDir => "existing-parent",
            PathValue::DeepMissing => "missing-parents",
            PathValue::OccupiedFile => "existing-file",
            PathValue::Relative => "relative",
            PathValue::InsideAppState => "inside-app-data",
        }
    }

    /// How `self` relates to `other`, lexically, the way the product's overlap
    /// check reads two absolute paths: equal, `self` inside `other`, `self`
    /// containing `other`, or unrelated.
    #[must_use]
    pub fn relation(self, other: PathValue) -> Relation {
        let (Some((a_anchor, a)), Some((b_anchor, b))) = (self.location(), other.location()) else {
            return Relation::Disjoint;
        };
        if a_anchor != b_anchor {
            return Relation::Disjoint;
        }
        if a == b {
            Relation::Same
        } else if a.len() > b.len() && a.starts_with(b) {
            Relation::Inside
        } else if b.len() > a.len() && b.starts_with(a) {
            Relation::Contains
        } else {
            Relation::Disjoint
        }
    }

    /// The directory a successful configuration would have to create, if the
    /// value is one the scenario starts without.
    #[must_use]
    pub const fn is_creatable_leaf(self) -> bool {
        matches!(
            self,
            PathValue::Alpha | PathValue::Beta | PathValue::AlphaInner
        )
    }

    /// The directory whose existence `self` needs, when that is a creatable
    /// scratch leaf.
    #[must_use]
    pub const fn creatable_parent(self) -> Option<PathValue> {
        match self {
            PathValue::AlphaInner => Some(PathValue::Alpha),
            _ => None,
        }
    }
}

/// The two anchors every scratch path is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Anchor {
    Roots,
    Data,
}

impl Anchor {
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Anchor::Roots => "<roots>",
            Anchor::Data => "<data>",
        }
    }
}

/// The lexical relation between two paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    Same,
    Inside,
    Contains,
    Disjoint,
}

/// Turns the two platform-dependent values into text.
///
/// The runner implements this with the scenario's real temporary directories
/// and this machine's OS and architecture tokens; the inventory uses
/// [`Symbolic`]. Nothing else in a command line depends on the machine.
pub trait Resolver {
    /// The absolute (or, for [`PathValue::Relative`], relative) path text.
    fn path(&self, value: PathValue) -> String;
    /// `rm-<host_label>-<os>-<arch>` for this machine.
    fn derived_label(&self, host_label: &str) -> String;
}

/// The platform-neutral resolver the checked-in inventory is rendered with.
#[derive(Debug, Clone, Copy, Default)]
pub struct Symbolic;

impl Resolver for Symbolic {
    fn path(&self, value: PathValue) -> String {
        value.symbolic()
    }

    fn derived_label(&self, host_label: &str) -> String {
        derived_symbol(host_label)
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.word())
    }
}
