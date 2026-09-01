// owner: a1-workspace-domain

//! Where a runner attempt's files live, and whether they survive it.
//!
//! `02-target-architecture.md` separates three path concepts that used to share
//! one directory: application paths (config, SQLite, logs, package cache),
//! the **host runner root** where disposable attempts are created, and a
//! **repository persistent root** holding stable slots. This module owns the two
//! facts the domain records about the second and third:
//!
//! * [`WorkspacePolicy`] — a repository's *configuration*: disposable (the
//!   default) or persistent under a configured root.
//! * [`AttemptWorkspace`] — one attempt's *allocation*: disposable, or the
//!   persistent slot it leased. Journalled before any external effect and
//!   immutable afterwards, because it is what tells recovery which cleanup
//!   algorithm is legal (`04-security-recovery.md`, "Safe path handling").
//!
//! Three rules are enforced here rather than downstream, and each one is a
//! decision from the owner ledger:
//!
//! 1. **Persistence is repository-scoped only (D7).** An organization-scoped JIT
//!    runner can accept work from more than one repository and nothing reveals
//!    which one before launch, so a retained `_work` would cross a repository
//!    boundary. [`WorkspacePolicy::persistent`] takes the target's scope and
//!    refuses `Organization`; [`WorkspacePolicy::from_persisted`] applies the
//!    same rule on load, so a hand-edited row cannot install what the constructor
//!    refuses.
//! 2. **A persistent attempt has a positive slot and an ephemeral one has
//!    none.** The pair is a single fact, so it is one enum with no illegal
//!    combination rather than two columns a caller must keep consistent.
//! 3. **Ephemeral is the default everywhere.** D3: disposable mode remains the
//!    default, and every constructor in this crate keeps producing it.
//!
//! This is *not* [`crate::model::CachePolicy`]. That answers "keep the verified
//! runner package between attempts?"; this answers "keep the job workspace
//! between attempts?". They have different cleanup paths and different security
//! consequences (`04-security-recovery.md`, "Revised trust boundary"), and
//! collapsing them would make the second answerable by accident.

use std::fmt;
use std::num::NonZeroU16;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::model::{TargetScope, ValidationError};
use crate::path::{LocalAbsolutePath, LocalPathError};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a workspace configuration or allocation cannot exist.
///
/// Every variant is a load-time refusal, because `04-security-recovery.md`
/// requires "load-time shape validation and immutable attempt workspace kind;
/// unknown values fail closed". The shape refusals below are already raised by
/// [`WorkspacePolicy::from_persisted`] and [`AttemptWorkspace::from_persisted`];
/// [`Self::InvalidPath`] is the `#[from]` conversion for the same load path and
/// starts being raised when the stored root column is parsed into a
/// [`LocalAbsolutePath`], which is `a2`'s store work rather than this crate's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkspaceError {
    #[error(transparent)]
    InvalidPath(#[from] LocalPathError),

    #[error(
        "a persistent workspace is repository-scoped only; an organization runner \
         can accept jobs from more than one repository, so a retained workspace \
         would cross a repository boundary (D7)"
    )]
    PersistentRequiresRepositoryScope,

    #[error("a persistent workspace policy requires a configured root path")]
    PersistentWithoutRoot,

    #[error(
        "an ephemeral workspace policy has no root path; attempts are placed \
         under the host runner root ({root})"
    )]
    EphemeralWithRoot { root: String },

    #[error("a persistent attempt requires the slot it leased")]
    PersistentWithoutSlot,

    #[error("an ephemeral attempt holds no slot, but slot {slot} was stored")]
    EphemeralWithSlot { slot: u16 },

    #[error("a persistent slot number must be positive; slots are named s1, s2, and so on")]
    SlotNotPositive,
}

// ---------------------------------------------------------------------------
// WorkspaceKind
// ---------------------------------------------------------------------------

/// The discriminant shared by [`WorkspacePolicy`] and [`AttemptWorkspace`].
///
/// It exists so `a2` can store one text column and `d1`/`e1` can render one word
/// without matching on a payload they do not need. The payload — a root path, a
/// slot number — belongs to the enum that owns it, and reconstructing either
/// from this kind plus its raw column goes through `from_persisted`, which is
/// where the illegal combinations are refused.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceKind {
    /// D3: the default. The attempt directory is unique and removed on cleanup.
    #[default]
    Ephemeral,
    /// D4: opt-in, repository-scoped, retaining `_work` in a stable slot.
    Persistent,
}

impl WorkspaceKind {
    #[must_use]
    pub const fn is_persistent(self) -> bool {
        matches!(self, WorkspaceKind::Persistent)
    }
}

impl fmt::Display for WorkspaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WorkspaceKind::Ephemeral => "ephemeral",
            WorkspaceKind::Persistent => "persistent",
        })
    }
}

impl FromStr for WorkspaceKind {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ephemeral" => Ok(WorkspaceKind::Ephemeral),
            "persistent" => Ok(WorkspaceKind::Persistent),
            other => Err(ValidationError::Unrecognised {
                what: "a workspace mode",
                got: other.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// WorkspacePolicy
// ---------------------------------------------------------------------------

/// A repository's configured workspace behaviour.
///
/// `Persistent` carries its root rather than pointing at one, so "persistent
/// without a path" and "ephemeral with a stale path" are both unrepresentable
/// rather than merely rejected — the rule [`crate::model`] states for capacity,
/// applied here.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum WorkspacePolicy {
    /// D3: attempts are created under the effective host runner root and the
    /// whole attempt directory is removed on cleanup.
    #[default]
    Ephemeral,
    /// D4/D5: attempts lease a stable `sN` slot under `root` and only `_work`
    /// survives cleanup.
    Persistent { root: LocalAbsolutePath },
}

impl WorkspacePolicy {
    /// Configure persistence for a target of `scope`.
    ///
    /// The scope is an argument rather than something the caller checks first,
    /// so D7 is stated at the call site rather than remembered. It is *not* the
    /// only gate: `Persistent { root }` is a public variant and so is
    /// constructible directly, which is why
    /// [`ScalePolicy::set_workspace_policy`](crate::policy::ScalePolicy::set_workspace_policy)
    /// and [`Self::from_persisted`] re-run [`Self::permitted_for`] on the value
    /// they are handed rather than trusting that it came through here.
    ///
    /// # Errors
    /// [`WorkspaceError::PersistentRequiresRepositoryScope`] for an
    /// organization target.
    pub fn persistent(root: LocalAbsolutePath, scope: TargetScope) -> Result<Self, WorkspaceError> {
        let policy = WorkspacePolicy::Persistent { root };
        policy.permitted_for(scope)?;
        Ok(policy)
    }

    /// D7: whether a target of `scope` may hold this policy.
    ///
    /// The one place the rule and its message live, so the constructor, the
    /// loader and `repo set-workspace` cannot drift apart. `scope` is matched
    /// exhaustively on purpose: a future third scope has to make this decision
    /// rather than inherit "not a repository, therefore refused".
    ///
    /// # Errors
    /// [`WorkspaceError::PersistentRequiresRepositoryScope`] for a persistent
    /// policy on an organization target.
    pub(crate) const fn permitted_for(&self, scope: TargetScope) -> Result<(), WorkspaceError> {
        match scope {
            TargetScope::Repository => Ok(()),
            TargetScope::Organization if self.is_persistent() => {
                Err(WorkspaceError::PersistentRequiresRepositoryScope)
            }
            TargetScope::Organization => Ok(()),
        }
    }

    /// Rebuild a stored workspace policy from its two columns.
    ///
    /// # Errors
    /// [`WorkspaceError::PersistentWithoutRoot`],
    /// [`WorkspaceError::EphemeralWithRoot`], or
    /// [`WorkspaceError::PersistentRequiresRepositoryScope`] — the three shapes
    /// a hand-edited row can claim and this crate cannot have written.
    pub fn from_persisted(
        kind: WorkspaceKind,
        root: Option<LocalAbsolutePath>,
        scope: TargetScope,
    ) -> Result<Self, WorkspaceError> {
        match (kind, root) {
            (WorkspaceKind::Ephemeral, None) => Ok(WorkspacePolicy::Ephemeral),
            (WorkspaceKind::Ephemeral, Some(root)) => {
                Err(WorkspaceError::EphemeralWithRoot { root: root.into() })
            }
            (WorkspaceKind::Persistent, None) => Err(WorkspaceError::PersistentWithoutRoot),
            (WorkspaceKind::Persistent, Some(root)) => Self::persistent(root, scope),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> WorkspaceKind {
        match self {
            WorkspacePolicy::Ephemeral => WorkspaceKind::Ephemeral,
            WorkspacePolicy::Persistent { .. } => WorkspaceKind::Persistent,
        }
    }

    /// The configured root, for `a2` to store and `d1`/`e1` to display.
    #[must_use]
    pub const fn root(&self) -> Option<&LocalAbsolutePath> {
        match self {
            WorkspacePolicy::Ephemeral => None,
            WorkspacePolicy::Persistent { root } => Some(root),
        }
    }

    #[must_use]
    pub const fn is_persistent(&self) -> bool {
        self.kind().is_persistent()
    }

    /// Whether the job workspace survives an attempt under this policy.
    ///
    /// The counterpart of [`crate::model::CachePolicy::retains_job_workspace`],
    /// which is `false` by construction. That constant is still correct: it
    /// answers whether the *runner package cache policy* retains a workspace,
    /// and it never will. This is the deliberate new decision D4 introduced, and
    /// it is spelled on a different type for exactly that reason.
    #[must_use]
    pub const fn retains_job_workspace(&self) -> bool {
        self.is_persistent()
    }
}

impl fmt::Display for WorkspacePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkspacePolicy::Ephemeral => f.write_str("ephemeral"),
            WorkspacePolicy::Persistent { root } => write!(f, "persistent ({root})"),
        }
    }
}

// ---------------------------------------------------------------------------
// AttemptWorkspace
// ---------------------------------------------------------------------------

/// The immutable allocation fact journalled with one runner attempt.
///
/// `02-target-architecture.md`: "`runtime_path` remains the exact path used by
/// the attempt. The workspace kind and slot number tell recovery which cleanup
/// algorithm is legal. Neither may change after allocation." There is therefore
/// no mutator here and none on `RunnerAttempt` — the value is set by the
/// allocating constructor and read thereafter.
///
/// A persistent variant is also a **durable slot lease**: every attempt whose
/// state is not `cleaned`, including a terminal one whose cleanup failed, holds
/// its slot. That is why the slot lives on the attempt rather than in a slot
/// table — the journal is already the authority on which leases exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AttemptWorkspace {
    /// A unique directory under the effective host runner root, removed whole.
    Ephemeral,
    /// The `sN` slot leased from the policy's persistent root.
    PersistentSlot { slot: NonZeroU16 },
}

impl AttemptWorkspace {
    /// Lease slot `slot`.
    #[must_use]
    pub const fn persistent_slot(slot: NonZeroU16) -> Self {
        AttemptWorkspace::PersistentSlot { slot }
    }

    /// Rebuild a journalled allocation from its two columns.
    ///
    /// The raw slot is a `u16` rather than a [`NonZeroU16`] precisely so that
    /// `0` — a value SQLite will happily hold and this crate will never write —
    /// is a refusal here rather than a panic or a silent `s0`.
    ///
    /// # Errors
    /// [`WorkspaceError::PersistentWithoutSlot`],
    /// [`WorkspaceError::EphemeralWithSlot`], or
    /// [`WorkspaceError::SlotNotPositive`].
    pub fn from_persisted(kind: WorkspaceKind, slot: Option<u16>) -> Result<Self, WorkspaceError> {
        match (kind, slot) {
            (WorkspaceKind::Ephemeral, None) => Ok(AttemptWorkspace::Ephemeral),
            (WorkspaceKind::Ephemeral, Some(slot)) => {
                Err(WorkspaceError::EphemeralWithSlot { slot })
            }
            (WorkspaceKind::Persistent, None) => Err(WorkspaceError::PersistentWithoutSlot),
            (WorkspaceKind::Persistent, Some(slot)) => NonZeroU16::new(slot)
                .map(Self::persistent_slot)
                .ok_or(WorkspaceError::SlotNotPositive),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> WorkspaceKind {
        match self {
            AttemptWorkspace::Ephemeral => WorkspaceKind::Ephemeral,
            AttemptWorkspace::PersistentSlot { .. } => WorkspaceKind::Persistent,
        }
    }

    /// The leased slot, for `a2`'s uncleaned-lease index and `c2`'s allocator.
    #[must_use]
    pub const fn slot(&self) -> Option<NonZeroU16> {
        match self {
            AttemptWorkspace::Ephemeral => None,
            AttemptWorkspace::PersistentSlot { slot } => Some(*slot),
        }
    }

    /// The stored slot column: `None` for an ephemeral attempt.
    #[must_use]
    pub const fn slot_number(&self) -> Option<u16> {
        match self {
            AttemptWorkspace::Ephemeral => None,
            AttemptWorkspace::PersistentSlot { slot } => Some(slot.get()),
        }
    }

    #[must_use]
    pub const fn is_persistent(&self) -> bool {
        self.kind().is_persistent()
    }

    /// The slot's directory name under the persistent root.
    ///
    /// `02-target-architecture.md`: "Names are `s1`, `s2`, and so on to minimize
    /// path length." It is derived here, once, so no caller builds the string a
    /// second way — the whole change exists because a path grew too long.
    #[must_use]
    pub fn slot_directory_name(&self) -> Option<String> {
        self.slot().map(|slot| format!("s{slot}"))
    }
}

impl fmt::Display for AttemptWorkspace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttemptWorkspace::Ephemeral => f.write_str("ephemeral"),
            AttemptWorkspace::PersistentSlot { slot } => write!(f, "persistent slot s{slot}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::path::{LocalAbsolutePath, PathPlatform};

    fn root() -> LocalAbsolutePath {
        LocalAbsolutePath::parse_for("/srv/rman/acme", PathPlatform::Unix).expect("valid root")
    }

    fn nz(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).expect("a positive slot")
    }

    // -- defaults -----------------------------------------------------------

    #[test]
    fn the_default_workspace_policy_is_ephemeral() {
        // D3: disposable mode remains the default.
        assert_eq!(WorkspacePolicy::default(), WorkspacePolicy::Ephemeral);
        assert_eq!(WorkspaceKind::default(), WorkspaceKind::Ephemeral);
        assert!(!WorkspacePolicy::default().is_persistent());
        assert!(!WorkspacePolicy::default().retains_job_workspace());
        assert_eq!(WorkspacePolicy::default().root(), None);
    }

    #[test]
    fn a_persistent_policy_retains_the_job_workspace() {
        let policy = WorkspacePolicy::persistent(root(), TargetScope::Repository)
            .expect("a repository may be persistent");
        assert!(policy.is_persistent());
        assert!(policy.retains_job_workspace());
        assert_eq!(policy.kind(), WorkspaceKind::Persistent);
        assert_eq!(policy.root(), Some(&root()));
    }

    // -- D7 -----------------------------------------------------------------

    #[test]
    fn an_organization_policy_cannot_be_constructed_as_persistent() {
        assert_eq!(
            WorkspacePolicy::persistent(root(), TargetScope::Organization),
            Err(WorkspaceError::PersistentRequiresRepositoryScope)
        );
    }

    #[test]
    fn an_organization_policy_cannot_be_restored_as_persistent() {
        assert_eq!(
            WorkspacePolicy::from_persisted(
                WorkspaceKind::Persistent,
                Some(root()),
                TargetScope::Organization,
            ),
            Err(WorkspaceError::PersistentRequiresRepositoryScope)
        );
        // The ephemeral row an organization is allowed to hold still loads.
        assert_eq!(
            WorkspacePolicy::from_persisted(
                WorkspaceKind::Ephemeral,
                None,
                TargetScope::Organization,
            ),
            Ok(WorkspacePolicy::Ephemeral)
        );
    }

    // -- stored shape -------------------------------------------------------

    #[test]
    fn a_workspace_policy_round_trips_through_its_columns() {
        for scope in [TargetScope::Repository, TargetScope::Organization] {
            let policy = WorkspacePolicy::Ephemeral;
            assert_eq!(
                WorkspacePolicy::from_persisted(policy.kind(), policy.root().cloned(), scope),
                Ok(policy)
            );
        }

        let policy = WorkspacePolicy::persistent(root(), TargetScope::Repository)
            .expect("a repository may be persistent");
        assert_eq!(
            WorkspacePolicy::from_persisted(
                policy.kind(),
                policy.root().cloned(),
                TargetScope::Repository,
            ),
            Ok(policy)
        );
    }

    #[test]
    fn mismatched_workspace_policy_columns_fail_closed() {
        assert_eq!(
            WorkspacePolicy::from_persisted(
                WorkspaceKind::Persistent,
                None,
                TargetScope::Repository
            ),
            Err(WorkspaceError::PersistentWithoutRoot)
        );
        assert_eq!(
            WorkspacePolicy::from_persisted(
                WorkspaceKind::Ephemeral,
                Some(root()),
                TargetScope::Repository,
            ),
            Err(WorkspaceError::EphemeralWithRoot {
                root: "/srv/rman/acme".to_string()
            })
        );
    }

    // -- attempt allocation -------------------------------------------------

    #[test]
    fn an_ephemeral_attempt_holds_no_slot() {
        let workspace = AttemptWorkspace::Ephemeral;
        assert_eq!(workspace.kind(), WorkspaceKind::Ephemeral);
        assert_eq!(workspace.slot(), None);
        assert_eq!(workspace.slot_number(), None);
        assert_eq!(workspace.slot_directory_name(), None);
        assert!(!workspace.is_persistent());
    }

    #[test]
    fn a_persistent_attempt_names_its_slot_directory() {
        let workspace = AttemptWorkspace::persistent_slot(nz(1));
        assert_eq!(workspace.kind(), WorkspaceKind::Persistent);
        assert_eq!(workspace.slot(), Some(nz(1)));
        assert_eq!(workspace.slot_number(), Some(1));
        assert_eq!(workspace.slot_directory_name().as_deref(), Some("s1"));
        assert!(workspace.is_persistent());
        assert_eq!(
            AttemptWorkspace::persistent_slot(nz(12))
                .slot_directory_name()
                .as_deref(),
            Some("s12")
        );
    }

    #[test]
    fn the_slot_directory_name_is_a_single_path_component() {
        // `c2` derives `<root>/sN`; deriving it through `join_child` is what
        // makes containment a property of construction rather than a check.
        let workspace = AttemptWorkspace::persistent_slot(nz(3));
        let name = workspace
            .slot_directory_name()
            .expect("a persistent attempt names a slot");
        assert_eq!(
            root().join_child(name).expect("a valid child").as_str(),
            "/srv/rman/acme/s3"
        );
    }

    #[test]
    fn an_attempt_workspace_round_trips_through_its_columns() {
        for workspace in [
            AttemptWorkspace::Ephemeral,
            AttemptWorkspace::persistent_slot(nz(1)),
            AttemptWorkspace::persistent_slot(nz(u16::MAX)),
        ] {
            assert_eq!(
                AttemptWorkspace::from_persisted(workspace.kind(), workspace.slot_number()),
                Ok(workspace)
            );
        }
    }

    #[test]
    fn mismatched_attempt_workspace_columns_fail_closed() {
        assert_eq!(
            AttemptWorkspace::from_persisted(WorkspaceKind::Persistent, None),
            Err(WorkspaceError::PersistentWithoutSlot)
        );
        assert_eq!(
            AttemptWorkspace::from_persisted(WorkspaceKind::Ephemeral, Some(1)),
            Err(WorkspaceError::EphemeralWithSlot { slot: 1 })
        );
        assert_eq!(
            AttemptWorkspace::from_persisted(WorkspaceKind::Ephemeral, Some(0)),
            Err(WorkspaceError::EphemeralWithSlot { slot: 0 })
        );
        assert_eq!(
            AttemptWorkspace::from_persisted(WorkspaceKind::Persistent, Some(0)),
            Err(WorkspaceError::SlotNotPositive)
        );
    }

    // -- representation -----------------------------------------------------

    #[test]
    fn workspace_kind_tokens_are_stable() {
        for (kind, token) in [
            (WorkspaceKind::Ephemeral, "ephemeral"),
            (WorkspaceKind::Persistent, "persistent"),
        ] {
            assert_eq!(kind.to_string(), token);
            assert_eq!(token.parse::<WorkspaceKind>().expect("a known token"), kind);
            assert_eq!(
                serde_json::to_value(kind).expect("serialisable"),
                serde_json::Value::String(token.to_string())
            );
        }
        assert!("durable".parse::<WorkspaceKind>().is_err());
        assert!(serde_json::from_str::<WorkspaceKind>("\"durable\"").is_err());
    }

    #[test]
    fn workspace_values_serialise_without_credentials() {
        // The whole point of the new state: it is placement, not authentication.
        // Nothing here may ever carry a token or a JIT configuration, and the
        // rendered forms are what `d1`, `e1` and status JSON print.
        let policy = WorkspacePolicy::persistent(root(), TargetScope::Repository)
            .expect("a repository may be persistent");
        let attempt = AttemptWorkspace::persistent_slot(nz(2));

        let rendered = format!(
            "{policy}|{attempt}|{:?}|{:?}|{}|{}",
            policy,
            attempt,
            serde_json::to_string(&policy).expect("serialisable"),
            serde_json::to_string(&attempt).expect("serialisable"),
        );
        for needle in ["token", "secret", "jit", "password", "ghs_", "ghp_"] {
            assert!(
                !rendered.to_ascii_lowercase().contains(needle),
                "workspace rendering leaked {needle:?}: {rendered}"
            );
        }
        assert!(rendered.contains("/srv/rman/acme"));
        assert!(rendered.contains("s2"));
    }

    #[test]
    fn workspace_values_round_trip_through_serde() {
        let attempt = AttemptWorkspace::persistent_slot(nz(7));
        let encoded = serde_json::to_string(&attempt).expect("serialisable");
        assert_eq!(
            serde_json::from_str::<AttemptWorkspace>(&encoded).expect("deserialisable"),
            attempt
        );
        assert_eq!(
            serde_json::from_str::<AttemptWorkspace>("{\"mode\":\"ephemeral\"}")
                .expect("deserialisable"),
            AttemptWorkspace::Ephemeral
        );
        // A slot of zero is not representable, so the journal cannot carry one
        // even through serde.
        assert!(
            serde_json::from_str::<AttemptWorkspace>("{\"mode\":\"persistent_slot\",\"slot\":0}")
                .is_err()
        );
    }
}
