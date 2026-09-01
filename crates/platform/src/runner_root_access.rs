// owner: b2-windows-root-acl

//! Who may write inside the **platform default** runner root, and how that is
//! established.
//!
//! [`runner_root`](crate::runner_root) decides *where* runner workspaces go and
//! deliberately mutates nothing: `02-target-architecture.md` keeps "directory
//! creation and the narrowly scoped default-root ACL operation" as explicit
//! application steps that happen after validation passes. This module is that
//! step, and it is the only place in the workspace that creates or
//! re-permissions a runner root.
//!
//! # The threat, stated exactly
//!
//! `04-security-recovery.md` lists it in one line: *"`%SystemDrive%\rman` is
//! writable by unrelated local users."* That is not hypothetical, it is the
//! **default** on every Windows host. The security descriptor of `C:\` carries
//! an inherit-only ACE of roughly this shape:
//!
//! ```text
//! (A;OICIIO;SDGXGWGR;;;AU)
//! ```
//!
//! — *Authenticated Users*, delete plus generic read/write/execute, inherited
//! by every child of `C:\`. A directory created there with inheritance left on
//! is therefore writable by every account that can log in, including the
//! account a hostile workflow's own leftovers could be running as. Runner
//! workspaces are executable content that a later job re-enters, so this is a
//! code-execution boundary rather than a tidiness one.
//!
//! The control is one character: `P`, the `SE_DACL_PROTECTED` flag, which
//! severs inheritance. Everything else in this module exists to apply it
//! **without ever widening anything**, to prove afterwards that it took, and to
//! refuse rather than adopt a directory that was already open.
//!
//! # What is admitted, and why that is the minimum
//!
//! | Trustee | Rights | Why it cannot be dropped |
//! |---|---|---|
//! | `SY` — LocalSystem | Full control, inherited | A boot registration runs as LocalSystem and must create, materialize and clean attempt directories |
//! | `BA` — Administrators | Full control, inherited | `07-security.md` already places a local administrator outside this threat model; without it an operator cannot clean up after a service account they are not logged in as |
//! | the selected account | [`ADMITTED_RIGHTS`], inherited | A login task or a foreground daemon runs as an ordinary user whose token contains neither of the above |
//!
//! The third row is load-bearing in a way that is easy to miss. A login-mode
//! registration is a Task Scheduler task rendered with
//! `RunLevel = LeastPrivilege` (see [`crate::service::windows_scheduled_task_xml`]),
//! so it runs under the operator's **filtered** token — in which the
//! Administrators group is present but *deny-only*. A DACL naming only `SY` and
//! `BA` therefore grants such a task nothing at all, even when the operator is
//! an administrator. The explicit per-account ACE is what makes login mode work,
//! and it is also why a mode change has to reconcile it: the account admitted
//! for login mode is not the account boot mode needs.
//!
//! # Why the account gets modify rather than full control
//!
//! `FA` is `FILE_ALL_ACCESS`, which includes `WRITE_DAC` and `WRITE_OWNER` — the
//! two rights that would let the admitted account undo the protection this
//! module exists to apply. [`ADMITTED_RIGHTS`] is read, write, execute and
//! delete, which is everything "create a child, materialize a runner into it,
//! and clean it up again" needs and nothing that can re-open the root. Deleting
//! a whole attempt tree works because the inherited ACE grants `DELETE` on every
//! entry below, which is what `remove_dir_all` actually requires; the parent's
//! `FILE_DELETE_CHILD` is a convenience this deliberately does not grant.
//!
//! # Custom roots are read, never rewritten
//!
//! An operator's `host set-runtime-root` path is theirs. This module offers no
//! public function that applies a security descriptor to a caller-chosen path:
//! [`ensure_default_root`] resolves [`crate::runner_root::default_runner_root`]
//! itself and takes no path at all, and [`report`] — the entry point for a
//! configured custom root — only reads. That is the whole of "custom roots are
//! never re-ACLed", enforced by the shape of the API rather than by a check
//! somebody has to remember to write.
//!
//! # Everything decidable is decided purely
//!
//! [`default_root_sddl`], [`grants_broad_write`], [`admits_exactly`] and
//! [`redact`] are pure functions over text with no `cfg`, no privileges and no
//! filesystem, for the reason this crate gives everywhere else: a Linux CI leg
//! can assert the exact descriptor a Windows host will write, and the one test
//! that needs a real DACL is the privileged one that has a real machine.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use runner_manager_domain::path::LocalAbsolutePath;

use crate::paths::AppPaths;
#[cfg(windows)]
use crate::runner_root::RootPreflight;
use crate::runner_root::{RootOwner, RunnerRootError};

// ---------------------------------------------------------------------------
// The descriptor
// ---------------------------------------------------------------------------

/// The rights the selected login or foreground account is admitted with.
///
/// `FR` `FW` `FX` `SD` — `FILE_GENERIC_READ`, `FILE_GENERIC_WRITE`,
/// `FILE_GENERIC_EXECUTE` and `DELETE`. See this module's documentation for why
/// this is deliberately not `FA`.
pub const ADMITTED_RIGHTS: &str = "FRFWFXSD";

/// The inheritance flags every ACE this module writes carries.
///
/// `OI` `CI` — object inherit and container inherit, with no `IO`: the ACE
/// applies to the root itself *and* propagates to every file and directory
/// created below it. Both halves are required. Without the propagation a
/// service could create `<root>\<attempt>` and then be unable to write inside
/// it; without the ACE applying to the root itself it could not create the
/// child in the first place.
pub const INHERITANCE: &str = "OICI";

/// Which account, beyond the two constants, the root must admit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootAdmission {
    /// A boot registration. LocalSystem is already `SY`, so nothing is added.
    LocalSystem,
    /// A login registration or a foreground daemon, named by its SID.
    ///
    /// A SID rather than a name for the reason [`crate::secrets`] gives at
    /// length: a DACL that describes an account and hopes the description still
    /// fits is a DACL that stops granting what it was written to grant.
    Account(String),
}

impl RootAdmission {
    /// The account this process is running as.
    ///
    /// This is the foreground-daemon and login-mode answer:
    /// `03-migration-rollout.md` has both of those "attempt ordinary creation",
    /// and ordinary creation by an ordinary account is exactly the case the
    /// third ACE exists for.
    ///
    /// # Errors
    /// [`RootAccessError::Identity`] when this process's own token cannot be
    /// read, which is the one failure that leaves nothing sensible to admit.
    #[cfg(windows)]
    pub fn of_this_account() -> Result<Self, RootAccessError> {
        crate::process::current_user_sid()
            .map(Self::Account)
            .map_err(|source| RootAccessError::Identity { source })
    }

    /// The SID this admission adds, when it adds one.
    #[must_use]
    pub fn sid(&self) -> Option<&str> {
        match self {
            Self::LocalSystem => None,
            Self::Account(sid) => Some(sid),
        }
    }

    /// Who the resulting descriptor admits, in the vocabulary `service status`
    /// already uses.
    #[must_use]
    pub fn admits(&self) -> Vec<AdmittedTrustee> {
        let mut admitted = vec![
            AdmittedTrustee::LocalSystem,
            AdmittedTrustee::Administrators,
        ];
        if matches!(self, Self::Account(_)) {
            admitted.push(AdmittedTrustee::SelectedAccount);
        }
        admitted
    }
}

/// One trustee a runner root admits, named without naming an account.
///
/// The task's scope note is *"add privileged inspection output without exposing
/// identities beyond what existing service status already reports"*, and what
/// `service status` already reports is [`crate::service::ServiceAccount`] —
/// `NT AUTHORITY\SYSTEM`, or the words "the invoking user". So this is an enum
/// of the same three ideas rather than a list of SIDs, and no caller can print
/// one by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdmittedTrustee {
    /// `SY`, `NT AUTHORITY\SYSTEM`.
    LocalSystem,
    /// `BA`, the local Administrators group.
    Administrators,
    /// The login or foreground account the registration selected.
    SelectedAccount,
}

impl fmt::Display for AdmittedTrustee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LocalSystem => "NT AUTHORITY\\SYSTEM",
            Self::Administrators => "the local Administrators group",
            Self::SelectedAccount => "the invoking user",
        })
    }
}

/// The security descriptor the default runner root is created and reconciled
/// with, in SDDL.
///
/// Split out and public for the same reason [`crate::secrets`] splits out its
/// own: a test asserts the exact string rather than inferring it from a file,
/// and a reviewer reads one line instead of three API calls.
#[must_use]
pub fn default_root_sddl(admission: &RootAdmission) -> String {
    // `P` first, because it is the entire control. `D:P` discards whatever the
    // volume root would otherwise inherit into this directory.
    let mut sddl = format!("D:P(A;{INHERITANCE};FA;;;SY)(A;{INHERITANCE};FA;;;BA)");
    if let Some(sid) = admission.sid()
        && !already_admitted(sid)
    {
        sddl.push_str(&format!("(A;{INHERITANCE};{ADMITTED_RIGHTS};;;{sid})"));
    }
    sddl
}

/// Whether the two constant ACEs already cover this SID.
///
/// A daemon running as LocalSystem reads its own SID as `S-1-5-18` and would
/// otherwise add a third ACE for the trustee the first one names. The same
/// applies to a caller that hands over the Administrators group.
fn already_admitted(sid: &str) -> bool {
    const COVERED: [&str; 4] = ["SY", "BA", SID_LOCAL_SYSTEM, SID_ADMINISTRATORS];
    COVERED.iter().any(|known| sid.eq_ignore_ascii_case(known))
}

/// `NT AUTHORITY\SYSTEM`.
const SID_LOCAL_SYSTEM: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";

// ---------------------------------------------------------------------------
// Reading a descriptor back
// ---------------------------------------------------------------------------

/// The access mask bits that amount to "may change what is in this directory,
/// or who may".
///
/// Spelled as bits rather than as SDDL abbreviations because the abbreviations
/// are not self-describing: `LC` and `DC` are the directory-service names for
/// `0x4` and `0x2`, which on a filesystem object are `FILE_ADD_SUBDIRECTORY`
/// and `FILE_ADD_FILE` — and those two are exactly how `C:\` grants ordinary
/// users the ability to create things. Matching on the letters would have
/// missed them.
///
/// | Bit | Right |
/// |---|---|
/// | `0x1000_0000` | `GENERIC_ALL` |
/// | `0x4000_0000` | `GENERIC_WRITE` |
/// | `0x0008_0000` | `WRITE_OWNER` |
/// | `0x0004_0000` | `WRITE_DAC` |
/// | `0x0001_0000` | `DELETE` |
/// | `0x0000_0100` | `FILE_WRITE_ATTRIBUTES` |
/// | `0x0000_0040` | `FILE_DELETE_CHILD` |
/// | `0x0000_0010` | `FILE_WRITE_EA` |
/// | `0x0000_0004` | `FILE_APPEND_DATA` / `FILE_ADD_SUBDIRECTORY` |
/// | `0x0000_0002` | `FILE_WRITE_DATA` / `FILE_ADD_FILE` |
pub const WRITE_MASK: u32 = 0x1000_0000
    | 0x4000_0000
    | 0x0008_0000
    | 0x0004_0000
    | 0x0001_0000
    | 0x0000_0100
    | 0x0000_0040
    | 0x0000_0010
    | 0x0000_0004
    | 0x0000_0002;

/// The trustees that mean "more or less anybody who can log in here", in both
/// the alias form SDDL is written in and the raw form the converter may hand
/// back instead.
///
/// The same list [`crate::process`] uses for the *read* question, plus Guests.
/// `CO` (CREATOR OWNER) is deliberately absent: inherited, it grants each
/// child's own creator access to that child, which is not a grant to an
/// unrelated user.
const BROAD_TRUSTEES: &[&str] = &[
    "WD",           // Everyone
    "S-1-1-0",      // Everyone
    "AU",           // Authenticated Users
    "S-1-5-11",     // Authenticated Users
    "BU",           // Builtin Users
    "S-1-5-32-545", // Builtin Users
    "BG",           // Guests
    "S-1-5-32-546", // Guests
    "DU",           // Domain Users
    "IU",           // Interactive
    "S-1-5-4",      // Interactive
    "AN",           // Anonymous
    "S-1-5-7",      // Anonymous
    "WR",           // Write Restricted
    "LU",           // Performance Log Users
];

/// One access-control entry, as SDDL spells it.
///
/// `(type;flags;rights;object;inherit_object;trustee)`, and the three fields
/// this module has an opinion about.
struct Ace<'a> {
    kind: &'a str,
    rights: &'a str,
    trustee: &'a str,
}

/// Every ACE of the `D:` part of a security descriptor.
///
/// `None` when there is no `D:` at all, which Windows reads as "everyone, full
/// control" and which therefore may never be confused with "an empty list of
/// ACEs".
fn aces(descriptor: &str) -> Option<Vec<Ace<'_>>> {
    let body = descriptor.split("D:").nth(1)?;
    // The other spelling of the same thing. `NO_ACCESS_CONTROL` is how SDDL
    // renders a **NULL** DACL, which grants everyone everything — so it is `D:`
    // present and no access control at all, not `D:` present with no entries.
    // Read as a flags field it parses to zero ACEs, which would read back as
    // the narrowest possible directory rather than the widest.
    if body
        .split('(')
        .next()
        .is_some_and(|flags| flags.contains("NO_ACCESS_CONTROL"))
    {
        return None;
    }
    Some(
        body.split('(')
            .skip(1)
            .filter_map(|ace| {
                let ace = ace.split(')').next()?;
                let fields: Vec<&str> = ace.split(';').collect();
                Some(Ace {
                    kind: fields.first()?.trim(),
                    rights: fields.get(2)?.trim(),
                    trustee: fields.get(5)?.trim(),
                })
            })
            .collect(),
    )
}

impl Ace<'_> {
    /// Whether this entry grants rather than denies or audits.
    ///
    /// Every allow type starts with `A` (`A`, `OA`, `XA`), and so does the audit
    /// type `AU`. Audit entries live in the `S:` part and cannot appear here,
    /// but treating one as a grant if it somehow did is the direction that fails
    /// closed, and it is the rule [`crate::process`] already applies to the read
    /// question.
    fn is_allow(&self) -> bool {
        self.kind.starts_with('A') || (self.kind.starts_with('X') && self.kind.contains('A'))
    }

    /// Whether this entry grants anything in [`WRITE_MASK`].
    ///
    /// An unreadable rights field counts as granting write. A descriptor this
    /// cannot parse is a descriptor this cannot vouch for, and the caller's
    /// response to `true` is to refuse rather than to widen.
    fn grants_write(&self) -> bool {
        rights_mask(self.rights).is_none_or(|mask| mask & WRITE_MASK != 0)
    }
}

/// The access mask an SDDL rights field denotes.
///
/// `None` for a field this does not recognise, which every caller treats as
/// "assume the worst".
fn rights_mask(field: &str) -> Option<u32> {
    if field.is_empty() {
        return Some(0);
    }
    if !field.is_ascii() {
        return None;
    }
    if let Some(hex) = field
        .strip_prefix("0x")
        .or_else(|| field.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex, 16).ok();
    }
    if !field.len().is_multiple_of(2) {
        return None;
    }
    let mut mask = 0u32;
    for index in (0..field.len()).step_by(2) {
        let token = field[index..index + 2].to_ascii_uppercase();
        mask |= match token.as_str() {
            // Generic.
            "GA" => 0x1000_0000,
            "GR" => 0x8000_0000,
            "GW" => 0x4000_0000,
            "GX" => 0x2000_0000,
            // Standard.
            "SD" => 0x0001_0000,
            "RC" => 0x0002_0000,
            "WD" => 0x0004_0000,
            "WO" => 0x0008_0000,
            // Object-specific bits, under their directory-service names. On a
            // filesystem object these are the FILE_* rights of the same value.
            "CC" => 0x0000_0001,
            "DC" => 0x0000_0002,
            "LC" => 0x0000_0004,
            "SW" => 0x0000_0008,
            "RP" => 0x0000_0010,
            "WP" => 0x0000_0020,
            "DT" => 0x0000_0040,
            "LO" => 0x0000_0080,
            "CR" => 0x0000_0100,
            // File and directory.
            "FA" => 0x001F_01FF,
            "FR" => 0x0012_0089,
            "FW" => 0x0012_0116,
            "FX" => 0x0012_00A0,
            // Registry, which cannot name a directory but is cheap to accept.
            "KA" => 0x000F_003F,
            "KR" | "KX" => 0x0002_0019,
            "KW" => 0x0002_0006,
            _ => return None,
        };
    }
    Some(mask)
}

/// Whether a DACL lets a local user unrelated to this product write inside the
/// object it protects.
///
/// This is the security preflight `04-security-recovery.md` requires and the
/// reason an existing root can fail an install. It is the *write* counterpart of
/// the read question [`crate::process::permissions_summary`] answers, and the
/// two differ in more than the mask: a directory whose DACL is merely readable
/// is a diagnostic, while one that is writable is an execution boundary.
///
/// Inheritance flags are ignored on purpose. An inherit-only broad ACE grants
/// nothing on the root and everything on the attempt directories created below
/// it, which is the half that matters.
#[must_use]
pub fn grants_broad_write(descriptor: &str) -> bool {
    let Some(aces) = aces(descriptor) else {
        // No DACL is not an empty DACL. Windows treats an object with no
        // discretionary access control as granting everyone everything, and
        // this is not a question to be optimistic about.
        return true;
    };
    aces.iter().any(|ace| {
        ace.is_allow()
            && BROAD_TRUSTEES
                .iter()
                .any(|broad| ace.trustee.eq_ignore_ascii_case(broad))
            && ace.grants_write()
    })
}

/// Whether a DACL carries `SE_DACL_PROTECTED`, so that nothing is inherited into
/// it from the volume root.
#[must_use]
pub fn is_protected(descriptor: &str) -> bool {
    descriptor.split("D:").nth(1).is_some_and(|body| {
        body.chars()
            .take_while(|character| *character != '(')
            .any(|character| character == 'P')
    })
}

/// Every trustee a DACL grants write access to, canonicalised.
#[must_use]
pub fn write_trustees(descriptor: &str) -> BTreeSet<String> {
    write_grants(descriptor).into_keys().collect()
}

/// The same, with what each trustee is granted.
///
/// A rights field this cannot parse contributes `u32::MAX` rather than nothing,
/// so a descriptor that cannot be read is a descriptor that never compares
/// equal to the one this module writes — which costs a rewrite and cannot cost
/// an under-reconciled root.
fn write_grants(descriptor: &str) -> BTreeMap<String, u32> {
    let mut grants: BTreeMap<String, u32> = BTreeMap::new();
    for ace in aces(descriptor).unwrap_or_default() {
        if ace.is_allow() && ace.grants_write() {
            *grants.entry(canonical_trustee(ace.trustee)).or_default() |=
                rights_mask(ace.rights).unwrap_or(u32::MAX);
        }
    }
    grants
}

/// One spelling for the two trustees that have a fixed SID.
///
/// Only those two. An account SID is machine-specific and Windows renders some
/// of them back as aliases it chose — the built-in Administrator's
/// `S-1-5-21-…-500` reads back as `LA`, which is the round trip that already
/// cost [`crate::secrets`] a bug — so no attempt is made to canonicalise one.
/// [`admits_exactly`] is written to be safe when that comparison fails.
fn canonical_trustee(trustee: &str) -> String {
    let upper = trustee.to_ascii_uppercase();
    match upper.as_str() {
        "SY" => SID_LOCAL_SYSTEM.to_owned(),
        "BA" => SID_ADMINISTRATORS.to_owned(),
        _ => upper,
    }
}

/// Whether a DACL is already exactly what [`default_root_sddl`] would write.
///
/// Used only to skip a rewrite that would change nothing. A false negative
/// costs one `SetNamedSecurityInfoW` — which is why an alias Windows substituted
/// for an account SID is allowed to produce one — and a false positive would
/// leave the root under-reconciled after a mode change, which is why the
/// comparison is equality rather than "contains what is needed".
///
/// The rights are compared as well as the trustees, and that is not
/// fastidiousness. A root that already names `SY`, `BA` and the selected
/// account but grants the third `FA` matches on trustees alone, and `FA`
/// carries the `WRITE_DAC` and `WRITE_OWNER` that [`ADMITTED_RIGHTS`] exists to
/// withhold — so accepting it would leave the admitted account able to undo the
/// protection this module applied. Masks rather than text, because Windows
/// renders `FRFWFXSD` back as `0x1301bf`.
#[must_use]
pub fn admits_exactly(descriptor: &str, admission: &RootAdmission) -> bool {
    let Some(full_control) = rights_mask("FA") else {
        return false;
    };
    if !is_protected(descriptor) {
        return false;
    }
    let mut expected: BTreeMap<String, u32> = [
        (SID_LOCAL_SYSTEM.to_owned(), full_control),
        (SID_ADMINISTRATORS.to_owned(), full_control),
    ]
    .into_iter()
    .collect();
    if let Some(sid) = admission.sid() {
        // `or_default` and `|=` rather than `insert`, because a daemon running
        // as LocalSystem names a SID the first entry already carries, and
        // `default_root_sddl` writes no second ACE for it.
        *expected.entry(canonical_trustee(sid)).or_default() |=
            rights_mask(ADMITTED_RIGHTS).unwrap_or(u32::MAX);
    }
    write_grants(descriptor) == expected
}

/// A security descriptor with account SIDs reduced to the fact that they are
/// account SIDs.
///
/// `S-1-5-21-<machine or domain>-<rid>` identifies a machine and a user. The
/// well-known trustees do not identify anything — `SY` and `BA` are the same
/// two words on every host — so they survive, and what an operator sees is the
/// *shape* of the access control without a new identity in it.
#[must_use]
pub fn redact(descriptor: &str) -> String {
    /// The authority every machine-local and domain account SID starts with.
    const PREFIX: &str = "S-1-5-21-";

    let mut out = String::with_capacity(descriptor.len());
    let mut rest = descriptor;
    while let Some(start) = rest.find(PREFIX) {
        out.push_str(&rest[..start]);
        out.push_str("S-1-5-21-<account>");
        // Past the prefix before looking for the end of the sub-authorities.
        // Resuming at `start` would find `S` — neither a digit nor a dash —
        // conclude that the SID is zero characters long, and match the same
        // prefix again on the next pass, forever.
        let tail = &rest[start + PREFIX.len()..];
        let end = tail
            .find(|character: char| !character.is_ascii_digit() && character != '-')
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why the default runner root could not be created, inspected, or reconciled.
///
/// Every variant is printed straight at an operator, so each says what to do
/// next. None carries an account SID: a message an operator pastes into an issue
/// should not be the thing that publishes their machine's identifiers, which is
/// what [`redact`] is applied for before a descriptor reaches one of these.
#[derive(Debug, thiserror::Error)]
pub enum RootAccessError {
    /// The default root could not be resolved, or failed `b1`'s preflight.
    #[error("{source}")]
    Resolve {
        /// What `b1` reported.
        #[source]
        source: Box<RunnerRootError>,
    },

    /// This process's own account could not be identified.
    #[error(
        "this account's identity could not be read, so the runner root cannot be given the \
         access a login-mode registration needs: {source}"
    )]
    Identity {
        /// What reading the process token reported.
        #[source]
        source: io::Error,
    },

    /// The root already exists and is open to ordinary local users.
    ///
    /// The refusal is the point. Tightening the directory instead would silently
    /// adopt whatever is already inside one that any local account could have
    /// created and filled, and a runner root's contents are executed.
    #[error(
        "{} already exists and grants write access to ordinary local users, so it is not a \
         safe place to run jobs: its access control is {dacl}. This is what a directory \
         created below {} with inheritance left on looks like, and it is refused rather \
         than tightened because the contents of a directory anybody could write cannot be \
         trusted. Remove or empty it and run this again, or point the runner root somewhere \
         this account controls with `{remediation}`.",
        path.display(),
        volume.display()
    )]
    BroadExistingAccess {
        /// The root.
        path: PathBuf,
        /// Its DACL, in SDDL, with account SIDs redacted.
        dacl: String,
        /// The volume the inherited grant would have come from.
        volume: PathBuf,
        /// The command that configures a different root.
        remediation: String,
    },

    /// The root does not exist and could not be created.
    #[error(
        "the default runner root {} could not be created: {source}. Create it as an \
         administrator, or configure a directory this account owns with `{remediation}`.",
        path.display()
    )]
    Create {
        /// The root.
        path: PathBuf,
        /// What the operating system reported.
        #[source]
        source: io::Error,
        /// The command that configures a different root.
        remediation: String,
    },

    /// The root exists but its access control could not be read.
    #[error(
        "the access control of the default runner root {} could not be read: {source}. \
         Without it there is no way to tell whether unrelated local users can write there, \
         so this fails closed. Read it as an administrator, or configure a directory this \
         account owns with `{remediation}`.",
        path.display()
    )]
    Inspect {
        /// The root.
        path: PathBuf,
        /// What the operating system reported.
        #[source]
        source: io::Error,
        /// The command that configures a different root.
        remediation: String,
    },

    /// The root exists and is not open, but could not be reconciled.
    #[error(
        "the access control of the default runner root {} could not be applied: {source}. \
         Changing a directory's access control needs WRITE_DAC, which this account has \
         only as its owner or as an administrator — an elevated shell is the usual answer. \
         Otherwise configure a directory this account owns with `{remediation}`.",
        path.display()
    )]
    Apply {
        /// The root.
        path: PathBuf,
        /// What the operating system reported.
        #[source]
        source: io::Error,
        /// The command that configures a different root.
        remediation: String,
    },
}

impl RootAccessError {
    /// The root the failure is about, when it is about one.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Resolve { .. } | Self::Identity { .. } => None,
            Self::BroadExistingAccess { path, .. }
            | Self::Create { path, .. }
            | Self::Inspect { path, .. }
            | Self::Apply { path, .. } => Some(path),
        }
    }
}

/// The command an operator runs to move the runner root elsewhere.
///
/// Every caller outside the tests is `reconcile`, which is Windows-only and is
/// the only place that builds an error carrying one. Named without an intra-doc
/// link for exactly that reason: off Windows there is no such item to link to.
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "only `reconcile`, which is Windows-only, builds an error that carries a remedy"
    )
)]
fn remediation() -> String {
    RootOwner::Host.remediation()
}

// ---------------------------------------------------------------------------
// What happened
// ---------------------------------------------------------------------------

/// What creating or reconciling the default runner root amounted to.
///
/// Carried out of `service install` and `service set-start-mode` so a command
/// can print it. It names trustees by [`AdmittedTrustee`] rather than by SID, so
/// printing the whole value adds no identity to the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootAccessSummary {
    /// Not a Windows host. Nothing was created and nothing was re-permissioned.
    ///
    /// macOS and Linux keep the runner root the application-data runtime
    /// directory has always been, and its permissions are the ones
    /// [`AppPaths`] already establishes. There is no inherited-broad-grant
    /// problem to solve, and inventing one would move live workspaces for no
    /// reason (`02-target-architecture.md`, "Platform defaults").
    NotApplicable,
    /// The root did not exist and was created with its access control applied by
    /// the call that created it.
    Created {
        /// The root.
        path: PathBuf,
        /// Who it admits.
        admits: Vec<AdmittedTrustee>,
    },
    /// The root existed and already admitted exactly the right trustees.
    AlreadyReconciled {
        /// The root.
        path: PathBuf,
        /// Who it admits.
        admits: Vec<AdmittedTrustee>,
    },
    /// The root existed and its access control was rewritten.
    Reconciled {
        /// The root.
        path: PathBuf,
        /// Who it admits now.
        admits: Vec<AdmittedTrustee>,
    },
}

impl RootAccessSummary {
    /// The root, when there was one.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::NotApplicable => None,
            Self::Created { path, .. }
            | Self::AlreadyReconciled { path, .. }
            | Self::Reconciled { path, .. } => Some(path),
        }
    }

    /// Whether this operation created the directory.
    #[must_use]
    pub const fn created(&self) -> bool {
        matches!(self, Self::Created { .. })
    }
}

impl fmt::Display for RootAccessSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (verb, path, admits) = match self {
            Self::NotApplicable => {
                // Said without claiming *which* root it is about. This is both
                // the macOS and Linux answer, where the root is the runtime
                // directory `AppPaths` already permissions, and the Windows
                // answer for an operation that moved nothing — and on Windows
                // the runner root is emphatically not the runtime directory.
                return f.write_str(
                    "The runner root's access control was not created or changed by this \
                     operation.",
                );
            }
            Self::Created { path, admits } => ("was created admitting", path, admits),
            Self::AlreadyReconciled { path, admits } => ("already admitted", path, admits),
            Self::Reconciled { path, admits } => ("was reconciled to admit", path, admits),
        };
        let names: Vec<String> = admits.iter().map(ToString::to_string).collect();
        write!(
            f,
            "The runner root {} {verb} {}, and inherits nothing from the volume above it, so \
             unrelated local users cannot write there.",
            path.display(),
            names.join(", ")
        )
    }
}

/// A [`RootAccessSummary`] plus what it would take to undo.
///
/// The task requires directory and ACL work to be "transactional where current
/// service installation rollback supports it". `service install` already rolls
/// back a registration when the record cannot be written, so this is the same
/// idea for the two effects this module has:
///
/// * a directory this call created can be removed again, and
/// * a descriptor this call replaced can be written back, because the previous
///   one was read first and kept.
///
/// What cannot be undone is a directory that was already there — and, per the
/// same requirement, that is *reported* rather than pretended about. See
/// [`Reversal`].
#[derive(Debug, Clone)]
pub struct RootAccessChange {
    summary: RootAccessSummary,
    /// Compiled where it is read rather than allowed where it is not.
    ///
    /// Only [`Self::revert`]'s Windows arm ever reads this, and only
    /// [`reconcile`] ever fills it. On a platform with no descriptor to put
    /// back the field is not there to be dead, so there is nothing to allow.
    /// [`crate::process`] states the rule for this shape of problem: an
    /// allowance leaves the lint's premise true and silences the report, while
    /// a `cfg` makes the premise false instead.
    #[cfg(windows)]
    previous_dacl: Option<String>,
}

impl RootAccessChange {
    /// The nothing that happens on a platform without this problem.
    #[must_use]
    pub const fn not_applicable() -> Self {
        Self {
            summary: RootAccessSummary::NotApplicable,
            #[cfg(windows)]
            previous_dacl: None,
        }
    }

    /// What happened, in a form a command can print.
    #[must_use]
    pub const fn summary(&self) -> &RootAccessSummary {
        &self.summary
    }

    /// Undoes as much of this change as can be undone, and says what could not
    /// be.
    ///
    /// Deliberately infallible in the type: a rollback runs while another
    /// failure is already being reported, and a rollback that could itself
    /// return `Err` would either hide that failure or replace it. The
    /// [`Reversal`] says what happened and the caller folds it into the message
    /// it was already writing.
    #[must_use]
    pub fn revert(&self) -> Reversal {
        #[cfg(windows)]
        {
            match &self.summary {
                RootAccessSummary::NotApplicable | RootAccessSummary::AlreadyReconciled { .. } => {
                    Reversal::NothingToUndo
                }
                RootAccessSummary::Created { path, .. } => match std::fs::remove_dir(path) {
                    Ok(()) => Reversal::Removed { path: path.clone() },
                    Err(source) if source.kind() == io::ErrorKind::NotFound => {
                        Reversal::NothingToUndo
                    }
                    Err(source) => Reversal::Retained {
                        path: path.clone(),
                        detail: format!(
                            "the directory this operation created could not be removed again \
                             ({source}); it is empty unless something else has written to it, \
                             and removing it by hand is safe"
                        ),
                    },
                },
                RootAccessSummary::Reconciled { path, .. } => {
                    let Some(previous) = self.previous_dacl.as_deref() else {
                        return Reversal::NothingToUndo;
                    };
                    match sys::write_dacl(path, previous) {
                        Ok(()) => Reversal::Restored { path: path.clone() },
                        Err(source) => Reversal::Retained {
                            path: path.clone(),
                            detail: format!(
                                "this directory existed before this operation and could not be \
                                 removed by it; its previous access control could not be put \
                                 back either ({source}), so it now carries the access control \
                                 this operation applied"
                            ),
                        },
                    }
                }
            }
        }
        #[cfg(not(windows))]
        {
            Reversal::NothingToUndo
        }
    }
}

/// What undoing a [`RootAccessChange`] achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reversal {
    /// There was nothing to undo, or nothing had been changed.
    NothingToUndo,
    /// A directory this operation created was removed again.
    Removed {
        /// The directory that is gone.
        path: PathBuf,
    },
    /// A descriptor this operation replaced was written back.
    Restored {
        /// The directory whose access control is as it was.
        path: PathBuf,
    },
    /// Something is left behind, and here is exactly what.
    ///
    /// This is the "report any non-reversible existing directory state
    /// explicitly" half of the requirement. It is never silent.
    Retained {
        /// The directory that remains.
        path: PathBuf,
        /// What about it could not be undone.
        detail: String,
    },
}

impl fmt::Display for Reversal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NothingToUndo => f.write_str("the runner root was left as it was found"),
            Self::Removed { path } => {
                write!(f, "the runner root {} was removed again", path.display())
            }
            Self::Restored { path } => write!(
                f,
                "the previous access control of {} was restored",
                path.display()
            ),
            Self::Retained { path, detail } => write!(f, "{}: {detail}", path.display()),
        }
    }
}

// ---------------------------------------------------------------------------
// Reading a root without touching it
// ---------------------------------------------------------------------------

/// What a runner root's access control amounts to, said without naming an
/// account.
///
/// The read-only half of this module, and the whole of what a **custom**
/// operator root ever gets: `03-migration-rollout.md` refuses to move or
/// re-permission a directory the operator chose, so a configured root is
/// preflighted and described, never rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootAccessReport {
    /// Not a Windows host, so there is no DACL to describe.
    NotApplicable,
    /// The directory is not there.
    Absent,
    /// The directory is there and its access control could not be read.
    Unreadable {
        /// Why not.
        detail: String,
    },
    /// The directory is there and this is what it grants.
    Present {
        /// Its DACL in SDDL, with account SIDs redacted by [`redact`].
        dacl: String,
        /// Whether it inherits nothing from the volume above it.
        protected: bool,
        /// Whether ordinary local users can write inside it.
        broad_write: bool,
    },
}

impl fmt::Display for RootAccessReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotApplicable => f.write_str("no Windows access control applies"),
            Self::Absent => f.write_str("does not exist yet"),
            Self::Unreadable { detail } => {
                write!(f, "exists, but its access control cannot be read: {detail}")
            }
            Self::Present {
                dacl,
                protected,
                broad_write,
            } => write!(
                f,
                "{}; {}; {dacl}",
                if *broad_write {
                    "ordinary local users can write there"
                } else {
                    "no ordinary local user can write there"
                },
                if *protected {
                    "inherits nothing from the volume above"
                } else {
                    "inherits from the volume above"
                }
            ),
        }
    }
}

/// Describes a runner root's access control **without changing it**.
///
/// This is what a configured custom root gets, and what `service status` reports
/// about the default one. It creates nothing, permissions nothing, and is safe
/// to call on a path this product does not own.
#[must_use]
pub fn report(path: &Path) -> RootAccessReport {
    #[cfg(windows)]
    {
        // `Path::exists` answers "absent" to every question it cannot answer,
        // including "this account may not traverse the parent". That is the one
        // answer this must not give for a directory that is there, because
        // `Absent` reads as "nothing to worry about yet" while the truthful
        // outcome is `Unreadable`, which says so.
        match std::fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return RootAccessReport::Absent;
            }
            Err(source) => {
                return RootAccessReport::Unreadable {
                    detail: source.to_string(),
                };
            }
        }
        // The reader `crate::process` already carries, rather than a second
        // descriptor round trip of this module's own.
        match crate::process::permissions_summary(path) {
            Ok(summary) => RootAccessReport::Present {
                protected: is_protected(&summary.description),
                broad_write: grants_broad_write(&summary.description),
                dacl: redact(&summary.description),
            },
            Err(source) => RootAccessReport::Unreadable {
                detail: source.to_string(),
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        RootAccessReport::NotApplicable
    }
}

// ---------------------------------------------------------------------------
// The operation
// ---------------------------------------------------------------------------

/// Creates or reconciles **the platform default** runner root.
///
/// Takes no path, and that is the design: there is no argument through which a
/// caller could aim this at an operator's configured directory. See this
/// module's documentation.
///
/// The order is the contract:
///
/// 1. resolve the platform default;
/// 2. run `b1`'s operational preflight, which mutates nothing;
/// 3. if the leaf is missing, create it **with its descriptor applied by the
///    call that creates it**, so there is no window in which it exists carrying
///    the volume's inherited grants;
/// 4. if it is already there, read its DACL and refuse if ordinary local users
///    can write inside it;
/// 5. otherwise reconcile the descriptor to admit exactly `SY`, `BA` and the
///    selected account, skipping the write when it already does.
///
/// # Errors
/// Any [`RootAccessError`]. In particular [`RootAccessError::BroadExistingAccess`]
/// when the directory is already open, which is a refusal rather than a repair.
pub fn ensure_default_root(
    paths: &AppPaths,
    admission: &RootAdmission,
) -> Result<RootAccessChange, RootAccessError> {
    #[cfg(windows)]
    {
        let root = crate::runner_root::default_runner_root(paths).map_err(|source| {
            RootAccessError::Resolve {
                source: Box::new(source),
            }
        })?;
        reconcile(paths, &root, admission)
    }
    #[cfg(not(windows))]
    {
        let _ = (paths, admission);
        Ok(RootAccessChange::not_applicable())
    }
}

/// [`ensure_default_root`] against a root the caller names.
///
/// `pub(crate)` and nothing more, so no consumer of this crate can reach it,
/// and Windows-only because every caller is: [`ensure_default_root`] and
/// [`crate::service::ServiceOperations`] both reach it from a Windows arm, so
/// on the other two platforms it is not there to be dead rather than dead and
/// allowed. [`RootAccessChange::not_applicable`] is what those platforms
/// return instead.
///
/// The only caller that passes a path other than the platform default is
/// [`crate::service::ServiceOperations::with_runner_root`], whose override is
/// honoured for a [`crate::service::ServiceIdentity::fixture`] registration or
/// under `cfg(test)` and is otherwise ignored in favour of
/// [`ensure_default_root`]. A shipped binary therefore honours the fixture name
/// alone, and a fixture name cannot be the product's — which is what keeps a
/// released `service install` pointed at the platform default whatever it is
/// handed. A privileged smoke test uses it to exercise a directory it owns
/// instead of the real `C:\rman`.
#[cfg(windows)]
pub(crate) fn reconcile(
    paths: &AppPaths,
    root: &LocalAbsolutePath,
    admission: &RootAdmission,
) -> Result<RootAccessChange, RootAccessError> {
    let checked = RootPreflight::new(paths)
        .check(&RootOwner::Host, root)
        .map_err(|source| RootAccessError::Resolve {
            source: Box::new(source),
        })?;
    let desired = default_root_sddl(admission);
    let path = root.as_path().to_path_buf();

    if checked.leaf_to_create().is_some() {
        match sys::create_with_dacl(&path, &desired) {
            Ok(()) => {
                return Ok(RootAccessChange {
                    summary: RootAccessSummary::Created {
                        path,
                        admits: admission.admits(),
                    },
                    previous_dacl: None,
                });
            }
            // Another process created it between the preflight and here.
            // Fall through and treat it as the pre-existing directory it now
            // is, which applies the same refusal to it as to any other.
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(RootAccessError::Create {
                    path,
                    source,
                    remediation: remediation(),
                });
            }
        }
    }

    let current = sys::read_dacl(&path).map_err(|source| RootAccessError::Inspect {
        path: path.clone(),
        source,
        remediation: remediation(),
    })?;

    if grants_broad_write(&current) {
        return Err(RootAccessError::BroadExistingAccess {
            dacl: redact(&current),
            volume: volume_of(&path),
            path,
            remediation: remediation(),
        });
    }

    if admits_exactly(&current, admission) {
        return Ok(RootAccessChange {
            summary: RootAccessSummary::AlreadyReconciled {
                path,
                admits: admission.admits(),
            },
            previous_dacl: None,
        });
    }

    sys::write_dacl(&path, &desired).map_err(|source| RootAccessError::Apply {
        path: path.clone(),
        source,
        remediation: remediation(),
    })?;
    Ok(RootAccessChange {
        summary: RootAccessSummary::Reconciled {
            path,
            admits: admission.admits(),
        },
        previous_dacl: Some(current),
    })
}

/// Creates a directory carrying an exact descriptor, for this crate's own tests
/// only.
///
/// [`crate::service`]'s unit tests need a runner root that is deliberately open
/// to ordinary local users, and no temporary directory is: `%TEMP%` is
/// per-account, so everything created below it is already narrow. Building the
/// case by hand is the only way to reach the refusal that matters, and it is
/// the same call [`reconcile`] makes.
#[cfg(all(test, windows))]
pub(crate) fn create_with_descriptor_for_tests(path: &Path, sddl: &str) -> io::Result<()> {
    sys::create_with_dacl(path, sddl)
}

/// The volume a path sits on, for the message that explains where an inherited
/// grant came from.
///
/// Windows-only because that message is: [`reconcile`] is the only caller, and
/// it is the item this file compiles where it is used rather than allows where
/// it is not.
#[cfg(windows)]
fn volume_of(path: &Path) -> PathBuf {
    path.ancestors()
        .last()
        .map_or_else(|| path.to_path_buf(), Path::to_path_buf)
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod sys {
    //! The three calls this module makes, and nothing else.
    //!
    //! Every one of them goes through SDDL rather than through
    //! `SetEntriesInAclW` and a hand-built ACL. That is the same choice
    //! [`crate::secrets`] and [`crate::process`] made, for the same two reasons:
    //! the descriptor a reviewer reads is the descriptor the host applies, and
    //! the unsafe surface is one conversion instead of an allocation protocol.

    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows::core::PCWSTR;

    /// A NUL-terminated wide string, as every `…W` entry point wants one.
    fn to_wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// A `windows` error as the `io::Error` this module's callers report.
    ///
    /// The facility is unwrapped rather than passed through, and that is not
    /// cosmetic. `windows-rs` reports a Win32 failure as `HRESULT_FROM_WIN32`,
    /// so `ERROR_ALREADY_EXISTS` arrives as `0x8007_00B7` — and
    /// `io::Error::from_raw_os_error` classifies the *Win32* code, which means
    /// the wrapped form reads back as [`io::ErrorKind::Uncategorized`] where
    /// the bare `183` reads back as [`io::ErrorKind::AlreadyExists`].
    /// [`super::reconcile`] branches on exactly that kind to absorb a directory
    /// created between the preflight and the creation, so leaving the facility
    /// on would make that branch unreachable.
    fn io_error(error: &windows::core::Error) -> io::Error {
        /// The high half `HRESULT_FROM_WIN32` puts in front of a Win32 code.
        const FACILITY_WIN32: u32 = 0x8007_0000;

        let hresult = error.code().0;
        let bits = hresult.cast_unsigned();
        if bits & 0xFFFF_0000 == FACILITY_WIN32 {
            io::Error::from_raw_os_error((bits & 0x0000_FFFF).cast_signed())
        } else {
            io::Error::from_raw_os_error(hresult)
        }
    }

    /// A security descriptor built from SDDL, freed when it goes out of scope.
    ///
    /// A guard rather than a `LocalFree` at each exit: the two callers below
    /// both have several, and a leak on the error path is exactly the kind of
    /// thing that is never noticed.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Descriptor {
        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
            // SAFETY: `wide` is NUL-terminated and outlives the call, which
            // fills `descriptor` with a LocalAlloc'd block this guard frees.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(wide.as_ptr()),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    None,
                )
            }
            .map_err(|error| io_error(&error))?;
            Ok(Self(descriptor))
        }

        /// The DACL inside it.
        ///
        /// The pointer is into the descriptor this guard owns, so it is only
        /// valid while `self` is.
        fn dacl(&self) -> io::Result<*const ACL> {
            let mut present = windows::core::BOOL(0);
            let mut acl: *mut ACL = std::ptr::null_mut();
            let mut defaulted = windows::core::BOOL(0);
            // SAFETY: `self.0` is a valid descriptor for the lifetime of `self`;
            // the three out-parameters are live locals.
            unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted) }
                .map_err(|error| io_error(&error))?;
            if !present.as_bool() || acl.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the security descriptor built from SDDL carries no DACL",
                ));
            }
            Ok(acl.cast_const())
        }
    }

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: LocalAlloc'd by the conversion above, freed exactly once.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }

    /// Creates a directory that carries its access control from the moment it
    /// exists.
    ///
    /// Not `create_dir` followed by a descriptor write. The gap between those
    /// two is a directory sitting on `C:\` with the volume's inherited grants,
    /// and a local account that loses that race gets a workspace root it can
    /// write into. The same reasoning `crate::process::RestrictiveHandoff`
    /// applies to the JIT configuration file applies here.
    pub(super) fn create_with_dacl(path: &Path, sddl: &str) -> io::Result<()> {
        let descriptor = Descriptor::from_sddl(sddl)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: windows::core::BOOL(0),
        };
        let wide = to_wide(path.as_os_str());
        // SAFETY: `wide` is NUL-terminated, and `attributes` points at a
        // descriptor that outlives the call.
        unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&raw const attributes)) }
            .map_err(|error| io_error(&error))
    }

    /// The DACL a directory carries, in SDDL.
    ///
    /// Goes through the reader [`crate::process`] already has rather than
    /// repeating its `GetNamedSecurityInfoW` round trip: one implementation of
    /// "read a DACL back" means one place where the descriptor is freed
    /// correctly, and it is already exercised by that module's own tests.
    pub(super) fn read_dacl(path: &Path) -> io::Result<String> {
        crate::process::permissions_summary(path)
            .map(|summary| summary.description)
            .map_err(|error| io::Error::other(error.to_string()))
    }

    /// Replaces a directory's DACL, honouring whether the SDDL asks for
    /// protection.
    ///
    /// The flag is read from the descriptor rather than hard-coded, because this
    /// is also the call that puts back a DACL that was **not** protected when a
    /// reconciliation is rolled back. Writing that one back as protected would
    /// leave the directory in a third state that was never true.
    pub(super) fn write_dacl(path: &Path, sddl: &str) -> io::Result<()> {
        let descriptor = Descriptor::from_sddl(sddl)?;
        let acl = descriptor.dacl()?;
        let information = DACL_SECURITY_INFORMATION
            | if super::is_protected(sddl) {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
        let wide = to_wide(path.as_os_str());
        // SAFETY: `wide` is NUL-terminated; `acl` points into `descriptor`,
        // which is still alive; the two SID parameters are deliberately absent,
        // so ownership is not touched.
        let status = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                information,
                None,
                None,
                Some(acl),
                None,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(
                i32::try_from(status.0).unwrap_or(i32::MAX),
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io;

        /// [`super::super::reconcile`] absorbs a directory created between the
        /// preflight and the creation by matching on
        /// [`io::ErrorKind::AlreadyExists`]. That branch is reachable only if
        /// [`super::io_error`] unwraps `HRESULT_FROM_WIN32`, so the mapping is
        /// pinned here against a failure Windows itself produced rather than
        /// against a constant this file chose.
        #[test]
        fn a_directory_that_already_exists_reads_back_as_already_exists() {
            let directory = tempfile::tempdir().expect("a temporary directory");
            let error = super::create_with_dacl(directory.path(), "D:P(A;OICI;FA;;;SY)")
                .expect_err("creating a directory that is already there fails");
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The DACL of `C:\` on a stock Windows host, near enough. The ACE that
    /// matters is the last one: inherit-only, Authenticated Users, delete plus
    /// generic write. Everything created below `C:\` without protection gets it.
    const VOLUME_ROOT: &str = "D:PAI(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;FA;;;BA)(A;OICIIO;GA;;;BA)\
                               (A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;;LC;;;BU)(A;CI;DC;;;BU)\
                               (A;;0x1301bf;;;AU)(A;OICIIO;SDGXGWGR;;;AU)";

    /// What a directory created below `C:\` with inheritance left on ends up
    /// carrying, as `GetNamedSecurityInfoW` renders it back.
    const INHERITED_FROM_VOLUME: &str =
        "D:AI(A;OICIID;GA;;;SY)(A;OICIID;GA;;;BA)(A;OICIID;GXGR;;;BU)(A;OICIID;SDGXGWGR;;;AU)";

    fn account() -> RootAdmission {
        RootAdmission::Account("S-1-5-21-1-2-3-1001".to_owned())
    }

    // -- the descriptor -----------------------------------------------------

    #[test]
    fn a_boot_root_admits_system_and_administrators_and_nothing_else() {
        assert_eq!(
            default_root_sddl(&RootAdmission::LocalSystem),
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        );
    }

    #[test]
    fn a_login_root_admits_the_selected_account_with_modify_rather_than_full_control() {
        assert_eq!(
            default_root_sddl(&account()),
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFWFXSD;;;S-1-5-21-1-2-3-1001)"
        );
        // The two rights that would let the admitted account undo the
        // protection are exactly the two it does not get.
        let mask = rights_mask(ADMITTED_RIGHTS).expect("the constant parses");
        assert_eq!(mask & 0x0004_0000, 0, "WRITE_DAC must not be granted");
        assert_eq!(mask & 0x0008_0000, 0, "WRITE_OWNER must not be granted");
        // And everything create-materialize-clean needs is.
        for (bit, name) in [
            (0x0000_0002, "FILE_WRITE_DATA"),
            (0x0000_0004, "FILE_APPEND_DATA"),
            (0x0001_0000, "DELETE"),
            (0x0000_0001, "FILE_READ_DATA"),
        ] {
            assert_ne!(mask & bit, 0, "{name} must be granted");
        }
    }

    #[test]
    fn a_daemon_running_as_local_system_does_not_add_an_ace_for_itself() {
        // `current_user_sid()` under a boot service answers S-1-5-18, which the
        // first ACE already names.
        let as_system = RootAdmission::Account("S-1-5-18".to_owned());
        assert_eq!(
            default_root_sddl(&as_system),
            default_root_sddl(&RootAdmission::LocalSystem)
        );
        let as_administrators = RootAdmission::Account("s-1-5-32-544".to_owned());
        assert_eq!(
            default_root_sddl(&as_administrators),
            default_root_sddl(&RootAdmission::LocalSystem)
        );
    }

    #[test]
    fn every_ace_the_default_writes_is_inherited_by_children() {
        // A service that could create `<root>\<attempt>` but not write inside it
        // would satisfy a descriptor review and fail the first job.
        for admission in [RootAdmission::LocalSystem, account()] {
            let sddl = default_root_sddl(&admission);
            for ace in sddl.split('(').skip(1) {
                let flags = ace.split(';').nth(1).expect("an ACE has a flags field");
                assert_eq!(flags, INHERITANCE, "in {sddl}");
            }
        }
    }

    // -- the security preflight ---------------------------------------------

    #[test]
    fn the_descriptor_this_module_writes_grants_no_broad_write() {
        for admission in [RootAdmission::LocalSystem, account()] {
            let sddl = default_root_sddl(&admission);
            assert!(!grants_broad_write(&sddl), "{sddl}");
            assert!(is_protected(&sddl), "{sddl}");
        }
    }

    #[test]
    fn a_root_that_inherited_the_volumes_grants_is_broadly_writable() {
        // The whole reason this module exists, in one assertion.
        assert!(grants_broad_write(INHERITED_FROM_VOLUME));
        assert!(!is_protected(INHERITED_FROM_VOLUME));
        assert!(grants_broad_write(VOLUME_ROOT));
    }

    #[test]
    fn the_directory_service_spellings_of_create_file_and_create_folder_are_caught() {
        // `LC` is 0x4 — FILE_ADD_SUBDIRECTORY — and `DC` is 0x2 —
        // FILE_ADD_FILE. Matching on the letters rather than the bits would
        // have read them as "list children" and "delete child" and missed the
        // grant entirely.
        assert!(grants_broad_write("D:P(A;OICI;LC;;;BU)"));
        assert!(grants_broad_write("D:P(A;OICI;DC;;;BU)"));
        // `CC` is 0x1, which on a directory is FILE_LIST_DIRECTORY: a read.
        assert!(!grants_broad_write("D:P(A;OICI;CC;;;BU)"));
    }

    #[test]
    fn a_broad_read_only_grant_is_not_a_write_grant() {
        // Deliberately different from `process::permissions_summary`'s question.
        // A world-readable runner root is untidy; a world-writable one is a
        // code-execution boundary, and only the second refuses an install.
        assert!(!grants_broad_write("D:P(A;OICI;FA;;;SY)(A;OICI;FR;;;WD)"));
        assert!(!grants_broad_write("D:P(A;OICI;FA;;;SY)(A;OICI;GR;;;AU)"));
        assert!(!grants_broad_write("D:P(A;OICI;FA;;;SY)(A;OICI;FX;;;BU)"));
    }

    #[test]
    fn a_hexadecimal_rights_field_is_read_as_bits() {
        // 0x1301bf is the "modify" mask Windows writes at `C:\` for
        // Authenticated Users; it contains FILE_WRITE_DATA.
        assert!(grants_broad_write("D:P(A;;0x1301bf;;;AU)"));
        // 0x1200a9 is read-and-execute, which is not a write grant.
        assert!(!grants_broad_write("D:P(A;;0x1200a9;;;BU)"));
    }

    #[test]
    fn a_deny_ace_naming_everyone_is_a_tightening_not_a_leak() {
        assert!(!grants_broad_write("D:P(D;OICI;FA;;;WD)(A;OICI;FA;;;SY)"));
    }

    #[test]
    fn an_unparseable_or_missing_descriptor_fails_closed() {
        assert!(
            grants_broad_write("O:BAG:BA"),
            "no DACL is not an empty DACL"
        );
        assert!(grants_broad_write("D:P(A;OICI;QQ;;;WD)"), "unknown rights");
        assert!(grants_broad_write("D:P(A;OICI;FAX;;;AU)"), "odd length");
        assert!(grants_broad_write("D:P(A;OICI;0xzz;;;AU)"), "bad hex");
        assert!(
            grants_broad_write("D:NO_ACCESS_CONTROL"),
            "a NULL DACL grants everyone everything; read as a flags field it would otherwise \
             parse to zero ACEs and be adopted as the narrowest directory on the machine"
        );
        assert!(!is_protected("D:NO_ACCESS_CONTROL"));
        assert!(write_trustees("D:NO_ACCESS_CONTROL").is_empty());
    }

    #[test]
    fn a_creator_owner_grant_is_not_a_grant_to_an_unrelated_user() {
        // Inherited, `CO` gives each child's creator rights over that child.
        assert!(!grants_broad_write("D:P(A;OICI;FA;;;SY)(A;OICIIO;GA;;;CO)"));
    }

    #[test]
    fn an_inherit_only_broad_ace_still_counts() {
        // It grants nothing on the root and everything on every attempt
        // directory created below it, which is the half that matters.
        assert!(grants_broad_write("D:P(A;OICIIO;GW;;;AU)"));
    }

    // -- reconciliation ------------------------------------------------------

    #[test]
    fn a_root_already_carrying_this_modules_descriptor_needs_no_rewrite() {
        for admission in [RootAdmission::LocalSystem, account()] {
            let sddl = default_root_sddl(&admission);
            assert!(admits_exactly(&sddl, &admission), "{sddl}");
        }
    }

    #[test]
    fn a_mode_change_is_visible_as_a_descriptor_that_no_longer_matches() {
        // Boot to login must add the account, and login to boot must drop it:
        // `04-security-recovery.md` requires the selected identity to be
        // reconciled when service mode changes, in both directions.
        let boot = default_root_sddl(&RootAdmission::LocalSystem);
        let login = default_root_sddl(&account());
        assert!(!admits_exactly(&boot, &account()));
        assert!(!admits_exactly(&login, &RootAdmission::LocalSystem));
    }

    #[test]
    fn a_root_that_admits_a_second_account_does_not_match() {
        let extra = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFWFXSD;;;S-1-5-21-1-2-3-1001)\
                     (A;OICI;FRFWFXSD;;;S-1-5-21-1-2-3-1002)";
        assert!(!admits_exactly(extra, &account()));
    }

    #[test]
    fn a_root_that_grants_the_account_full_control_is_reconciled_rather_than_accepted() {
        // The trustees are exactly right and the rights are not: `FA` carries
        // `WRITE_DAC` and `WRITE_OWNER`, the two the admitted account must not
        // have, because either one lets it undo the protection. Matching on
        // trustees alone would adopt this and leave the root re-openable by the
        // account it exists to constrain.
        let too_much = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)";
        assert!(!grants_broad_write(too_much), "no broad trustee is named");
        assert_eq!(
            write_trustees(too_much),
            write_trustees(&default_root_sddl(&account()))
        );
        assert!(!admits_exactly(too_much, &account()), "{too_much}");
    }

    #[test]
    fn windows_own_spelling_of_the_admitted_rights_still_matches() {
        // `FRFWFXSD` is not a form the converter hands back; it renders the
        // same mask as `0x1301bf`. Comparing the text rather than the bits
        // would rewrite the descriptor on every single install.
        let rendered = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-21-1-2-3-1001)";
        assert!(admits_exactly(rendered, &account()), "{rendered}");
    }

    #[test]
    fn an_unprotected_root_never_matches_however_narrow_it_looks() {
        let narrow = "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)";
        assert!(!grants_broad_write(narrow), "nothing broad is granted");
        assert!(
            !admits_exactly(narrow, &RootAdmission::LocalSystem),
            "but it still inherits, so it is reconciled rather than accepted"
        );
    }

    #[test]
    fn the_two_well_known_trustees_compare_equal_in_either_spelling() {
        let aliases = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        let sids = "D:P(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)";
        assert_eq!(write_trustees(aliases), write_trustees(sids));
        assert!(admits_exactly(sids, &RootAdmission::LocalSystem));
    }

    #[test]
    fn an_account_alias_windows_substituted_is_reconciled_rather_than_trusted() {
        // Windows renders the built-in Administrator's S-1-5-21-…-500 back as
        // `LA` — the round trip that already cost the secret store a bug. This
        // module cannot resolve that, so it declines to claim a match and pays
        // for one redundant descriptor write instead.
        let substituted = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFWFXSD;;;LA)";
        assert!(!grants_broad_write(substituted));
        assert!(!admits_exactly(
            substituted,
            &RootAdmission::Account("S-1-5-21-1-2-3-500".to_owned())
        ));
    }

    // -- reporting -----------------------------------------------------------

    #[test]
    fn redaction_removes_the_machine_and_the_user_from_an_account_sid() {
        let redacted = redact(
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFWFXSD;;;S-1-5-21-4004-77-9-1001)",
        );
        assert_eq!(
            redacted,
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFWFXSD;;;S-1-5-21-<account>)"
        );
        assert!(!redacted.contains("4004"), "{redacted}");
        assert!(!redacted.contains("1001"), "{redacted}");
    }

    #[test]
    fn redaction_keeps_the_well_known_trustees_that_identify_nobody() {
        // `SY` and `S-1-5-18` are the same two words on every host, and
        // `service status` already prints the first of them.
        let descriptor = "D:P(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)";
        assert_eq!(redact(descriptor), descriptor);
    }

    #[test]
    fn redaction_handles_several_accounts_and_a_trailing_one() {
        assert_eq!(
            redact("(A;;FA;;;S-1-5-21-1-2-3-1001)(A;;FA;;;S-1-5-21-9-8-7-1002)"),
            "(A;;FA;;;S-1-5-21-<account>)(A;;FA;;;S-1-5-21-<account>)"
        );
        assert_eq!(redact("S-1-5-21-1-2-3-1001"), "S-1-5-21-<account>");
    }

    #[test]
    fn a_summary_names_trustees_without_naming_an_account() {
        let summary = RootAccessSummary::Created {
            path: PathBuf::from("C:\\rman"),
            admits: account().admits(),
        };
        let rendered = summary.to_string();
        assert!(rendered.contains("C:\\rman"), "{rendered}");
        assert!(rendered.contains("the invoking user"), "{rendered}");
        assert!(!rendered.contains("S-1-5-21"), "{rendered}");
        assert!(summary.created());
    }

    #[test]
    fn a_boot_summary_does_not_claim_to_admit_an_invoking_user() {
        let rendered = RootAccessSummary::Reconciled {
            path: PathBuf::from("C:\\rman"),
            admits: RootAdmission::LocalSystem.admits(),
        }
        .to_string();
        assert!(!rendered.contains("the invoking user"), "{rendered}");
        assert!(rendered.contains("NT AUTHORITY\\SYSTEM"), "{rendered}");
    }

    #[test]
    fn a_reversal_that_left_something_behind_says_so() {
        let retained = Reversal::Retained {
            path: PathBuf::from("C:\\rman"),
            detail: "it existed before this operation".to_owned(),
        };
        assert!(retained.to_string().contains("existed before"));
        assert_ne!(retained, Reversal::NothingToUndo);
    }

    #[test]
    fn a_not_applicable_change_reverts_to_nothing() {
        let change = RootAccessChange::not_applicable();
        assert_eq!(change.summary(), &RootAccessSummary::NotApplicable);
        assert_eq!(change.revert(), Reversal::NothingToUndo);
        assert_eq!(change.summary().path(), None);
    }

    #[test]
    fn the_broad_access_refusal_names_the_path_the_volume_and_the_remedy() {
        let error = RootAccessError::BroadExistingAccess {
            path: PathBuf::from("C:\\rman"),
            dacl: redact(INHERITED_FROM_VOLUME),
            volume: PathBuf::from("C:\\"),
            remediation: remediation(),
        };
        let message = error.to_string();
        assert!(message.contains("C:\\rman"), "{message}");
        assert!(message.contains("host set-runtime-root"), "{message}");
        assert!(
            message.contains("refused rather than tightened"),
            "an operator has to be told why it was not simply fixed: {message}"
        );
        assert_eq!(error.path(), Some(Path::new("C:\\rman")));
    }

    // -- platform behaviour --------------------------------------------------

    #[cfg(not(windows))]
    #[test]
    fn nothing_is_created_or_re_permissioned_off_windows() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(root.path());
        let change =
            ensure_default_root(&paths, &RootAdmission::LocalSystem).expect("a no-op succeeds");
        assert_eq!(change.summary(), &RootAccessSummary::NotApplicable);
        assert_eq!(report(root.path()), RootAccessReport::NotApplicable);
    }

    #[cfg(windows)]
    #[test]
    fn a_directory_this_process_created_is_reported_as_narrow() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let directory = root.path().join("narrow");
        let admission = RootAdmission::of_this_account().expect("this process has an account");
        let checked = LocalAbsolutePath::new(directory.to_str().expect("a unicode temp path"))
            .expect("a local absolute path");
        // A separate application-data tree, so `b1`'s overlap check has nothing
        // to object to.
        let elsewhere = tempfile::tempdir().expect("a second temporary directory");
        let app_paths = AppPaths::rooted_at(elsewhere.path());

        let change = reconcile(&app_paths, &checked, &admission).expect("creation succeeds");
        assert!(change.summary().created(), "{:?}", change.summary());

        match report(&directory) {
            RootAccessReport::Present {
                protected,
                broad_write,
                dacl,
            } => {
                assert!(protected, "{dacl}");
                assert!(!broad_write, "{dacl}");
                assert!(!dacl.contains("S-1-5-21-1"), "unredacted account: {dacl}");
            }
            other => panic!("expected a readable descriptor, got {other:?}"),
        }
        let after_creation = read_back(&directory);

        // A second pass creates nothing, and reverting it removes nothing,
        // because there is nothing of this call's to remove.
        //
        // Whether it also *rewrites* the descriptor is a property of the host
        // rather than of this code, so it is deliberately not asserted here.
        // `admits_exactly` compares SDDL text, and Windows renders an account
        // whose RID has an alias back as that alias -- the built-in
        // administrator's `S-1-5-21-...-500` reads back as `LA`. This module
        // declines to claim a match it cannot resolve and pays for one
        // redundant write instead, which is what a CI host running as that
        // account did while a developer host running as an ordinary one did
        // not. Both outcomes are correct; only removing the directory would
        // not be.
        // `an_account_alias_windows_substituted_is_reconciled_rather_than_trusted`
        // pins that decision purely. What holds on every host, and is asserted
        // instead, is that neither outcome changes anything: the directory
        // survives and still carries the descriptor creation wrote.
        let again = reconcile(&app_paths, &checked, &admission).expect("a second pass succeeds");
        assert!(!again.summary().created(), "{:?}", again.summary());
        // Read back BEFORE reverting. A rewriting second pass keeps the
        // descriptor it read as `previous_dacl`, so reverting puts
        // `after_creation` back whatever it wrote — asserting only afterwards
        // would pass however wrong that write had been.
        //
        // Compared by what it grants rather than by its exact text, for the
        // reason `reverting_a_reconciliation_puts_the_previous_descriptor_back`
        // gives: `SetNamedSecurityInfoW` records that it ran the
        // auto-inheritance algorithm by adding `AI` to the control flags, so a
        // host that took the rewriting branch reads back as `D:PAI` where
        // `CreateDirectoryW` wrote `D:P`. Demanding the same characters would
        // fail on exactly the host the comment above describes.
        assert_same_grants(
            &read_back(&directory),
            &after_creation,
            "a second pass must leave the descriptor granting what creation wrote",
        );
        let reversal = again.revert();
        assert!(
            matches!(
                reversal,
                Reversal::NothingToUndo | Reversal::Restored { .. }
            ),
            "a second pass has nothing of its own to undo: {reversal:?}"
        );
        assert!(directory.is_dir(), "the second pass must not remove it");
        assert_same_grants(
            &read_back(&directory),
            &after_creation,
            "and reverting it must leave those grants alone",
        );

        // The child a runner attempt would be, created and cleaned as this
        // account.
        let child = directory.join("s1");
        std::fs::create_dir(&child).expect("a child below the root");
        std::fs::write(child.join("marker"), b"job").expect("content inside the child");
        std::fs::remove_dir_all(&child).expect("the child is removable again");
    }

    #[cfg(windows)]
    #[test]
    fn an_existing_broad_directory_is_refused_rather_than_tightened() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let directory = root.path().join("open");
        // Explicitly broad, without depending on what the temp directory
        // happens to inherit on this machine.
        sys::create_with_dacl(&directory, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)")
            .expect("a deliberately open directory");
        let before = read_back(&directory);
        assert!(grants_broad_write(&before), "{before}");

        let elsewhere = tempfile::tempdir().expect("a second temporary directory");
        let app_paths = AppPaths::rooted_at(elsewhere.path());
        let checked = LocalAbsolutePath::new(directory.to_str().expect("a unicode temp path"))
            .expect("a local absolute path");

        let error = reconcile(&app_paths, &checked, &RootAdmission::LocalSystem)
            .expect_err("an open directory is refused");
        assert!(
            matches!(error, RootAccessError::BroadExistingAccess { .. }),
            "{error}"
        );
        // And it was refused rather than repaired: the directory is untouched.
        assert_eq!(read_back(&directory), before);
    }

    #[cfg(windows)]
    #[test]
    fn reverting_a_reconciliation_puts_the_previous_descriptor_back() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let directory = root.path().join("narrow");
        let admission = RootAdmission::of_this_account().expect("this process has an account");
        let sid = admission
            .sid()
            .expect("an ordinary account has a SID")
            .to_owned();
        // Narrow enough to pass the preflight, but not what this module writes.
        // Named for this account so that an unelevated test run can still read
        // the descriptor back; the previous DACL is restorable either way,
        // because the owner of a directory implicitly holds WRITE_DAC.
        sys::create_with_dacl(&directory, &format!("D:P(A;OICI;FA;;;{sid})"))
            .expect("a narrow directory");
        let before = read_back(&directory);
        assert!(!grants_broad_write(&before), "{before}");

        let elsewhere = tempfile::tempdir().expect("a second temporary directory");
        let app_paths = AppPaths::rooted_at(elsewhere.path());
        let checked = LocalAbsolutePath::new(directory.to_str().expect("a unicode temp path"))
            .expect("a local absolute path");

        let change =
            reconcile(&app_paths, &checked, &admission).expect("a narrow directory is reconciled");
        assert!(matches!(
            change.summary(),
            RootAccessSummary::Reconciled { .. }
        ));
        assert_ne!(read_back(&directory), before, "it was actually rewritten");

        assert_eq!(
            change.revert(),
            Reversal::Restored {
                path: directory.clone()
            }
        );
        // Compared by what it grants rather than by its exact text.
        // `SetNamedSecurityInfoW` records that it ran the auto-inheritance
        // algorithm by adding `AI` to the control flags, so a descriptor
        // written back through it reads as `D:PAI` where the original —
        // applied by `CreateDirectoryW` — read as `D:P`. The protection and
        // every ACE are identical, which is what "put back" has to mean.
        let after = read_back(&directory);
        assert_eq!(aces_of(&after), aces_of(&before), "{after} vs {before}");
        assert!(is_protected(&after), "{after}");
        assert!(
            directory.is_dir(),
            "a pre-existing directory is never removed"
        );
    }

    /// A descriptor from its first ACE onwards, for a comparison that ignores
    /// the control flags Windows maintains for itself.
    #[cfg(windows)]
    fn aces_of(descriptor: &str) -> &str {
        descriptor
            .find('(')
            .map_or(descriptor, |start| &descriptor[start..])
    }

    /// Two descriptors grant the same thing, whoever wrote them.
    ///
    /// The same comparison [`aces_of`] exists for: every ACE identical and the
    /// protection still in force, without demanding the `AI` control flag that
    /// `SetNamedSecurityInfoW` adds and `CreateDirectoryW` does not.
    #[cfg(windows)]
    fn assert_same_grants(actual: &str, expected: &str, context: &str) {
        assert_eq!(
            aces_of(actual),
            aces_of(expected),
            "{context}: {actual} vs {expected}"
        );
        assert!(is_protected(actual), "{context}: {actual}");
    }

    #[cfg(windows)]
    #[test]
    fn reverting_a_creation_removes_the_directory_it_created() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let directory = root.path().join("created");
        let elsewhere = tempfile::tempdir().expect("a second temporary directory");
        let app_paths = AppPaths::rooted_at(elsewhere.path());
        let checked = LocalAbsolutePath::new(directory.to_str().expect("a unicode temp path"))
            .expect("a local absolute path");
        // The login and foreground admission, which is the one an unelevated
        // caller can roll back: `ADMITTED_RIGHTS` carries `SD`, and creating a
        // directory does not by itself confer the right to delete it again.
        let admission = RootAdmission::of_this_account().expect("this process has an account");

        let change = reconcile(&app_paths, &checked, &admission).expect("creation succeeds");
        assert!(directory.is_dir());
        assert_eq!(
            change.revert(),
            Reversal::Removed {
                path: directory.clone()
            }
        );
        assert!(!directory.exists(), "the rollback is a real rollback");
    }

    #[cfg(windows)]
    #[test]
    fn a_rollback_that_cannot_finish_reports_what_it_left_behind() {
        // The boot admission names only `SY` and `BA`, so an unelevated caller
        // creating one cannot delete it again — the owner of a directory holds
        // WRITE_DAC implicitly but not DELETE. That is a real outcome rather
        // than a contrived one, and the requirement is that it is *reported*
        // rather than swallowed. An elevated run has `BA` and takes the
        // `Removed` branch above, so both are accepted here.
        let root = tempfile::tempdir().expect("a temporary directory");
        let directory = root.path().join("boot-owned");
        let elsewhere = tempfile::tempdir().expect("a second temporary directory");
        let app_paths = AppPaths::rooted_at(elsewhere.path());
        let checked = LocalAbsolutePath::new(directory.to_str().expect("a unicode temp path"))
            .expect("a local absolute path");

        let change = reconcile(&app_paths, &checked, &RootAdmission::LocalSystem)
            .expect("creation succeeds");
        match change.revert() {
            Reversal::Removed { path } => assert_eq!(path, directory),
            Reversal::Retained { path, detail } => {
                assert_eq!(path, directory);
                assert!(
                    detail.contains("removing it by hand is safe"),
                    "a non-reversible state must say what to do about it: {detail}"
                );
            }
            other => panic!("expected a removal or an explicit retention, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_custom_root_is_described_without_being_changed() {
        // `report` is the whole of what a configured operator root gets.
        let root = tempfile::tempdir().expect("a temporary directory");
        let directory = root.path().join("operators-own");
        sys::create_with_dacl(&directory, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)")
            .expect("an operator directory this product did not create");
        let before = read_back(&directory);

        match report(&directory) {
            RootAccessReport::Present { broad_write, .. } => assert!(broad_write),
            other => panic!("expected a readable descriptor, got {other:?}"),
        }
        assert_eq!(read_back(&directory), before, "reporting must not rewrite");
    }

    #[cfg(windows)]
    #[test]
    fn an_absent_directory_reports_absent() {
        let root = tempfile::tempdir().expect("a temporary directory");
        assert_eq!(
            report(&root.path().join("nothing")),
            RootAccessReport::Absent
        );
    }

    #[cfg(windows)]
    fn read_back(path: &Path) -> String {
        sys::read_dacl(path).expect("this process can read the descriptor it just wrote")
    }
}
